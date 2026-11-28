package cli

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/discordacl"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/service"
)

var errACLDeclined = errors.New("ACL change declined")

func init() {
	acl := &cobra.Command{Use: "acl", Short: "Manage live Discord access for installed modules"}
	show := &cobra.Command{
		Use:   "show <module>",
		Short: "Show a module's current Discord access",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return showACL(cmd, args[0])
		},
	}
	jsonOutputFlag(show)
	acl.AddCommand(show, &cobra.Command{
		Use:   "set <module>",
		Short: "Change a module's Discord access without restarting it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setACL(cmd, args[0])
		},
	})
	addOperatorCommands("modules", acl)
}

func aclControl(ctx context.Context, dir, op string, query discordacl.Query, result any) error {
	payload, err := json.Marshal(query)
	if err != nil {
		return err
	}
	response, err := service.Control(ctx, dir, op, payload)
	if err != nil || result == nil {
		return err
	}
	if err := json.Unmarshal(response, result); err != nil {
		return fmt.Errorf("decode %s response: %w", op, err)
	}
	return nil
}

func showACL(cmd *cobra.Command, module string) error {
	dir, err := install.Directory()
	if err != nil {
		return err
	}
	var status discordacl.Status
	if err := aclControl(cmd.Context(), dir, discordacl.Show, discordacl.Query{Module: module}, &status); err != nil {
		return err
	}
	view, human := operatorOutput(cmd)
	if !human {
		return printJSON(cmd, status)
	}
	return view.detail("Discord access", aclStatusText(status))
}

func aclStatusText(status discordacl.Status) string {
	if !status.Managed {
		return "Existing approved configuration"
	}
	if len(status.Policy.Scopes) == 0 {
		return "No access"
	}
	labels := make([]string, len(status.Policy.Scopes))
	for i, scope := range status.Policy.Scopes {
		kind, id := "Server", scope.GuildID
		if scope.ChannelID != "" {
			kind, id = "Channel", scope.GuildID+"/"+scope.ChannelID
		}
		labels[i] = kind + " " + id
		if i < len(status.Labels) && status.Labels[i] != "" {
			labels[i] = fmt.Sprintf("%s %q [%s]", kind, status.Labels[i], id)
		}
	}
	return strings.Join(labels, ", ")
}

func setACL(cmd *cobra.Command, module string) error {
	stdin, inputTTY := aclTerminal(cmd.InOrStdin())
	if _, outputTTY := aclTerminal(cmd.ErrOrStderr()); !inputTTY || !outputTTY {
		return errors.New("acl set requires an interactive terminal")
	}
	dir, err := install.Directory()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	prompt := aclPrompt{ctx: ctx, input: bufio.NewReader(stdin), view: commandView(cmd, cmd.ErrOrStderr())}
	query, err := prompt.review(dir, module)
	if errors.Is(err, errACLDeclined) || ctx.Err() != nil {
		if _, err := fmt.Fprintln(prompt.view.out); err != nil {
			return err
		}
		return prompt.view.log(logInfo, "ACL unchanged.")
	}
	if err != nil {
		return err
	}
	if err := aclControl(ctx, dir, discordacl.Apply, query, nil); err != nil {
		return err
	}
	return prompt.view.log(logInfo, fmt.Sprintf("Updated %q without restarting it.", module))
}

func aclTerminal(stream any) (*os.File, bool) {
	f, ok := stream.(*os.File)
	return f, ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}

type aclPrompt struct {
	ctx   context.Context
	input *bufio.Reader
	view  terminalView
}

func (p aclPrompt) review(dir, module string) (discordacl.Query, error) {
	policy, err := p.selectPolicy(dir, module)
	if err != nil {
		return discordacl.Query{}, err
	}
	query := discordacl.Query{Module: module, Policy: policy}
	var plan discordacl.Plan
	if err := aclControl(p.ctx, dir, discordacl.Preview, query, &plan); err != nil {
		return discordacl.Query{}, err
	}
	if plan.Digest == "" {
		return discordacl.Query{}, errors.New("ACL preview did not include an approval digest")
	}
	if err := p.view.detail("Before", aclStatusText(plan.Before)); err != nil {
		return discordacl.Query{}, err
	}
	if err := p.view.detail("After", aclStatusText(plan.After)); err != nil {
		return discordacl.Query{}, err
	}
	if err := p.confirm(); err != nil {
		return discordacl.Query{}, err
	}
	query.Approval = plan.Digest
	return query, nil
}

func (p aclPrompt) confirm() error {
	if _, err := fmt.Fprintf(p.view.out, "      Apply now? %s: ", p.view.paint("[y/N]", "1;33")); err != nil {
		return err
	}
	answer, err := p.line()
	if err != nil {
		return err
	}
	if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
		return errACLDeclined
	}
	return nil
}

func (p aclPrompt) selectPolicy(dir, module string) (discordacl.Policy, error) {
	const noAccess, selectedServers, allCurrentServers = 0, 2, 3
	var policy discordacl.Policy
	if err := p.view.detail("Scope", "1) No access / 2) Selected channels / 3) Selected servers / 4) All current servers"); err != nil {
		return policy, err
	}
	scope, err := p.numbers(4, false)
	if err != nil || scope[0] == noAccess {
		return policy, err
	}
	query := discordacl.Query{Module: module}
	var guilds []discordacl.Choice
	if err := aclControl(p.ctx, dir, discordacl.Guilds, query, &guilds); err != nil {
		return policy, err
	}
	if scope[0] == allCurrentServers {
		if len(guilds) > discordacl.MaxScopes {
			return policy, fmt.Errorf("the bot belongs to more than %d servers; choose Selected servers instead", discordacl.MaxScopes)
		}
		policy.Scopes = make([]discordacl.Scope, 0, len(guilds))
		for _, guild := range guilds {
			policy.Scopes = append(policy.Scopes, discordacl.Scope{GuildID: guild.ID})
		}
		return policy, nil
	}
	if len(guilds) == 0 {
		return policy, errors.New("the bot has no accessible Discord servers")
	}
	selected, err := p.pick("Servers", guilds, false)
	if err != nil {
		return policy, err
	}
	for _, i := range selected {
		guild := guilds[i]
		if scope[0] == selectedServers {
			policy.Scopes = append(policy.Scopes, discordacl.Scope{GuildID: guild.ID})
			continue
		}
		query.GuildID = guild.ID
		var channels []discordacl.Choice
		if err := aclControl(p.ctx, dir, discordacl.Channels, query, &channels); err != nil {
			return policy, err
		}
		if len(channels) == 0 {
			return policy, fmt.Errorf("no accessible Discord channels in %q", aclChoiceName(guild))
		}
		selected, err := p.pick("Channels in "+safeTerminalText(aclChoiceName(guild)), channels, true)
		if err != nil {
			return policy, err
		}
		for _, j := range selected {
			policy.Scopes = append(policy.Scopes, discordacl.Scope{GuildID: guild.ID, ChannelID: channels[j].ID})
		}
	}
	if len(policy.Scopes) > discordacl.MaxScopes {
		return discordacl.Policy{}, fmt.Errorf("select at most %d servers or channels", discordacl.MaxScopes)
	}
	return policy, nil
}

func aclChoiceName(choice discordacl.Choice) string {
	if strings.TrimSpace(choice.Name) == "" {
		return choice.ID
	}
	return choice.Name
}

func (p aclPrompt) pick(title string, choices []discordacl.Choice, channels bool) ([]int, error) {
	slices.SortFunc(choices, func(a, b discordacl.Choice) int {
		if order := cmp.Compare(aclChoiceName(a), aclChoiceName(b)); order != 0 {
			return order
		}
		return cmp.Compare(a.ID, b.ID)
	})
	if err := p.view.indented(p.view.paint(title+":", "1")); err != nil {
		return nil, err
	}
	for i, choice := range choices {
		name := aclChoiceName(choice)
		duplicate := (i > 0 && aclChoiceName(choices[i-1]) == name) ||
			(i+1 < len(choices) && aclChoiceName(choices[i+1]) == name)
		if channels && name != choice.ID && !strings.HasPrefix(name, "#") {
			name = "#" + name
		}
		if duplicate {
			name += " [" + choice.ID + "]"
		}
		if err := p.view.indented(fmt.Sprintf("%d) %s", i+1, safeTerminalText(name))); err != nil {
			return nil, err
		}
	}
	return p.numbers(len(choices), true)
}

func (p aclPrompt) numbers(count int, multiple bool) ([]int, error) {
	question := "Select a number (Enter cancels)"
	if multiple {
		question = "Select numbers separated by commas (Enter cancels)"
	}
	for {
		if _, err := fmt.Fprintf(p.view.out, "      %s: ", question); err != nil {
			return nil, err
		}
		line, err := p.line()
		if err != nil {
			return nil, err
		}
		if selection := aclSelection(line, count, multiple); selection != nil {
			return selection, nil
		}
		if err := p.view.indented(fmt.Sprintf("Enter distinct choice numbers from 1 to %d.", count)); err != nil {
			return nil, err
		}
	}
}

func aclSelection(line string, count int, multiple bool) []int {
	var selection []int
	for field := range strings.SplitSeq(line, ",") {
		field = strings.TrimSpace(field)
		n, err := strconv.Atoi(field)
		if err != nil || field[0] < '0' || field[0] > '9' || n < 1 || n > count ||
			(!multiple && len(selection) != 0) || slices.Contains(selection, n-1) {
			return nil
		}
		selection = append(selection, n-1)
	}
	return selection
}

func (p aclPrompt) line() (string, error) {
	if err := p.ctx.Err(); err != nil {
		return "", err
	}
	type result struct {
		text string
		err  error
	}
	lines := make(chan result, 1)
	// Stdin belongs to the CLI process. On SIGINT, return without waiting for a
	// line from the terminal; the blocked read ends when the CLI exits.
	go func() {
		b, err := p.input.ReadSlice('\n')
		lines <- result{text: strings.TrimSpace(string(b)), err: err}
	}()
	select {
	case <-p.ctx.Done():
		return "", p.ctx.Err()
	case line := <-lines:
		if err := p.ctx.Err(); err != nil {
			return "", err
		}
		if errors.Is(line.err, io.EOF) || strings.ContainsRune(line.text, '\x03') {
			return "", errACLDeclined
		}
		if line.err != nil {
			return "", fmt.Errorf("read ACL selection: %w", line.err)
		}
		if line.text == "" {
			return "", errACLDeclined
		}
		return line.text, nil
	}
}
