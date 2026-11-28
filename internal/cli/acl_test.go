package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/discordacl"
)

func TestACLNumberedChoices(t *testing.T) {
	var output bytes.Buffer
	p := aclPrompt{
		ctx:   context.Background(),
		input: bufio.NewReader(strings.NewReader("920\n1,1\n1, 3\n")),
		view:  terminalView{out: &output},
	}
	choices := []discordacl.Choice{
		{ID: "930", Name: "Zulu"},
		{ID: "920", Name: "Alpha"},
		{ID: "910", Name: "Alpha"},
	}
	selected, err := p.pick("Servers", choices, false)
	if err != nil || !slices.Equal(selected, []int{0, 2}) {
		t.Fatalf("selection = %v, %v", selected, err)
	}
	if choices[selected[0]].ID != "910" || choices[selected[1]].ID != "930" {
		t.Fatalf("choices not ordered by name and ID: %v", choices)
	}
	text := output.String()
	if !strings.Contains(text, "1) Alpha [910]\n      2) Alpha [920]\n      3) Zulu") ||
		strings.Contains(text, "930") ||
		strings.Count(text, "Enter distinct choice numbers from 1 to 3.") != 2 {
		t.Fatalf("unexpected numbered menu: %q", text)
	}
	for _, line := range []string{"0", "4", "1,", "+1", "1 3", "1,3"} {
		if result := aclSelection(line, 3, false); result != nil {
			t.Errorf("single choice accepted %q: %v", line, result)
		}
	}
}

func TestACLConfirmation(t *testing.T) {
	for _, tc := range []struct {
		input  string
		cancel bool
		want   error
	}{
		{input: "Y\n"},
		{input: "yes\n"},
		{input: "n\n", want: errACLDeclined},
		{input: "\n", want: errACLDeclined},
		{input: "y\x03\n", want: errACLDeclined},
		{input: "y", want: errACLDeclined},
		{input: "y\n", cancel: true, want: context.Canceled},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		if tc.cancel {
			cancel()
		}
		var output bytes.Buffer
		p := aclPrompt{ctx: ctx, input: bufio.NewReader(strings.NewReader(tc.input)), view: terminalView{out: &output}}
		err := p.confirm()
		cancel()
		if !errors.Is(err, tc.want) || !strings.Contains(output.String(), "Apply now? [y/N]: ") {
			t.Errorf("confirm(%q, canceled=%t) = %v, output %q; want %v", tc.input, tc.cancel, err, output.String(), tc.want)
		}
	}
}

func TestACLReviewCannotConfuseServerNameWithDenial(t *testing.T) {
	denied := aclStatusText(discordacl.Status{Managed: true})
	server := aclStatusText(discordacl.Status{
		Managed: true,
		Policy:  discordacl.Policy{Scopes: []discordacl.Scope{{GuildID: "910"}}},
		Labels:  []string{"No access"},
	})
	if denied != "No access" || server != `Server "No access" [910]` {
		t.Fatalf("deny = %q, allow = %q", denied, server)
	}
}

func TestACLSetRequiresTerminal(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("1\ny\n"))
	cmd.SetErr(&bytes.Buffer{})
	if err := setACL(cmd, "hello"); err == nil || !strings.Contains(err.Error(), "requires an interactive terminal") {
		t.Fatalf("setACL returned %v for scripted input", err)
	}
}
