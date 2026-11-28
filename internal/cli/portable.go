package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/portable/install"
)

func init() {
	addOperatorCommands("runtime", serveCommand(), stopCommand(), initCommand(), doctorCommand())
	addOperatorCommands("modules", prepareImageCommand(), generateConfigCommand(), configureCommand(), inspectConfigCommand())
	addMaintenanceCommands()
	for _, name := range []string{"service", "_owner", "prepare-dev-worker", "discard-dev-revision", "inspect-dev-lock"} {
		rootCmd.AddCommand(&cobra.Command{Use: name, Hidden: true, DisableFlagParsing: true, RunE: func(_ *cobra.Command, _ []string) error { return install.ErrLegacy }})
	}
}

func installedCommand(name, summary string, run func(*cobra.Command, string) error) *cobra.Command {
	cmd := &cobra.Command{Use: name, Short: summary, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		path, err := install.Directory()
		if err != nil {
			return err
		}
		return run(cmd, path)
	}}
	cmd.SetFlagErrorFunc(legacyFlagError)
	return cmd
}

func legacyFlagError(_ *cobra.Command, err error) error {
	if name, ok := strings.CutPrefix(err.Error(), "unknown flag: --"); ok {
		switch name {
		case "archive-digest", "credential-file", "dev-mode", "dev-module-image", "dev-revision",
			"dev-socket", "draft", "entrypoint", "input", "job-id", "operator", "plan":
			return errors.Join(err, install.ErrLegacy)
		}
	}
	return err
}

func approvalFlag(cmd *cobra.Command) {
	cmd.Flags().StringArray("approve", nil, "approve exact digests in order (repeatable)")
	cmd.Flags().Bool("json-approvals", false, "show complete approval plans as JSON")
}

func approval(cmd *cobra.Command) install.Confirm {
	input := approvalInput(cmd)
	view := commandView(cmd, cmd.ErrOrStderr())
	_, human := operatorOutput(cmd)
	jsonMode, _ := cmd.Flags().GetBool("json-approvals")
	if !human || !view.terminal || jsonMode || cmd.Flags().Changed("approve") {
		return digestApproval(cmd, input)
	}
	return func(_ string, value any, digest string) error {
		summary, err := install.DescribeSetupApproval(value)
		if err != nil {
			return err
		}
		level := logInfo
		if view.area == "PURGE" {
			level = logWarn
		}
		if err := showApproval(view, level, summary); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(view.out, "      Type %s to approve: ", view.paint(digest, "1;33")); err != nil {
			return err
		}
		return readDigestApproval(view.out, input, digest)
	}
}

func approvalInput(cmd *cobra.Command) *bufio.Reader {
	return bufio.NewReader(io.LimitReader(cmd.InOrStdin(), 128<<10))
}

func digestApproval(cmd *cobra.Command, stdin *bufio.Reader) install.Confirm {
	approved, _ := cmd.Flags().GetStringArray("approve")
	return func(description string, value any, digest string) error {
		if err := json.NewEncoder(cmd.ErrOrStderr()).Encode(value); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "%s\nType %s to approve: ", description, digest); err != nil {
			return err
		}
		if len(approved) == 0 {
			return readDigestApproval(cmd.ErrOrStderr(), stdin, digest)
		}
		received := approved[0]
		approved = approved[1:]
		return finishDigestApproval(cmd.ErrOrStderr(), received, digest)
	}
}

func readDigestApproval(out io.Writer, input *bufio.Reader, digest string) error {
	received, err := input.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && received != "") {
		return errors.New("explicit approval required")
	}
	return finishDigestApproval(out, received, digest)
}

func finishDigestApproval(out io.Writer, received, digest string) error {
	if strings.TrimSpace(received) != digest {
		return errors.New("APPROVAL_MISMATCH: displayed digest was not approved")
	}
	_, err := fmt.Fprintln(out)
	return err
}
