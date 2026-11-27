package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/portable/install"
)

var errSetupDeclined = errors.New("setup declined")

func setupApproval(cmd *cobra.Command, input *bufio.Reader, startFreshIdle bool) install.Confirm {
	jsonMode, _ := cmd.Flags().GetBool("json-approvals")
	if jsonMode || cmd.Flags().Changed("approve") {
		return digestApproval(cmd, input)
	}

	approvedFreshIdle := false
	return func(_ string, plan any, _ string) error {
		summary, err := install.DescribeSetupApproval(plan)
		if err != nil {
			return err
		}
		// The first prompt already included starting the exact default config.
		// A separate invocation or an explicit digest workflow still approves it.
		if approvedFreshIdle && summary.EmptyConfiguration {
			approvedFreshIdle = false
			return nil
		}
		question := "Continue?"
		if startFreshIdle {
			question = "Set up and start Chatanium?"
		}
		yes, err := promptSetupApproval(runtimeView(cmd.ErrOrStderr()), input, summary, question)
		if err != nil {
			return err
		}
		if !yes {
			return errSetupDeclined
		}
		approvedFreshIdle = startFreshIdle
		return nil
	}
}

func promptSetupApproval(view terminalView, input *bufio.Reader, summary install.SetupApprovalSummary, question string) (bool, error) {
	if err := showApproval(view, summary); err != nil {
		return false, err
	}
	if _, err := fmt.Fprintf(view.out, "      %s %s: ", question, view.paint("[y/N]", "1;33")); err != nil {
		return false, err
	}
	yes, err := readYesNo(input)
	_, writeErr := fmt.Fprintln(view.out)
	return yes, errors.Join(err, writeErr)
}

func readYesNo(input *bufio.Reader) (bool, error) {
	line, err := input.ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := bytes.TrimSpace(line)
	return bytes.EqualFold(answer, []byte("y")) || bytes.EqualFold(answer, []byte("yes")), nil
}

func reportSetupDeclined(cmd *cobra.Command) error {
	return runtimeView(cmd.ErrOrStderr()).status("CANCEL", "Setup canceled.")
}

func showApproval(view terminalView, summary install.SetupApprovalSummary) error {
	if err := view.status("REVIEW", summary.Heading); err != nil {
		return err
	}
	for _, line := range summary.Lines {
		if err := view.indented(safeTerminalText(line)); err != nil {
			return err
		}
	}
	return nil
}
