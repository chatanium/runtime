package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/portable/install"
)

var errResetDeclined = errors.New("reset declined")

func initializeOrReset(cmd *cobra.Command, budget int64, first *install.FirstModule) (install.Manifest, error) {
	path, err := install.Directory()
	if err != nil {
		return install.Manifest{}, err
	}
	old, err := install.InstalledManifest(path)
	if err != nil {
		return install.Manifest{}, err
	}
	input := approvalInput(cmd)
	setup := setupApproval(cmd, input, false)
	if old == nil {
		return install.Init(cmd.Context(), budget, first, setup)
	}
	jsonMode, _ := cmd.Flags().GetBool("json-approvals")
	confirmReset := func(description string, plan any, digest string) error {
		out := cmd.ErrOrStderr()
		var yes bool
		var err error
		if jsonMode {
			if err := json.NewEncoder(out).Encode(plan); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(out, "%s (%s)\nReset this installation? [y/N]: ", description, digest); err != nil {
				return err
			}
			yes, err = readYesNo(input)
		} else {
			summary, describeErr := install.DescribeSetupApproval(plan)
			if describeErr != nil {
				return describeErr
			}
			yes, err = promptSetupApproval(commandView(cmd, out), input, summary, "Reset this installation?")
		}
		if err != nil {
			return err
		}
		if !yes {
			return errResetDeclined
		}
		return nil
	}
	m, err := install.Reinitialize(cmd.Context(), path, old.ID, budget, first, setup, confirmReset)
	if errors.Is(err, errResetDeclined) {
		if writeErr := commandView(cmd, cmd.ErrOrStderr()).status("CANCEL", "Installation unchanged."); writeErr != nil {
			return *old, writeErr
		}
		return *old, err
	}
	return m, err
}

