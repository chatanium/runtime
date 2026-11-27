package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

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
	if old == nil {
		return install.Init(cmd.Context(), budget, first, approval(cmd))
	}
	input := approvalInput(cmd)
	confirmReset := func(description string, plan any, digest string) error {
		out := cmd.ErrOrStderr()
		if err := json.NewEncoder(out).Encode(plan); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "%s (%s)\nReset %s? This permanently deletes its configuration, image cache, module data and backups. [y/N]: ", description, digest, path); err != nil {
			return err
		}
		return readResetConsent(input)
	}
	m, err := install.Reinitialize(cmd.Context(), path, old.ID, budget, first, digestApproval(cmd, input), confirmReset)
	if errors.Is(err, errResetDeclined) {
		_, err := fmt.Fprintln(cmd.ErrOrStderr(), "Installation unchanged.")
		return *old, err
	}
	return m, err
}

func readResetConsent(input *bufio.Reader) error {
	line, err := input.ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	answer := bytes.TrimSpace(line)
	if bytes.EqualFold(answer, []byte("y")) || bytes.EqualFold(answer, []byte("yes")) {
		return nil
	}
	return errResetDeclined
}
