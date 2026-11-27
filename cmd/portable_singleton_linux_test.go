//go:build linux

package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/portable/install"
)

func TestPortableCommandsUseSingleInstallation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", home)
	var output strings.Builder
	rootCmd.SetOut(&output)
	rootCmd.SetErr(io.Discard)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	for _, name := range []string{
		"doctor", "init", "prepare-image", "generate-config", "configure", "inspect-config",
		"serve", "stop", "update", "uninstall", "purge", "bind-restored-volumes",
	} {
		rootCmd.SetArgs([]string{name, "--installation-id=old"})
		command, err := rootCmd.ExecuteC()
		if err == nil || err.Error() != "unknown flag: --installation-id" {
			t.Fatalf("%s --installation-id: got %v, want only an unknown flag error", name, err)
		}
		if strings.Contains(command.UsageString(), "--installation-id") {
			t.Fatalf("%s still advertises --installation-id", name)
		}
		switch name {
		case "init", "generate-config":
			if command.Flags().Lookup("module-id") == nil {
				t.Fatalf("%s no longer accepts --module-id", name)
			}
		case "bind-restored-volumes":
			if command.Flags().Lookup("backup-id") == nil {
				t.Fatal("bind-restored-volumes no longer accepts --backup-id")
			}
		}
	}

	rootCmd.SetArgs([]string{"init", "--plan", "/legacy/plan.json"})
	if err := rootCmd.Execute(); !errors.Is(err, install.ErrLegacy) {
		t.Fatalf("init --plan: got %v, want legacy installation guidance", err)
	}

	output.Reset()
	rootCmd.SetArgs([]string{"doctor"})
	doctorErr := rootCmd.Execute() // The launcher may not have an embedded portable release.
	var report struct {
		Directory string `json:"installation_directory"`
	}
	if err := json.NewDecoder(strings.NewReader(output.String())).Decode(&report); err != nil {
		t.Fatalf("doctor report: %v (command error: %v)", err, doctorErr)
	}
	if want := filepath.Join(home, "chatanium", "runtime"); report.Directory != want {
		t.Fatalf("doctor directory = %q, want %q", report.Directory, want)
	}
	if _, err := os.Lstat(filepath.Join(home, "chatanium")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("portable commands changed the data home: %v", err)
	}
}
