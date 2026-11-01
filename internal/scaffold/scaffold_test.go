package scaffold

import (
	"os"
	"path/filepath"
	"testing"
)

func fixtureSDK(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sdk checkout")
	if err := os.MkdirAll(filepath.Join(dir, "shared", "core-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{
		"go.mod":                   "module github.com/thirdscam/chatanium\n\ngo 1.27.0\n",
		"shared/core-v2/plugin.go": "package corev2\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCreateRefusesOverwrite(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "ping-bot")
	sdk := fixtureSDK(t)
	dir, err := Create(Options{Name: "ping-bot", Directory: destination, SDKPath: sdk, ModulePath: "example.com/team/ping-bot"})
	if err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dir, "user-work")
	if err := os.WriteFile(sentinel, []byte("keep this work"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(Options{Name: "ping-bot", Directory: dir, SDKPath: sdk}); err == nil {
		t.Fatal("existing output must not be overwritten")
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "keep this work" {
		t.Fatal("existing user work was modified")
	}
}

func TestCreateRejectsUnsafeNamesAndMissingSDK(t *testing.T) {
	sdk := fixtureSDK(t)
	for _, name := range []string{"", "../escape", "bad/name", "bad\"name", "Uppercase", "two words"} {
		t.Run(name, func(t *testing.T) {
			if _, err := Create(Options{Name: name, Directory: filepath.Join(t.TempDir(), "output"), SDKPath: sdk}); err == nil {
				t.Fatal("unsafe module name accepted")
			}
		})
	}
	if _, err := Create(Options{Name: "ping", Directory: filepath.Join(t.TempDir(), "output"), SDKPath: t.TempDir()}); err == nil {
		t.Fatal("missing SDK accepted")
	}
}
