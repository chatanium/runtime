package scaffold

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

func TestDefaultDestination(t *testing.T) {
	checkout := t.TempDir()
	t.Chdir(checkout)
	dir, err := Destination("ping-bot", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(checkout, "modules", "ping-bot"); dir != want {
		t.Fatalf("destination = %q, want %q", dir, want)
	}
	if got := BuildTarget(checkout, dir); got != "modules/ping-bot" {
		t.Fatalf("build target = %q, want modules/ping-bot", got)
	}
}

func TestCreateGoReplacements(t *testing.T) {
	sdk := fixtureSDK(t)
	t.Run("in checkout", func(t *testing.T) {
		dir := filepath.Join(sdk, "modules", "ping-bot")
		_, err := Create(Options{Name: "ping-bot", Directory: dir, SDKPath: sdk, Template: Discord})
		if err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			`replace github.com/thirdscam/chatanium => "../.."`,
			`replace github.com/bwmarrin/discordgo => "../../.tools/deps/discordgo"`,
		} {
			if !strings.Contains(string(contents), want+"\n") {
				t.Errorf("go.mod is missing %s", want)
			}
		}
	})
	t.Run("outside checkout", func(t *testing.T) {
		dir := filepath.Join(filepath.Dir(sdk), "ping-bot")
		_, err := Create(Options{Name: "ping-bot", Directory: dir, SDKPath: sdk, Template: Discord})
		if err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			`replace github.com/thirdscam/chatanium => ` + strconv.Quote(filepath.ToSlash(sdk)),
			`replace github.com/bwmarrin/discordgo => "../sdk checkout/.tools/deps/discordgo"`,
		} {
			if !strings.Contains(string(contents), want+"\n") {
				t.Errorf("go.mod is missing %s", want)
			}
		}
	})
}

func TestCreateViaSymlinkOutsideCheckout(t *testing.T) {
	sdk := fixtureSDK(t)
	outside := filepath.Join(filepath.Dir(sdk), "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(sdk, "modules")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create a directory symlink: %v", err)
		}
		t.Fatal(err)
	}
	dir, err := Create(Options{Name: "ping-bot", Directory: filepath.Join(link, "missing", "ping-bot"), SDKPath: sdk, Template: Discord})
	if err != nil {
		t.Fatal(err)
	}
	if got := BuildTarget(sdk, dir); got != "" {
		t.Errorf("outside module has a checkout build target: %s", got)
	}
	contents, err := os.ReadFile(filepath.Join(outside, "missing", "ping-bot", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`replace github.com/thirdscam/chatanium => ` + strconv.Quote(filepath.ToSlash(sdk)),
		`replace github.com/bwmarrin/discordgo => "../../../sdk checkout/.tools/deps/discordgo"`,
	} {
		if !strings.Contains(string(contents), want+"\n") {
			t.Errorf("go.mod is missing %s", want)
		}
	}
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
