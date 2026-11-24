package install

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestPortableDirectoryIsReadOnlyAndSeparateFromLegacy(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_DATA_HOME", base)
	got, err := Directory("demo-1")
	want := filepath.Join(base, "chatanium", Format, "demo-1")
	if err != nil || got != want {
		t.Fatalf("Directory = %q, %v; want %q", got, err, want)
	}
	if _, err := os.Lstat(filepath.Join(base, "chatanium")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Directory created storage: %v", err)
	}
	for _, id := range []string{"", "../other", "con", "Demo", "demo-", "-demo", "a/b"} {
		if _, err := Directory(id); err == nil {
			t.Errorf("invalid installation ID %q was accepted", id)
		}
	}
	t.Setenv("XDG_DATA_HOME", "/var/lib")
	if _, err := Directory("demo"); !errors.Is(err, ErrLegacy) {
		t.Fatalf("legacy root = %v; want LEGACY_INSTALLATION", err)
	}
	if f, err := OpenInput("/etc/chatanium/runtime.json", false); !errors.Is(err, ErrLegacy) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("legacy input = %v; want LEGACY_INSTALLATION", err)
	}
}

func TestOwnedDeleteDoesNotTraverseLinks(t *testing.T) {
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep")
	if err := os.WriteFile(keep, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	owned := t.TempDir()
	root, err := os.OpenRoot(owned)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Symlink(outside, filepath.Join(owned, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := removeOwned(root, "linked/keep"); err == nil {
		t.Fatal("deletion accepted a link as a directory")
	}
	if err := removeOwned(root, "linked"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(keep)
	if err != nil || string(data) != "retained" {
		t.Fatalf("external file changed: %q, %v", data, err)
	}
}

func TestConfigDigestMatchesPersistedRawJSON(t *testing.T) {
	original := json.RawMessage(`{ "markup" : "<a>&</a>" , "number" : 1.0 }`)
	before, err := documentDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(Manifest{Config: original})
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	after, err := documentDigest(m.Config)
	if err != nil || after != before || hashBytes(m.Config) != before {
		t.Fatalf("persisted configuration changed its digest: before %s after %s (%v)", before, after, err)
	}
}
