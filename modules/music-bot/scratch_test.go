package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScratchUsesAuthenticatedMountAndPreservesOtherOwnedData(t *testing.T) {
	root := t.TempDir()
	scratchMount := filepath.Join(root, "var", "lib", "flexmodule", "scratch")
	persistentMount := filepath.Join(root, "var", "lib", "flexmodule", "data")
	if err := os.MkdirAll(scratchMount, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(persistentMount, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(persistentMount, "retained.json")
	if err := os.WriteFile(marker, []byte("persistent data"), 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(scratchMount, "other-owner")
	if err := os.WriteFile(unrelated, []byte("retained scratch"), 0600); err != nil {
		t.Fatal(err)
	}
	config, init := constrainedMusicInit(t)
	init.ScratchDirectory = scratchMount
	init.PersistentDirectory = persistentMount
	if err := validateGrants(config, init); err != nil {
		t.Fatalf("authenticated nonliteral mount rejected: %v", err)
	}
	owned, err := openScratch(init.ScratchDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(owned) != scratchMount || !strings.HasPrefix(filepath.Base(owned), "music-") {
		t.Fatalf("private scratch escaped authenticated mount: %q", owned)
	}
	preparer := newPreparer(owned, MediaLimits{Workers: 1, HTTPTimeoutMS: 1000, MaxRedirects: 1})
	source, err := os.CreateTemp(preparer.directory, "source-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.Write([]byte("owned bytes")); err != nil {
		t.Fatal(err)
	}
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	// Instance cleanup must remove only the generated child, not a hardcoded
	// mount, its sibling scratch entries, or authenticated persistent storage.
	if err = os.RemoveAll(owned); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(source.Name()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generated input survived cleanup: %v", err)
	}
	for _, path := range []string{marker, unrelated} {
		if _, err = os.Stat(path); err != nil {
			t.Fatalf("instance cleanup removed unrelated storage %q: %v", path, err)
		}
	}
	preparer.client.CloseIdleConnections()
}
func TestScratchRejectsAliasesRelativePathsAndSymlinkMount(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"", "relative", "/", root + "/../alias", root + "/"} {
		if _, err := openScratch(path); err == nil {
			t.Fatalf("unsafe or aliased scratch path accepted: %q", path)
		}
		config, init := constrainedMusicInit(t)
		init.ScratchDirectory = path
		if err := validateGrants(config, init); err == nil {
			t.Fatalf("unsafe INIT scratch path accepted: %q", path)
		}
	}
	link := filepath.Join(t.TempDir(), "mount-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openScratch(link); err == nil {
		t.Fatal("symlink scratch mount accepted")
	}
}
