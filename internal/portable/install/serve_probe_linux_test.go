package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/thirdscam/chatanium/internal/portable/store"
)

func TestFirstUseDoesNotAdoptAnIncompletePurgeOrUnmarkedRoot(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	path, err := Directory()
	if err != nil {
		t.Fatal(err)
	}
	if m, err := InstalledManifest(path); m != nil || err != nil {
		t.Fatalf("fresh data home: %v, %v", m, err)
	}
	parent := filepath.Dir(path)
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(parent, purgeTerminalName(path))
	if err := os.WriteFile(receipt, []byte("pending purge"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstalledManifest(path); !errors.Is(err, store.ErrCleanupPending) {
		t.Fatalf("pending purge treated as first use: %v", err)
	}
	if err := os.Remove(receipt); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if m, err := InstalledManifest(path); m != nil || err == nil {
		t.Fatalf("an existing directory without a manifest was treated as new: %v, %v", m, err)
	}
}
