package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackendOwnershipDirectoryCannotOverlapModuleMounts(t *testing.T) {
	root := t.TempDir()
	mount := filepath.Join(root, "modules")
	private := filepath.Join(root, "host-only")
	for _, path := range []string{mount, private, filepath.Join(mount, "nested")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "module-alias")
	if err := os.Symlink(mount, alias); err != nil {
		t.Fatal(err)
	}
	if !isolatedHostDirectory(private, mount) {
		t.Fatal("separate private host directory rejected")
	}
	for _, path := range []string{mount, filepath.Join(mount, "nested"), filepath.Join(alias, "nested")} {
		if isolatedHostDirectory(path, mount) {
			t.Fatal("lexical or symlink-resolved module directory accepted as host-only ownership storage")
		}
	}
}
