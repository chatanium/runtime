package upload

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConstructorRejectsPublicManagementParent(t *testing.T) {
	config := testConfig(t)
	if err := os.Chmod(config.ManagementDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	if store, err := New(context.Background(), config); err == nil {
		_ = store.Close(context.Background())
		t.Fatal("constructor accepted a public management parent")
	}
	if err := os.Chmod(config.ManagementDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConstructorRequiresProvisionedPrivateChild(t *testing.T) {
	config := testConfig(t)
	child := filepath.Join(config.ManagementDirectory, "uploads")
	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}
	if store, err := New(context.Background(), config); err == nil {
		_ = store.Close(context.Background())
		t.Fatal("constructor created an unprovisioned spool")
	}
	if _, err := os.Stat(child); !os.IsNotExist(err) {
		t.Fatalf("constructor mutated missing child: %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, child); err != nil {
		t.Fatal(err)
	}
	if store, err := New(context.Background(), config); err == nil {
		_ = store.Close(context.Background())
		t.Fatal("constructor followed a spool symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, ".owner")); !os.IsNotExist(err) {
		t.Fatal("symlink target was touched")
	}
}

func TestConstructorRejectsResolvedModuleMountOverlap(t *testing.T) {
	config := testConfig(t)
	config.ModuleMountRoots = []string{config.ManagementDirectory}
	if store, err := New(context.Background(), config); err == nil {
		_ = store.Close(context.Background())
		t.Fatal("spool inside module mount accepted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(config.ManagementDirectory, alias); err != nil {
		t.Fatal(err)
	}
	config.ModuleMountRoots = []string{alias}
	if store, err := New(context.Background(), config); err == nil {
		_ = store.Close(context.Background())
		t.Fatal("resolved spool overlap accepted")
	}
}

func TestOrphanSymlinkDoesNotDeleteTarget(t *testing.T) {
	config := testConfig(t)
	target := filepath.Join(t.TempDir(), "preserve")
	if err := os.WriteFile(target, []byte("owned elsewhere"), 0600); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(config.ManagementDirectory, "uploads", "file-00000000000000000000000000000000")
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
	if store, err := New(context.Background(), config); err == nil {
		_ = store.Close(context.Background())
		t.Fatal("orphan symlink accepted")
	}
	bytes, err := os.ReadFile(target)
	if err != nil || string(bytes) != "owned elsewhere" {
		t.Fatalf("target modified: %q %v", bytes, err)
	}
}
