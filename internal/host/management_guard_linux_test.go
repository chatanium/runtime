//go:build linux

package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testManagementGuard(t *testing.T) *ManagementGuard {
	t.Helper()
	root := filepath.Join(t.TempDir(), "management")
	uid := uint32(os.Geteuid())
	observation, err := observeManagementAnchorAt(root, uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ensureManagementAnchorAt(context.Background(), root, uid, observation); err != nil {
		t.Fatal(err)
	}
	guard, err := acquireManagementGuardAt(context.Background(), root, uid, ManagementShared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Close() })
	return guard
}
func TestManagementGuardExclusionAndStableMarker(t *testing.T) {
	shared := testManagementGuard(t)
	before, err := observeManagementAnchorAt(shared.root, shared.uid)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if other, err := acquireManagementGuardAt(ctx, shared.root, shared.uid, ManagementExclusive); !errors.Is(err, context.DeadlineExceeded) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("exclusive guard bypassed live shared acquisition: %v", err)
	}
	if err = shared.Close(); err != nil {
		t.Fatal(err)
	}
	exclusive, err := acquireManagementGuardAt(context.Background(), shared.root, shared.uid, ManagementExclusive)
	if err != nil {
		t.Fatal(err)
	}
	defer exclusive.Close()
	after, err := observeManagementAnchorAt(exclusive.root, exclusive.uid)
	if err != nil || !managementAnchorMatches(before, after) {
		t.Fatalf("fixed coordination inode changed: %+v %v", after, err)
	}
	id := strings.Repeat("f", 32)
	path, err := exclusive.receiptPath(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("unrecognized protected terminal receipt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = CreateStore(context.Background(), InstallationManifest{RuntimeInstallationID: id}, exclusive); !errors.Is(err, ErrTerminalPurge) {
		t.Fatalf("same-ID init bypassed terminal receipt: %v", err)
	}
}
func TestManagementGuardRequiredBeforeSQLite(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("a", 32)
	if _, err := OpenStore(context.Background(), dir, id, nil); !errors.Is(err, ErrManagementGuardRequired) {
		t.Fatalf("unguarded Store open: %v", err)
	}
	if _, err := OpenMetadata(context.Background(), dir, id, nil); !errors.Is(err, ErrManagementGuardRequired) {
		t.Fatalf("unguarded metadata open: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "supervisor.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unguarded acquisition changed SQLite path: %v", err)
	}
	if _, err := ManagementGuardFromContext(context.Background()); !errors.Is(err, ErrManagementGuardAbsent) {
		t.Fatalf("missing context guard: %v", err)
	}
	if _, err := ManagementGuardFromContext(WithManagementGuard(context.Background(), nil)); !errors.Is(err, ErrManagementGuardRequired) {
		t.Fatalf("nil context guard silently became absence: %v", err)
	}
}
