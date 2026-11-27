package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

func mustReset(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func resetFixture(t *testing.T) (string, Manifest) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	path, err := Directory()
	mustReset(t, err)
	m, err := Init(t.Context(), DefaultBudgetBytes, nil, func(string, any, string) error { return nil })
	mustReset(t, err)
	t.Cleanup(func() {
		if err := Purge(context.Background(), path, func(string, any, string) error { return nil }); err != nil {
			t.Error(err)
		}
	})
	return path, m
}

func resetLedger(t *testing.T, path string, use func(*Installation, *store.Store, string)) {
	t.Helper()
	ctx := t.Context()
	i, err := Lock(path)
	mustReset(t, err)
	defer func() { mustReset(t, i.Close()) }()
	db, err := i.Store(ctx)
	mustReset(t, err)
	defer func() { mustReset(t, db.Close()) }()
	epoch, err := i.beginEpoch(ctx, db)
	mustReset(t, err)
	use(i, db, epoch)
	mustReset(t, db.EndEpoch(ctx, epoch))
}

func assertResetAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s still exists: %v", path, err)
	}
}

func TestReinitializeRetainedInstallation(t *testing.T) {
	path, old := resetFixture(t)
	ctx := t.Context()
	var image store.Image
	resetLedger(t, path, func(_ *Installation, db *store.Store, epoch string) {
		var err error
		image, err = db.ReserveImage(ctx, epoch, "", hashBytes([]byte("image")), 2<<20)
		mustReset(t, err)
		dir := filepath.Join(path, image.Path)
		mustReset(t, os.MkdirAll(dir, 0700))
		mustReset(t, os.WriteFile(filepath.Join(dir, "cache"), []byte("retained cache"), 0600))
		mustReset(t, db.StageImage(ctx, epoch, image.ID, store.PublishProof{WritersExited: true, Verified: true, ReadOnly: true, Synchronized: true}))
	})
	_, err := Uninstall(ctx, path)
	mustReset(t, err)
	var backup store.Backup
	resetLedger(t, path, func(i *Installation, db *store.Store, epoch string) {
		ceiling, err := store.SQLiteFileBudget(i.Manifest.MetadataBytes)
		mustReset(t, err)
		backup, err = db.BeginBackup(ctx, epoch, ceiling, false)
		mustReset(t, err)
		mustReset(t, os.MkdirAll(filepath.Join(path, backup.Path), 0700))
		mustReset(t, db.SnapshotDatabase(ctx, epoch, backup.ID))
		mustReset(t, db.CompleteBackup(ctx, epoch, backup.ID, store.BackupProof{WritersExited: true, Verified: true, Synchronized: true}))
	})
	beforeLedger, err := os.ReadFile(filepath.Join(path, store.DatabaseName))
	mustReset(t, err)
	beforeManifest, err := os.ReadFile(filepath.Join(path, manifestName))
	mustReset(t, err)
	calls := 0
	review := func(_ string, value any, digest string) error {
		calls++
		p, ok := value.(ResetPlan)
		if !ok {
			t.Fatalf("reset review got %T", value)
		}
		if len(p.Purge.Ledger.Images) != 1 || p.Purge.Ledger.Images[0].ID != image.ID || len(p.Purge.Ledger.Backups) != 1 || p.Purge.Ledger.Backups[0].ID != backup.ID || p.Purge.Ledger.ID != old.ID {
			t.Fatalf("wrong retained inventory: %+v", p.Purge.Ledger)
		}
		purgeDigest, err := planDigest(p.Purge)
		mustReset(t, err)
		resetDigest, err := planDigest(p)
		mustReset(t, err)
		if p.PurgeDigest != purgeDigest || p.Replacement.PlanDigest == "" || p.Replacement.Path != path || p.Replacement.BudgetBytes != DefaultBudgetBytes || digest != resetDigest {
			t.Fatalf("review does not bind both plans: %s", digest)
		}
		for _, lock := range []string{filepath.Join(path, ownerLock), filepath.Join(filepath.Dir(path), anchorLock)} {
			l, err := process.Lock(lock)
			if !errors.Is(err, process.ErrOwnerBusy) {
				if l != nil {
					l.Close()
				}
				t.Fatalf("lock %s was not held during reset approval: %v", lock, err)
			}
		}
		if calls == 1 {
			return io.EOF
		}
		return nil
	}
	secondApproval := func(string, any, string) error {
		t.Fatal("empty replacement requested another approval")
		return nil
	}
	if _, err := Reinitialize(ctx, path, old.ID, DefaultBudgetBytes, nil, secondApproval, review); !errors.Is(err, io.EOF) || calls != 1 {
		t.Fatalf("refusal: calls=%d, error=%v", calls, err)
	}
	for name, want := range map[string][]byte{store.DatabaseName: beforeLedger, manifestName: beforeManifest} {
		got, err := os.ReadFile(filepath.Join(path, name))
		mustReset(t, err)
		if !bytes.Equal(got, want) {
			t.Fatalf("denial changed %s", name)
		}
	}
	assertResetAbsent(t, filepath.Join(path, purgeIntent))
	assertResetAbsent(t, initStaging(path))
	if _, err := os.Stat(filepath.Join(path, image.Path, "cache")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, backup.Path, store.DatabaseName)); err != nil {
		t.Fatal(err)
	}
	fresh, err := Reinitialize(ctx, path, old.ID, DefaultBudgetBytes, nil, secondApproval, review)
	mustReset(t, err)
	if calls != 2 || fresh.ID == old.ID || fresh.State != store.Initializing {
		t.Fatalf("replacement: calls=%d, manifest=%+v", calls, fresh)
	}
	assertResetAbsent(t, filepath.Join(path, image.Path))
	assertResetAbsent(t, filepath.Join(path, backup.Path))
	assertResetAbsent(t, filepath.Join(filepath.Dir(path), purgeTerminalName(path)))
	assertResetAbsent(t, initStaging(path))
	i, err := Open(path)
	mustReset(t, err)
	defer i.Close()
	mustReset(t, i.verifyInitializationLedger(ctx))
	if i.Manifest.ID != fresh.ID {
		t.Fatal("published manifest differs from replacement")
	}
}

func TestReinitializeRefusesStaleOrInterruptedInstallation(t *testing.T) {
	path, old := resetFixture(t)
	ctx := t.Context()
	noReview := func(string, any, string) error {
		t.Fatal("reset prompted for a stale or unfinished installation")
		return nil
	}
	attempt := func(id string, want error) {
		t.Helper()
		if _, err := Reinitialize(ctx, path, id, DefaultBudgetBytes, nil, nil, noReview); !errors.Is(err, want) {
			t.Fatalf("reset error = %v, want %v", err, want)
		}
	}
	attempt(strings.Repeat("a", 32), store.ErrApprovalMismatch)
	lock, err := Lock(path)
	mustReset(t, err)
	attempt(old.ID, process.ErrOwnerBusy)
	mustReset(t, lock.Close())
	for _, marker := range []string{initStaging(path), filepath.Join(path, pendingName), filepath.Join(path, store.DatabaseName+"-journal"), filepath.Join(path, purgeIntent), filepath.Join(filepath.Dir(path), ".writing-"+purgeTerminalName(path))} {
		mustReset(t, os.WriteFile(marker, []byte("unfinished"), 0600))
		attempt(old.ID, store.ErrCleanupPending)
		got, err := os.ReadFile(marker)
		mustReset(t, err)
		if string(got) != "unfinished" {
			t.Fatalf("reset changed unfinished state %s", marker)
		}
		mustReset(t, os.Remove(marker))
	}
	assertResetAbsent(t, filepath.Join(path, purgeIntent))
}

func TestReinitializeRechecksOccupantAndScope(t *testing.T) {
	path, old := resetFixture(t)
	ctx := t.Context()
	moved := filepath.Join(filepath.Dir(path), "old-runtime")
	_, err := Reinitialize(ctx, path, old.ID, DefaultBudgetBytes, nil, nil, func(string, any, string) error {
		mustReset(t, os.Rename(path, moved))
		return os.Mkdir(path, 0700)
	})
	if !errors.Is(err, store.ErrApprovalMismatch) {
		t.Fatalf("unexpected result after occupant changed: %v", err)
	}
	mustReset(t, os.Remove(path)) // The new, empty occupant was not deleted.
	mustReset(t, os.Rename(moved, path))
	unknown := filepath.Join(path, "unknown")
	_, err = Reinitialize(ctx, path, old.ID, DefaultBudgetBytes, nil, nil, func(string, any, string) error {
		return os.WriteFile(unknown, []byte("foreign"), 0600)
	})
	if err == nil {
		t.Fatal("reset accepted an entry outside the approved inventory")
	}
	mustReset(t, os.Remove(unknown))
	assertResetAbsent(t, filepath.Join(path, purgeIntent))
	i, err := Open(path)
	mustReset(t, err)
	defer i.Close()
	if i.Manifest.ID != old.ID {
		t.Fatal("original installation did not survive rejected replacement")
	}
	mustReset(t, i.verifyInitializationLedger(ctx))
}

func TestReinitializeValidatesReplacementBeforeDeleting(t *testing.T) {
	path, old := resetFixture(t)
	ctx := t.Context()
	archive := filepath.Join(path, "app", "uploads", ".owner")
	mustReset(t, os.WriteFile(archive, []byte("offline archive"), 0600))
	accept := func(string, any, string) error { return nil }
	first := FirstModule{
		Image: ImageInput{Source: images.Source{Kind: "oci-archive", Digest: hashBytes([]byte("offline archive"))}, Archive: archive, Limits: DefaultPreparationLimits()},
		Module: GenerateOptions{ModuleID: "example", UID: 1000, GID: 1000, ModuleConfig: []byte(`{}`), Grant: []byte(`{}`)},
	}
	if _, err := Reinitialize(ctx, path, old.ID, 1, nil, nil, accept); !errors.Is(err, store.ErrBudgetExceeded) {
		t.Fatalf("insufficient budget: %v", err)
	}
	if _, err := Reinitialize(ctx, path, old.ID, DefaultBudgetBytes, &first, accept, accept); err == nil || !strings.Contains(err.Error(), "grant needs explicit") {
		t.Fatalf("invalid grant: %v", err)
	}
	first.Module.Grant = []byte(`{"egressPolicy":"EGRESS_POLICY_NONE","resourceClass":"RESOURCE_CLASS_GENERAL","resourceLimits":{"cpuMillicores":500,"memoryBytes":"67108864","maxPids":64,"persistentBytes":"16777216","scratchBytes":"16777216"}}`)
	if _, err := Reinitialize(ctx, path, old.ID, DefaultBudgetBytes, &first, accept, accept); err == nil || !strings.Contains(err.Error(), "archive must be outside") {
		t.Fatalf("archive in the deletion scope: %v", err)
	}
	assertResetAbsent(t, filepath.Join(path, purgeIntent))
	if contents, err := os.ReadFile(archive); err != nil || string(contents) != "offline archive" {
		t.Fatalf("reset changed replacement input: %s, %v", contents, err)
	}
}
