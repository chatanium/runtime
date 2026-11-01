//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newPersistentStateFixture(t *testing.T) *createStateFixture {
	t.Helper()
	f := newCreateStateFixture(t, EgressNone)
	f.lease.Spec.Resources.PersistentBytes = 1 << 30
	f.lease.Spec.Resources.PersistentInodes = 65536
	raw, err := json.Marshal(f.lease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.journal.db.ExecContext(context.Background(), "UPDATE instances SET lease=? WHERE id=?", string(raw), f.lease.Spec.InstanceID); err != nil {
		t.Fatal(err)
	}
	return f
}

// These exercise real SQLite transactions/reopen and the production checkpoint
// guard. They do not claim to exercise an XFS ioctl or prove host reclamation.
func TestPartialPersistentCheckpointSurvivesCleanupAndRestart(t *testing.T) {
	for _, target := range []string{"QUOTA_INTENT", "QUOTA_READY", "DIRECTORY_INTENT"} {
		t.Run(target, func(t *testing.T) {
			ctx := context.Background()
			f := newPersistentStateFixture(t)
			phase := "RESERVED"
			for _, next := range []string{"QUOTA_INTENT", "QUOTA_READY", "DIRECTORY_INTENT"} {
				if err := f.journal.persistentTransition(ctx, f.lease, phase, next, 1<<30, 65536); err != nil {
					t.Fatal(err)
				}
				phase = next
				if phase == target {
					break
				}
			}
			if err := f.journal.state(ctx, f.lease.Spec.InstanceID, "FAILED", "HOST_PREREQUISITE_FAILED"); err != nil {
				t.Fatal(err)
			}
			if err := f.journal.cleanup(ctx, f.lease.Spec.InstanceID, true, nil); err != nil {
				t.Fatal(err)
			}
			var claim string
			if err := f.journal.db.QueryRowContext(ctx, "SELECT state FROM resource_claims WHERE instance=? AND kind='persistent'", f.lease.Spec.InstanceID).Scan(&claim); err != nil {
				t.Fatal(err)
			}
			if claim != "INTENT" {
				t.Fatalf("partial persistent ownership fabricated completed retention: %s", claim)
			}
			f.reopen(t)
			next := f.lease.Spec
			next.InstanceID = strings.Repeat("d", 32)
			lease, err := f.journal.allocate(ctx, f.lease.Ownership.EpochID, next, SupervisorConfig{StorageRoot: filepath.Join(f.directory, "storage"), IPCRoot: filepath.Join(f.directory, "ipc"), ManagementDirectory: f.directory})
			if err != nil {
				t.Fatal(err)
			}
			if lease.PersistentProject != f.lease.PersistentProject || lease.PersistentPath != f.lease.PersistentPath || lease.Ownership.InstallationID != f.lease.Ownership.InstallationID {
				t.Fatal("stable persistent reservation changed after partial setup")
			}
			if lease.ScratchProject == f.lease.ScratchProject {
				t.Fatal("transient project identity was reused")
			}
			got, err := f.journal.persistentProvision(ctx, lease)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != target || got.Bytes != 1<<30 || got.Inodes != 65536 {
				t.Fatalf("restart lost recoverable checkpoint: %+v", got)
			}
		})
	}
}

func TestCompletedPersistentDirectoryIsNeverRecreated(t *testing.T) {
	ctx := context.Background()
	f := newPersistentStateFixture(t)
	if err := f.journal.persistentTransition(ctx, f.lease, "RESERVED", "READY", 1<<30, 65536); err != nil {
		t.Fatal(err)
	}
	s := storage{journal: f.journal, quota: &quotaFS{blockBytes: 4096}}
	err := s.provisionPersistent(ctx, f.lease)
	if err == nil || !strings.Contains(err.Error(), "completed persistent directory is missing") {
		t.Fatalf("missing completed ownership did not fail closed: %v", err)
	}
	if _, err = os.Lstat(f.lease.PersistentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing persistent directory was recreated: %v", err)
	}
	phase, err := f.journal.persistentProvision(ctx, f.lease)
	if err != nil || phase.State != "READY" {
		t.Fatalf("failure discarded completed ownership: %+v %v", phase, err)
	}
}

func TestMissingPersistentCheckpointRequiresExplicitAttestation(t *testing.T) {
	ctx := context.Background()
	f := newPersistentStateFixture(t)
	if _, err := f.journal.db.ExecContext(ctx, "DELETE FROM persistent_provisions WHERE module_id=?", f.lease.Spec.ModuleID); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	if _, err := f.journal.persistentProvision(ctx, f.lease); err == nil || !strings.Contains(err.Error(), "operator-attested migration") {
		t.Fatalf("legacy intent was automatically adopted: %v", err)
	}
	var count int
	if err := f.journal.db.QueryRowContext(ctx, "SELECT count(*) FROM persistent_provisions WHERE module_id=?", f.lease.Spec.ModuleID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed lookup fabricated a checkpoint: %d %v", count, err)
	}
}

func TestPersistentCheckpointRejectsForeignInstallationIdentity(t *testing.T) {
	ctx := context.Background()
	f := newPersistentStateFixture(t)
	foreign := f.lease
	foreign.Ownership.InstallationID = strings.Repeat("f", 32)
	if _, err := f.journal.persistentProvision(ctx, foreign); err == nil {
		t.Fatal("foreign storage key read persistent checkpoint")
	}
	if err := f.journal.persistentTransition(ctx, foreign, "RESERVED", "QUOTA_INTENT", 1<<30, 65536); err == nil {
		t.Fatal("foreign storage key changed persistent checkpoint")
	}
	got, err := f.journal.persistentProvision(ctx, f.lease)
	if err != nil || got.State != "RESERVED" {
		t.Fatalf("foreign request altered reserved ownership: %+v %v", got, err)
	}
}

func TestPersistentCollisionCannotBecomeRecoverableIntent(t *testing.T) {
	ctx := context.Background()
	f := newPersistentStateFixture(t)
	if err := f.journal.persistentTransition(ctx, f.lease, "RESERVED", "COLLISION", 1<<30, 65536); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.cleanup(ctx, f.lease.Spec.InstanceID, true, nil); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	s := storage{journal: f.journal, quota: &quotaFS{blockBytes: 4096}}
	if err := s.provisionPersistent(ctx, f.lease); err == nil || !strings.Contains(err.Error(), "foreign allocation") {
		t.Fatalf("collision became resumable ownership: %v", err)
	}
	got, err := f.journal.persistentProvision(ctx, f.lease)
	if err != nil || got.State != "COLLISION" {
		t.Fatalf("collision evidence lost: %+v %v", got, err)
	}
}
