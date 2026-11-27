//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

type createStateFixture struct {
	journal   *Store
	directory string
	lease     Lease
	guard     *ManagementGuard
}

func newCreateStateFixture(t *testing.T, policy EgressPolicy) *createStateFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	guard := testManagementGuard(t)
	database, err := os.OpenFile(filepath.Join(dir, "supervisor.sqlite"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := openStoreDB(ctx, dir, true, guard)
	if err != nil {
		t.Fatal(err)
	}
	s.productID = strings.Repeat("1", 32)
	if err = s.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcquireLease(ctx); err != nil {
		t.Fatal(err)
	}
	f := &createStateFixture{journal: s, directory: dir, guard: guard}
	t.Cleanup(func() {
		if f.journal != nil {
			if f.journal.installationLease != nil {
				_ = f.journal.installationLease.Close()
			}
			_ = f.journal.Close()
		}
	})
	spec := LaunchSpec{ModuleID: "installed-module", InstanceID: strings.Repeat("b", 32), ImageDigest: "registry.example/module@sha256:" + strings.Repeat("c", 64), InitialEgress: policy, Entrypoint: []string{"/module"}, UID: 1001, GID: 1001, Resources: ResourceLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Pids: 64, PersistentBytes: 1 << 30, PersistentInodes: 65536, ScratchBytes: 1 << 30, ScratchInodes: 65536, ControlMessageMaxBytes: 65536, LogBufferBytes: 1 << 20, LogFileMaxBytes: 1 << 20, LogRetainedFiles: 2}}
	approved := spec
	approved.InstanceID = ""
	revision := RevisionRecord{ID: "revision", BundleDigest: "bundle", Images: []ApprovedImageBinding{{ModuleID: spec.ModuleID, ImageSelector: spec.ImageDigest, ImageRecordID: "image"}}, LaunchPolicies: []LaunchSpec{approved}, PublicProfile: NetworkPublicV4}
	m := InstallationManifest{Format: "chatanium-gvx", FormatVersion: 1, SchemaVersion: 1, RuntimeInstallationID: s.productID, State: "READY", DesiredRunState: "RUNNING", ActiveRevision: revision.ID, BundleDigest: "bundle", Paths: InstallationPaths{Control: dir}, Budget: StorageBudget{DataBytes: 8 << 30, DataInodes: 1 << 20, AppBytes: 1 << 30, AppInodes: 65536}}
	for _, v := range []struct {
		q     string
		id    string
		value any
	}{
		{"INSERT INTO runtime_installations VALUES(?,?)", s.productID, m},
		{"INSERT INTO revisions VALUES(?,?)", revision.ID, revision},
	} {
		raw, e := json.Marshal(v.value)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.db.ExecContext(ctx, v.q, v.id, raw); e != nil {
			t.Fatal(e)
		}
	}
	if _, err = s.ReserveAppStorage(ctx); err != nil {
		t.Fatal(err)
	}
	cache := CacheGeneration{ID: "cache", ImageRecordID: "image", BundleDigest: "bundle", State: "READY"}
	raw, _ := json.Marshal(cache)
	if _, err = s.db.ExecContext(ctx, "INSERT INTO image_records VALUES('image','{}')"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, "INSERT INTO cache_generations VALUES('cache','image',?)", raw); err != nil {
		t.Fatal(err)
	}
	epoch := strings.Repeat("a", 32)
	if err = s.epoch(ctx, epoch, "boot", 123, "held-pidfd"); err != nil {
		t.Fatal(err)
	}
	f.lease, err = s.allocate(ctx, epoch, spec, f.config())
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *createStateFixture) config() SupervisorConfig {
	return SupervisorConfig{RuntimeInstallationID: f.journal.productID, StorageRoot: filepath.Join(f.directory, "storage"), IPCRoot: filepath.Join(f.directory, "ipc"), ManagementDirectory: f.directory, RuntimeGID: 1001, Sandbox: NumericIdentity{UID: 1002, GID: 1002}, PublicProfile: NetworkPublicV4, StartupTimeout: time.Second}
}
func (f *createStateFixture) reopen(t *testing.T) {
	t.Helper()
	id := f.journal.productID
	if err := f.journal.installationLease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	guard, err := acquireManagementGuardAt(ctx, f.guard.root, f.guard.uid, ManagementShared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Close() })
	s, err := openStoreDB(ctx, f.directory, false, guard)
	if err != nil {
		t.Fatal(err)
	}
	s.productID = id
	if _, err = s.AcquireLease(ctx); err != nil {
		t.Fatal(err)
	}
	f.journal = s
	f.guard = guard
}
func testUnit(name string) UnitIdentity {
	return UnitIdentity{Name: name, Generation: "generation", InvocationID: "invocation", BootID: "boot", CgroupPath: "/owned", ExecutableDigest: "sha256:binary", ResourceFingerprint: "limits", MainPID: 123, StartTime: 42}
}

func TestSubmittedCreateRetainsOwnershipAcrossAbsentObservationsAndRestart(t *testing.T) {
	for _, kind := range []CreateKind{CreateService, CreateNetwork} {
		t.Run(string(kind), func(t *testing.T) {
			ctx := context.Background()
			f := newCreateStateFixture(t, EgressPublicInternet)
			o := f.lease.Ownership
			identity := "owned.service"
			if kind == CreateNetwork {
				identity = "owned-network"
			}
			if err := f.journal.SubmitCreate(ctx, o, kind, identity); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if err := requireCreateResolved(ctx, f.journal, o, kind, identity); !errors.Is(err, ErrCreateUnresolved) {
					t.Fatalf("absence retired submission: %v", err)
				}
				if err := f.journal.cleanup(ctx, o.InstanceID, true, nil); !errors.Is(err, ErrCreateUnresolved) {
					t.Fatalf("unknown outcome released claims: %v", err)
				}
			}
			if err := f.journal.cleanup(ctx, o.InstanceID, false, ErrCreateUnresolved); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			record, found, err := f.journal.LookupCreate(ctx, o, kind)
			if err != nil || !found || record.State != CreateSubmitted {
				t.Fatalf("restart lost submission: %+v %v", record, err)
			}
			next := f.lease.Spec
			next.InstanceID = strings.Repeat("d", 32)
			if _, err = f.journal.allocate(ctx, o.EpochID, next, f.config()); err == nil {
				t.Fatal("unresolved module became reusable")
			}
			if err = f.journal.SubmitCreate(ctx, o, kind, identity); !errors.Is(err, ErrCreateAlreadySubmitted) {
				t.Fatalf("resubmission: %v", err)
			}
			wrong := o
			wrong.EpochID = strings.Repeat("e", 32)
			if err = f.journal.ObserveCreated(ctx, wrong, kind, identity, "late"); err == nil {
				t.Fatal("foreign epoch resolved submission")
			}
			if kind == CreateService {
				u := testUnit(identity)
				if err = f.journal.RecordUnit(ctx, o, UnitObservation{Unit: u}); err != nil {
					t.Fatal(err)
				}
				if err = f.journal.ObserveCreated(ctx, o, kind, identity, unitObjectID(u)); err != nil {
					t.Fatal(err)
				}
				u.InvocationID = "replacement"
				if err = f.journal.RecordUnit(ctx, o, UnitObservation{Unit: u}); err == nil {
					t.Fatal("invocation replacement accepted")
				}
			} else {
				if err = f.journal.ObserveCreated(ctx, o, kind, identity, "late"); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.journal.ObserveCreated(ctx, o, kind, identity, "other"); err == nil {
				t.Fatal("observed object replaced")
			}
			if err = requireCreateResolved(ctx, f.journal, o, kind, identity); err != nil {
				t.Fatal(err)
			}
			if err = f.journal.cleanup(ctx, o.InstanceID, true, nil); err != nil {
				t.Fatal(err)
			}
			if _, err = f.journal.allocate(ctx, o.EpochID, next, f.config()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestNeverDispatchedCleanupNeedsNoHostResources(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	for _, kind := range []CreateKind{CreateService, CreateNetwork} {
		if err := requireCreateResolved(context.Background(), f.journal, f.lease.Ownership, kind, "never-dispatched"); err != nil {
			t.Fatal(err)
		}
	}
}
func TestUnresolvedCreateBlocksSupervisorStorageCleanup(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	if err := f.journal.SubmitCreate(ctx, o, CreateService, "owned.service"); err != nil {
		t.Fatal(err)
	}
	s := &Supervisor{config: SupervisorConfig{OperationTimeout: time.Second}, journal: f.journal, platform: pointInTimeAbsentPlatform{}}
	if err := s.cleanup(ctx, f.lease); !errors.Is(err, ErrCreateUnresolved) {
		t.Fatalf("absence bypassed guard: %v", err)
	}
	var status string
	if err := f.journal.db.QueryRowContext(ctx, "SELECT cleanup FROM instances WHERE id=?", o.InstanceID).Scan(&status); err != nil || status != "UNRESOLVED_CREATE" {
		t.Fatalf("unresolved status: %s %v", status, err)
	}
}
func TestOnlyUnresolvedCleanupMayContinueSupervisorStartup(t *testing.T) {
	for _, v := range []struct {
		err  error
		want bool
	}{{nil, false}, {ErrCleanupIncomplete, false}, {ErrCreateUnresolved, true}, {fmt.Errorf("cleanup: %w", errors.Join(ErrCleanupIncomplete, ErrCreateUnresolved)), true}, {errors.Join(ErrCreateUnresolved, context.Canceled), false}, {errors.Join(ErrCleanupIncomplete, ErrCreateUnresolved, errors.New("quota unavailable")), false}} {
		if got := unresolvedCleanupOnly(v.err); got != v.want {
			t.Fatalf("%v: %t", v.err, got)
		}
	}
}
func TestReconciliationErrorOnlyAdvertisesPendingForUnresolvedCleanup(t *testing.T) {
	for _, v := range []struct {
		err     error
		pending bool
	}{{nil, false}, {ErrCreateUnresolved, true}, {cleanupStep(FailureCleanupPlatform, errors.Join(ErrCleanupIncomplete, ErrCreateUnresolved)), true}, {ErrCleanupIncomplete, false}, {errors.Join(ErrCreateUnresolved, context.DeadlineExceeded), false}, {errors.Join(ErrCreateUnresolved, prerequisite(errors.New("enforcement unavailable"))), false}} {
		err := reconciliationError(v.err)
		if v.err == nil {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		raw, e := marshalControl(controlResponse{Version: controlVersion, Error: controlError(err)})
		if e != nil {
			t.Fatal(e)
		}
		var out controlResponse
		if e = strictJSON(raw, &out); e != nil {
			t.Fatal(e)
		}
		if (out.Error.Reason == "HOST_RECONCILIATION_PENDING") != v.pending {
			t.Fatalf("unsafe admission: %+v", out.Error)
		}
	}
}
func TestMarkerlessLegacyStateRejectedUnmodified(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	ctx := context.Background()
	if _, err := f.journal.db.ExecContext(ctx, "DELETE FROM metadata WHERE key='format'"); err != nil {
		t.Fatal(err)
	}
	guard, err := acquireManagementGuardAt(ctx, f.guard.root, f.guard.uid, ManagementShared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Close() })
	if unexpected, err := openStoreDB(ctx, f.directory, false, guard); err == nil {
		_ = unexpected.Close()
		t.Fatal("markerless database accepted")
	} else if !strings.Contains(err.Error(), "markerless installation") {
		t.Fatalf("markerless database rejection: %v", err)
	}
	var n int
	if err := f.journal.db.QueryRowContext(ctx, "SELECT count(*) FROM metadata WHERE key='format'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("legacy database mutated: %d %v", n, err)
	}
}

type pointInTimeAbsentPlatform struct{}

func (pointInTimeAbsentPlatform) BindCreateJournal(CreateJournal) error { return nil }
func (pointInTimeAbsentPlatform) Preflight(context.Context) error       { panic("unused") }
func (pointInTimeAbsentPlatform) ImageManifest(context.Context, string, int64) ([]byte, error) {
	panic("unused")
}
func (pointInTimeAbsentPlatform) Create(context.Context, LaunchSpec, Lease, []string) (*StageProcess, error) {
	panic("unused")
}
func (pointInTimeAbsentPlatform) Start(context.Context, Ownership) error { panic("unused") }
func (pointInTimeAbsentPlatform) ConfirmGuestStorage(context.Context, Ownership, gvxcontract.RootInitResult) error {
	panic("unused")
}
func (pointInTimeAbsentPlatform) Wait(context.Context, Ownership) (ProcessExit, error) {
	panic("unused")
}
func (pointInTimeAbsentPlatform) Terminate(context.Context, Ownership) error { panic("unused") }
func (pointInTimeAbsentPlatform) SetEgress(context.Context, Ownership, EgressPolicy) error {
	panic("unused")
}
func (pointInTimeAbsentPlatform) Reconcile(context.Context, Ownership) error { return nil }
