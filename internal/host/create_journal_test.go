package host

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

type createStateFixture struct {
	journal   *journal
	directory string
	lease     Lease
}

func newCreateStateFixture(t *testing.T, policy EgressPolicy) *createStateFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	j, err := openJournal(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	f := &createStateFixture{journal: j, directory: dir}
	t.Cleanup(func() {
		if f.journal != nil {
			f.journal.db.Close()
		}
	})
	epoch := strings.Repeat("a", 32)
	if err := j.epoch(ctx, epoch, "boot", 123, "held-pidfd"); err != nil {
		t.Fatal(err)
	}
	spec := LaunchSpec{ModuleID: "installed-module", InstanceID: strings.Repeat("b", 32), ImageDigest: "registry.example/module@sha256:" + strings.Repeat("c", 64), InitialEgress: policy, UID: 1001, GID: 1001}
	lease, err := j.allocate(ctx, epoch, spec, SupervisorConfig{StorageRoot: filepath.Join(dir, "storage"), IPCRoot: filepath.Join(dir, "ipc"), ManagementDirectory: dir, RuntimeGID: 1001})
	if err != nil {
		t.Fatal(err)
	}
	f.lease = lease
	return f
}
func (f *createStateFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.journal.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.journal = nil
	j, err := openJournal(context.Background(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	f.journal = j
}

// These are durable state tests, not proof of Docker's late-publication timing.
// A timed-out submission is followed by any number of absent observations,
// process restart, and finally the exact late-created object's observation.
func TestSubmittedCreateRetainsOwnershipAcrossAbsentObservationsAndRestart(t *testing.T) {
	for _, kind := range []CreateKind{CreateContainer, CreateNetwork} {
		t.Run(string(kind), func(t *testing.T) {
			ctx := context.Background()
			f := newCreateStateFixture(t, EgressPublicInternet)
			o := f.lease.Ownership
			identity := containerName(o)
			if kind == CreateNetwork {
				identity += "-net"
			}
			if err := f.journal.SubmitCreate(ctx, o, kind, identity); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if err := requireCreateResolved(ctx, f.journal, o, kind, identity); !errors.Is(err, ErrCreateUnresolved) {
					t.Fatalf("point-in-time absence retired submitted create: %v", err)
				}
				if err := f.journal.cleanup(ctx, o.InstanceID, true, nil); !errors.Is(err, ErrCreateUnresolved) {
					t.Fatalf("cleanup COMPLETE accepted unknown outcome: %v", err)
				}
			}
			if err := f.journal.cleanup(ctx, o.InstanceID, false, ErrCreateUnresolved); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			record, found, err := f.journal.LookupCreate(ctx, o, kind)
			if err != nil || !found || record.State != CreateSubmitted {
				t.Fatalf("restart lost unresolved submission: %+v %t %v", record, found, err)
			}
			leases, err := f.journal.pending(ctx, "")
			if err != nil || len(leases) != 1 {
				t.Fatalf("unresolved lease disappeared from reconciliation: %d %v", len(leases), err)
			}
			next := f.lease.Spec
			next.InstanceID = strings.Repeat("d", 32)
			if _, err := f.journal.allocate(ctx, o.EpochID, next, SupervisorConfig{StorageRoot: f.directory, IPCRoot: f.directory, ManagementDirectory: f.directory}); err == nil {
				t.Fatal("unresolved installation became reusable")
			}
			if err := f.journal.SubmitCreate(ctx, o, kind, identity); !errors.Is(err, ErrCreateAlreadySubmitted) {
				t.Fatalf("submitted operation was retried: %v", err)
			}
			// Only the trusted platform may make this observation, after verifying every
			// ownership label. The state layer also rejects a different epoch/principal.
			wrong := o
			wrong.EpochID = strings.Repeat("e", 32)
			if err := f.journal.ObserveCreated(ctx, wrong, kind, identity, "late-id"); err == nil {
				t.Fatal("foreign epoch resolved a submission")
			}
			if err := f.journal.ObserveCreated(ctx, o, kind, identity, "late-id"); err != nil {
				t.Fatal(err)
			}
			if err := f.journal.ObserveCreated(ctx, o, kind, identity, "different-id"); err == nil {
				t.Fatal("second object replaced the exact observed result")
			}
			if err := requireCreateResolved(ctx, f.journal, o, kind, identity); err != nil {
				t.Fatalf("exact observation did not resolve submission: %v", err)
			}
			if err := f.journal.SubmitCreate(ctx, o, kind, identity); !errors.Is(err, ErrCreateAlreadySubmitted) {
				t.Fatalf("observed operation was resubmitted: %v", err)
			}
			// The platform must still prove this observed object's deletion. At that
			// point the journal permits completion and releases installation exclusivity.
			if err := f.journal.cleanup(ctx, o.InstanceID, true, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := f.journal.allocate(ctx, o.EpochID, next, SupervisorConfig{StorageRoot: f.directory, IPCRoot: f.directory, ManagementDirectory: f.directory}); err != nil {
				t.Fatalf("resolved cleanup retained installation forever: %v", err)
			}
		})
	}
}

func TestNeverDispatchedPlatformCleanupNeedsNoDockerOrFirewall(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	// Nil SDK/network fields deliberately detect any accidental host dependency.
	// All submissions must be durable before a request can reach either API.
	p := &DockerPlatform{cfg: DockerConfig{TerminationDeadline: time.Second}, creates: f.journal}
	if err := p.Reconcile(context.Background(), f.lease.Ownership); err != nil {
		t.Fatalf("never-dispatched cleanup depended on host resources: %v", err)
	}
	for _, kind := range []CreateKind{CreateContainer, CreateNetwork} {
		if _, found, err := f.journal.LookupCreate(context.Background(), f.lease.Ownership, kind); err != nil || found {
			t.Fatalf("cleanup fabricated %s submission: %t %v", kind, found, err)
		}
	}
}

func TestUnresolvedCreateBlocksSupervisorStorageCleanup(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	if err := f.journal.SubmitCreate(ctx, o, CreateContainer, containerName(o)); err != nil {
		t.Fatal(err)
	}
	// Storage deliberately nil: an erroneous reclamation attempt would panic.
	// Match NewSupervisor's required positive journal-operation deadline.
	s := &Supervisor{config: SupervisorConfig{OperationTimeout: time.Second}, journal: f.journal, platform: pointInTimeAbsentPlatform{}}
	err := s.cleanup(ctx, f.lease)
	if !errors.Is(err, ErrCreateUnresolved) {
		t.Fatalf("absence bypassed reservation guard: %v", err)
	}
	var status string
	if err := f.journal.db.QueryRowContext(ctx, "SELECT cleanup FROM instances WHERE id=?", o.InstanceID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "UNRESOLVED_CREATE" {
		t.Fatalf("operator-visible unresolved state missing: %q", status)
	}
	if got := controlError(errors.Join(context.DeadlineExceeded, err)); got.Reason != "CREATE_OUTCOME_UNRESOLVED" {
		t.Fatalf("wire reason concealed unresolved create: %+v", got)
	}
	if _, found, err := f.journal.LookupCreate(ctx, o, CreateNetwork); err != nil || found {
		t.Fatalf("NONE topology acquired a network submission: %t %v", found, err)
	}
}

func TestOnlyUnresolvedCleanupMayContinueSupervisorStartup(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false}, {ErrCleanupIncomplete, false}, {ErrCreateUnresolved, true},
		{fmt.Errorf("cleanup: %w", errors.Join(ErrCleanupIncomplete, ErrCreateUnresolved)), true},
		{errors.Join(ErrCreateUnresolved, context.Canceled), false},
		{errors.Join(ErrCleanupIncomplete, ErrCreateUnresolved, errors.New("quota unavailable")), false},
	} {
		if got := unresolvedCleanupOnly(tc.err); got != tc.want {
			t.Fatalf("startup classification %v = %t, want %t", tc.err, got, tc.want)
		}
	}
}

func TestReconciliationErrorOnlyAdvertisesPendingForUnresolvedCleanup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		pending bool
	}{
		{"resolved", nil, false},
		{"unresolved", ErrCreateUnresolved, true},
		{"wrapped cleanup", cleanupStep(FailureCleanupPlatform, errors.Join(ErrCleanupIncomplete, ErrCreateUnresolved)), true},
		{"cleanup only", ErrCleanupIncomplete, false},
		{"deadline", errors.Join(ErrCreateUnresolved, context.DeadlineExceeded), false},
		{"enforcement", errors.Join(ErrCreateUnresolved, prerequisite(errors.New("enforcement unavailable"))), false},
		{"journal", errors.Join(ErrCleanupIncomplete, ErrCreateUnresolved, errors.New("journal unavailable")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := reconciliationError(tc.err)
			if tc.err == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !tc.pending && err != tc.err {
				t.Fatal("fatal reconciliation error was replaced")
			}
			// Exercise the same sanitization and JSON boundary as the real RPC.
			data, marshalErr := marshalControl(controlResponse{Version: controlVersion, Error: controlError(err)})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var response controlResponse
			if decodeErr := strictJSON(data, &response); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if response.Error == nil || (response.Error.Reason == "HOST_RECONCILIATION_PENDING") != tc.pending {
				t.Fatalf("unsafe pending admission result: %+v", response.Error)
			}
		})
	}
}

func TestLegacyPendingCreateMigrationDoesNotInventPreflightSubmission(t *testing.T) {
	for _, state := range []string{"ALLOCATING", "ALLOCATED", "CREATING"} {
		t.Run(state, func(t *testing.T) {
			f := newCreateStateFixture(t, EgressNone)
			ctx := context.Background()
			if err := f.journal.state(ctx, f.lease.Spec.InstanceID, state, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := f.journal.db.ExecContext(ctx, "DELETE FROM metadata WHERE key='create_journal_v1'"); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			record, found, err := f.journal.LookupCreate(ctx, f.lease.Ownership, CreateContainer)
			if err != nil {
				t.Fatal(err)
			}
			if found != (state == "CREATING") {
				t.Fatalf("legacy %s submission = %t", state, found)
			}
			if found && record.State != CreateSubmitted {
				t.Fatalf("legacy uncertain create was resolved: %+v", record)
			}
		})
	}
}

func TestExactContainerOwnershipRequiredBeforeLateObservation(t *testing.T) {
	o := Ownership{InstallationID: "installation", EpochID: "epoch", InstanceID: "instance"}
	if err := verifyOwnership(container.InspectResponse{ID: "late-id", Config: &container.Config{Labels: ownershipLabels(o)}}, o); err != nil {
		t.Fatal(err)
	}
	for key := range ownershipLabels(o) {
		c := container.InspectResponse{ID: "late-id", Config: &container.Config{Labels: ownershipLabels(o)}}
		c.Config.Labels[key] = "foreign"
		if err := verifyOwnership(c, o); err == nil {
			t.Fatalf("mismatched %s ownership accepted", key)
		}
	}
}

// Models the concrete regression: an API's absent response does not mean an
// already submitted create cannot subsequently publish an object.
type pointInTimeAbsentPlatform struct{}

func (pointInTimeAbsentPlatform) BindCreateJournal(CreateJournal) error { return nil }
func (pointInTimeAbsentPlatform) Preflight(context.Context) error       { panic("unused") }
func (pointInTimeAbsentPlatform) ImageManifest(context.Context, string, int64) ([]byte, error) {
	panic("unused")
}
func (pointInTimeAbsentPlatform) Create(context.Context, LaunchSpec, Lease, []string, string) (*Container, error) {
	panic("unused")
}
func (pointInTimeAbsentPlatform) Start(context.Context, Ownership) error        { panic("unused") }
func (pointInTimeAbsentPlatform) Wait(context.Context, Ownership) (Exit, error) { panic("unused") }
func (pointInTimeAbsentPlatform) Terminate(context.Context, Ownership) error    { panic("unused") }
func (pointInTimeAbsentPlatform) SetEgress(context.Context, Ownership, EgressPolicy) error {
	panic("unused")
}
func (pointInTimeAbsentPlatform) Reconcile(context.Context, Ownership) error { return nil }
