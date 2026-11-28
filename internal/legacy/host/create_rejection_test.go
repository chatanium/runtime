//go:build linux

package host

import (
	"context"
	"errors"
	"testing"

	sharedhost "github.com/thirdscam/chatanium/internal/host"
)

func TestCreateRejectionPreservesDurableRecordsAcrossRestart(t *testing.T) {
	f := newCreateStateFixture(t, sharedhost.EgressPublicInternet)
	ctx := context.Background()
	o := f.lease.Ownership
	if err := f.journal.SubmitCreate(ctx, o, CreateService, "owned.service"); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.SubmitCreate(ctx, o, CreateNetwork, "network"); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.ObserveCreated(ctx, o, CreateNetwork, "network", "network-id"); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	if err := f.journal.unresolvedCreates(ctx, o.InstanceID); !errors.Is(err, ErrCreateUnresolved) {
		t.Fatalf("restart guessed outcome: %v", err)
	}
	var claims int
	if err := f.journal.db.QueryRowContext(ctx, "SELECT count(*) FROM resource_claims WHERE instance=? AND state!='RELEASED'", o.InstanceID).Scan(&claims); err != nil || claims != 6 {
		t.Fatalf("restart changed claims: %d %v", claims, err)
	}
	if err := f.journal.RejectCreate(ctx, o, CreateService, "owned.service", "completed authoritative dbus rejection"); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	record, found, err := f.journal.LookupCreate(ctx, o, CreateService)
	if err != nil || !found || record.State != CreateRejected || record.ObjectID != "" || record.Rejection == "" {
		t.Fatalf("lost rejection: %+v %v", record, err)
	}
	if err = f.journal.SubmitCreate(ctx, o, CreateService, "owned.service"); !errors.Is(err, ErrCreateAlreadySubmitted) {
		t.Fatalf("rejection permits retry: %v", err)
	}
}
func TestCreateRejectionCannotReplaceOwnershipOrObservedResult(t *testing.T) {
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	if err := f.journal.RejectCreate(ctx, o, CreateService, "owned.service", "proof"); err == nil {
		t.Fatal("rejection fabricated submission")
	}
	if err := f.journal.SubmitCreate(ctx, o, CreateService, "owned.service"); err != nil {
		t.Fatal(err)
	}
	wrong := o
	wrong.EpochID = "foreign"
	for _, v := range []struct {
		o           sharedhost.Ownership
		name, proof string
	}{{wrong, "owned.service", "proof"}, {o, "other", "proof"}, {o, "owned.service", ""}} {
		if err := f.journal.RejectCreate(ctx, v.o, CreateService, v.name, v.proof); err == nil {
			t.Fatal("unmatched rejection accepted")
		}
	}
	if err := f.journal.RecordUnit(ctx, o, UnitObservation{Unit: testUnit("owned.service")}); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.RejectCreate(ctx, o, CreateService, "owned.service", "proof"); err == nil {
		t.Fatal("rejection overwrote observed invocation")
	}
}
func TestCreateRejectionJournalFailureRetainsSubmittedReservation(t *testing.T) {
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	if err := f.journal.SubmitCreate(ctx, o, CreateService, "owned.service"); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.RejectCreate(ctx, o, CreateService, "owned.service", "completed rejection"); err == nil {
		t.Fatal("closed journal accepted rejection")
	}
	f.reopen(t)
	record, found, err := f.journal.LookupCreate(ctx, o, CreateService)
	if err != nil || !found || record.State != CreateSubmitted || record.Rejection != "" {
		t.Fatalf("failed commit lost reservation: %+v %v", record, err)
	}
	if err = f.journal.cleanup(ctx, o.InstanceID, true, nil); !errors.Is(err, ErrCreateUnresolved) {
		t.Fatalf("failed rejection released claims: %v", err)
	}
}
