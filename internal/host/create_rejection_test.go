package host

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCreateRejectionMigrationPreservesExistingDurableRecords(t *testing.T) {
	f := newCreateStateFixture(t, EgressPublicInternet)
	ctx := context.Background()
	o := f.lease.Ownership
	identity := containerName(o)
	if err := f.journal.SubmitCreate(ctx, o, CreateContainer, identity); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.SubmitCreate(ctx, o, CreateNetwork, identity+"-net"); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.ObserveCreated(ctx, o, CreateNetwork, identity+"-net", "network-id"); err != nil {
		t.Fatal(err)
	}
	// Recreate the exact pre-rejection schema to exercise the actual migration,
	// not a fresh database that already has the widened state constraint.
	tx, err := f.journal.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE old_create_submissions(instance TEXT NOT NULL REFERENCES instances(id),kind TEXT NOT NULL CHECK(kind IN ('container','network')),identity TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('SUBMITTED','OBSERVED')),object_id TEXT NOT NULL,PRIMARY KEY(instance,kind),UNIQUE(kind,identity))`,
		`INSERT INTO old_create_submissions SELECT instance,kind,identity,state,object_id FROM create_submissions`,
		`DROP TABLE create_submissions`,
		`ALTER TABLE old_create_submissions RENAME TO create_submissions`,
		`DELETE FROM metadata WHERE key='create_journal_v2'`,
	} {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	for _, tc := range []struct {
		kind  CreateKind
		state CreateState
		id    string
	}{
		{CreateContainer, CreateSubmitted, ""},
		{CreateNetwork, CreateObserved, "network-id"},
	} {
		record, found, err := f.journal.LookupCreate(ctx, o, tc.kind)
		if err != nil || !found || record.State != tc.state || record.ObjectID != tc.id || record.Rejection != "" {
			t.Fatalf("migration changed old %s outcome: %+v %t %v", tc.kind, record, found, err)
		}
	}
	if err := f.journal.unresolvedCreates(ctx, o.InstanceID); !errors.Is(err, ErrCreateUnresolved) {
		t.Fatalf("migration guessed the old submitted outcome: %v", err)
	}
	var claims int
	if err := f.journal.db.QueryRowContext(ctx, "SELECT count(*) FROM resource_claims WHERE instance=? AND state!='RELEASED'", o.InstanceID).Scan(&claims); err != nil || claims != 6 {
		t.Fatalf("migration changed ownership claims: %d %v", claims, err)
	}
	if err := f.journal.RejectCreate(ctx, o, CreateContainer, identity, "authoritative completed response"); err != nil {
		t.Fatalf("migrated schema rejected definitive-negative state: %v", err)
	}
	f.reopen(t)
	record, found, err := f.journal.LookupCreate(ctx, o, CreateContainer)
	if err != nil || !found || record.State != CreateRejected || record.Rejection != "authoritative completed response" || record.ObjectID != "" {
		t.Fatalf("restart lost rejection proof: %+v %t %v", record, found, err)
	}
}

func TestCreateRejectionCannotReplaceOwnershipOrObservedResult(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	identity := containerName(o)
	if err := f.journal.RejectCreate(ctx, o, CreateContainer, identity, "proof"); err == nil {
		t.Fatal("rejection fabricated a submission")
	}
	if err := f.journal.SubmitCreate(ctx, o, CreateContainer, identity); err != nil {
		t.Fatal(err)
	}
	wrong := o
	wrong.EpochID = "foreign"
	for _, tc := range []struct {
		owner    Ownership
		identity string
		proof    string
	}{
		{wrong, identity, "proof"},
		{o, "wrong-name", "proof"},
		{o, identity, ""},
	} {
		if err := f.journal.RejectCreate(ctx, tc.owner, CreateContainer, tc.identity, tc.proof); err == nil {
			t.Fatal("unmatched or unproven rejection accepted")
		}
	}
	if err := f.journal.ObserveCreated(ctx, o, CreateContainer, identity, "actual-object"); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.RejectCreate(ctx, o, CreateContainer, identity, "proof"); err == nil {
		t.Fatal("rejection overwrote an observed object")
	}
	if err := f.journal.SubmitCreate(ctx, o, CreateContainer, identity); !errors.Is(err, ErrCreateAlreadySubmitted) {
		t.Fatalf("rejection allowed resubmission: %v", err)
	}
}

func TestCreateRejectionJournalFailureRetainsSubmittedReservation(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	identity := containerName(o)
	if err := f.journal.SubmitCreate(ctx, o, CreateContainer, identity); err != nil {
		t.Fatal(err)
	}
	receipt := &createReceipt{kind: CreateContainer, identity: identity, path: "/v1.54/containers/create?name=" + identity, status: 500, complete: true}
	receipt.body.WriteString(`{"message":"rejected"}`)
	if err := f.journal.db.Close(); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("original create rejection")
	err := recordCreateRejection(cause, receipt, f.journal, o, time.Second)
	if !errors.Is(err, cause) || err.Error() == cause.Error() {
		t.Fatal("failed rejection commit concealed either the create or journal failure")
	}
	f.reopen(t)
	record, found, err := f.journal.LookupCreate(ctx, o, CreateContainer)
	if err != nil || !found || record.State != CreateSubmitted || record.Rejection != "" {
		t.Fatalf("failed commit lost unresolved reservation: %+v %t %v", record, found, err)
	}
	if err := f.journal.cleanup(ctx, o.InstanceID, true, nil); !errors.Is(err, ErrCreateUnresolved) {
		t.Fatalf("failed rejection commit released claims: %v", err)
	}
}
