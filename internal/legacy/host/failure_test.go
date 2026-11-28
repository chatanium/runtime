//go:build linux

package host

import (
	"context"
	"errors"
	"strings"
	"testing"

	sharedhost "github.com/thirdscam/chatanium/internal/host"
)

func TestOriginalSandboxFailureSurvivesCleanupAndLateStartupWrites(t *testing.T) {
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	secret := "raw-module-or-daemon-content-must-not-be-journaled"
	err := classifiedFailure(FailureBootstrapMux, errors.New(secret))
	if recordErr := f.journal.RecordFailure(ctx, o, PhaseAttach, FailureBootstrapMux); recordErr != nil {
		t.Fatal(recordErr)
	}
	if failureReason(err, FailureInspect) != FailureBootstrapMux {
		t.Fatalf("original consumer classification lost: %v", err)
	}
	if err := f.journal.cleanup(ctx, o.InstanceID, false, errors.New(secret)); err != nil {
		t.Fatal(err)
	}
	// The main Start/Create path can finish after the collector noticed failure.
	if err := f.journal.state(ctx, o.InstanceID, "CREATED", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.state(ctx, o.InstanceID, "READY", ""); err != nil {
		t.Fatal(err)
	}
	// A secondary poststart/cgroup failure must not replace the first cause.
	if err := f.journal.RecordFailure(ctx, o, PhasePoststart, FailureCgroupPids); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.cleanup(ctx, o.InstanceID, true, nil); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	var state, reason, cleanup string
	if err := f.journal.db.QueryRowContext(ctx, "SELECT state,reason,cleanup FROM instances WHERE id=?", o.InstanceID).Scan(&state, &reason, &cleanup); err != nil {
		t.Fatal(err)
	}
	if state != "STOPPED" || reason != "ATTACH:BOOTSTRAP_MULTIPLEX_REQUIRED" || cleanup != "COMPLETE" {
		t.Fatalf("original failure/cleanup independence lost: %s %s %s", state, reason, cleanup)
	}
	if strings.Contains(reason, secret) {
		t.Fatal("raw error text leaked into durable diagnostic")
	}
}

func TestCleanupDoesNotInventOriginalFailureAndCodesAreClosed(t *testing.T) {
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	if err := f.journal.cleanup(ctx, o.InstanceID, false, sharedhost.ErrCleanupIncomplete); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := f.journal.db.QueryRowContext(ctx, "SELECT reason FROM instances WHERE id=?", o.InstanceID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "" {
		t.Fatalf("secondary cleanup became original failure: %q", reason)
	}
	if err := f.journal.RecordFailure(ctx, o, PhaseAttach, FailureReason("untrusted child text")); err == nil {
		t.Fatal("arbitrary diagnostic reason accepted")
	}
	if err := f.journal.RecordFailure(ctx, o, FailurePhase("untrusted phase"), FailureBootstrapEOF); err == nil {
		t.Fatal("arbitrary diagnostic phase accepted")
	}
	if err := f.journal.RecordFailure(ctx, o, PhaseAttach, FailureBootstrapEOF); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.db.QueryRowContext(ctx, "SELECT reason FROM instances WHERE id=?", o.InstanceID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "ATTACH:BOOTSTRAP_EOF" {
		t.Fatalf("original cause could not follow cleanup bookkeeping: %q", reason)
	}
}
