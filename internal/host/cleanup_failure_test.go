package host

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFirstCleanupStepSurvivesSuccessfulReaperAndRestart(t *testing.T) {
	cases := []struct{ reason FailureReason }{
		{FailureCleanupPlatform},
		{FailureCleanupCreateGuard},
		{FailureCleanupScratch},
		{FailureCleanupIPC},
		{FailureCleanupLogs},
		{FailureCleanupSync},
		{FailureCleanupBarrier},
		{FailureCleanupQuotaRead},
		{FailureCleanupQuotaReferences},
		{FailureCleanupJournal},
	}
	for _, tc := range cases {
		t.Run(string(tc.reason), func(t *testing.T) {
			ctx := context.Background()
			f := newCreateStateFixture(t, EgressNone)
			const unsafe = "untrusted-child-or-daemon-body-must-not-enter-diagnostic"
			first := cleanupStep(tc.reason, errors.New(unsafe))
			if strings.Contains(first.Error(), unsafe) {
				t.Fatal("raw cause entered diagnostic text")
			}
			// This is the production ordering: finite first cause before bookkeeping.
			if err := f.journal.recordCleanupFailure(ctx, f.lease.Ownership, first); err != nil {
				t.Fatal(err)
			}
			if err := f.journal.cleanup(ctx, f.lease.Spec.InstanceID, false, first); err != nil {
				t.Fatal(err)
			}
			if err := f.journal.recordCleanupFailure(ctx, f.lease.Ownership, cleanupStep(FailureCleanupPlatform, ErrCleanupIncomplete)); err != nil {
				t.Fatal(err)
			}
			if err := f.journal.cleanup(ctx, f.lease.Spec.InstanceID, true, nil); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			var state, reason, cleanup string
			if err := f.journal.db.QueryRowContext(ctx, "SELECT state,reason,cleanup FROM instances WHERE id=?", f.lease.Spec.InstanceID).Scan(&state, &reason, &cleanup); err != nil {
				t.Fatal(err)
			}
			if state != "FAILED" || cleanup != "COMPLETE" || reason != string(PhaseCleanup)+":"+string(tc.reason) {
				t.Fatalf("first cleanup cause lost: %s/%s/%s", state, reason, cleanup)
			}
		})
	}
}

func TestCleanupStepDoesNotReplaceOriginalSandboxFailure(t *testing.T) {
	ctx := context.Background()
	f := newCreateStateFixture(t, EgressNone)
	if err := f.journal.RecordFailure(ctx, f.lease.Ownership, PhaseAttach, FailureBootstrapTLS); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.recordCleanupFailure(ctx, f.lease.Ownership, cleanupStep(FailureCleanupQuotaReferences, ErrCleanupIncomplete)); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.cleanup(ctx, f.lease.Spec.InstanceID, true, nil); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := f.journal.db.QueryRowContext(ctx, "SELECT reason FROM instances WHERE id=?", f.lease.Spec.InstanceID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "ATTACH:BOOTSTRAP_CERTIFICATE_INVALID" {
		t.Fatalf("cleanup replaced original failure: %q", reason)
	}
}

func TestCleanupStepRejectsUnknownClassificationAndForeignOwnership(t *testing.T) {
	ctx := context.Background()
	f := newCreateStateFixture(t, EgressNone)
	if err := f.journal.recordCleanupFailure(ctx, f.lease.Ownership, cleanupStep(FailureReason("untrusted text"), ErrCleanupIncomplete)); err == nil {
		t.Fatal("unregistered phase was journaled")
	}
	foreign := f.lease.Ownership
	foreign.InstallationID = strings.Repeat("f", 32)
	if err := f.journal.recordCleanupFailure(ctx, foreign, cleanupStep(FailureCleanupQuotaReferences, ErrCleanupIncomplete)); err == nil {
		t.Fatal("foreign installation wrote cleanup cause")
	}
	var reason string
	if err := f.journal.db.QueryRowContext(ctx, "SELECT reason FROM instances WHERE id=?", f.lease.Spec.InstanceID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "" {
		t.Fatalf("failed diagnostic validation changed original reason: %q", reason)
	}
}

func TestCleanupStepPreservesOwnershipSentinels(t *testing.T) {
	for _, cause := range []error{ErrCleanupIncomplete, ErrCreateUnresolved, context.Canceled, context.DeadlineExceeded} {
		if !errors.Is(cleanupStep(FailureCleanupCreateGuard, cause), cause) {
			t.Fatalf("cleanup classification hid underlying ownership outcome: %v", cause)
		}
	}
	if cleanupStep(FailureCleanupPlatform, nil) != nil {
		t.Fatal("successful cleanup was classified as failure")
	}
}
