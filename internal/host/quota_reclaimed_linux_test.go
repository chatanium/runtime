//go:build linux

package host

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestQuotaReclamationHonorsExistingCancellationBeforeHostCalls(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancelled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			cause := context.Canceled
			if deadline {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				cause = context.DeadlineExceeded
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			// Nil root deliberately detects any host syscall before the cancellation
			// check. No filesystem/quota mock or privileged test host is necessary.
			q := quotaFS{}
			err := q.reclaimed(ctx, 1)
			if !errors.Is(err, ErrCleanupIncomplete) || !errors.Is(err, cause) {
				t.Fatalf("lost original context or unresolved ownership: %v", err)
			}
			if failureReason(err, "") != FailureCleanupQuotaReferences {
				t.Fatalf("timeout was not observable as unproved reclamation: %v", err)
			}
		})
	}
}

func TestQuotaReclamationKernelErrorIsNotConditionWait(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "closed-quota-root-")
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	q := quotaFS{root: file}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = q.reclaimed(ctx, 1)
	if !errors.Is(err, unix.EBADF) || errors.Is(err, context.DeadlineExceeded) || failureReason(err, "") != FailureCleanupSync {
		t.Fatalf("kernel error was retried or hidden: %v", err)
	}
}

func TestCancelledQuotaReclamationRetainsInstallationClaimsAcrossRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q := quotaFS{}
	incomplete := q.reclaimed(ctx, 1)
	if !errors.Is(incomplete, ErrCleanupIncomplete) || !errors.Is(incomplete, context.Canceled) {
		t.Fatalf("unexpected reclamation result: %v", incomplete)
	}
	f := newCreateStateFixture(t, EgressNone)
	recordCtx := context.Background()
	if err := f.journal.recordCleanupFailure(recordCtx, f.lease.Ownership, incomplete); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.cleanup(recordCtx, f.lease.Spec.InstanceID, false, incomplete); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	var cleanup, reason string
	if err := f.journal.db.QueryRowContext(recordCtx, "SELECT cleanup,reason FROM instances WHERE id=?", f.lease.Spec.InstanceID).Scan(&cleanup, &reason); err != nil {
		t.Fatal(err)
	}
	if cleanup != "INCOMPLETE" || reason != "CLEANUP:QUOTA_REFERENCES_REMAIN" {
		t.Fatalf("reclamation uncertainty was discarded: %s/%s", cleanup, reason)
	}
	var released int
	if err := f.journal.db.QueryRowContext(recordCtx, "SELECT count(*) FROM resource_claims WHERE instance=? AND state='RELEASED'", f.lease.Spec.InstanceID).Scan(&released); err != nil || released != 0 {
		t.Fatalf("claims released without a zero-usage observation: %d %v", released, err)
	}
	next := f.lease.Spec
	next.InstanceID = strings.Repeat("d", 32)
	_, err := f.journal.allocate(recordCtx, f.lease.Ownership.EpochID, next, SupervisorConfig{StorageRoot: f.directory, IPCRoot: f.directory, ManagementDirectory: f.directory})
	var typed *Error
	if !errors.As(err, &typed) || typed.Reason != "MODULE_ALREADY_ACTIVE" {
		t.Fatalf("uncertain old ownership allowed installation reuse: %v", err)
	}
}
