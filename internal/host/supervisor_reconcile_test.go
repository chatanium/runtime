//go:build linux

package host

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A real journal snapshot races the same per-instance lock used by Release.
// Host components are deliberately nil: a completed claim must not trigger
// quota/path verification, platform cleanup, or any other host operation.
func TestStaleReaperSnapshotDoesNotReopenCompletedCleanup(t *testing.T) {
	for _, orphan := range []bool{false, true} {
		for _, failed := range []bool{false, true} {
			name := "live"
			if orphan {
				name = "orphan"
			}
			if failed {
				name += "/failed"
			} else {
				name += "/normal"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				f := newCreateStateFixture(t, EgressNone)
				if err := f.journal.state(ctx, f.lease.Spec.InstanceID, "STARTED", ""); err != nil {
					t.Fatal(err)
				}
				if failed {
					if err := f.journal.state(ctx, f.lease.Spec.InstanceID, "FAILED", "HOST_PREREQUISITE_FAILED"); err != nil {
						t.Fatal(err)
					}
				}
				leases, err := f.journal.pending(ctx, "")
				if err != nil || len(leases) != 1 {
					t.Fatalf("pending snapshot: %d %v", len(leases), err)
				}
				s := &Supervisor{journal: f.journal, locks: make(map[string]*sync.Mutex)}
				lock := s.instanceLock(f.lease.Spec.InstanceID)
				lock.Lock()
				started := make(chan struct{})
				done := make(chan error, 1)
				go func() { close(started); done <- s.reconcileLease(ctx, leases[0], orphan) }()
				<-started
				// Simulate Release's durable completion while the stale reaper waits.
				err = f.journal.cleanup(ctx, f.lease.Spec.InstanceID, true, nil)
				lock.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("stale reaper failed to join completed cleanup")
				}
				var state, reason, cleanup string
				if err = f.journal.db.QueryRowContext(ctx, "SELECT state,reason,cleanup FROM instances WHERE id=?", f.lease.Spec.InstanceID).Scan(&state, &reason, &cleanup); err != nil {
					t.Fatal(err)
				}
				expectedState, expectedReason := "STOPPED", ""
				if failed {
					expectedState, expectedReason = "FAILED", "HOST_PREREQUISITE_FAILED"
				}
				if state != expectedState || reason != expectedReason || cleanup != "COMPLETE" {
					t.Fatalf("stale snapshot changed terminal outcome: %s/%s/%s", state, reason, cleanup)
				}
			})
		}
	}
}
