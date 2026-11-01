package runtime

import (
	"context"
	"errors"
	"testing"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
)

// These fixtures exercise the consumer-visible state/cleanup classification,
// not a replacement host cleanup. They own no sandbox or transient host claims.
func TestExpectedTerminalHelperTeardownRemainsStopped(t *testing.T) {
	for _, notification := range []string{"error", "closed"} {
		t.Run(notification, func(t *testing.T) {
			manager := regressionManager()
			instance := regressionInstance(t, manager, "owner")
			instance.mu.Lock()
			instance.state = Draining
			instance.mu.Unlock()
			instance.beginTerminalCleanup()

			// Deterministically exercise the error branch that select is allowed
			// to choose when both lifetime.Done and HelperErrors are ready.
			instance.failTransport("BROKER_TRANSPORT_LOST")
			helperErrors := make(chan error, 1)
			if notification == "error" {
				helperErrors <- errors.New("fixture helper listener ended")
			}
			close(helperErrors)
			instance.watchHelperErrors(helperErrors)
			before := instance.Snapshot()
			if before.State != Draining || before.FailureReason != "" {
				t.Fatalf("expected terminal notification became a failure: %+v", before)
			}
			// With no owned claims, completed cleanup is represented by the same
			// final classification used after the real cleanup joins succeed.
			manager.finishCleanup(instance, nil)
			after := instance.Snapshot()
			if after.State != Stopped || after.FailureReason != "" || !after.CleanupComplete || after.CleanupError != nil {
				t.Fatalf("normal stop would be reported as terminal failure: %+v", after)
			}
		})
	}
}

func TestUnexpectedLiveHelperExitRemainsFailed(t *testing.T) {
	for _, state := range []RuntimeState{Running, Draining} {
		for _, notification := range []string{"error", "closed"} {
			t.Run(string(state)+"/"+notification, func(t *testing.T) {
				manager := regressionManager()
				instance := regressionInstance(t, manager, "owner")
				peer := regressionInstance(t, manager, "peer")
				ctx, finish, err := instance.beginRPC(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer finish()
				_, err = (&Authorizer{instance: instance}).Authorize(ctx, AccessRequest{
					Backend: regressionBackend, Operation: "write",
					Scopes: []*wire.ResourceScope{regressionScope("group", "a")},
				})
				if err != nil {
					t.Fatal(err)
				}
				admission, err := AdmissionFromContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				instance.mu.Lock()
				instance.state = state
				// The fixture owns classification, not a host cleanup goroutine.
				instance.stopStarted = true
				instance.mu.Unlock()
				helperErrors := make(chan error, 1)
				if notification == "error" {
					helperErrors <- errors.New("fixture unexpected helper listener loss")
				}
				close(helperErrors)
				instance.watchHelperErrors(helperErrors)
				failed := instance.Snapshot()
				if failed.State != Failed || failed.FailureReason != "BROKER_TRANSPORT_LOST" || failed.CleanupComplete {
					t.Fatalf("unexpected live transport exit was masked: %+v", failed)
				}
				if admission.Context().Err() != context.Canceled || instance.startup.Err() != context.Canceled {
					t.Fatal("unexpected exit did not cancel admitted work and startup")
				}
				_, _, err = instance.beginRPC(context.Background())
				regressionError(t, err, codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
				if peer.Snapshot().State != Running || peer.lifetime.Err() != nil {
					t.Fatal("one helper exit failed an unrelated module")
				}
				finish()
				// Successful resource cleanup must not erase the original failure.
				manager.finishCleanup(instance, nil)
				terminal := instance.Snapshot()
				if terminal.State != Failed || terminal.FailureReason != "BROKER_TRANSPORT_LOST" || !terminal.CleanupComplete {
					t.Fatalf("cleanup reclassified unexpected exit as normal stop: %+v", terminal)
				}
			})
		}
	}
}
