package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/host"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestCleanupFailurePhasesAreFiniteOrderedAndPreserveCauses(t *testing.T) {
	const secret = "https://credential.invalid/RAW_SECRET"
	hostCause := &host.Error{Reason: "HOST_OPERATION_FAILED", Message: secret}
	timeout := fmt.Errorf("unsafe %s: %w", secret, context.DeadlineExceeded)
	joined := errors.Join(
		cleanupPhaseError(CleanupHostRelease, hostCause),
		errors.Join(cleanupPhaseError(CleanupStopHook, timeout), cleanupPhaseError(CleanupHostRelease, hostCause)),
	)
	phases := CleanupFailurePhases(joined)
	if len(phases) != 2 || phases[0] != CleanupStopHook || phases[1] != CleanupHostRelease {
		t.Fatalf("phase ordering/dedup changed: %v", phases)
	}
	if !errors.Is(joined, context.DeadlineExceeded) {
		t.Fatal("cleanup wrapper lost context error identity")
	}
	var extracted *host.Error
	if !errors.As(joined, &extracted) || extracted != hostCause {
		t.Fatal("cleanup wrapper lost original typed host error")
	}
	if strings.Contains(joined.Error(), secret) || strings.Contains(joined.Error(), "RAW_SECRET") {
		t.Fatal("cleanup phase diagnostics copied source error text")
	}
	original := status.Error(codes.PermissionDenied, secret)
	wrapped := cleanupPhaseError(CleanupHelperClose, original)
	if status.Code(wrapped) != status.Code(original) {
		t.Fatal("phase attribution changed the original gRPC status")
	}
}

type cleanupCauseProbe struct {
	visited *bool
	inner   error
}

func (*cleanupCauseProbe) Error() string       { return "RAW_SECRET" }
func (probe *cleanupCauseProbe) Unwrap() error { *probe.visited = true; return probe.inner }

func TestCleanupFailurePhasesDoNotInspectOpaqueBackendCauses(t *testing.T) {
	visited := false
	cause := &cleanupCauseProbe{visited: &visited, inner: cleanupPhaseError(CleanupTransport, errors.New("RAW_SECRET"))}
	phases := CleanupFailurePhases(cleanupPhaseError(CleanupHostTerminate, cause))
	if visited || len(phases) != 1 || phases[0] != CleanupHostTerminate {
		t.Fatal("phase accessor inspected or attributed opaque backend cause internals")
	}
	for _, err := range []error{
		nil,
		errors.New("RAW_SECRET"),
		cleanupPhaseError(CleanupHostRelease, nil),
		cleanupPhaseError(CleanupPhase(255), errors.New("RAW_SECRET")),
		runtimeError(codes.Unavailable, "CLEANUP_INCOMPLETE"),
	} {
		if len(CleanupFailurePhases(err)) != 0 {
			t.Fatal("phase accessor fabricated a failed or skipped step")
		}
	}
	if CleanupPhase(255).String() != "UNKNOWN" {
		t.Fatal("unknown phase escaped the fixed diagnostic vocabulary")
	}
}

func TestHookNestedDeadlineDoesNotImplyHookExpiration(t *testing.T) {
	for _, test := range []struct {
		name  string
		cause error
	}{
		{"context", context.DeadlineExceeded},
		{"grpc", status.Error(codes.DeadlineExceeded, "nested helper deadline")},
		{"safe", core.SafeRPCError(context.DeadlineExceeded)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var callback context.Context
			value, err := callHook(context.Background(), Limits{HookRPCDeadline: Duration(time.Hour)}, func(ctx context.Context) (int, error) {
				callback = ctx
				if ctx.Err() != nil {
					t.Fatal("hook context expired before nested failure")
				}
				return 7, test.cause
			})
			if value != 7 || err != test.cause {
				t.Fatal("live-hook nested failure changed the returned value/error")
			}
			if callback.Err() != context.Canceled {
				t.Fatal("hook context was not canceled on return")
			}
			if reason := failureReason(context.Background(), err, "HOOK_FAILED"); reason != "HOOK_FAILED" {
				t.Fatalf("nested deadline was attributed to the hook: %s", reason)
			}
		})
	}
}

func TestHookDeadlineExpirationPreservesReturnedStatus(t *testing.T) {
	cause := core.SafeRPCError(context.DeadlineExceeded)
	value, err := callHook(context.Background(), Limits{HookRPCDeadline: Duration(time.Millisecond)}, func(ctx context.Context) (int, error) {
		<-ctx.Done()
		if ctx.Err() != context.DeadlineExceeded {
			t.Fatal("hook context did not reach its own deadline")
		}
		return 7, cause
	})
	if value != 7 || !errors.Is(err, cause) {
		t.Fatal("hook deadline marker lost the returned value or original cause")
	}
	if err.Error() != cause.Error() || !proto.Equal(status.Convert(err).Proto(), status.Convert(cause).Proto()) {
		t.Fatal("hook deadline marker changed the safe gRPC error/status")
	}
	if reason := failureReason(context.Background(), err, "HOOK_FAILED"); reason != "HOOK_DEADLINE_EXCEEDED" {
		t.Fatalf("actual hook expiration was not attributed: %s", reason)
	}
}

func TestStartupDeadlineTakesPrecedenceOverHookExpiration(t *testing.T) {
	startup, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := callHook(startup, Limits{HookRPCDeadline: Duration(time.Hour)}, func(ctx context.Context) (struct{}, error) {
		<-ctx.Done()
		return struct{}{}, core.SafeRPCError(ctx.Err())
	})
	var hookDeadline *hookDeadlineFailure
	if !errors.As(err, &hookDeadline) {
		t.Fatal("inherited startup expiration did not expire the hook context")
	}
	if reason := failureReason(startup, err, "HOOK_FAILED"); reason != "STARTUP_DEADLINE_EXCEEDED" {
		t.Fatalf("hook classification hid total startup expiration: %s", reason)
	}
}

func TestHookCancellationClassificationUnchanged(t *testing.T) {
	for _, parentCanceled := range []bool{false, true} {
		name := "nested"
		if parentCanceled {
			name = "parent"
		}
		t.Run(name, func(t *testing.T) {
			startup, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := core.SafeRPCError(context.Canceled)
			_, err := callHook(startup, Limits{HookRPCDeadline: Duration(time.Hour)}, func(ctx context.Context) (struct{}, error) {
				if parentCanceled {
					cancel()
					<-ctx.Done()
				}
				return struct{}{}, cause
			})
			if err != cause {
				t.Fatal("cancellation changed the original safe error")
			}
			if reason := failureReason(startup, err, "HOOK_FAILED"); reason != "CANCELLED" {
				t.Fatalf("cancellation classification changed: %s", reason)
			}
		})
	}
}
