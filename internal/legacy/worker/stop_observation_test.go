package worker

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStopObservationPreservesFailureAfterSuccessfulCleanup(t *testing.T) {
	snapshot := runtime.InstanceSnapshot{
		Principal: runtime.InstancePrincipal{InstanceID: "0123456789abcdef0123456789abcdef"},
		State:     runtime.Failed, FailureReason: "BROKER_TRANSPORT_LOST", CleanupComplete: true,
		IncompleteEvents: 3,
	}
	out := describeStopFailure(&snapshot, nil)
	if out == nil || out.State != "FAILED" || out.FailureReason != "BROKER_TRANSPORT_LOST" || !out.CleanupComplete || out.StopErrorCode != "OK" || out.CleanupErrorCode != "OK" || out.IncompleteEvents != 3 {
		t.Fatal("terminal instance failure was lost after successful cleanup")
	}
}

func TestStopObservationDistinguishesIncompleteCleanup(t *testing.T) {
	err := status.Error(codes.Unavailable, "unsafe remote cleanup message")
	snapshot := runtime.InstanceSnapshot{State: runtime.Failed, FailureReason: "CLEANUP_INCOMPLETE", CleanupError: err}
	out := describeStopFailure(&snapshot, err)
	if out == nil || out.CleanupComplete || out.StopErrorCode != "Unavailable" || out.CleanupErrorCode != "Unavailable" || out.FailureReason != "CLEANUP_INCOMPLETE" {
		t.Fatal("cleanup failure codes or state missing")
	}
	if describeStopFailure(&runtime.InstanceSnapshot{State: runtime.Stopped, CleanupComplete: true}, nil) != nil {
		t.Fatal("normal successful stop was reported as failure")
	}
}

func TestStopObservationNeverSerializesUntrustedDiagnostics(t *testing.T) {
	const secret = "private-fixture-token"
	snapshot := runtime.InstanceSnapshot{
		Principal: runtime.InstancePrincipal{ModuleID: runtime.ModuleID(secret), InstanceID: runtime.InstanceID(secret)},
		State:     runtime.RuntimeState(secret), FailureReason: secret,
		CleanupError: status.Error(codes.Internal, secret),
	}
	out := describeStopFailure(&snapshot, errors.New(secret))
	encoded, err := json.Marshal(observation{Phase: "STOP_FAILED", Modules: 1, StopFailure: out})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || out.State != "UNKNOWN" || out.FailureReason != "UNRECOGNIZED" || out.InstanceID != "" || out.StopErrorCode != "Unknown" || out.CleanupErrorCode != "Internal" {
		t.Fatal("untrusted snapshot fields or error text crossed observation boundary")
	}
}

func TestStopObservationReportsOnlyKnownDistinctCleanupPhases(t *testing.T) {
	phases := safeCleanupPhases(
		[]runtime.CleanupPhase{runtime.CleanupHostRelease, runtime.CleanupStopHook, runtime.CleanupHostTerminate},
		[]runtime.CleanupPhase{runtime.CleanupStopHook, runtime.CleanupPhase(255)},
	)
	if strings.Join(phases, ",") != "HOOK_STOP,HOST_TERMINATE,HOST_RELEASE" {
		t.Fatal("cleanup phase output must be closed, deduplicated and in canonical order")
	}
	if len(safeCleanupPhases([]runtime.CleanupPhase{runtime.CleanupPhase(255)})) != 0 {
		t.Fatal("unknown cleanup phase was exposed")
	}
}
