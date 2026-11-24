package app

import (
	"context"
	"errors"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stopFailureObservation contains only finite states, allowlisted reasons,
// canonical status codes, counters and a validated host-generated instance ID.
// Never serialize the snapshot itself: it also contains grants and raw errors.
// CleanupComplete reports this snapshot, not a later supervisor reaper outcome.
// Only explicitly wrapped failed cleanup phases are reported; absent phases
// are not inferred from a status code, journal state or skipped cleanup step.
type stopFailureObservation struct {
	InstanceID           string   `json:"instance_id,omitempty"`
	SnapshotPresent      bool     `json:"snapshot_present"`
	State                string   `json:"state"`
	FailureReason        string   `json:"failure_reason"`
	CleanupComplete      bool     `json:"cleanup_complete"`
	RetainedEvents       int      `json:"retained_events"`
	RetainedBytes        int64    `json:"retained_bytes"`
	IncompleteEvents     int      `json:"incomplete_events"`
	StopErrorCode        string   `json:"stop_error_code"`
	CleanupErrorCode     string   `json:"cleanup_error_code"`
	CleanupFailurePhases []string `json:"cleanup_failure_phases,omitempty"`
}

func describeStopFailure(snapshot *runtime.InstanceSnapshot, stopErr error) *stopFailureObservation {
	if stopErr == nil && (snapshot == nil || snapshot.State != runtime.Failed) {
		return nil
	}
	out := &stopFailureObservation{State: "UNKNOWN", StopErrorCode: stopErrorCode(stopErr), CleanupErrorCode: "OK"}
	if snapshot == nil {
		out.CleanupFailurePhases = safeCleanupPhases(runtime.CleanupFailurePhases(stopErr))
		return out
	}
	out.SnapshotPresent = true
	out.State = stopState(snapshot.State)
	out.FailureReason = stopFailureReason(snapshot.FailureReason)
	out.CleanupComplete = snapshot.CleanupComplete
	out.RetainedEvents = snapshot.RetainedEvents
	out.RetainedBytes = snapshot.RetainedBytes
	out.IncompleteEvents = snapshot.IncompleteEvents
	out.CleanupErrorCode = stopErrorCode(snapshot.CleanupError)
	out.CleanupFailurePhases = safeCleanupPhases(runtime.CleanupFailurePhases(stopErr), runtime.CleanupFailurePhases(snapshot.CleanupError))
	id := string(snapshot.Principal.InstanceID)
	if len(id) == 32 {
		valid := true
		for _, c := range id {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				valid = false
				break
			}
		}
		if valid {
			out.InstanceID = id
		}
	}
	return out
}

func stopState(state runtime.RuntimeState) string {
	switch state {
	case runtime.Starting, runtime.Initializing, runtime.Ready, runtime.Running, runtime.Draining, runtime.Stopped, runtime.Failed:
		return string(state)
	default:
		return "UNKNOWN"
	}
}

func stopFailureReason(reason string) string {
	switch reason {
	case "APPROVAL_MISMATCH", "BUDGET_EXCEEDED", "VOLUME_BUSY", "EGRESS_REVOKED", "UNSUPPORTED_TARGET", "ENGINE_CAPABILITY_MISSING", "NOT_FOUND":
		return reason
	case "", "BROKER_TRANSPORT_LOST", "BROKER_PROTOCOL_VIOLATION", "DRAIN_DEADLINE_EXCEEDED", "HOOK_FAILED", "HOOK_DEADLINE_EXCEEDED", "STARTUP_DEADLINE_EXCEEDED", "CANCELLED", "CLEANUP_INCOMPLETE", "EVENT_QUEUE_OVERFLOW", "EVENT_PROJECTION_FAILED", "EVENT_WORK_REFERENCE_FAILED", "HOST_PREREQUISITE_FAILED", "INVALID_CONFIGURATION", "MODULE_ALREADY_ACTIVE", "PROTOCOL_INCOMPATIBLE", "EGRESS_POLICY_MISMATCH", "REQUIRED_CAPABILITY_DENIED", "RESOURCE_SCOPE_DENIED", "MODULE_REPORTED_FAILURE", "BACKEND_RECONFIGURATION_REQUIRED":
		return reason
	default:
		return "UNRECOGNIZED"
	}
}

func stopErrorCode(err error) string {
	if err == nil {
		return "OK"
	}
	code := status.Code(err)
	if code == codes.Unknown {
		if errors.Is(err, context.DeadlineExceeded) {
			code = codes.DeadlineExceeded
		} else if errors.Is(err, context.Canceled) {
			code = codes.Canceled
		}
	}
	if code <= codes.OK || code > codes.Unauthenticated {
		return "Unknown"
	}
	return code.String()
}

// Keep the output set closed even if the runtime later adds enum values.
// Duplicate Stop and snapshot errors usually point at the same cleanup result.
func safeCleanupPhases(groups ...[]runtime.CleanupPhase) []string {
	var seen [256]bool
	for _, phases := range groups {
		for _, phase := range phases {
			seen[uint8(phase)] = true
		}
	}
	var out []string
	for _, known := range [...]struct {
		phase runtime.CleanupPhase
		name  string
	}{
		{runtime.CleanupBackendDrain, "BACKEND_DRAIN"},
		{runtime.CleanupLaunchJoin, "LAUNCH_JOIN"},
		{runtime.CleanupCallbackJoin, "CALLBACK_JOIN"},
		{runtime.CleanupStopHook, "HOOK_STOP"},
		{runtime.CleanupHelperClose, "HELPER_CLOSE"},
		{runtime.CleanupHostTerminate, "HOST_TERMINATE"},
		{runtime.CleanupBackend, "BACKEND_CLEANUP"},
		{runtime.CleanupFiles, "FILE_CLEANUP"},
		{runtime.CleanupCredentials, "CREDENTIAL_REVOKE"},
		{runtime.CleanupPluginJoin, "PLUGIN_JOIN"},
		{runtime.CleanupConnectJoin, "CONNECT_JOIN"},
		{runtime.CleanupControls, "CONTROL_JOIN"},
		{runtime.CleanupTransport, "TRANSPORT_CLOSE"},
		{runtime.CleanupHostRelease, "HOST_RELEASE"},
	} {
		if seen[uint8(known.phase)] {
			out = append(out, known.name)
		}
	}
	return out
}
