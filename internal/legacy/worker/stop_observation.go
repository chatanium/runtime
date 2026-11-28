package worker

import (
	"context"
	"errors"

	"github.com/thirdscam/chatanium/internal/app"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type observation struct {
	Phase           string                      `json:"phase"`
	Modules         int                         `json:"modules"`
	Voice           bool                        `json:"voice"`
	StopFailure     *stopFailureObservation     `json:"stop_failure,omitempty"`
	DevelopmentStop *developmentStopObservation `json:"development_stop,omitempty"`
}

type developmentStopObservation struct {
	CleanupComplete bool              `json:"cleanup_complete"`
	CommittedImages map[string]string `json:"committed_images"`
}

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
	out.State = app.ReportedState(snapshot.State)
	out.FailureReason = app.ReportedFailureReason(snapshot.FailureReason)
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
