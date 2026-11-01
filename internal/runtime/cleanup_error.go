package runtime

// CleanupPhase identifies an existing teardown step, not an operation result or
// a new retry policy. String returns only fixed diagnostic identifiers.
type CleanupPhase uint8

const (
	CleanupBackendDrain CleanupPhase = iota + 1
	CleanupLaunchJoin
	CleanupCallbackJoin
	CleanupStopHook
	CleanupHelperClose
	CleanupHostTerminate
	CleanupBackend
	CleanupFiles
	CleanupCredentials
	CleanupPluginJoin
	CleanupConnectJoin
	CleanupControls
	CleanupTransport
	CleanupHostRelease
)

func (phase CleanupPhase) String() string {
	switch phase {
	case CleanupBackendDrain:
		return "BACKEND_DRAIN"
	case CleanupLaunchJoin:
		return "LAUNCH_JOIN"
	case CleanupCallbackJoin:
		return "CALLBACK_JOIN"
	case CleanupStopHook:
		return "HOOK_STOP"
	case CleanupHelperClose:
		return "HELPER_CLOSE"
	case CleanupHostTerminate:
		return "HOST_TERMINATE"
	case CleanupBackend:
		return "BACKEND_CLEANUP"
	case CleanupFiles:
		return "FILE_CLEANUP"
	case CleanupCredentials:
		return "CREDENTIAL_REVOKE"
	case CleanupPluginJoin:
		return "PLUGIN_JOIN"
	case CleanupConnectJoin:
		return "CONNECT_JOIN"
	case CleanupControls:
		return "CONTROL_JOIN"
	case CleanupTransport:
		return "TRANSPORT_CLOSE"
	case CleanupHostRelease:
		return "HOST_RELEASE"
	default:
		return "UNKNOWN"
	}
}

type cleanupFailure struct {
	phase CleanupPhase
	cause error
}

// Keep Error safe as well as the structured accessor. Original backend/daemon
// text is retained only as the unwrap cause, never copied into this diagnostic.
func (failure *cleanupFailure) Error() string {
	return "cleanup phase " + failure.phase.String() + " failed"
}
func (failure *cleanupFailure) Unwrap() error { return failure.cause }

func cleanupPhaseError(phase CleanupPhase, cause error) error {
	if cause == nil {
		return nil
	}
	return &cleanupFailure{phase: phase, cause: cause}
}

// CleanupFailurePhases returns a deduplicated, fixed-order list from the current
// Stop cleanup wrappers and errors.Join aggregates. It deliberately does not
// inspect opaque backend causes, their text, or their arbitrary unwrap chains.
// errors.Is/errors.As still reach those original causes through Unwrap.
func CleanupFailurePhases(err error) []CleanupPhase {
	var phases uint16
	var visit func(error)
	visit = func(err error) {
		if err == nil {
			return
		}
		if failure, ok := err.(*cleanupFailure); ok {
			if failure.phase >= CleanupBackendDrain && failure.phase <= CleanupHostRelease {
				phases |= uint16(1) << uint(failure.phase-1)
			}
			return
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				visit(child)
			}
		}
	}
	visit(err)
	var result []CleanupPhase
	for phase := CleanupBackendDrain; phase <= CleanupHostRelease; phase++ {
		if phases&(uint16(1)<<uint(phase-1)) != 0 {
			result = append(result, phase)
		}
	}
	return result
}
