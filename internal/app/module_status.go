package app

import "github.com/thirdscam/chatanium/internal/runtime"

func ReportedState(state runtime.RuntimeState) string {
	switch state {
	case runtime.Starting, runtime.Initializing, runtime.Ready, runtime.Running, runtime.Draining, runtime.Stopped, runtime.Failed:
		return string(state)
	default:
		return "UNKNOWN"
	}
}

func ReportedFailureReason(reason string) string {
	switch reason {
	case "APPROVAL_MISMATCH", "BUDGET_EXCEEDED", "VOLUME_BUSY", "EGRESS_REVOKED", "UNSUPPORTED_TARGET", "ENGINE_CAPABILITY_MISSING", "NOT_FOUND":
		return reason
	case "", "BROKER_TRANSPORT_LOST", "BROKER_PROTOCOL_VIOLATION", "DRAIN_DEADLINE_EXCEEDED", "HOOK_FAILED", "HOOK_DEADLINE_EXCEEDED", "STARTUP_DEADLINE_EXCEEDED", "CANCELLED", "CLEANUP_INCOMPLETE", "EVENT_QUEUE_OVERFLOW", "EVENT_PROJECTION_FAILED", "EVENT_WORK_REFERENCE_FAILED", "HOST_PREREQUISITE_FAILED", "INVALID_CONFIGURATION", "MODULE_ALREADY_ACTIVE", "PROTOCOL_INCOMPATIBLE", "EGRESS_POLICY_MISMATCH", "REQUIRED_CAPABILITY_DENIED", "RESOURCE_SCOPE_DENIED", "MODULE_REPORTED_FAILURE", "BACKEND_RECONFIGURATION_REQUIRED":
		return reason
	default:
		return "UNRECOGNIZED"
	}
}
