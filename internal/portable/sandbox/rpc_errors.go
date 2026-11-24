package sandbox

import (
	"context"
	"errors"

	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

// Keep the worker session independent of the supervisor's store and engine
// packages; their errors cross the wire as the fixed host reason vocabulary.
func annotateRPCError(err *error) {
	cause := *err
	var reason string
	switch {
	case cause == nil:
		return
	case errors.Is(cause, store.ErrCleanupPending):
		cause = errors.Join(host.ErrCleanupIncomplete, cause)
		reason = "CLEANUP_INCOMPLETE"
	case errors.Is(cause, context.Canceled), errors.Is(cause, context.DeadlineExceeded):
		return
	case errors.Is(cause, store.ErrApprovalMismatch), errors.Is(cause, engine.ErrApprovalMismatch):
		reason = "APPROVAL_MISMATCH"
	case errors.Is(cause, store.ErrBudgetExceeded):
		reason = "BUDGET_EXCEEDED"
	case errors.Is(cause, store.ErrVolumeBusy):
		reason = "VOLUME_BUSY"
	case errors.Is(cause, store.ErrEgressRevoked), errors.Is(cause, engine.ErrEgressRevoked):
		reason = "EGRESS_REVOKED"
	case errors.Is(cause, engine.ErrUnsupportedTarget):
		reason = "UNSUPPORTED_TARGET"
	case errors.Is(cause, engine.ErrCapabilityMissing):
		reason = "ENGINE_CAPABILITY_MISSING"
	case errors.Is(cause, store.ErrNotFound):
		reason = "NOT_FOUND"
	default:
		return
	}
	*err = errors.Join(cause, &host.Error{Reason: reason, Message: "portable sandbox operation failed"})
}
