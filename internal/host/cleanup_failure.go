package host

import (
	"context"
	"errors"
)

func validCleanupReason(reason FailureReason) bool {
	switch reason {
	case FailureCleanupPlatform, FailureCleanupCreateGuard, FailureCleanupScratch, FailureCleanupIPC, FailureCleanupLogs, FailureCleanupSync, FailureCleanupBarrier, FailureCleanupQuotaRead, FailureCleanupQuotaReferences, FailureCleanupJournal:
		return true
	}
	return false
}
func cleanupStep(reason FailureReason, err error) error {
	if err == nil {
		return nil
	}
	if !validCleanupReason(reason) {
		return errors.New("unregistered cleanup failure step")
	}
	return classifiedFailure(reason, err)
}

// Reuse the existing bounded first-failure journal. Cleanup diagnostics fill
// only an empty reason; an earlier startup/runtime failure remains authoritative.
func (j *journal) recordCleanupFailure(ctx context.Context, o Ownership, err error) error {
	reason := failureReason(err, "")
	if !validCleanupReason(reason) {
		return errors.New("cleanup failure lacks a registered step")
	}
	return j.RecordFailure(ctx, o, PhaseCleanup, reason)
}
