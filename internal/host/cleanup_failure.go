//go:build linux

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

// Cleanup diagnostics survive independently of the original runtime failure.
func (j *Store) recordCleanupFailure(ctx context.Context, o Ownership, err error) error {
	reason := failureReason(err, "")
	if !validCleanupReason(reason) {
		return errors.New("cleanup failure lacks a registered step")
	}
	recordErr := j.recordCleanupCode(ctx, o.InstanceID, reason)
	return errors.Join(recordErr, j.RecordFailure(ctx, o, PhaseCleanup, reason))
}

func (s *Store) recordCleanupCode(ctx context.Context, id string, reason FailureReason) error {
	if !validCleanupReason(reason) {
		return errors.New("unregistered cleanup failure code")
	}
	_, err := s.db.ExecContext(ctx, "UPDATE instances SET cleanup_errors=CASE WHEN instr(','||cleanup_errors||',',','||?||',')!=0 THEN cleanup_errors WHEN cleanup_errors='' THEN ? ELSE cleanup_errors||','||? END WHERE id=?", string(reason), string(reason), string(reason), id)
	return err
}
