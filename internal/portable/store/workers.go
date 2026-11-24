package store

import (
	"context"
	"database/sql"
)

// StartWorker durably claims the epoch worker slot before the native spawn.
// This includes crashes before any module has been admitted.
func (s *Store) StartWorker(ctx context.Context, epochID string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if install.State != Ready || install.Desired != DesiredRunning {
			return ErrState
		}
		if install.WorkerPending {
			return ErrCleanupPending
		}
		if err := requireNoBackupWriter(ctx, tx); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE epochs SET worker_pending=1 WHERE id=?`, epochID))
	})
}

// FinishWorker is for the same supervisor epoch that owns the native handle.
// Call only after exit and its runtime files have been positively observed, or
// after a spawn failed without leaving a child or runtime files.
func (s *Store) FinishWorker(ctx context.Context, epochID string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := requireEpoch(ctx, tx, epochID); err != nil {
			return err
		}
		if err := exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET desired='STOPPED' WHERE singleton=1`)); err != nil {
			return err
		}
		if err := stopEpochRuns(ctx, tx, epochID); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE epochs SET worker_pending=0 WHERE id=?`, epochID))
	})
}

// RecoverWorker retires a previous epoch's worker only after the new owner has
// checked native child and runtime-file absence for that exact epoch.
func (s *Store) RecoverWorker(ctx context.Context, actorEpoch, previousEpoch string, proof RemovalProof) error {
	if !proof.complete() || actorEpoch == previousEpoch {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := requireEpoch(ctx, tx, actorEpoch); err != nil {
			return err
		}
		if err := exactlyOne(tx.ExecContext(ctx, `UPDATE epochs SET worker_pending=0 WHERE id=? AND worker_pending=1`, previousEpoch)); err != nil {
			return err
		}
		return pruneEpochs(ctx, tx)
	})
}

func (s *Store) WorkerEpochs(ctx context.Context) ([]Epoch, error) {
	return collect(ctx, s.db, `SELECT id,boot_id,pid,start_identity FROM epochs WHERE worker_pending=1 ORDER BY id`, func(row scanner) (Epoch, error) {
		var e Epoch
		err := row.Scan(&e.ID, &e.BootID, &e.PID, &e.StartIdentity)
		return e, err
	})
}

func requireNoPriorWorker(ctx context.Context, q rowReader, epochID string) error {
	var pending bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM epochs WHERE worker_pending=1 AND id<>?)`, epochID).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrCleanupPending
	}
	return nil
}
