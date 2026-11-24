package store

import (
	"context"
	"database/sql"
	"fmt"
)

const backupColumns = `b.id,b.epoch_id,b.state,b.max_bytes,b.sqlite_bytes,b.for_update,b.update_fence,
	b.bundle_digest,b.engine_digest,b.plan_digest,b.config_revision,b.config_digest, s.id,s.owner,s.target`
const backupQuery = `SELECT ` + backupColumns + ` FROM backups AS b CROSS JOIN installation AS s WHERE s.singleton=1`

func scanBackup(row scanner) (Backup, error) {
	var b Backup
	err := row.Scan(&b.ID, &b.EpochID, &b.State, &b.MaxBytes, &b.SQLiteBytes, &b.ForUpdate, &b.UpdatePending,
		&b.BundleDigest, &b.EngineDigest, &b.PlanDigest, &b.ConfigRevision, &b.ConfigDigest, &b.InstallationIdentity.ID, &b.Owner, &b.Target)
	b.Path = "backups/" + b.ID
	return b, err
}

func (s *Store) Volumes(ctx context.Context) ([]Volume, error) { return volumes(ctx, s.db) }

func volumes(ctx context.Context, q queryReader) ([]Volume, error) {
	return collect(ctx, q, `SELECT `+volumeColumns+` FROM volumes AS v ORDER BY v.id`, scanVolume)
}

func readBackupRefs(ctx context.Context, q queryReader, b *Backup) error {
	var err error
	// Backups can only begin after every run is retired, so a snapshot's
	// nonempty native ID is always initialized, never provisional.
	b.Volumes, err = collect(ctx, q, `SELECT v.id,v.module_id,bv.native_id,bv.max_bytes,'',bv.native_id<>'' FROM backup_volumes AS bv JOIN volumes AS v ON v.id=bv.volume_id WHERE bv.backup_id=? ORDER BY v.id`, scanVolume, b.ID)
	if err != nil {
		return err
	}
	b.Images, err = collect(ctx, q, `SELECT `+imageColumns+` FROM backup_images AS bi JOIN images AS i ON i.id=bi.image_id WHERE bi.backup_id=? ORDER BY i.id`, scanImage, b.ID)
	return err
}

func backups(ctx context.Context, q queryReader) ([]Backup, error) {
	items, err := collect(ctx, q, backupQuery+` ORDER BY b.id`, scanBackup)
	if err != nil {
		return nil, err
	}
	for i := range items {
		if err := readBackupRefs(ctx, q, &items[i]); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (s *Store) Backups(ctx context.Context) ([]Backup, error) {
	var items []Backup
	err := s.write(ctx, func(tx *sql.Tx) error {
		var err error
		items, err = backups(ctx, tx)
		return err
	})
	return items, err
}

func requireNoBackupWriter(ctx context.Context, q rowReader) error {
	var pending bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM backups WHERE state IN ('WRITING','CLEANUP_PENDING') OR update_fence=1)`).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrCleanupPending
	}
	return nil
}

func requireStopped(ctx context.Context, tx *sql.Tx, install InstallationRecord) error {
	if install.Desired != DesiredStopped || install.WorkerPending {
		return ErrCleanupPending
	}
	if err := requireNoRuns(ctx, tx); err != nil {
		return err
	}
	return requireNoPreparationWriters(ctx, tx)
}

// BeginBackup creates a durable writer and update fence while pinning the
// exact volume and cache references in the database snapshot. The caller
// must supply a copy ceiling that includes the SQLite file, config, and the
// logical (not allocated) lengths of all copied data and metadata. This is
// done before any destination file is created.
func (s *Store) BeginBackup(ctx context.Context, epochID string, maxBytes int64, forUpdate bool) (Backup, error) {
	if maxBytes <= 0 {
		return Backup{}, ErrInvalid
	}
	var b Backup
	err := s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if install.State != Ready && (forUpdate || install.State != Uninstalled) {
			return ErrState
		}
		if err := requireStopped(ctx, tx, install); err != nil {
			return err
		}
		if err := requireNoBackupWriter(ctx, tx); err != nil {
			return err
		}
		sqliteBytes, err := SQLiteFileBudget(install.MetadataBytes)
		if err != nil {
			return err
		}
		if maxBytes < sqliteBytes {
			return fmt.Errorf("%w: backup ceiling cannot hold the ledger", ErrBudgetExceeded)
		}
		if err := admitBytes(ctx, tx, maxBytes); err != nil {
			return err
		}
		id := newID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO backups (id,epoch_id,state,update_fence,for_update,max_bytes,sqlite_bytes,
			bundle_digest,engine_digest,plan_digest,config_revision,config_digest) VALUES (?,?,'WRITING',?,?,?,?,?,?,?,?,?)`,
			id, epochID, forUpdate, forUpdate, maxBytes, sqliteBytes, install.BundleDigest, install.EngineDigest,
			install.PlanDigest, install.ConfigRevision, install.ConfigDigest); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO backup_volumes SELECT ?,id,max_bytes,native_id FROM volumes`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO backup_images SELECT DISTINCT ?,image_id FROM approvals`, id); err != nil {
			return err
		}
		b, err = scanBackup(tx.QueryRowContext(ctx, backupQuery+` AND b.id=?`, id))
		if err != nil {
			return err
		}
		return readBackupRefs(ctx, tx, &b)
	})
	if err != nil {
		return Backup{}, err
	}
	return b, nil
}

func (s *Store) CompleteBackup(ctx context.Context, epochID, id string, proof BackupProof) error {
	if !proof.WritersExited || !proof.Verified || !proof.Synchronized {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if err := requireStopped(ctx, tx, install); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE backups SET state='VERIFIED' WHERE id=? AND epoch_id=? AND state='WRITING'`, id, epochID))
	})
}

// FinishUpdate switches installation identity only after a verified backup
// and the caller's verified, durable new bundle publication. Images compiled
// or approved against a different bundle/engine must be reviewed again.
func (s *Store) FinishUpdate(ctx context.Context, epochID, backupID string, next InstallationIdentity, planDigest string) error {
	if !next.valid() || !validDigest(planDigest) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if install.State != Ready || next.ID != install.ID || next.Owner != install.Owner || next.Target != install.Target {
			return ErrIdentity
		}
		if err := requireStopped(ctx, tx, install); err != nil {
			return err
		}
		b, err := scanBackup(tx.QueryRowContext(ctx, backupQuery+` AND b.id=?`, backupID))
		if err != nil {
			return err
		}
		if b.State != Verified || !b.UpdatePending || b.InstallationIdentity != install.InstallationIdentity ||
			b.PlanDigest != install.PlanDigest || b.ConfigRevision != install.ConfigRevision || b.ConfigDigest != install.ConfigDigest {
			return ErrApprovalMismatch
		}
		if next != install.InstallationIdentity {
			if _, err := tx.ExecContext(ctx, `DELETE FROM approvals`); err != nil {
				return err
			}
			if err := exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET state='INITIALIZING',config_revision='',config_digest='',bundle_digest=?,engine_digest=?,plan_digest=? WHERE singleton=1`,
				next.BundleDigest, next.EngineDigest, planDigest)); err != nil {
				return err
			}
		} else {
			if err := exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET plan_digest=? WHERE singleton=1`, planDigest)); err != nil {
				return err
			}
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE backups SET update_fence=0 WHERE id=? AND update_fence=1`, backupID))
	})
}

func (s *Store) MarkBackupPending(ctx context.Context, epochID, id string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := requireBackupCleanup(ctx, tx, epochID); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE backups SET state='CLEANUP_PENDING' WHERE id=?`, id))
	})
}

func (s *Store) ReleaseBackup(ctx context.Context, epochID, id string, proof RemovalProof) error {
	if !proof.complete() {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := requireBackupCleanup(ctx, tx, epochID); err != nil {
			return err
		}
		if err := exactlyOne(tx.ExecContext(ctx, `DELETE FROM backups WHERE id=? AND state='CLEANUP_PENDING'`, id)); err != nil {
			return err
		}
		return pruneEpochs(ctx, tx)
	})
}

func requireBackupCleanup(ctx context.Context, tx *sql.Tx, epochID string) error {
	install, err := requireEpoch(ctx, tx, epochID)
	if err != nil {
		return err
	}
	if install.State == Uninstalling || install.State == Purging || install.State == Purged || install.Desired != DesiredStopped || install.WorkerPending {
		return ErrState
	}
	return nil
}
