package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

// SealBackupSnapshot binds the already verified destination volume identities
// in the exact private SQLite copy produced by SnapshotDatabase. The caller
// must hold the owner lock, check all manifest/cache and volume copies against
// the admitted inventory, and hash and sync the sealed SQLite leaf afterwards.
// A failed seal leaves the disposable copy unapproved. Nothing in the live
// ledger, including its original persistent identities, is changed.
func (s *Store) SealBackupSnapshot(ctx context.Context, epochID, backupID string, copies []BackupVolumeBinding) error {
	if !lowerHex(backupID, 32) {
		return ErrInvalid
	}
	byVolume, err := indexVolumeBindings(copies)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) (result error) {
		install, backup, err := snapshotBackup(ctx, tx, epochID, backupID)
		if err != nil {
			return err
		}
		captured, err := volumes(ctx, tx)
		if err != nil {
			return err
		}
		if err := matchVolumeBindings(captured, byVolume); err != nil {
			return err
		}
		for _, binding := range copies {
			if binding.SourceNativeID == binding.NativeID {
				return ErrIdentity
			}
		}

		path, err := s.backupDatabasePath(backupID, false)
		if err != nil {
			return err
		}
		liveInfo, err := os.Lstat(s.path)
		if err != nil {
			return err
		}
		copyInfo, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if os.SameFile(liveInfo, copyInfo) {
			return ErrIdentity
		}
		if copyInfo.Size() <= 0 || copyInfo.Size() > backup.SQLiteBytes || copyInfo.Size()%pageBytes != 0 {
			return ErrBudgetExceeded
		}
		if err := noSQLiteSidecars(path); err != nil {
			return err
		}
		if err := checkFormat(ctx, path); err != nil {
			return err
		}
		// The snapshot has not been approved as a backup yet. Rewriting only
		// this disposable file with journaling disabled keeps the entire
		// operation within the already reserved SQLite copy ceiling.
		copyStore, err := connectMode(ctx, path, backup.SQLiteBytes/pageBytes, true)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, copyStore.Close()) }()
		return copyStore.write(ctx, func(copyTx *sql.Tx) error {
			copyInstall, copyBackup, err := snapshotBackup(ctx, copyTx, epochID, backupID)
			if err != nil {
				return err
			}
			if copyInstall != install || copyBackup.MaxBytes != backup.MaxBytes || copyBackup.SQLiteBytes != backup.SQLiteBytes ||
				copyBackup.ForUpdate != backup.ForUpdate || copyBackup.UpdatePending != backup.UpdatePending {
				return ErrApprovalMismatch
			}
			copyVolumes, err := volumes(ctx, copyTx)
			if err != nil {
				return err
			}
			if !slices.Equal(copyVolumes, captured) {
				return ErrApprovalMismatch
			}
			return sealSnapshot(ctx, copyTx, backup, copies)
		})
	})
}

func sealSnapshot(ctx context.Context, tx *sql.Tx, backup Backup, copies []BackupVolumeBinding) error {
	// Only the copied references belong to a restored installation. Source
	// backup/update records cannot own a writer on the restored root.
	for _, statement := range []string{
		`DELETE FROM backups`,
		`DELETE FROM images WHERE NOT EXISTS (SELECT 1 FROM approvals WHERE image_id=images.id)`,
		`DELETE FROM snapshot_volumes`,
		`DELETE FROM snapshot_origin`,
		`UPDATE installation SET epoch_id=NULL, desired='STOPPED' WHERE singleton=1`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	for _, binding := range copies {
		if err := applyVolumeBinding(ctx, tx, binding); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO snapshot_volumes VALUES (?,?,?)`, binding.VolumeID, binding.Digest, binding.SizeBytes); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO snapshot_origin (singleton,backup_id,epoch_id,state) VALUES (1,?,?,'PENDING')`, backup.ID, backup.EpochID); err != nil {
		return err
	}
	return pruneEpochs(ctx, tx)
}

// RebindRestoredVolumes is allowed once on a sealed backup copy before its
// first epoch. The caller must hold the private destination's native owner
// lock and verify the entire approved detached backup receipt (including
// SQLite) and the no-follow identity, hash, size and sync of each staged
// file. The archived copy is not the mutation target.
func (s *Store) RebindRestoredVolumes(ctx context.Context, backupID, receiptDigest string, copies []BackupVolumeBinding) error {
	if !lowerHex(backupID, 32) || !validDigest(receiptDigest) {
		return ErrInvalid
	}
	dir := filepath.Dir(s.path)
	if filepath.Base(dir) == backupID && filepath.Base(filepath.Dir(dir)) == "backups" {
		return ErrIdentity
	}
	byVolume, err := indexVolumeBindings(copies)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := readInstallation(ctx, tx)
		if err != nil {
			return err
		}
		if install.EpochID != "" || install.State != Ready && install.State != Uninstalled {
			return ErrState
		}
		if err := requireStopped(ctx, tx, install); err != nil {
			return err
		}
		completed, err := restoreBinding(ctx, tx, backupID, receiptDigest)
		if err != nil {
			return err
		}
		if completed {
			return ErrState
		}
		retained, err := volumes(ctx, tx)
		if err != nil {
			return err
		}
		if err := matchVolumeBindings(retained, byVolume); err != nil {
			return err
		}
		for _, binding := range copies {
			var matched bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM snapshot_volumes WHERE volume_id=? AND digest=? AND size_bytes=?)`,
				binding.VolumeID, binding.Digest, binding.SizeBytes).Scan(&matched); err != nil {
				return err
			}
			if !matched {
				return ErrApprovalMismatch
			}
			if binding.SourceNativeID != binding.NativeID {
				if err := applyVolumeBinding(ctx, tx, binding); err != nil {
					return err
				}
			}
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE snapshot_origin SET state='BOUND',receipt_digest=? WHERE backup_id=? AND state='PENDING'`,
			receiptDigest, backupID))
	})
}

// ProbeRestoreBinding reads the durable restore result without opening a
// candidate for write. The caller holds the staged native owner lock. A hot
// journal is not a post-commit receipt and cannot authorize a raw hash miss.
func ProbeRestoreBinding(ctx context.Context, installationDir, backupID, receiptDigest string) (bool, error) {
	if !lowerHex(backupID, 32) || !validDigest(receiptDigest) {
		return false, ErrInvalid
	}
	path, err := databasePath(installationDir, false)
	if err != nil {
		return false, err
	}
	if err := noSQLiteSidecars(path); err != nil {
		return false, err
	}
	if err := checkFormat(ctx, path); err != nil {
		return false, err
	}
	u := sqliteURL(path)
	u.RawQuery = "mode=ro&immutable=1"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return false, err
	}
	defer db.Close()
	return restoreBinding(ctx, db, backupID, receiptDigest)
}

// RestoreBinding distinguishes a pending seal from the exact completed
// restore, before a normal epoch consumes restore authority. After an
// ambiguous response the caller still verifies all non-SQLite receipt
// members and the current ledger-bound native volume identities.
func (s *Store) RestoreBinding(ctx context.Context, backupID, receiptDigest string) (bool, error) {
	if !lowerHex(backupID, 32) || !validDigest(receiptDigest) {
		return false, ErrInvalid
	}
	return restoreBinding(ctx, s.db, backupID, receiptDigest)
}

// RestoredReceiptDigest returns the durable approved detached inventory hash
// used by a completed restore, including after its first epoch. Ordinary and
// not-yet-bound ledgers have no approved restore receipt.
func (s *Store) RestoredReceiptDigest(ctx context.Context) (string, error) {
	var digest string
	err := s.db.QueryRowContext(ctx, `SELECT receipt_digest FROM snapshot_origin WHERE singleton=1 AND state IN ('BOUND','ACTIVE')`).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return digest, err
}

func restoreBinding(ctx context.Context, q rowReader, backupID, receiptDigest string) (bool, error) {
	var state, recordedDigest string
	err := q.QueryRowContext(ctx, `SELECT state,receipt_digest FROM snapshot_origin WHERE backup_id=?`, backupID).
		Scan(&state, &recordedDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrApprovalMismatch
	}
	if err != nil {
		return false, err
	}
	switch state {
	case "PENDING":
		return false, nil
	case "BOUND":
		if recordedDigest != receiptDigest {
			return false, ErrApprovalMismatch
		}
		return true, nil
	default:
		return false, ErrState
	}
}

func activateRestoredOrigin(ctx context.Context, tx *sql.Tx) error {
	var state string
	err := tx.QueryRowContext(ctx, `SELECT state FROM snapshot_origin WHERE singleton=1`).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) || err == nil && state == "ACTIVE" {
		return nil
	}
	if err != nil {
		return err
	}
	if state == "PENDING" {
		return ErrCleanupPending
	}
	return exactlyOne(tx.ExecContext(ctx, `UPDATE snapshot_origin SET state='ACTIVE' WHERE singleton=1 AND state='BOUND'`))
}

func indexVolumeBindings(copies []BackupVolumeBinding) (map[string]BackupVolumeBinding, error) {
	byVolume := make(map[string]BackupVolumeBinding, len(copies))
	for _, binding := range copies {
		if !lowerHex(binding.VolumeID, 32) || !validOpaque(binding.SourceNativeID) || !validOpaque(binding.NativeID) ||
			!validDigest(binding.Digest) || !validVolumeSize(binding.SizeBytes) {
			return nil, ErrInvalid
		}
		if _, duplicate := byVolume[binding.VolumeID]; duplicate {
			return nil, ErrInvalid
		}
		byVolume[binding.VolumeID] = binding
	}
	return byVolume, nil
}

func matchVolumeBindings(volumes []Volume, copies map[string]BackupVolumeBinding) error {
	var count int
	for _, volume := range volumes {
		if !volume.Initialized {
			if volume.NativeID != "" || volume.CreationRunID != "" {
				return ErrCleanupPending
			}
			continue
		}
		binding, ok := copies[volume.ID]
		if !ok || binding.SourceNativeID != volume.NativeID {
			return ErrApprovalMismatch
		}
		if binding.SizeBytes > volume.MaxBytes {
			return ErrBudgetExceeded
		}
		count++
	}
	if count != len(copies) {
		return ErrApprovalMismatch
	}
	return nil
}

func applyVolumeBinding(ctx context.Context, tx *sql.Tx, binding BackupVolumeBinding) error {
	return exactlyOne(tx.ExecContext(ctx, `UPDATE volumes SET native_id=? WHERE id=? AND initialized=1 AND native_id=?`,
		binding.NativeID, binding.VolumeID, binding.SourceNativeID))
}
