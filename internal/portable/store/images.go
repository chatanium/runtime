package store

import (
	"context"
	"database/sql"
)

func (i *Image) fields() []any {
	return []any{&i.ID, &i.EpochID, &i.PreparationID, &i.Digest, &i.EngineDigest, &i.State, &i.MaxBytes}
}

func (i *Image) path() { i.Path = "images/" + i.EpochID + "/" + i.ID }

func scanImage(row scanner) (Image, error) {
	var image Image
	err := row.Scan(image.fields()...)
	image.path()
	return image, err
}

func scanPreparation(row scanner) (Preparation, error) {
	var prep Preparation
	err := row.Scan(&prep.ID, &prep.EpochID, &prep.State, &prep.MaxBytes)
	prep.Path = "preparations/" + prep.ID
	return prep, err
}

func (s *Store) Images(ctx context.Context) ([]Image, error) {
	return images(ctx, s.db)
}

func images(ctx context.Context, q queryReader) ([]Image, error) {
	return collect(ctx, q, `SELECT `+imageColumns+` FROM images AS i ORDER BY i.id`, scanImage)
}

func (s *Store) Preparations(ctx context.Context) ([]Preparation, error) {
	return collect(ctx, s.db, `SELECT id,epoch_id,state,max_bytes FROM preparations ORDER BY id`, scanPreparation)
}

func (s *Store) ReservePreparation(ctx context.Context, epochID string, maxBytes int64) (Preparation, error) {
	if maxBytes <= 0 {
		return Preparation{}, ErrInvalid
	}
	prep := Preparation{ID: newID(), EpochID: epochID, State: Writing, MaxBytes: maxBytes}
	prep.Path = "preparations/" + prep.ID
	err := s.write(ctx, func(tx *sql.Tx) error {
		if _, err := requireImageAdmission(ctx, tx, epochID); err != nil {
			return err
		}
		if err := admitBytes(ctx, tx, maxBytes); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `INSERT INTO preparations (id,epoch_id,state,max_bytes) VALUES (?,?,'WRITING',?)`, prep.ID, epochID, maxBytes))
	})
	if err != nil {
		return Preparation{}, err
	}
	return prep, nil
}

// ReserveImage separately charges the cache destination before any copy or
// publish. preparationID is empty only for a pinned bundle source; an
// external preparation's source/scratch ceiling remains charged separately.
func (s *Store) ReserveImage(ctx context.Context, epochID, preparationID, imageDigest string, maxBytes int64) (Image, error) {
	if !validDigest(imageDigest) || maxBytes <= 0 {
		return Image{}, ErrInvalid
	}
	image := Image{ID: newID(), EpochID: epochID, PreparationID: preparationID, Digest: imageDigest, State: Writing, MaxBytes: maxBytes}
	image.path()
	err := s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireImageAdmission(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if preparationID != "" {
			var active bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM preparations WHERE id=? AND epoch_id=? AND state='WRITING')`, preparationID, epochID).Scan(&active); err != nil {
				return err
			}
			if !active {
				return ErrCleanupPending
			}
			var inUse bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM images WHERE preparation_id=?)`, preparationID).Scan(&inUse); err != nil {
				return err
			}
			if inUse {
				return ErrReferenced
			}
		}
		if err := admitBytes(ctx, tx, maxBytes); err != nil {
			return err
		}
		image.EngineDigest = install.EngineDigest
		return exactlyOne(tx.ExecContext(ctx, `INSERT INTO images (id,epoch_id,preparation_id,digest,engine_digest,state,max_bytes) VALUES (?,?,?,?,?,'WRITING',?)`,
			image.ID, epochID, preparationID, imageDigest, install.EngineDigest, maxBytes))
	})
	if err != nil {
		return Image{}, err
	}
	return image, nil
}

func requireImageAdmission(ctx context.Context, tx *sql.Tx, epochID string) (InstallationRecord, error) {
	install, err := requireEpoch(ctx, tx, epochID)
	if err != nil {
		return InstallationRecord{}, err
	}
	if install.State != Initializing && install.State != Ready {
		return InstallationRecord{}, ErrState
	}
	if err := requireNoBackupWriter(ctx, tx); err != nil {
		return InstallationRecord{}, err
	}
	return install, nil
}

// StageImage records that the caller verified and synced the exact immutable
// cache generation. It survives a supervisor restart but cannot be run or
// approved until PublishImage, after the operator has reviewed the image.
func (s *Store) StageImage(ctx context.Context, epochID, imageID string, proof PublishProof) error {
	if !proof.WritersExited || !proof.Verified || !proof.ReadOnly || !proof.Synchronized {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireImageAdmission(ctx, tx, epochID)
		if err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE images SET state='PREPARED',may_write=0 WHERE id=? AND epoch_id=? AND engine_digest=? AND state='WRITING'`,
			imageID, epochID, install.EngineDigest))
	})
}

func (s *Store) PublishImage(ctx context.Context, epochID, imageID string, proof PublishProof) error {
	if !proof.WritersExited || !proof.Verified || !proof.ReadOnly || !proof.Synchronized {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireImageAdmission(ctx, tx, epochID)
		if err != nil {
			return err
		}
		var held bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM images AS i JOIN preparations AS p ON p.id=i.preparation_id WHERE i.id=?)`, imageID).Scan(&held); err != nil {
			return err
		}
		if held {
			return ErrCleanupPending
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE images SET state='PUBLISHED' WHERE id=? AND engine_digest=? AND state IN ('PREPARED','PUBLISHED')`, imageID, install.EngineDigest))
	})
}

func (s *Store) MarkPreparationPending(ctx context.Context, epochID, preparationID string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := requireGenerationCleanup(ctx, tx, epochID); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE preparations SET state='CLEANUP_PENDING' WHERE id=?`, preparationID))
	})
}

func (s *Store) ReleasePreparation(ctx context.Context, epochID, preparationID string, proof RemovalProof) error {
	if !proof.complete() {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := requireGenerationCleanup(ctx, tx, epochID); err != nil {
			return err
		}
		var held bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM images WHERE preparation_id=? AND may_write=1)`, preparationID).Scan(&held); err != nil {
			return err
		}
		if held {
			return ErrCleanupPending
		}
		if err := exactlyOne(tx.ExecContext(ctx, `DELETE FROM preparations WHERE id=? AND state='CLEANUP_PENDING'`, preparationID)); err != nil {
			return err
		}
		return pruneEpochs(ctx, tx)
	})
}

// MarkImagePending fences new references before native removal. A held
// generation, whether live, pending, configured or backed up, cannot retire.
func (s *Store) MarkImagePending(ctx context.Context, epochID, imageID string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := requireGenerationCleanup(ctx, tx, epochID); err != nil {
			return err
		}
		var ref bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM approvals WHERE image_id=?) OR EXISTS(SELECT 1 FROM runs WHERE image_id=?) OR EXISTS(SELECT 1 FROM backup_images WHERE image_id=?)`,
			imageID, imageID, imageID).Scan(&ref); err != nil {
			return err
		}
		if ref {
			return ErrReferenced
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE images SET state='CLEANUP_PENDING' WHERE id=?`, imageID))
	})
}

func (s *Store) ReleaseImage(ctx context.Context, epochID, imageID string, proof RemovalProof) error {
	if !proof.complete() {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := requireGenerationCleanup(ctx, tx, epochID); err != nil {
			return err
		}
		if err := exactlyOne(tx.ExecContext(ctx, `DELETE FROM images WHERE id=? AND state='CLEANUP_PENDING'`, imageID)); err != nil {
			return err
		}
		return pruneEpochs(ctx, tx)
	})
}

func requireGenerationCleanup(ctx context.Context, tx *sql.Tx, epochID string) error {
	install, err := requireEpoch(ctx, tx, epochID)
	if err != nil {
		return err
	}
	if install.State == Purging || install.State == Purged || install.State == Uninstalling {
		return ErrState
	}
	return requireNoBackupWriter(ctx, tx)
}
