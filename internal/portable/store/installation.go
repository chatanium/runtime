package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

const installationQuery = `SELECT format,id,owner,target,bundle_digest,engine_digest,plan_digest,
	budget_bytes,metadata_bytes,log_bytes,state,desired,config_revision,config_digest,coalesce(epoch_id,''),purge_digest,
	EXISTS(SELECT 1 FROM epochs WHERE worker_pending=1) FROM installation WHERE singleton=1`

func readInstallation(ctx context.Context, q rowReader) (InstallationRecord, error) {
	var record InstallationRecord
	var format string
	err := q.QueryRowContext(ctx, installationQuery).Scan(&format, &record.ID, &record.Owner, &record.Target,
		&record.BundleDigest, &record.EngineDigest, &record.PlanDigest, &record.BudgetBytes, &record.MetadataBytes,
		&record.LogBytes, &record.State, &record.Desired, &record.ConfigRevision, &record.ConfigDigest, &record.EpochID, &record.PurgeDigest, &record.WorkerPending)
	if err == nil && format != Format {
		err = ErrFormat
	}
	return record, err
}

func (s *Store) Installation(ctx context.Context) (InstallationRecord, error) {
	record, err := readInstallation(ctx, s.db)
	return record, translate(err)
}

func (s *Store) Epoch(ctx context.Context, id string) (Epoch, error) {
	var epoch Epoch
	err := s.db.QueryRowContext(ctx, `SELECT id,boot_id,pid,start_identity FROM epochs WHERE id=?`, id).
		Scan(&epoch.ID, &epoch.BootID, &epoch.PID, &epoch.StartIdentity)
	return epoch, translate(err)
}

// BeginEpoch requires the installation's exclusive native supervisor lock.
// A previous epoch is fenced, not presumed dead. File and child proof remains
// necessary for every previously touched run, image, preparation and backup.
func (s *Store) BeginEpoch(ctx context.Context, identity EpochIdentity) (Epoch, error) {
	return s.beginEpoch(ctx, identity, true)
}

// BeginOfflineEpoch holds the same native lock and recovery authority without
// authorizing a worker launch or a module run.
func (s *Store) BeginOfflineEpoch(ctx context.Context, identity EpochIdentity) (Epoch, error) {
	return s.beginEpoch(ctx, identity, false)
}

func (s *Store) beginEpoch(ctx context.Context, identity EpochIdentity, start bool) (Epoch, error) {
	if !validOpaque(identity.BootID) || identity.PID <= 0 || !validOpaque(identity.StartIdentity) {
		return Epoch{}, ErrIdentity
	}
	epoch := Epoch{ID: newID(), EpochIdentity: identity}
	err := s.write(ctx, func(tx *sql.Tx) error {
		install, err := readInstallation(ctx, tx)
		if err != nil {
			return err
		}
		if install.State == Purged {
			return ErrState
		}
		if err := activateRestoredOrigin(ctx, tx); err != nil {
			return err
		}
		if err := fenceEpoch(ctx, tx, install.EpochID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO epochs (id,boot_id,pid,start_identity) VALUES (?,?,?,?)`, epoch.ID, epoch.BootID, epoch.PID, epoch.StartIdentity); err != nil {
			return err
		}
		desired := DesiredStopped
		if start && (install.State == Initializing || install.State == Ready) {
			desired = DesiredRunning
		}
		if err := exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET epoch_id=?, desired=? WHERE singleton=1`, epoch.ID, desired)); err != nil {
			return err
		}
		return pruneEpochs(ctx, tx)
	})
	if err != nil {
		return Epoch{}, err
	}
	return epoch, nil
}

// RequestStop is the only mutation that may be issued by a separate owner
// management connection while the supervisor holds its lifetime lock. It does
// not perform process signalling or certify cleanup.
func (s *Store) RequestStop(ctx context.Context, expectedEpochID string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := readInstallation(ctx, tx)
		if err != nil {
			return err
		}
		if install.EpochID != expectedEpochID {
			return ErrIdentity
		}
		if install.State == Purged {
			return ErrState
		}
		if install.EpochID == "" {
			var pending bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM runs) OR EXISTS(SELECT 1 FROM epochs WHERE worker_pending=1)`).Scan(&pending); err != nil {
				return err
			}
			if pending {
				return ErrCleanupPending
			}
			return nil
		}
		if install.Desired == DesiredStopped {
			return nil
		}
		if err := exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET desired='STOPPED' WHERE singleton=1`)); err != nil {
			return err
		}
		return stopEpochRuns(ctx, tx, install.EpochID)
	})
}

func (s *Store) EndEpoch(ctx context.Context, epochID string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := requireEpoch(ctx, tx, epochID); err != nil {
			return err
		}
		var pending bool
		if err := tx.QueryRowContext(ctx, `SELECT worker_pending FROM epochs WHERE id=?`, epochID).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return ErrCleanupPending
		}
		if err := fenceEpoch(ctx, tx, epochID); err != nil {
			return err
		}
		if err := exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET epoch_id=NULL, desired='STOPPED' WHERE singleton=1`)); err != nil {
			return err
		}
		return pruneEpochs(ctx, tx)
	})
}

func stopEpochRuns(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, `UPDATE runs SET desired='STOPPED',state='UNKNOWN',cleanup=1,egress_state='SEALED' WHERE epoch_id=? AND cleanup=0`, id)
	return err
}

func fenceEpoch(ctx context.Context, tx *sql.Tx, id string) error {
	if id == "" {
		return nil
	}
	if err := stopEpochRuns(ctx, tx, id); err != nil {
		return err
	}
	for _, q := range []string{
		`UPDATE preparations SET state='CLEANUP_PENDING' WHERE epoch_id=? AND state='WRITING'`,
		`UPDATE images SET state='CLEANUP_PENDING' WHERE epoch_id=? AND state='WRITING'`,
		`UPDATE backups SET state='CLEANUP_PENDING' WHERE epoch_id=? AND state='WRITING'`,
		`DELETE FROM run_identities WHERE epoch_id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return nil
}

func pruneEpochs(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM epochs WHERE worker_pending=0 AND
		NOT EXISTS (SELECT 1 FROM installation WHERE epoch_id=epochs.id) AND
		NOT EXISTS (SELECT 1 FROM preparations WHERE epoch_id=epochs.id) AND
		NOT EXISTS (SELECT 1 FROM images WHERE epoch_id=epochs.id) AND
		NOT EXISTS (SELECT 1 FROM runs WHERE epoch_id=epochs.id) AND
		NOT EXISTS (SELECT 1 FROM backups WHERE epoch_id=epochs.id)`)
	return err
}

func requireEpoch(ctx context.Context, tx *sql.Tx, id string) (InstallationRecord, error) {
	install, err := readInstallation(ctx, tx)
	if err == nil && (id == "" || id != install.EpochID) {
		err = ErrIdentity
	}
	return install, err
}

// Configure commits all approved modules and the external config digest in
// one CAS. The caller must already have checked the exact ReviewDigests and
// external config's digest. Only a published, matching local generation may
// be approved. Stop and finish recovering all runs before changing approvals.
func (s *Store) Configure(ctx context.Context, epochID, expectedRevision string, config Configuration) error {
	if !validDigest(config.Revision) || !validDigest(config.ConfigDigest) || expectedRevision != "" && !validDigest(expectedRevision) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(config.Approvals))
	for _, a := range config.Approvals {
		if err := a.validate(); err != nil {
			return err
		}
		if _, duplicate := seen[a.ModuleID]; duplicate {
			return fmt.Errorf("%w: duplicate approval for %s", ErrInvalid, a.ModuleID)
		}
		seen[a.ModuleID] = struct{}{}
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if install.State != Initializing && install.State != Ready {
			return ErrState
		}
		if install.ConfigRevision != expectedRevision {
			return ErrApprovalMismatch
		}
		if err := requireNoBackupWriter(ctx, tx); err != nil {
			return err
		}
		if err := requireStopped(ctx, tx, install); err != nil {
			return err
		}
		if config.Revision == expectedRevision {
			return sameConfiguration(ctx, tx, config, install.ConfigDigest)
		}
		for _, a := range config.Approvals {
			if err := checkModuleApproval(ctx, tx, install, a); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM approvals`); err != nil {
			return err
		}
		for _, a := range config.Approvals {
			raw, err := json.Marshal(a)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO approvals VALUES (?,?,?,?)`, a.ModuleID, a.ImageGeneration, a.ReviewDigest, raw); err != nil {
				return err
			}
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET config_revision=?,config_digest=? WHERE singleton=1`, config.Revision, config.ConfigDigest))
	})
}

func checkModuleApproval(ctx context.Context, tx *sql.Tx, install InstallationRecord, a Approval) error {
	var imageOK bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM images WHERE id=? AND digest=? AND engine_digest=? AND state='PUBLISHED')`,
		a.ImageGeneration, a.ImageDigest, install.EngineDigest).Scan(&imageOK); err != nil {
		return err
	}
	if !imageOK {
		return fmt.Errorf("%w: module image %s", ErrApprovalMismatch, a.ModuleID)
	}
	var uid, gid uint32
	err := tx.QueryRowContext(ctx, `SELECT uid,gid FROM volumes WHERE module_id=?`, a.ModuleID).Scan(&uid, &gid)
	if err == nil && (uid != a.UID || gid != a.GID) {
		return fmt.Errorf("%w: retained volume UID/GID %s", ErrApprovalMismatch, a.ModuleID)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

func sameConfiguration(ctx context.Context, tx *sql.Tx, config Configuration, configDigest string) error {
	if config.ConfigDigest != configDigest {
		return ErrApprovalMismatch
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approvals`).Scan(&count); err != nil {
		return err
	}
	if count != len(config.Approvals) {
		return ErrApprovalMismatch
	}
	for _, a := range config.Approvals {
		var old []byte
		err := tx.QueryRowContext(ctx, `SELECT record FROM approvals WHERE module_id=?`, a.ModuleID).Scan(&old)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrApprovalMismatch
		}
		if err != nil {
			return err
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, raw) {
			return ErrApprovalMismatch
		}
	}
	return nil
}

func (s *Store) Configuration(ctx context.Context) (Configuration, error) {
	// One statement ensures the approvals and revision are the same snapshot,
	// even if another management connection commits in parallel.
	rows, err := s.db.QueryContext(ctx, `SELECT config_revision,config_digest,record FROM installation LEFT JOIN approvals ON true WHERE singleton=1 ORDER BY module_id`)
	if err != nil {
		return Configuration{}, err
	}
	defer rows.Close()
	var config Configuration
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&config.Revision, &config.ConfigDigest, &raw); err != nil {
			return Configuration{}, err
		}
		if raw != nil {
			var a Approval
			if err := json.Unmarshal(raw, &a); err != nil {
				return Configuration{}, err
			}
			config.Approvals = append(config.Approvals, a)
		}
	}
	return config, rows.Err()
}

func (s *Store) Activate(ctx context.Context, epochID, approvedPlanDigest, revision string) error {
	if !validDigest(approvedPlanDigest) || !validDigest(revision) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if install.PlanDigest != approvedPlanDigest || install.ConfigRevision != revision {
			return ErrApprovalMismatch
		}
		if install.State == Ready {
			return nil
		}
		if install.State != Initializing {
			return ErrState
		}
		if err := requireStopped(ctx, tx, install); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET state='READY' WHERE singleton=1`))
	})
}

func requireNoRuns(ctx context.Context, q rowReader) error {
	var held bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM runs)`).Scan(&held); err != nil {
		return err
	}
	if held {
		return ErrVolumeBusy
	}
	return nil
}

func requireNoPreparationWriters(ctx context.Context, q rowReader) error {
	var held bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM preparations) OR EXISTS(SELECT 1 FROM images WHERE state='WRITING') OR EXISTS(SELECT 1 FROM images WHERE state='CLEANUP_PENDING' AND may_write=1)`).Scan(&held); err != nil {
		return err
	}
	if held {
		return ErrCleanupPending
	}
	return nil
}
