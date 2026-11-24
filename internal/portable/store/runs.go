package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

const volumeColumns = `v.id,v.module_id,v.native_id,v.max_bytes,v.creation_run_id,v.initialized`
const imageColumns = `i.id,i.epoch_id,i.preparation_id,i.digest,i.engine_digest,i.state,i.max_bytes`
const runQuery = `SELECT r.id,r.epoch_id,r.instance_id,r.config_revision,r.approval,r.state,r.desired,
	r.cleanup,r.launch_begun,r.engine_id,r.egress_generation,r.egress_state,r.log_bytes,` + volumeColumns + `,` + imageColumns + `
	FROM runs AS r JOIN volumes AS v ON r.volume_id=v.id JOIN images AS i ON r.image_id=i.id`

func (v *Volume) fields() []any {
	return []any{&v.ID, &v.ModuleID, &v.NativeID, &v.MaxBytes, &v.CreationRunID, &v.Initialized}
}
func (v *Volume) path() { v.Path = "volumes/" + v.ID + ".ext4" }

func scanVolume(row scanner) (Volume, error) {
	var volume Volume
	err := row.Scan(volume.fields()...)
	volume.path()
	return volume, err
}

func scanRun(row scanner) (Run, error) {
	var run Run
	var approval []byte
	args := []any{&run.Key.ID, &run.Key.EpochID, &run.InstanceID, &run.ConfigRevision, &approval,
		&run.State, &run.Desired, &run.CleanupPending, &run.LaunchBegun, &run.EngineID, &run.EgressGeneration, &run.EgressState, &run.LogBytes}
	if err := row.Scan(append(append(args, run.Persistent.fields()...), run.Image.fields()...)...); err != nil {
		return Run{}, err
	}
	if err := json.Unmarshal(approval, &run.Approval); err != nil {
		return Run{}, err
	}
	run.Persistent.path()
	run.Image.path()
	run.InstancePath = "instances/" + run.Key.ID
	run.ScratchID = run.Key.ID
	return run, nil
}

func (s *Store) Runs(ctx context.Context) ([]Run, error) {
	return collect(ctx, s.db, runQuery+` ORDER BY r.id`, scanRun)
}

// Run reads the durable record for an exact key, including a prior epoch's
// pending cleanup. Use this after any ambiguous launch or completion result.
func (s *Store) Run(ctx context.Context, key RunKey) (Run, error) {
	run, err := runByKey(ctx, s.db, key)
	return run, translate(err)
}

func runByKey(ctx context.Context, q rowReader, key RunKey) (Run, error) {
	return scanRun(q.QueryRowContext(ctx, runQuery+` WHERE r.id=? AND r.epoch_id=?`, key.ID, key.EpochID))
}

// AdmitRun commits before creating files or starting any child. The retained
// volume ceiling, one fresh scratch ceiling, and this run's log/runtime-file
// allowance count simultaneously with all other active/pending/retained rows.
func (s *Store) AdmitRun(ctx context.Context, req RunRequest) (Run, error) {
	if !lowerHex(req.InstanceID, 32) || !validToken(req.ModuleID) || !validDigest(req.ConfigRevision) || !validDigest(req.ReviewDigest) {
		return Run{}, ErrInvalid
	}
	var run Run
	err := s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, req.EpochID)
		if err != nil {
			return err
		}
		if install.State != Ready || install.Desired != DesiredRunning {
			return ErrState
		}
		if err := requireNoPriorWorker(ctx, tx, req.EpochID); err != nil {
			return err
		}
		if err := requireNoBackupWriter(ctx, tx); err != nil {
			return err
		}
		if install.ConfigRevision != req.ConfigRevision {
			return ErrApprovalMismatch
		}
		var raw []byte
		err = tx.QueryRowContext(ctx, `SELECT record FROM approvals WHERE module_id=? AND review_digest=?`, req.ModuleID, req.ReviewDigest).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrApprovalMismatch
		}
		if err != nil {
			return err
		}
		var approval Approval
		if err := json.Unmarshal(raw, &approval); err != nil {
			return err
		}
		if err := checkModuleApproval(ctx, tx, install, approval); err != nil {
			return err
		}
		var alreadyUsed bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM run_identities WHERE instance_id=?)`, req.InstanceID).Scan(&alreadyUsed); err != nil {
			return err
		}
		if alreadyUsed {
			return fmt.Errorf("%w: instance identifier already admitted", ErrState)
		}
		var volumeID string
		var maxBytes int64
		var busy bool
		err = tx.QueryRowContext(ctx, `SELECT v.id,v.max_bytes,EXISTS(SELECT 1 FROM runs WHERE volume_id=v.id) FROM volumes AS v WHERE module_id=?`, req.ModuleID).
			Scan(&volumeID, &maxBytes, &busy)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if busy {
			return ErrVolumeBusy
		}
		delta := max(approval.PersistentBytes-maxBytes, 0)
		if err := admitBytes(ctx, tx, delta, approval.ScratchBytes, install.LogBytes); err != nil {
			return err
		}
		if volumeID == "" {
			volumeID = newID()
			if _, err := tx.ExecContext(ctx, `INSERT INTO volumes (id,module_id,uid,gid,max_bytes) VALUES (?,?,?,?,?)`, volumeID, req.ModuleID, approval.UID, approval.GID, approval.PersistentBytes); err != nil {
				return err
			}
		} else if delta > 0 {
			if err := exactlyOne(tx.ExecContext(ctx, `UPDATE volumes SET max_bytes=? WHERE id=?`, approval.PersistentBytes, volumeID)); err != nil {
				return err
			}
		}
		key := RunKey{EpochID: req.EpochID, ID: newID()}
		if _, err := tx.ExecContext(ctx, `INSERT INTO run_identities (instance_id,epoch_id) VALUES (?,?)`, req.InstanceID, req.EpochID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO runs (id,epoch_id,instance_id,volume_id,image_id,config_revision,approval,state,desired,
			egress_generation,egress_state,scratch_bytes,log_bytes) VALUES (?,?,?,?,?,?,?,'RESERVED','RUNNING',?,'CLOSED',?,?)`,
			key.ID, key.EpochID, req.InstanceID, volumeID, approval.ImageGeneration, req.ConfigRevision, raw, newID(), approval.ScratchBytes, install.LogBytes); err != nil {
			return err
		}
		run, err = runByKey(ctx, tx, key)
		return err
	})
	if err != nil {
		return Run{}, err
	}
	return run, nil
}

// BeginLaunch verifies the prior persistent backing while holding its writer
// slot and durably makes this run ineligible for proof-free cancellation.
// A lower ceiling is adopted only after the file fits. An uninitialized
// volume may start only at an absent path; never adopt an unbound file.
func (s *Store) BeginLaunch(ctx context.Context, key RunKey, observed PersistentObservation) error {
	if !validPersistentObservation(observed) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		run, err := liveRun(ctx, tx, key)
		if err != nil {
			return err
		}
		if run.State != Reserved || run.LaunchBegun {
			return ErrState
		}
		if (run.Persistent.Initialized && (!observed.Exists || observed.NativeID != run.Persistent.NativeID)) ||
			(!run.Persistent.Initialized && (observed.Exists || run.Persistent.NativeID != "")) {
			return fmt.Errorf("%w: persistent backing identity", ErrIdentity)
		}
		if observed.SizeBytes > run.Approval.PersistentBytes {
			return fmt.Errorf("%w: persistent image exceeds approved ceiling", ErrBudgetExceeded)
		}
		if err := exactlyOne(tx.ExecContext(ctx, `UPDATE volumes SET max_bytes=? WHERE id=?`,
			run.Approval.PersistentBytes, run.Persistent.ID)); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE runs SET state='STARTING',launch_begun=1 WHERE id=?`, key.ID))
	})
}

func validPersistentObservation(o PersistentObservation) bool {
	if !o.Exists {
		return o.NativeID == "" && o.SizeBytes == 0
	}
	return validOpaque(o.NativeID) && o.SizeBytes >= MinVolumeBytes && o.SizeBytes%VolumeAlignmentBytes == 0
}

// RecordPersistentCreation binds a fresh empty file before publishing it at
// the durable volume path or letting GVX open it. The caller must have
// exclusively created the candidate in this run's owned private workspace.
func (s *Store) RecordPersistentCreation(ctx context.Context, key RunKey, observed PersistentObservation) error {
	if !observed.Exists || !validOpaque(observed.NativeID) || observed.SizeBytes != 0 {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		run, err := liveRun(ctx, tx, key)
		if err != nil {
			return err
		}
		if run.State != Starting || !run.LaunchBegun || run.Persistent.Initialized {
			return ErrState
		}
		if run.Persistent.NativeID != "" {
			if run.Persistent.NativeID != observed.NativeID || run.Persistent.CreationRunID != key.ID {
				return ErrIdentity
			}
			return nil
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE volumes SET native_id=?,creation_run_id=? WHERE id=?`,
			observed.NativeID, key.ID, run.Persistent.ID))
	})
}

// RecordPersistent accepts the same durable volume identity after trusted
// ROOTS_READY verifies guest ownership and mode. It makes any provisional
// backing retained before ROOTS_COMMIT can start module code.
func (s *Store) RecordPersistent(ctx context.Context, key RunKey, observed PersistentObservation) error {
	if !observed.Exists || !validPersistentObservation(observed) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		run, err := liveRun(ctx, tx, key)
		if err != nil {
			return err
		}
		if run.State != Starting || !run.LaunchBegun {
			return ErrState
		}
		if run.Persistent.NativeID != observed.NativeID || !run.Persistent.Initialized && run.Persistent.CreationRunID != key.ID {
			return ErrIdentity
		}
		if observed.SizeBytes > run.Approval.PersistentBytes {
			return ErrBudgetExceeded
		}
		if !run.Persistent.Initialized {
			if err := exactlyOne(tx.ExecContext(ctx, `UPDATE volumes SET initialized=1,creation_run_id='' WHERE id=?`, run.Persistent.ID)); err != nil {
				return err
			}
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE runs SET persistent_verified=1 WHERE id=?`, key.ID))
	})
}

func (s *Store) RecordEngine(ctx context.Context, key RunKey, engineID string) error {
	if !validOpaque(engineID) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		run, err := liveRun(ctx, tx, key)
		if err != nil {
			return err
		}
		if run.State != Starting {
			return ErrState
		}
		if run.EngineID != "" && run.EngineID != engineID {
			return ErrIdentity
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE runs SET engine_id=? WHERE id=?`, engineID, key.ID))
	})
}

func liveRun(ctx context.Context, tx *sql.Tx, key RunKey) (Run, error) {
	install, err := requireEpoch(ctx, tx, key.EpochID)
	if err != nil {
		return Run{}, err
	}
	run, err := runByKey(ctx, tx, key)
	if err != nil {
		return Run{}, err
	}
	if run.CleanupPending || run.Desired != DesiredRunning || install.Desired != DesiredRunning {
		return Run{}, ErrCleanupPending
	}
	if install.State != Ready || install.ConfigRevision != run.ConfigRevision {
		return Run{}, ErrApprovalMismatch
	}
	return run, nil
}

// SetEgressOpen records (but does not grant) an already verified policy on
// this exact engine and generation. The native adapter serializes the actual
// control call and terminates the engine if this compare-and-set fails.
func (s *Store) SetEgressOpen(ctx context.Context, key RunKey, generation, verifiedPolicyDigest string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		run, err := liveRun(ctx, tx, key)
		if errors.Is(err, ErrCleanupPending) {
			return ErrEgressRevoked
		}
		if err != nil {
			return err
		}
		if run.EgressGeneration != generation || run.Approval.Network.Mode != NetworkPublic || run.Approval.Network.PolicyDigest != verifiedPolicyDigest {
			return ErrApprovalMismatch
		}
		if run.EgressState == EgressSealed {
			return ErrEgressRevoked
		}
		if run.State != Starting || run.EngineID == "" || run.EgressState != EgressClosed {
			return ErrState
		}
		var persistentVerified bool
		if err := tx.QueryRowContext(ctx, `SELECT persistent_verified FROM runs WHERE id=?`, key.ID).Scan(&persistentVerified); err != nil {
			return err
		}
		if !persistentVerified {
			return ErrState
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE runs SET egress_state='OPEN' WHERE id=?`, key.ID))
	})
}

// SealEgress revokes this generation permanently and puts its instance into
// recovery. Call before applying deny-all and confirming native termination.
func (s *Store) SealEgress(ctx context.Context, key RunKey, generation string) error {
	return s.stopRun(ctx, key, generation, true)
}

func (s *Store) MarkRunning(ctx context.Context, key RunKey) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		run, err := liveRun(ctx, tx, key)
		if err != nil {
			return err
		}
		if run.State == Running {
			return nil
		}
		if run.State != Starting || run.EngineID == "" ||
			run.Approval.Network.Mode == NetworkPublic && run.EgressState != EgressOpen ||
			run.Approval.Network.Mode == NetworkNone && run.EgressState != EgressClosed {
			return ErrState
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE runs SET state='RUNNING' WHERE id=? AND persistent_verified=1`, key.ID))
	})
}

// StopRun records intent before touching native children. Children can still
// be alive; only ReleaseRun may subsequently free the per-run charge.
func (s *Store) StopRun(ctx context.Context, key RunKey) error {
	return s.stopRun(ctx, key, "", false)
}

func (s *Store) stopRun(ctx context.Context, key RunKey, generation string, checkGeneration bool) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := requireEpoch(ctx, tx, key.EpochID); err != nil {
			return err
		}
		if checkGeneration {
			var current string
			if err := tx.QueryRowContext(ctx, `SELECT egress_generation FROM runs WHERE id=? AND epoch_id=?`, key.ID, key.EpochID).Scan(&current); err != nil {
				return err
			}
			if current != generation {
				return ErrApprovalMismatch
			}
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE runs SET desired='STOPPED',state='UNKNOWN',cleanup=1,egress_state='SEALED' WHERE id=? AND epoch_id=?`, key.ID, key.EpochID))
	})
}

// CancelRun retires an untouched admission. BeginLaunch is the durable cut:
// after it, callers must use StopRun and provide native proof to ReleaseRun.
func (s *Store) CancelRun(ctx context.Context, actorEpoch string, key RunKey) error {
	return s.releaseRun(ctx, actorEpoch, key, nil)
}

// ReleaseRun retires scratch/runtime/log occupancy and the writer slot. An
// initialized backing remains retained; a provisional birth may reset only
// after an exact native reclaim (or no publication) and observed absence.
func (s *Store) ReleaseRun(ctx context.Context, actorEpoch string, key RunKey, proof RunCleanup) error {
	if !proof.ChildrenExited || !proof.BackingClosed || !proof.TemporaryFilesAbsent {
		return ErrCleanupPending
	}
	return s.releaseRun(ctx, actorEpoch, key, &proof)
}

func (s *Store) releaseRun(ctx context.Context, actorEpoch string, key RunKey, proof *RunCleanup) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := requireEpoch(ctx, tx, actorEpoch); err != nil {
			return err
		}
		var begun, pending, initialized bool
		var volumeID, creationRunID string
		if err := tx.QueryRowContext(ctx, `SELECT r.launch_begun,r.cleanup,v.id,v.initialized,v.creation_run_id
			FROM runs AS r JOIN volumes AS v ON v.id=r.volume_id WHERE r.id=? AND r.epoch_id=?`, key.ID, key.EpochID).
			Scan(&begun, &pending, &volumeID, &initialized, &creationRunID); err != nil {
			return err
		}
		if proof != nil && !pending || proof == nil && begun {
			return ErrCleanupPending
		}
		if proof != nil && begun {
			if initialized {
				if proof.PersistentBackingAbsent {
					return ErrIdentity
				}
			} else {
				if !proof.PersistentBackingAbsent {
					return ErrCleanupPending
				}
				if creationRunID != "" && creationRunID != key.ID {
					return ErrIdentity
				}
				if creationRunID != "" {
					if err := exactlyOne(tx.ExecContext(ctx, `UPDATE volumes SET native_id='',creation_run_id='' WHERE id=? AND initialized=0 AND creation_run_id=?`, volumeID, key.ID)); err != nil {
						return err
					}
				}
			}
		}
		if err := exactlyOne(tx.ExecContext(ctx, `DELETE FROM runs WHERE id=? AND epoch_id=?`, key.ID, key.EpochID)); err != nil {
			return err
		}
		return pruneEpochs(ctx, tx)
	})
}
