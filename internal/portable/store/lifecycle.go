package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
)

// BeginUninstall prevents future runs before the caller removes installed
// code. Configuration and all retained data/cache/backup rows stay charged.
func (s *Store) BeginUninstall(ctx context.Context, epochID string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		switch install.State {
		case Uninstalled, Uninstalling:
			return nil
		case Ready, Initializing:
		default:
			return ErrState
		}
		if err := requireStopped(ctx, tx, install); err != nil {
			return err
		}
		if err := requireNoBackupWriter(ctx, tx); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET state='UNINSTALLING' WHERE singleton=1`))
	})
}

func (s *Store) CompleteUninstall(ctx context.Context, epochID string, proof RemovalProof) error {
	if !proof.complete() {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if install.State == Uninstalled {
			return nil
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET state='UNINSTALLED' WHERE singleton=1 AND state='UNINSTALLING'`))
	})
}

// PlanPurge enumerates ledger-owned retained generations. The caller must
// present the approved installation root and fixed installation objects
// (including manifest, code and SQLite, not the downloaded binary or shared
// parent dirs), and use native rooted/no-follow deletion for that scope.
func (s *Store) PlanPurge(ctx context.Context) (PurgePlan, error) {
	var plan PurgePlan
	err := s.write(ctx, func(tx *sql.Tx) error {
		install, err := readInstallation(ctx, tx)
		if err != nil {
			return err
		}
		plan, err = planPurge(ctx, tx, install)
		return err
	})
	return plan, err
}

func planPurge(ctx context.Context, tx *sql.Tx, install InstallationRecord) (PurgePlan, error) {
	switch install.State {
	case Initializing, Ready, Uninstalled, Purging:
	default:
		return PurgePlan{}, ErrState
	}
	if err := requireStopped(ctx, tx, install); err != nil {
		return PurgePlan{}, err
	}
	if err := requireNoBackupWriter(ctx, tx); err != nil {
		return PurgePlan{}, err
	}
	p := PurgePlan{InstallationIdentity: install.InstallationIdentity}
	var err error
	if p.Volumes, err = volumes(ctx, tx); err != nil {
		return PurgePlan{}, err
	}
	if p.Images, err = images(ctx, tx); err != nil {
		return PurgePlan{}, err
	}
	if p.Backups, err = backups(ctx, tx); err != nil {
		return PurgePlan{}, err
	}
	raw, err := json.Marshal(struct {
		Format, PlanDigest, ConfigRevision, ConfigDigest string
		Inventory                                        PurgePlan
	}{Format, install.PlanDigest, install.ConfigRevision, install.ConfigDigest, p})
	if err != nil {
		return PurgePlan{}, err
	}
	digest := sha256.Sum256(raw)
	p.Digest = "sha256:" + hex.EncodeToString(digest[:])
	return p, nil
}

// BeginPurge checks the exact operator-approved inventory and freezes it.
// Partial native removal never changes the plan or releases its reservations.
func (s *Store) BeginPurge(ctx context.Context, epochID, digest string) (PurgePlan, error) {
	if !validDigest(digest) {
		return PurgePlan{}, ErrApprovalMismatch
	}
	var plan PurgePlan
	err := s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		plan, err = planPurge(ctx, tx, install)
		if err != nil {
			return err
		}
		if plan.Digest != digest {
			return ErrApprovalMismatch
		}
		if install.State == Purging {
			return matchPurgeDigest(ctx, tx, digest)
		}
		return exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET state='PURGING',purge_digest=? WHERE singleton=1`, digest))
	})
	if err != nil {
		return PurgePlan{}, err
	}
	return plan, nil
}

func matchPurgeDigest(ctx context.Context, tx *sql.Tx, digest string) error {
	var expected string
	if err := tx.QueryRowContext(ctx, `SELECT purge_digest FROM installation WHERE singleton=1`).Scan(&expected); err != nil {
		return err
	}
	if digest != expected {
		return ErrApprovalMismatch
	}
	return nil
}

// CompletePurge releases persistent and retained charges only after removal
// of the exact frozen inventory and owned code/config files. SQLite and its
// guard must remain until this transaction commits and Store is closed.
func (s *Store) CompletePurge(ctx context.Context, epochID, digest string, proof RemovalProof) error {
	if !proof.complete() {
		return ErrCleanupPending
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		install, err := requireEpoch(ctx, tx, epochID)
		if err != nil {
			return err
		}
		if install.State != Purging && install.State != Purged {
			return ErrState
		}
		if err := matchPurgeDigest(ctx, tx, digest); err != nil {
			return err
		}
		if install.State == Purged {
			return nil
		}
		for _, statement := range []string{"DELETE FROM backups", "DELETE FROM approvals", "DELETE FROM images", "DELETE FROM volumes"} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		if err := exactlyOne(tx.ExecContext(ctx, `UPDATE installation SET state='PURGED',config_revision='',config_digest='' WHERE singleton=1`)); err != nil {
			return err
		}
		return pruneEpochs(ctx, tx)
	})
}
