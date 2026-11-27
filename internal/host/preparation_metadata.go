//go:build linux

package host

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/provision"
)

// AvailablePreparationStorage is only a read-only planning snapshot. Actual
// preparation must reserve again under the sole installation lease.
func (s *Store) AvailablePreparationStorage(ctx context.Context) (StorageBudget, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return StorageBudget{}, err
	}
	defer tx.Rollback()
	manifest, err := readManagementManifest(ctx, tx, s.productID)
	if err != nil {
		return StorageBudget{}, err
	}
	budget := manifest.Budget
	rows, err := tx.QueryContext(ctx, "SELECT kind,coalesce(sum(bytes),0),coalesce(sum(inodes),0) FROM storage_claims WHERE state!='RELEASED' AND kind IN ('source','cache','preparation') GROUP BY kind")
	if err != nil {
		return StorageBudget{}, err
	}
	for rows.Next() {
		var kind string
		var usedBytes, usedInodes int64
		if err = rows.Scan(&kind, &usedBytes, &usedInodes); err != nil {
			rows.Close()
			return StorageBudget{}, err
		}
		var bytes, inodes *int64
		switch kind {
		case "source":
			bytes, inodes = &budget.SourceBytes, &budget.SourceInodes
		case "cache":
			bytes, inodes = &budget.CacheBytes, &budget.CacheInodes
		case "preparation":
			bytes, inodes = &budget.PreparationBytes, &budget.PreparationInodes
		}
		if usedBytes < 0 || usedInodes < 0 || *bytes < usedBytes || *inodes < usedInodes {
			rows.Close()
			return StorageBudget{}, errors.New("preparation reservations exceed installed finite pool")
		}
		*bytes -= usedBytes
		*inodes -= usedInodes
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return StorageBudget{}, err
	}
	if err = tx.Commit(); err != nil {
		return StorageBudget{}, err
	}
	return budget, nil
}
func (r *MetadataReader) AvailablePreparationStorage(ctx context.Context) (StorageBudget, error) {
	return r.store.AvailablePreparationStorage(ctx)
}

func validateImageAcquisitionProperties(p ProvisionProperties) error {
	if p.ApprovedImageInput == nil {
		return nil
	}
	input := p.ApprovedImageInput
	if err := input.Validate(); err != nil {
		return err
	}
	if input.CredentialRef != "" && (!validLedgerID(input.CredentialRef) || strings.Contains(input.CredentialRef, ".")) {
		return invalid("acquisition credential reference must be an opaque task token, not a path")
	}
	if p.Name != input.JobID || p.PrepareLimits == nil || *p.PrepareLimits != input.Limits || p.ImageSpace == nil || p.ImageSpace.JobID != input.JobID || p.Path != p.ImageSpace.Source || p.Target != p.ImageSpace.Cache || p.Source != p.ImageSpace.Work {
		return invalid("original acquisition input differs from its bounded native job intent")
	}
	return nil
}
func (s *Store) validateImageAcquisitionScope(ctx context.Context, p ProvisionProperties) error {
	if err := validateImageAcquisitionProperties(p); err != nil {
		return err
	}
	if p.ApprovedImageInput == nil {
		return invalid("original acquisition input is missing")
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	job := p.ApprovedImageInput.JobID
	if !filepath.IsAbs(m.Paths.StorageRoot) || filepath.Clean(m.Paths.StorageRoot) != m.Paths.StorageRoot || p.ImageSpace.Source != filepath.Join(m.Paths.StorageRoot, "images", job) || p.ImageSpace.Cache != filepath.Join(m.Paths.StorageRoot, "prepared", job) || p.ImageSpace.Work != filepath.Join(m.Paths.StorageRoot, "preparation", job) {
		return invalid("acquisition intent is outside this installation's fixed preparation scope")
	}
	return nil
}

// ImagePreparationInput is provenance, not current preparation or launch
// authority. Callers must independently revalidate live policy and retirement.
func (s *Store) ImagePreparationInput(ctx context.Context, jobID string) (provision.ApprovedImageInput, error) {
	var input provision.ApprovedImageInput
	if jobID == "" || len(jobID) > 4096 || strings.ContainsAny(jobID, "./\\\x00\r\n") {
		return input, invalid("invalid original acquisition job identity")
	}
	records, err := s.ObjectProvisions(ctx, "image", jobID)
	if err != nil {
		return input, err
	}
	if len(records) == 0 {
		return input, sql.ErrNoRows
	}
	originalMissing := false
	for index, record := range records {
		if err = validProvision(record.Kind, record.Desired); err != nil {
			return input, err
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return input, err
		}
		if index == 0 {
			originalMissing = desired.ApprovedImageInput == nil
		}
		if desired.ApprovedImageInput == nil {
			if !originalMissing {
				return input, errors.New("original acquisition input was discarded by a later job intent")
			}
			continue
		}
		if originalMissing {
			return input, errors.New("later image intent cannot introduce original acquisition authority")
		}
		if record.Identity != jobID || !record.ProductCreated || record.ExistedBefore || desired.ApprovedImageInput.JobID != jobID {
			return input, errors.New("original acquisition journal identity mismatch")
		}
		if err = s.validateImageAcquisitionScope(ctx, desired); err != nil {
			return input, err
		}
		if index == 0 {
			input = *desired.ApprovedImageInput
		} else if input != *desired.ApprovedImageInput {
			return input, errors.New("conflicting immutable original acquisition inputs")
		}
	}
	if originalMissing {
		return input, sql.ErrNoRows
	}
	return input, nil
}
func (r *MetadataReader) ImagePreparationInput(ctx context.Context, jobID string) (provision.ApprovedImageInput, error) {
	return r.store.ImagePreparationInput(ctx, jobID)
}
