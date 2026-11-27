//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/provision"
)

func validatePreparedBinding(b ApprovedImageBinding, image provision.ImageRecord) error {
	if !validLedgerID(b.ModuleID) || !validLedgerID(b.ConfigRevision) || !validLedgerID(b.ApprovalRevision) || b.ImageRecordID != image.ID {
		return invalid("invalid prepared image binding")
	}
	if err := provision.ValidateSelector(b.ImageSelector); err != nil {
		return err
	}
	if strings.HasPrefix(b.ImageSelector, "record:") {
		if b.ImageSelector != "record:"+image.ID {
			return errors.New("prepared selector names another record")
		}
	} else if image.SourceKind != "registry" || b.ImageSelector != image.SourceRef {
		return errors.New("prepared registry selector differs from committed source")
	}
	return nil
}
func preparationInputMatches(input provision.ApprovedImageInput, b ApprovedImageBinding, image provision.ImageRecord) bool {
	return input.Validate() == nil && input.ModuleID == b.ModuleID && input.ConfigRevision == b.ConfigRevision && input.ApprovalRevision == b.ApprovalRevision && provision.Revision(input) == image.Revision && input.SourceKind == image.SourceKind && input.SourceRef == image.SourceRef
}
func (s *Store) preparedBindingApproved(ctx context.Context, b ApprovedImageBinding, image provision.ImageRecord) error {
	manifest, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	if manifest.ActiveRevision != "" {
		revision, err := s.Revision(ctx, manifest.ActiveRevision)
		if err != nil {
			return err
		}
		for _, approved := range revision.Images {
			if approved == b {
				return nil
			}
		}
		rows, err := s.db.QueryContext(ctx, "SELECT binding FROM approved_image_candidates WHERE revision=? AND image=?", manifest.ActiveRevision, image.ID)
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			var approved ApprovedImageBinding
			if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 16, &approved); err != nil {
				rows.Close()
				return err
			}
			found = found || approved == b
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if found {
			return nil
		}
	}
	for _, kind := range []string{"init"} {
		plans, err := s.ManagementPlans(ctx, kind)
		if err != nil {
			return err
		}
		for _, plan := range plans {
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(plan.Plan, &fields); err != nil {
				return err
			}
			var modules []map[string]json.RawMessage
			if err = json.Unmarshal(fields["modules"], &modules); err != nil {
				return err
			}
			for _, module := range modules {
				var input provision.ApprovedImageInput
				if err = gvxcontract.DecodeStrict(module["image"], managementPlanBytesMax, 32, &input); err != nil {
					return err
				}
				if preparationInputMatches(input, b, image) {
					return nil
				}
			}
		}
	}
	return errors.New("prepared image lacks exact journaled preparation or approved revision provenance")
}

type preparedImageReceipt struct {
	ImageID                 string `json:"image_id"`
	CacheID                 string `json:"cache_id"`
	PreparationBundleDigest string `json:"preparation_bundle_digest"`
	PreparationPlanID       string `json:"preparation_plan_id,omitempty"`
	PreparationPlanDigest   string `json:"preparation_plan_digest,omitempty"`
}

func (s *Store) preparedBindingReceipt(ctx context.Context, b ApprovedImageBinding, image provision.ImageRecord) (preparedImageReceipt, error) {
	receipt := preparedImageReceipt{ImageID: image.ID}
	plans, err := s.ManagementPlans(ctx, "operator-preparation")
	if err != nil {
		return receipt, err
	}
	var selected *ManagementPlanRecord
	var input *provision.ApprovedImageInput
	for _, plan := range plans {
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(plan.Plan, &fields); err != nil {
			return receipt, err
		}
		var candidate provision.ApprovedImageInput
		if err = gvxcontract.DecodeStrict(fields["input"], managementPlanBytesMax, 32, &candidate); err != nil {
			return receipt, err
		}
		if !preparationInputMatches(candidate, b, image) {
			continue
		}
		if selected != nil {
			return receipt, errors.New("ambiguous exact operator preparation authority")
		}
		a, e := operatorPreparationApproval(plan)
		if e != nil {
			return receipt, e
		}
		if plan.Phase != "APPROVED" && plan.Phase != "PREPARED" && plan.Phase != "COMMITTED" {
			return receipt, errors.New("operator preparation phase cannot bind usable outputs")
		}
		selected = &plan
		input = &a.Input
		receipt.PreparationBundleDigest = a.BundleDigest
		receipt.PreparationPlanID = plan.ID
		receipt.PreparationPlanDigest = plan.Digest
	}
	if selected == nil {
		if err = s.preparedBindingApproved(ctx, b, image); err != nil {
			return receipt, err
		}
		m, e := s.Installation(ctx)
		if e != nil {
			return receipt, e
		}
		receipt.PreparationBundleDigest = m.BundleDigest
	}
	cache, err := s.CacheForImage(ctx, image.ID, receipt.PreparationBundleDigest)
	if err != nil {
		return receipt, err
	}
	receipt.CacheID = cache.ID
	if selected != nil && selected.Phase != "APPROVED" {
		var saved struct {
			ImageID                 string `json:"image_id,omitempty"`
			CacheID                 string `json:"cache_id,omitempty"`
			PreparationBundleDigest string `json:"preparation_bundle_digest,omitempty"`
			Failure                 string `json:"failure,omitempty"`
		}
		if err = gvxcontract.DecodeStrict(selected.State, managementStateBytesMax, 16, &saved); err != nil {
			return receipt, err
		}
		if saved.Failure != "" || saved.ImageID != receipt.ImageID || saved.CacheID != receipt.CacheID || saved.PreparationBundleDigest != receipt.PreparationBundleDigest {
			return receipt, errors.New("prepared image differs from exact immutable preparation receipt")
		}
	}
	if err = s.requireCommittedImageCacheWriter(ctx, image, cache, input); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func (s *Store) requireCommittedImageCacheWriter(ctx context.Context, image provision.ImageRecord, cache CacheGeneration, input *provision.ApprovedImageInput) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	records, err := quarantineHistoryTx(ctx, tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	acquisitions, err := quarantineAcquisitions(records)
	if err != nil {
		tx.Rollback()
		return err
	}
	var space ImageSpace
	found := false
	for _, a := range acquisitions {
		if a.record.Kind != "image" || a.observed.Digest != image.ID || a.observed.Revision != cache.ID {
			continue
		}
		if found {
			tx.Rollback()
			return errors.New("ambiguous committed acquisition/cache receipt")
		}
		if a.desired.Revision != cache.BundleDigest {
			tx.Rollback()
			return errors.New("prepared output helper bundle differs from reviewed bundle")
		}
		if err = verifyPreparationRecordBinding(a.desired, image); err != nil {
			tx.Rollback()
			return err
		}
		if input != nil && (a.space.ReusedSource || a.desired.ApprovedImageInput == nil || *a.desired.ApprovedImageInput != *input || a.observed.ApprovedImageInput == nil || *a.observed.ApprovedImageInput != *input) {
			tx.Rollback()
			return errors.New("operator output changed exact approved acquisition input")
		}
		if _, err = quarantineCacheTx(ctx, tx, a, image); err != nil {
			tx.Rollback()
			return err
		}
		space = a.space
		found = true
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if !found {
		return errors.New("prepared image lacks unique exact committed acquisition/cache receipt")
	}
	return s.RequirePreparationWriterDomain(ctx, space)
}

// BindPreparedImage preserves preparation provenance only. It cannot install a
// revision, alter grants, authorize a candidate, or grant launch admission.
func (s *Store) BindPreparedImage(ctx context.Context, b ApprovedImageBinding) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	image, err := s.Image(ctx, b.ImageRecordID)
	if err != nil {
		return err
	}
	if err = validatePreparedBinding(b, image); err != nil {
		return err
	}
	receipt, err := s.preparedBindingReceipt(ctx, b, image)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	key := "prepared_image:" + image.ID
	var old []byte
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&old)
	if err == nil {
		if string(old) != string(raw) {
			return errors.New("immutable prepared image provenance reuse")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if _, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?)", key, raw); err != nil {
			return err
		}
	} else {
		return err
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if err = immutableMetadataTx(ctx, tx, "prepared_image_receipt:"+image.ID, receiptRaw); err != nil {
		return err
	}
	for _, generation := range []string{image.ID, receipt.CacheID, receipt.PreparationBundleDigest} {
		if err = checkGenerationAvailableTx(ctx, tx, generation); err != nil {
			return err
		}
	}
	claim := "prepared-image:" + image.ID
	for _, generation := range []string{image.ID, receipt.CacheID, receipt.PreparationBundleDigest} {
		if err = retainGenerationTx(ctx, tx, "recovery", generation, claim); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) PreparedImageBinding(ctx context.Context, recordID string) (ApprovedImageBinding, error) {
	var binding ApprovedImageBinding
	if err := s.CheckGenerationAvailable(ctx, recordID); err != nil {
		return binding, err
	}
	image, err := s.Image(ctx, recordID)
	if err != nil {
		return binding, err
	}
	var raw []byte
	err = s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "prepared_image:"+recordID).Scan(&raw)
	if err == nil {
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 16, &binding); err != nil {
			return binding, err
		}
		return binding, validatePreparedBinding(binding, image)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return binding, err
	}
	manifest, err := s.Installation(ctx)
	if err != nil {
		return binding, err
	}
	if manifest.ActiveRevision == "" {
		return binding, sql.ErrNoRows
	}
	revision, err := s.Revision(ctx, manifest.ActiveRevision)
	if err != nil {
		return binding, err
	}
	var matches []ApprovedImageBinding
	for _, approved := range revision.Images {
		if approved.ImageRecordID == recordID {
			matches = append(matches, approved)
		}
	}
	rows, err := s.db.QueryContext(ctx, "SELECT binding FROM approved_image_candidates WHERE revision=? AND image=?", manifest.ActiveRevision, recordID)
	if err != nil {
		return binding, err
	}
	for rows.Next() {
		var value []byte
		if err = rows.Scan(&value); err != nil {
			rows.Close()
			return binding, err
		}
		var approved ApprovedImageBinding
		if err = gvxcontract.DecodeStrict(value, durableJSONMax, 16, &approved); err != nil {
			rows.Close()
			return binding, err
		}
		matches = append(matches, approved)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return binding, err
	}
	for _, approved := range matches {
		if binding.ImageRecordID != "" && binding != approved {
			return binding, errors.New("ambiguous approved prepared image provenance")
		}
		binding = approved
	}
	if binding.ImageRecordID == "" {
		return binding, sql.ErrNoRows
	}
	return binding, validatePreparedBinding(binding, image)
}
func (r *MetadataReader) PreparedImageBinding(ctx context.Context, recordID string) (ApprovedImageBinding, error) {
	return r.store.PreparedImageBinding(ctx, recordID)
}
func preparedImageReferenceTx(ctx context.Context, tx *sql.Tx, ref GenerationReference) (bool, error) {
	if ref.Kind != "recovery" || !strings.HasPrefix(ref.Claim, "prepared-image:") {
		return false, nil
	}
	imageID := strings.TrimPrefix(ref.Claim, "prepared-image:")
	var raw []byte
	err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "prepared_image:"+imageID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var binding ApprovedImageBinding
	if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 16, &binding); err != nil {
		return false, err
	}
	if binding.ImageRecordID != imageID {
		return false, errors.New("prepared image reference identity mismatch")
	}
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "prepared_image_receipt:"+imageID).Scan(&raw)
	if err == nil {
		var receipt preparedImageReceipt
		if err = gvxcontract.DecodeStrict(raw, 64<<10, 8, &receipt); err != nil {
			return false, err
		}
		if receipt.ImageID != imageID {
			return false, errors.New("prepared image receipt identity mismatch")
		}
		return ref.ID == imageID || ref.ID == receipt.CacheID || ref.ID == receipt.PreparationBundleDigest, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if ref.ID == imageID {
		return true, nil
	}
	err = tx.QueryRowContext(ctx, "SELECT record FROM cache_generations WHERE id=?", ref.ID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var cache CacheGeneration
	if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &cache); err != nil {
		return false, err
	}
	return cache.ImageRecordID == imageID, nil
}
