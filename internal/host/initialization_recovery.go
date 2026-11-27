//go:build linux

package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/provision"
)

type initializationPendingReceipt struct {
	PlanID           string `json:"plan_id"`
	PlanDigest       string `json:"plan_digest"`
	BaseConfigDigest string `json:"base_config_digest"`
	RevisionID       string `json:"revision_id"`
	ConfigDigest     string `json:"config_digest"`
	BundleDigest     string `json:"bundle_digest"`
}

func initializationPlanTx(ctx context.Context, tx *sql.Tx, product, planID, digest string) (ManagementPlanRecord, error) {
	var plan ManagementPlanRecord
	key, err := managementKey("init", planID)
	if err != nil {
		return plan, err
	}
	var active string
	if err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='management_active'").Scan(&active); err != nil {
		return plan, err
	}
	if active != key {
		return plan, errors.New("initialization recovery requires its exact active approved transaction")
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&raw); err != nil {
		return plan, err
	}
	plan, err = decodeManagementPlan(raw, product, "init", planID)
	if err != nil {
		return plan, err
	}
	if plan.Digest != digest || plan.Phase != "APPROVED" && plan.Phase != "PREPARED" || plan.Snapshot.State != "PROVISIONING" || plan.Snapshot.DesiredRunState != "STOPPED" || plan.Snapshot.ActiveRevision != "" || plan.Snapshot.PendingRevision != "" {
		return plan, errors.New("initialization approval or original base binding changed")
	}
	return plan, nil
}
func initializationPlanData(plan ManagementPlanRecord) ([]byte, string, []provision.ApprovedImageInput, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plan.Plan, &fields); err != nil {
		return nil, "", nil, err
	}
	var base []byte
	if err := json.Unmarshal(fields["base_config"], &base); err != nil {
		return nil, "", nil, err
	}
	if len(base) == 0 || len(base) > revisionConfigMax {
		return nil, "", nil, invalid("invalid approved initialization base config")
	}
	var bundle string
	if err := json.Unmarshal(fields["bundle_digest"], &bundle); err != nil {
		return nil, "", nil, err
	}
	if bundle == "" || bundle != plan.Snapshot.BundleDigest {
		return nil, "", nil, errors.New("initialization bundle approval changed")
	}
	var modules []map[string]json.RawMessage
	if err := json.Unmarshal(fields["modules"], &modules); err != nil {
		return nil, "", nil, err
	}
	inputs := make([]provision.ApprovedImageInput, 0, len(modules))
	seen := make(map[string]bool, len(modules))
	for _, module := range modules {
		var input provision.ApprovedImageInput
		if err := gvxcontract.DecodeStrict(module["image"], managementPlanBytesMax, 32, &input); err != nil {
			return nil, "", nil, err
		}
		if err := input.Validate(); err != nil {
			return nil, "", nil, err
		}
		if seen[input.ModuleID] {
			return nil, "", nil, errors.New("duplicate initialization module binding")
		}
		seen[input.ModuleID] = true
		inputs = append(inputs, input)
	}
	return base, bundle, inputs, nil
}
func validateInitializationRevisionTx(ctx context.Context, tx *sql.Tx, plan ManagementPlanRecord, revision RevisionRecord) error {
	base, bundle, inputs, err := initializationPlanData(plan)
	if err != nil {
		return err
	}
	if revision.DevelopmentWorker != nil || revision.BundleDigest != bundle || revision.ConfigDigest != provision.Digest(revision.Config) {
		return errors.New("initialization pending revision changed its immutable config or bundle")
	}
	if err = validateRevisionLaunchPolicies(revision); err != nil {
		return err
	}
	if revision.ID == plan.ID {
		if plan.Phase != "APPROVED" || !bytes.Equal(revision.Config, base) || len(revision.Images) != 0 || len(revision.LaunchPolicies) != 0 {
			return errors.New("initialization base revision differs from approved original config")
		}
		return nil
	}
	if len(revision.Images) != len(inputs) {
		return errors.New("initialization final revision module set differs from approved plan")
	}
	byModule := make(map[string]provision.ApprovedImageInput, len(inputs))
	for _, input := range inputs {
		byModule[input.ModuleID] = input
	}
	for _, binding := range revision.Images {
		input, ok := byModule[binding.ModuleID]
		if !ok || binding.ConfigRevision != input.ConfigRevision || binding.ApprovalRevision != input.ApprovalRevision {
			return errors.New("initialization final image binding differs from approved module revisions")
		}
		delete(byModule, binding.ModuleID)
		var raw []byte
		if err = tx.QueryRowContext(ctx, "SELECT record FROM image_records WHERE id=?", binding.ImageRecordID).Scan(&raw); err != nil {
			return err
		}
		var image provision.ImageRecord
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &image); err != nil {
			return err
		}
		if image.ID != binding.ImageRecordID || image.Revision != provision.Revision(input) || image.SourceKind != input.SourceKind || image.SourceRef != input.SourceRef {
			return errors.New("initialization final image does not preserve exact acquisition approval")
		}
		if err = provision.ValidateRecord(image, provision.PrepareLimits{JSONBytes: durableJSONMax, InputBytes: plan.Snapshot.Budget.SourceBytes, DescriptorCount: 4096, IndexDepth: 32}); err != nil {
			return err
		}
		if err = validatePreparedBinding(binding, image); err != nil {
			return err
		}
	}
	return nil
}

// bindInitializationPendingTx closes the final-revision/phase-publication crash
// window in the same transaction that changes the authoritative pending ID.
func bindInitializationPendingTx(ctx context.Context, tx *sql.Tx, product string, m InstallationManifest, revision RevisionRecord) error {
	var key string
	err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='management_active'").Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	prefix := "management_plan:init:"
	if !strings.HasPrefix(key, prefix) {
		return nil
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&raw); err != nil {
		return err
	}
	plan, err := decodeManagementPlan(raw, product, "init", strings.TrimPrefix(key, prefix))
	if err != nil {
		return err
	}
	plan, err = initializationPlanTx(ctx, tx, product, plan.ID, plan.Digest)
	if err != nil {
		return err
	}
	if m.ActiveRevision != "" || m.BundleDigest != plan.Snapshot.BundleDigest || m.Paths != plan.Snapshot.Paths || m.Identities != plan.Snapshot.Identities || m.Budget != plan.Snapshot.Budget {
		return errors.New("initialization pending revision cannot rebind original installation authority")
	}
	if err = validateInitializationRevisionTx(ctx, tx, plan, revision); err != nil {
		return err
	}
	base, _, _, err := initializationPlanData(plan)
	if err != nil {
		return err
	}
	receipt := initializationPendingReceipt{PlanID: plan.ID, PlanDigest: plan.Digest, BaseConfigDigest: provision.Digest(base), RevisionID: revision.ID, ConfigDigest: revision.ConfigDigest, BundleDigest: revision.BundleDigest}
	receiptKey := "initialization_pending:" + plan.ID
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", receiptKey).Scan(&raw)
	if err == nil {
		var old initializationPendingReceipt
		if err = gvxcontract.DecodeStrict(raw, 64<<10, 8, &old); err != nil {
			return err
		}
		if old.PlanID != receipt.PlanID || old.PlanDigest != receipt.PlanDigest || old.BaseConfigDigest != receipt.BaseConfigDigest || old.BundleDigest != receipt.BundleDigest || m.PendingRevision != old.RevisionID {
			return errors.New("initialization pending receipt base identity changed")
		}
		if old.RevisionID != receipt.RevisionID && (old.RevisionID != plan.ID || plan.Phase != "APPROVED" || receipt.RevisionID == plan.ID) {
			return errors.New("approved final initialization revision cannot be replaced")
		}
		if old.RevisionID == receipt.RevisionID && old != receipt {
			return errors.New("initialization pending immutable revision changed")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if revision.ID != plan.ID || m.PendingRevision != "" && m.PendingRevision != plan.ID {
			return errors.New("final initialization revision lacks original pending receipt")
		}
	} else {
		return err
	}
	raw, err = json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", receiptKey, raw)
	return err
}

// ResumeInitialization is deliberately separate from normal release recovery.
// It cannot activate a release, adopt new approval, clear pending state, recreate
// native objects, or restore a generation that has entered retirement.
func (s *Store) ResumeInitialization(ctx context.Context, planID, digest string, e CleanupEvidence) error {
	if err := validateCleanup(e); err != nil {
		return err
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		if m.State != "RECOVERY_REQUIRED" || m.DesiredRunState != "STOPPED" || m.ActiveRevision != "" {
			return errors.New("initialization recovery requires stopped recovery state without active release")
		}
		plan, err := initializationPlanTx(ctx, tx, s.productID, planID, digest)
		if err != nil {
			return err
		}
		if m.Paths != plan.Snapshot.Paths || m.Identities != plan.Snapshot.Identities || m.Budget != plan.Snapshot.Budget || m.BundleDigest != plan.Snapshot.BundleDigest {
			return errors.New("initialization recovery cannot change original approved installation")
		}
		var unfinished int
		if err = tx.QueryRowContext(ctx, `SELECT
   (SELECT count(*) FROM instances WHERE cleanup!='COMPLETE')+
   (SELECT count(*) FROM create_submissions WHERE state='SUBMITTED')+
   (SELECT count(*) FROM runtime_epochs WHERE state NOT IN ('DEAD','REVOKED'))+
   (SELECT count(*) FROM storage_claims WHERE kind IN ('scratch','preparation') AND state!='RELEASED')+
   (SELECT count(*) FROM generation_references WHERE kind IN ('live','preparation'))`).Scan(&unfinished); err != nil {
			return err
		}
		if unfinished != 0 {
			return ErrCleanupIncomplete
		}
		var retired int
		if err = tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM metadata WHERE substr(key,1,20)='retiring_generation:')+(SELECT count(*) FROM storage_claims WHERE kind IN ('native-app','persistent','source','cache') AND state!='RESERVED')").Scan(&retired); err != nil {
			return err
		}
		if retired != 0 {
			return errors.New("initialization recovery cannot resurrect retired data or generations")
		}
		rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger")
		if err != nil {
			return err
		}
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			var record ProvisionRecord
			if err = decodeProvisionRecord(raw, &record); err != nil {
				rows.Close()
				return err
			}
			var desired ProvisionProperties
			if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
				rows.Close()
				return err
			}
			if desired.Source == "remove" {
				rows.Close()
				return errors.New("initialization approval cannot adopt retired provision objects")
			}
			if record.Kind == "unit" && record.CleanupState != "COMPLETE" && (desired.Name != "" || desired.Unit != nil) {
				rows.Close()
				return ErrCleanupIncomplete
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		var raw []byte
		receiptErr := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "initialization_pending:"+plan.ID).Scan(&raw)
		if m.PendingRevision == "" {
			if plan.Phase != "APPROVED" || !errors.Is(receiptErr, sql.ErrNoRows) {
				return errors.New("initialization pending identity was lost")
			}
		} else {
			if receiptErr != nil {
				return receiptErr
			}
			var receipt initializationPendingReceipt
			if err = gvxcontract.DecodeStrict(raw, 64<<10, 8, &receipt); err != nil {
				return err
			}
			base, _, _, err := initializationPlanData(plan)
			if err != nil {
				return err
			}
			if receipt.PlanID != plan.ID || receipt.PlanDigest != plan.Digest || receipt.BaseConfigDigest != provision.Digest(base) || receipt.RevisionID != m.PendingRevision || receipt.BundleDigest != m.BundleDigest {
				return errors.New("initialization pending revision differs from original durable receipt")
			}
			if err = tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", m.PendingRevision).Scan(&raw); err != nil {
				return err
			}
			var revision RevisionRecord
			if err = gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &revision); err != nil {
				return err
			}
			if revision.ID != receipt.RevisionID || revision.ConfigDigest != receipt.ConfigDigest {
				return errors.New("initialization immutable pending config identity changed")
			}
			if err = validateInitializationRevisionTx(ctx, tx, plan, revision); err != nil {
				return err
			}
			if err = retainRevisionTx(ctx, tx, revision); err != nil {
				return err
			}
		}
		for _, generation := range plan.RetainedGenerations {
			if err = checkGenerationAvailableTx(ctx, tx, generation); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM metadata WHERE key='recovery_reason'"); err != nil {
			return err
		}
		m.State = "PROVISIONING"
		return nil
	})
}
