//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

// This interface is shared by passive planning and lease-held execution. Neither
// path can turn installed-bundle Configure into candidate-bundle authority.
type reacquisitionMetadata interface {
	Image(context.Context, string) (provision.ImageRecord, error)
	PreparedImageBinding(context.Context, string) (host.ApprovedImageBinding, error)
	ImagePreparationInput(context.Context, string) (provision.ApprovedImageInput, error)
	CacheForImage(context.Context, string, string) (host.CacheGeneration, error)
	ObjectProvisions(context.Context, string, string) ([]host.ProvisionRecord, error)
	PendingProvisions(context.Context) ([]host.ProvisionRecord, error)
	Provision(context.Context, string) (host.ProvisionRecord, error)
	StorageGeneration(context.Context, string) (string, error)
	RequirePreparationWriterDomain(context.Context, host.ImageSpace) error
	LegacyAcquisitionQuarantine(context.Context, string, string) (host.LegacyAcquisitionQuarantineRecord, bool, error)
	ManagementPlans(context.Context, string) ([]host.ManagementPlanRecord, error)
}

type selectedReacquisition struct {
	plan    ApprovedPreparationPlan
	receipt operatorPreparationReceipt
	binding host.ApprovedImageBinding
}

// Resolve only immutable quarantine receipts for the original base binding.
// Re-deriving today's quarantine set would break replay after activation.
func quarantinedUpdateBinding(ctx context.Context, metadata reacquisitionMetadata, records []host.ProvisionRecord, binding host.ApprovedImageBinding) (host.LegacyAcquisitionQuarantineRecord, bool, error) {
	var found host.LegacyAcquisitionQuarantineRecord
	matched := false
	for _, record := range records {
		if record.Kind != "image" || record.State != "OBSERVED" {
			continue
		}
		var published host.ProvisionProperties
		if err := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &published); err != nil {
			return found, false, err
		}
		if published.Digest != binding.ImageRecordID {
			continue
		}
		receipt, exists, err := metadata.LegacyAcquisitionQuarantine(ctx, "image", record.Identity)
		if err != nil {
			return found, false, err
		}
		if !exists {
			continue
		}
		if receipt.Lineage.Kind != "image" || receipt.Lineage.ImageRecordID != binding.ImageRecordID || !provision.ValidDigest(receipt.QuarantineSetDigest) {
			return found, false, errors.New("quarantine receipt differs from original update image")
		}
		if matched && (found.PlanID != receipt.PlanID || found.PlanDigest != receipt.PlanDigest || found.QuarantineSetDigest != receipt.QuarantineSetDigest || found.Lineage.JobID != receipt.Lineage.JobID) {
			return found, false, errors.New("ambiguous original update image quarantine")
		}
		found, matched = receipt, true
	}
	return found, matched, nil
}

func committedReacquisitionPlans(records []host.ManagementPlanRecord) ([]struct {
	plan    ApprovedPreparationPlan
	receipt operatorPreparationReceipt
}, error) {
	var result []struct {
		plan    ApprovedPreparationPlan
		receipt operatorPreparationReceipt
	}
	for _, record := range records {
		if record.Phase != "COMMITTED" {
			continue
		}
		var plan ApprovedPreparationPlan
		if err := gvxcontract.DecodeStrict(record.Plan, 32<<20, 32, &plan); err != nil {
			return nil, err
		}
		if plan.Reacquisition == nil {
			continue
		}
		digest, err := PreparationPlanDigest(plan)
		if err != nil || record.Kind != "operator-preparation" || record.ID != plan.PlanID || record.Digest != plan.PlanDigest || digest != plan.PlanDigest || !validID(plan.PlanID) || plan.Input.Validate() != nil {
			return nil, errors.New("committed preparation approval is inconsistent")
		}
		var receipt operatorPreparationReceipt
		if err = gvxcontract.DecodeStrict(record.State, 1<<20, 16, &receipt); err != nil {
			return nil, err
		}
		if !provision.ValidDigest(receipt.PreparationBundleDigest) || receipt.PreparationBundleDigest != plan.PreparationBundleDigest {
			return nil, errors.New("committed reacquisition receipt is inconsistent")
		}
		if receipt.Failure != "" {
			if receipt.ImageID != "" || receipt.CacheID != "" {
				return nil, errors.New("committed reacquisition failure receipt contains outputs")
			}
			// COMMITTED also records successful cleanup of a failed preparation.
			// It preserves history but supplies no replacement authority.
			continue
		}
		if !provision.ValidDigest(receipt.ImageID) || !provision.ValidDigest(receipt.CacheID) {
			return nil, errors.New("committed reacquisition receipt is inconsistent")
		}
		result = append(result, struct {
			plan    ApprovedPreparationPlan
			receipt operatorPreparationReceipt
		}{plan, receipt})
	}
	return result, nil
}

// A nil explicit list is unique automatic planning; execution always supplies a
// non-nil list, including an empty one, and never substitutes another approval.
func selectUpdateReacquisitions(ctx context.Context, metadata reacquisitionMetadata, installation RuntimeInstallationID, previous host.RevisionRecord, bundleDigest string, explicit []ReacquiredPreparation) ([]ReacquiredPreparation, []selectedReacquisition, error) {
	records, err := metadata.ManagementPlans(ctx, "operator-preparation")
	if err != nil {
		return nil, nil, err
	}
	plans, err := committedReacquisitionPlans(records)
	if err != nil {
		return nil, nil, err
	}
	publications, err := metadata.PendingProvisions(ctx)
	if err != nil {
		return nil, nil, err
	}
	used := make(map[string]bool, len(explicit))
	var refs []ReacquiredPreparation
	var selected []selectedReacquisition
	for _, old := range previous.Images {
		quarantine, quarantined, err := quarantinedUpdateBinding(ctx, metadata, publications, old)
		if err != nil {
			return nil, nil, err
		}
		if !quarantined {
			continue
		}
		var requested *ReacquiredPreparation
		if explicit != nil {
			for index := range explicit {
				ref := &explicit[index]
				if ref.ModuleID != old.ModuleID {
					continue
				}
				if requested != nil || ref.PreviousImageRecordID != old.ImageRecordID {
					return nil, nil, errors.New("duplicate or mismatched update replacement selection")
				}
				requested = ref
			}
			if requested == nil {
				return nil, nil, errors.New("update omits a quarantined active image replacement")
			}
		}
		var match *selectedReacquisition
		var reference ReacquiredPreparation
		for _, candidate := range plans {
			plan := candidate.plan
			q := plan.Reacquisition
			if plan.InstallationID != installation || plan.ExpectedActiveRevision != previous.ID || plan.Input.ModuleID != old.ModuleID || q.ReplacesImageRecordID != old.ImageRecordID || q.QuarantineSetDigest != quarantine.QuarantineSetDigest || plan.PreparationBundleDigest != bundleDigest {
				continue
			}
			if q.Version != 1 || q.RequiredWriterDomainVersion != gvxcontract.PreparationWriterDomainVersion {
				return nil, nil, errors.New("unsupported reacquisition writer authority")
			}
			if requested != nil && (requested.PreparationPlanID != plan.PlanID || requested.PreparationPlanDigest != plan.PlanDigest) {
				continue
			}
			if match != nil {
				return nil, nil, errors.New("ambiguous committed reacquisition; explicitly select an approved preparation plan")
			}
			binding, err := inspectCandidatePreparation(ctx, metadata, plan, candidate.receipt, bundleDigest)
			if err != nil {
				return nil, nil, err
			}
			match = &selectedReacquisition{plan: plan, receipt: candidate.receipt, binding: binding}
			reference = ReacquiredPreparation{ModuleID: old.ModuleID, PreviousImageRecordID: old.ImageRecordID, PreparationPlanID: plan.PlanID, PreparationPlanDigest: plan.PlanDigest}
		}
		if match == nil {
			return nil, nil, errors.New("no exact committed reacquisition for quarantined active image and candidate bundle")
		}
		if used[old.ModuleID] {
			return nil, nil, errors.New("duplicate active module replacement")
		}
		used[old.ModuleID] = true
		refs, selected = append(refs, reference), append(selected, *match)
	}
	if explicit != nil && len(refs) != len(explicit) {
		return nil, nil, errors.New("update selection includes an unrelated preparation")
	}
	return refs, selected, nil
}

// Change only the selected image and its reviewed provenance. All workload
// documents, grants, identities, limits and secret bindings remain unchanged.
func reacquiredUpdateConfig(raw []byte, bundleDigest string, selected []selectedReacquisition) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	var hostDocument map[string]json.RawMessage
	if err := json.Unmarshal(document["host"], &hostDocument); err != nil {
		return nil, err
	}
	hostDocument["bundle_digest"], _ = json.Marshal(bundleDigest)
	var err error
	document["host"], err = json.Marshal(hostDocument)
	if err != nil {
		return nil, err
	}
	if len(selected) != 0 {
		var modules []map[string]json.RawMessage
		if err = json.Unmarshal(document["modules"], &modules); err != nil {
			return nil, err
		}
		for _, replacement := range selected {
			count := 0
			for _, module := range modules {
				var id string
				if err = json.Unmarshal(module["module_id"], &id); err != nil {
					return nil, err
				}
				if id != replacement.binding.ModuleID {
					continue
				}
				count++
				module["image"], _ = json.Marshal(replacement.binding.ImageSelector)
				module["config_revision"], _ = json.Marshal(replacement.binding.ConfigRevision)
				module["approval_revision"], _ = json.Marshal(replacement.binding.ApprovalRevision)
			}
			if count != 1 {
				return nil, errors.New("replacement module is missing or ambiguous in full configuration")
			}
		}
		document["modules"], err = json.Marshal(modules)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(document)
}

func applyReacquiredBindings(previous []host.ApprovedImageBinding, selected []selectedReacquisition) []host.ApprovedImageBinding {
	bindings := append([]host.ApprovedImageBinding(nil), previous...)
	for index := range bindings {
		for _, replacement := range selected {
			if bindings[index].ModuleID == replacement.binding.ModuleID {
				bindings[index] = replacement.binding
			}
		}
	}
	return bindings
}

func validateReacquiredCandidate(previous, candidate host.RevisionRecord, selected []selectedReacquisition) error {
	if len(selected) == 0 {
		return nil
	}
	expected := applyReacquiredBindings(previous.Images, selected)
	if len(expected) != len(candidate.Images) {
		return errors.New("reacquisition update cannot remove intended modules")
	}
	for index := range expected {
		if expected[index] != candidate.Images[index] {
			return errors.New("candidate differs from exact selected replacement bindings")
		}
	}
	raw, err := reacquiredUpdateConfig(previous.Config, candidate.BundleDigest, selected)
	if err != nil {
		return err
	}
	canonical := func(raw []byte) ([]byte, error) {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		return json.Marshal(value)
	}
	expectedConfig, err := canonical(raw)
	if err != nil {
		return err
	}
	actualConfig, err := canonical(candidate.Config)
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedConfig, actualConfig) {
		return errors.New("reacquisition update changes unrelated configuration or workload authority")
	}
	return nil
}

// The normal manager performs native verification; identity comparisons here
// additionally pin the result to the immutable selected preparation receipt.
func verifyReacquiredCaches(ctx context.Context, images interface {
	LookupPreparedImage(context.Context, provision.ApprovedImageInput) (provision.ImageRecord, host.CacheGeneration, bool, error)
}, selected []selectedReacquisition) error {
	for _, replacement := range selected {
		image, cache, found, err := images.LookupPreparedImage(ctx, replacement.plan.Input)
		if err != nil {
			return err
		}
		if !found || image.ID != replacement.receipt.ImageID || cache.ID != replacement.receipt.CacheID || cache.BundleDigest != replacement.plan.PreparationBundleDigest {
			return errors.New("replacement cache differs from selected committed preparation receipt")
		}
	}
	return nil
}
