//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

type ApprovedPreparationPlan struct {
	PlanID                  string                       `json:"plan_id"`
	PlanDigest              string                       `json:"plan_digest"`
	InstallationID          RuntimeInstallationID        `json:"installation_id"`
	ExpectedActiveRevision  string                       `json:"expected_active_revision"`
	Input                   provision.ApprovedImageInput `json:"input"`
	PreparationBundleDigest string                       `json:"preparation_bundle_digest"`
	Reacquisition           *host.OperatorReacquisition  `json:"reacquisition,omitempty"`
}

type operatorPreparationReceipt struct {
	ImageID                 string `json:"image_id,omitempty"`
	CacheID                 string `json:"cache_id,omitempty"`
	PreparationBundleDigest string `json:"preparation_bundle_digest"`
	Failure                 string `json:"failure,omitempty"`
}

func checkedOperatorPreparationReceipt(record host.ManagementPlanRecord, plan ApprovedPreparationPlan) (operatorPreparationReceipt, error) {
	var receipt operatorPreparationReceipt
	switch record.Phase {
	case "APPROVED":
		if len(record.State) != 0 {
			return receipt, errors.New("unprepared operator transaction has a completion receipt")
		}
		return receipt, nil
	case "PREPARED", "COMMITTED", "FAILED_CLEAN":
		if e := gvxcontract.DecodeStrict(record.State, 1<<20, 16, &receipt); e != nil {
			return receipt, e
		}
	default:
		return receipt, errors.New("unsupported operator preparation transaction phase")
	}
	if receipt.PreparationBundleDigest != plan.PreparationBundleDigest {
		return receipt, errors.New("operator preparation receipt differs from reviewed helper bundle")
	}
	if receipt.Failure != "" {
		if record.Phase == "PREPARED" || receipt.ImageID != "" || receipt.CacheID != "" {
			return receipt, errors.New("operator preparation failure receipt is inconsistent")
		}
		if record.Phase == "COMMITTED" {
			return receipt, errors.New("operator preparation previously failed; a new approval and job are required")
		}
	} else if record.Phase == "FAILED_CLEAN" || !provision.ValidDigest(receipt.ImageID) || !provision.ValidDigest(receipt.CacheID) {
		return receipt, errors.New("operator preparation completion receipt is inconsistent")
	}
	return receipt, nil
}

func PreparationPlanDigest(plan ApprovedPreparationPlan) (string, error) {
	return approvalDigest("chatanium-operator-preparation-plan-v1", plan, "plan_digest")
}

func PlanImagePreparation(ctx context.Context, id RuntimeInstallationID, input provision.ApprovedImageInput) (ApprovedPreparationPlan, error) {
	var plan ApprovedPreparationPlan
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return plan, e
	}
	defer metadata.Close()
	m, e := metadata.Installation(ctx)
	if e != nil {
		return plan, e
	}
	if (m.State != "READY" && m.State != "RECOVERY_REQUIRED") || m.DesiredRunState != "STOPPED" || m.PendingRevision != "" {
		return plan, errors.New("operator preparation requires a stopped committed installation")
	}
	if input.JobID != "" {
		records, e := metadata.ManagementPlans(ctx, "operator-preparation")
		if e != nil {
			return plan, e
		}
		plan, e = operatorPreparationReplayPlan(records, input)
		if e != nil {
			return plan, e
		}
		if plan.InstallationID != id || plan.ExpectedActiveRevision != m.ActiveRevision {
			return plan, errors.New("operator preparation stopped revision changed")
		}
		return plan, nil
	}
	if input.ConfigRevision != "" || input.ApprovalRevision != "" {
		return plan, errors.New("operator preparation reservations are root-derived")
	}
	plan = ApprovedPreparationPlan{PlanID: newID(), InstallationID: id, ExpectedActiveRevision: m.ActiveRevision}
	source, e := configuredSource()
	if e != nil {
		return plan, e
	}
	raw, e := source.Manifest()
	if e != nil {
		return plan, e
	}
	manifest, e := bundle.VerifyManifest(raw)
	if e != nil {
		return plan, e
	}
	if !compatibleBundle(manifest, m) {
		return plan, errors.New("preparation bundle is not installation-compatible")
	}
	plan.PreparationBundleDigest = manifest.Digest
	set, e := metadata.LegacyAcquisitionQuarantineSet(ctx)
	if e != nil {
		return plan, e
	}
	revision, e := metadata.Revision(ctx, m.ActiveRevision)
	if e != nil {
		return plan, e
	}
	plan.Reacquisition, e = plannedOperatorReacquisition(m, set, revision, input.ModuleID)
	if e != nil {
		return plan, e
	}
	input.ConfigRevision, input.ApprovalRevision, input.JobID = newID(), newID(), newID()
	if input.Platform == "" {
		input.Platform = "linux/amd64"
	}
	if input.SourceKind == "" {
		input.SourceKind = "registry"
	}
	available, e := metadata.AvailablePreparationStorage(ctx)
	if e != nil {
		return plan, e
	}
	maximum := maximumPreparationLimits(m)
	if input.Limits == (provision.PrepareLimits{}) {
		input.Limits, e = FitPreparationLimits(maximum, m.Budget, available)
		if e != nil {
			return plan, e
		}
	}
	if e = checkPrepareLimits(input.Limits, maximum); e != nil {
		return plan, e
	}
	if e = checkOperatorPreparationStorage(input.Limits, available); e != nil {
		return plan, e
	}
	if e = input.Validate(); e != nil {
		return plan, e
	}
	plan.Input = input
	plan.PlanDigest, e = PreparationPlanDigest(plan)
	return plan, e
}

func plannedOperatorReacquisition(m host.InstallationManifest, set host.LegacyQuarantineSet, revision host.RevisionRecord, moduleID string) (*host.OperatorReacquisition, error) {
	if len(set.Lineages) == 0 {
		if m.State != "READY" {
			return nil, errors.New("recovery-required preparation requires exact legacy quarantine authority")
		}
		return nil, nil
	}
	if set.Version != 1 || set.InstallationID != m.RuntimeInstallationID || set.ActiveRevision != m.ActiveRevision || revision.ID != m.ActiveRevision ||
		!provision.ValidDigest(set.Digest) || set.RequiredWriterDomainVersion != gvxcontract.PreparationWriterDomainVersion {
		return nil, errors.New("legacy quarantine set differs from the stopped installation")
	}
	reacquisition := &host.OperatorReacquisition{Version: set.Version, ExpectedState: m.State, QuarantineSetDigest: set.Digest, RequiredWriterDomainVersion: set.RequiredWriterDomainVersion}
	for _, binding := range revision.Images {
		if binding.ModuleID != moduleID {
			continue
		}
		for _, lineage := range set.Lineages {
			if lineage.Kind != "image" || lineage.ImageRecordID != binding.ImageRecordID {
				continue
			}
			if reacquisition.ReplacesImageRecordID != "" {
				return nil, errors.New("ambiguous legacy image replacement")
			}
			reacquisition.ReplacesImageRecordID = binding.ImageRecordID
		}
	}
	return reacquisition, nil
}

func validateOperatorPreparationPlan(plan ApprovedPreparationPlan) error {
	digest, e := PreparationPlanDigest(plan)
	if e != nil || digest != plan.PlanDigest || !validID(plan.PlanID) || plan.ExpectedActiveRevision == "" || !provision.ValidDigest(plan.PreparationBundleDigest) {
		return errors.New("operator preparation approval differs from reviewed plan")
	}
	if e = plan.Input.Validate(); e != nil {
		return e
	}
	if r := plan.Reacquisition; r != nil {
		if r.Version != 1 || r.RequiredWriterDomainVersion != gvxcontract.PreparationWriterDomainVersion ||
			(r.ExpectedState != "READY" && r.ExpectedState != "RECOVERY_REQUIRED") || !provision.ValidDigest(r.QuarantineSetDigest) ||
			r.ReplacesImageRecordID != "" && !provision.ValidDigest(r.ReplacesImageRecordID) {
			return errors.New("invalid reviewed operator reacquisition authority")
		}
	}
	return nil
}

// Select the reviewed helper closure under the same owner/lease and early native
// recovery prerequisites as ordinary maintenance, before any image recovery.
func preparationMaintenance(ctx context.Context, id RuntimeInstallationID, plan ApprovedPreparationPlan) (*ownedSession, bundle.Verified, error) {
	var selected bundle.Verified
	session, e := openOwnerWithBundle(ctx, id, Foreground, false, func(ctx context.Context, store *host.Store, m host.InstallationManifest) (bundle.Verified, error) {
		if m.ActiveRevision != plan.ExpectedActiveRevision || m.DesiredRunState != "STOPPED" || m.PendingRevision != "" ||
			m.State != "READY" && (plan.Reacquisition == nil || m.State != "RECOVERY_REQUIRED") {
			return selected, errors.New("operator preparation stopped revision changed")
		}
		source, e := configuredSource()
		if e != nil {
			return selected, e
		}
		raw, e := source.Manifest()
		if e != nil {
			return selected, e
		}
		manifest, e := bundle.VerifyManifest(raw)
		if e != nil || manifest.Digest != plan.PreparationBundleDigest {
			return selected, errors.New("preparation bundle differs from executing launcher's verified source")
		}
		if !compatibleBundle(manifest, m) {
			return selected, errors.New("preparation bundle is not installation-compatible")
		}
		if e = store.CheckGenerationAvailable(ctx, manifest.Digest); e != nil {
			return selected, e
		}
		selected, e = publishUpdateBundle(ctx, &ownedSession{manifest: m, store: store}, source, manifest)
		if e == nil && selected.Digest != plan.PreparationBundleDigest {
			return bundle.Verified{}, errors.New("published preparation bundle differs from reviewed source")
		}
		return selected, e
	})
	return session, selected, e
}

// A retry selects the durable approval, never a new job or credential identity.
func operatorPreparationReplayPlan(records []host.ManagementPlanRecord, input provision.ApprovedImageInput) (ApprovedPreparationPlan, error) {
	var found ApprovedPreparationPlan
	for _, record := range records {
		var plan ApprovedPreparationPlan
		if e := gvxcontract.DecodeStrict(record.Plan, 32<<20, 32, &plan); e != nil {
			return found, e
		}
		if plan.Input.JobID != input.JobID {
			continue
		}
		if record.Kind != "operator-preparation" || record.ID != plan.PlanID || record.Digest != plan.PlanDigest || validateOperatorPreparationPlan(plan) != nil {
			return found, errors.New("operator preparation durable approval is inconsistent")
		}
		if _, e := checkedOperatorPreparationReceipt(record, plan); e != nil {
			return found, e
		}
		saved := plan.Input
		if input.ModuleID != "" && input.ModuleID != saved.ModuleID ||
			input.SourceKind != "" && input.SourceKind != saved.SourceKind ||
			input.SourceRef != "" && input.SourceRef != saved.SourceRef ||
			input.ArchiveDigest != "" && input.ArchiveDigest != saved.ArchiveDigest ||
			input.CredentialRef != "" && input.CredentialRef != saved.CredentialRef ||
			input.ConfigRevision != "" && input.ConfigRevision != saved.ConfigRevision ||
			input.ApprovalRevision != "" && input.ApprovalRevision != saved.ApprovalRevision ||
			input.Platform != "" && input.Platform != saved.Platform ||
			input.Limits != (provision.PrepareLimits{}) && input.Limits != saved.Limits {
			return found, errors.New("operator preparation retry differs from its exact approved input")
		}
		if found.PlanID != "" {
			return found, errors.New("ambiguous operator preparation job identity")
		}
		found = plan
	}
	if found.PlanID == "" {
		return found, errors.New("unknown operator preparation job; new reservations are root-derived")
	}
	return found, nil
}

func checkOperatorPreparationStorage(l provision.PrepareLimits, available host.StorageBudget) error {
	if e := l.Validate(); e != nil {
		return e
	}
	if l.InputBytes%4096 != 0 || l.OutputBytes%4096 != 0 || l.ExpandedBytes%4096 != 0 ||
		l.InputBytes > available.SourceBytes/2 || l.OutputBytes > available.CacheBytes ||
		l.OutputBytes > available.PreparationBytes || l.ExpandedBytes > available.PreparationBytes-l.OutputBytes ||
		l.Inodes > available.SourceInodes || l.Inodes > available.CacheInodes || l.Inodes > available.PreparationInodes {
		return errors.New("preparation exceeds exact remaining source/cache/work peak reservation")
	}
	return nil
}

func PrepareOperatorImageWithInput(ctx context.Context, id RuntimeInstallationID, plan ApprovedPreparationPlan, archive, credential io.ReadCloser) (image provision.ImageRecord, retErr error) {
	inputs := &taskInputs{archive: ownInputStream(archive), credential: ownInputStream(credential)}
	defer closeTaskInputs(inputs)
	cancelInput := context.AfterFunc(ctx, func() { closeTaskInputs(inputs) })
	defer cancelInput()
	if e := rootRequired(); e != nil {
		return image, e
	}
	if plan.InstallationID != id {
		return image, errors.New("operator preparation belongs to another installation")
	}
	if e := validateOperatorPreparationPlan(plan); e != nil {
		return image, e
	}
	session, verified, e := preparationMaintenance(ctx, id, plan)
	if e != nil {
		return image, e
	}
	defer func() { retErr = errors.Join(retErr, closeMaintenance(session)) }()
	m, e := session.store.Installation(ctx)
	if e != nil {
		return image, e
	}
	if m.DesiredRunState != "STOPPED" || m.PendingRevision != "" || m.ActiveRevision != plan.ExpectedActiveRevision ||
		m.State != "READY" && (plan.Reacquisition == nil || m.State != "RECOVERY_REQUIRED") {
		return image, errors.New("operator preparation stopped revision changed")
	}
	if e = session.store.AssertRemovable(ctx); e != nil {
		return image, e
	}
	if e = checkPrepareLimits(plan.Input.Limits, maximumPreparationLimits(m)); e != nil {
		return image, e
	}
	raw, e := json.Marshal(plan)
	if e != nil {
		return image, e
	}
	transaction, e := session.store.ManagementPlan(ctx, "operator-preparation", plan.PlanID)
	if errors.Is(e, sql.ErrNoRows) {
		available, e := session.store.AvailablePreparationStorage(ctx)
		if e != nil {
			return image, e
		}
		if e = checkOperatorPreparationStorage(plan.Input.Limits, available); e != nil {
			return image, e
		}
		transaction = host.ManagementPlanRecord{Kind: "operator-preparation", ID: plan.PlanID, Digest: plan.PlanDigest, Plan: raw, Snapshot: m, Phase: "APPROVED"}
		if plan.Reacquisition != nil {
			e = session.store.BeginOperatorReacquisition(ctx, transaction)
		} else {
			e = session.store.BeginManagementPlan(ctx, transaction)
		}
		if e != nil {
			return image, e
		}
	} else if e != nil {
		return image, e
	} else if transaction.Digest != plan.PlanDigest || !bytes.Equal(transaction.Plan, raw) {
		return image, errors.New("operator preparation differs from durable approved transaction")
	}
	phase := transaction.Phase
	receipt, e := checkedOperatorPreparationReceipt(transaction, plan)
	if e != nil {
		return image, e
	}
	// An attach failure can still have native effects. Only real complete cleanup
	// evidence may settle the durable transaction, including the failure path.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		var cleanupErr error
		if session.images != nil {
			cleanupErr = session.images.Recover(cleanup)
		}
		var proof host.CleanupEvidence
		if session.storage != nil {
			quota, qe := session.storage.ReclaimEvidence(cleanup)
			cleanupErr = errors.Join(cleanupErr, qe, session.storage.Close())
			proof.QuotaReclaimed = quota.QuotaReclaimed
		}
		native, ne := session.systemd.RecoverHelpers(cleanup)
		cleanupErr = errors.Join(cleanupErr, ne)
		native.QuotaReclaimed = proof.QuotaReclaimed
		if cleanupErr == nil {
			cleanupErr = host.DetachBacking(cleanup, m, session.store, session.systemd, native)
		}
		if cleanupErr == nil {
			cleanupErr = completeEvidence(cleanup, m, &native)
		}
		session.cleanupEvidence = native
		if cleanupErr == nil && phase != "COMMITTED" {
			if retErr != nil && phase == "APPROVED" {
				state, se := json.Marshal(operatorPreparationReceipt{PreparationBundleDigest: verified.Digest, Failure: "PREPARATION_FAILED"})
				cleanupErr = se
				if cleanupErr == nil {
					cleanupErr = session.store.AdvanceManagementPlanState(cleanup, "operator-preparation", plan.PlanID, plan.PlanDigest, phase, "FAILED_CLEAN", state)
					phase = "FAILED_CLEAN"
				}
			}
			if cleanupErr == nil && (retErr == nil || phase == "FAILED_CLEAN") {
				cleanupErr = session.store.CompleteManagementPlan(cleanup, "operator-preparation", plan.PlanID, plan.PlanDigest, phase, native)
			}
		}
		retErr = errors.Join(retErr, cleanupErr)
	}()
	if e = host.AttachBacking(ctx, m, session.store, session.systemd); e != nil {
		return image, e
	}
	storage, e := host.NewStorage(ctx, supervisorConfig(m, session.config), session.store, session.systemd)
	if e != nil {
		return image, e
	}
	session.storage = storage
	manager, e := host.NewImageManager(imageConfig(m, verified, session.owner, privateTaskInput), session.store, session.systemd, storage)
	if e != nil {
		return image, e
	}
	session.images = manager
	if phase == "APPROVED" || phase == "FAILED_CLEAN" {
		if e = manager.Recover(ctx); e != nil {
			return image, e
		}
	}
	if phase == "FAILED_CLEAN" {
		return image, errors.New("operator preparation previously failed; a new approval and job are required")
	}
	image, cache, found, e := manager.LookupPreparedImage(ctx, plan.Input)
	if e != nil {
		return image, e
	}
	if !found {
		if phase != "APPROVED" {
			return image, errors.New("completed operator preparation has no retained committed job")
		}
		available, e := session.store.AvailablePreparationStorage(ctx)
		if e != nil {
			return image, e
		}
		if e = checkOperatorPreparationStorage(plan.Input.Limits, available); e != nil {
			return image, e
		}
		if _, e = manager.PrepareImage(context.WithValue(ctx, taskKey{}, inputs), plan.Input); e != nil {
			return image, e
		}
		image, cache, found, e = manager.LookupPreparedImage(ctx, plan.Input)
		if e != nil {
			return image, e
		}
		if !found {
			return image, errors.New("preparation returned without its retained committed job")
		}
	}
	if cache.BundleDigest != verified.Digest || verified.Digest != plan.PreparationBundleDigest {
		return image, errors.New("committed preparation cache differs from reviewed helper bundle")
	}
	selector := image.SourceRef
	if image.SourceKind != "registry" {
		selector = "record:" + image.ID
	}
	binding := host.ApprovedImageBinding{ModuleID: plan.Input.ModuleID, ConfigRevision: plan.Input.ConfigRevision, ApprovalRevision: plan.Input.ApprovalRevision, ImageRecordID: image.ID, ImageSelector: selector}
	if phase != "APPROVED" {
		if receipt.ImageID != image.ID || receipt.CacheID != cache.ID {
			return image, errors.New("operator preparation receipt differs from retained committed record or cache")
		}
		saved, e := session.store.PreparedImageBinding(ctx, image.ID)
		if e != nil {
			return image, e
		}
		if saved != binding {
			return image, errors.New("operator preparation retained provenance changed")
		}
		return image, nil
	}
	if e = session.store.BindPreparedImage(ctx, binding); e != nil {
		return image, e
	}
	state, e := json.Marshal(operatorPreparationReceipt{ImageID: image.ID, CacheID: cache.ID, PreparationBundleDigest: verified.Digest})
	if e != nil {
		return image, e
	}
	if e = session.store.AdvanceManagementPlanState(ctx, "operator-preparation", plan.PlanID, plan.PlanDigest, "APPROVED", "PREPARED", state); e != nil {
		return image, e
	}
	phase = "PREPARED"
	return image, nil
}
