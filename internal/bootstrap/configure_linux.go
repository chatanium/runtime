//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
)

// ApprovedConfigurePlan replaces only configuration, never the installed release.
type ApprovedConfigurePlan struct {
	InstallationID         RuntimeInstallationID               `json:"installation_id"`
	PlanID                 string                              `json:"plan_id"`
	PlanDigest             string                              `json:"plan_digest"`
	ExpectedActiveRevision string                              `json:"expected_active_revision"`
	BaseConfig             []byte                              `json:"base_config"`
	Modules                []InitModuleInput                   `json:"modules"`
	Objects                []ApprovedObject                    `json:"objects"`
	SecretSources          []SecretSource                      `json:"secret_sources"`
	SecretObservations     []SecretSourceObservation           `json:"secret_observations"`
	NetworkPrerequisites   host.NetworkPrerequisiteObservation `json:"network_prerequisites"`
}

func ConfigurePlanDigest(p ApprovedConfigurePlan) (string, error) {
	return approvalDigest("chatanium-configure-plan-v1", p, "plan_digest")
}

// ConfigurePlan resolves committed preparation bindings before operator review.
// With modules omitted, every module in base is the desired reviewed module set.
func ConfigurePlan(ctx context.Context, id RuntimeInstallationID, base []byte, modules []InitModuleInput) (ApprovedConfigurePlan, error) {
	p := ApprovedConfigurePlan{InstallationID: id, PlanID: newID()}
	if e := rootRequired(); e != nil {
		return p, e
	}
	control, e := controlPath(id)
	if e != nil {
		return p, e
	}
	gate, e := acquireManagementGuard(ctx)
	if e != nil {
		return p, e
	}
	reader, e := host.OpenMetadata(ctx, control, string(id), gate)
	if e != nil {
		closeUnadoptedManagementGuard(gate)
		return p, e
	}
	defer reader.Close()
	m, e := reader.Installation(ctx)
	if e != nil {
		return p, e
	}
	if m.State != "READY" || m.DesiredRunState != "STOPPED" || m.PendingRevision != "" {
		return p, errors.New("configuration requires a ready stopped installation without pending cutover")
	}
	current, e := reader.Revision(ctx, m.ActiveRevision)
	if e != nil {
		return p, e
	}
	if len(base) == 0 {
		base = current.Config
	}
	cfg, e := runtime.DecodeConfig(base)
	if e != nil {
		return p, e
	}
	if e = validateConfigureHost(m, cfg, current); e != nil {
		return p, e
	}
	p.SecretSources, p.SecretObservations, p.Objects, e = configureAuthority(ctx, m, cfg)
	if e != nil {
		return p, e
	}
	if e = validateAppBudget(cfg, m.Budget, nil); e != nil {
		return p, e
	}
	p.NetworkPrerequisites, e = host.ObserveNetworkPrerequisites(ctx, networkPlanConfig(cfg))
	if e != nil {
		return p, e
	}
	p.ExpectedActiveRevision = m.ActiveRevision
	if modules == nil {
		modules = make([]InitModuleInput, 0, len(cfg.Modules))
		for _, candidate := range cfg.Modules {
			modules = append(modules, InitModuleInput{Candidate: candidate, Image: provision.ApprovedImageInput{SourceKind: "prepared", SourceRef: candidate.ImageDigest}})
		}
	}
	p.BaseConfig, e = exactConfig(base, []runtime.ModuleSpec{})
	if e != nil {
		return p, e
	}
	p.Modules = make([]InitModuleInput, 0, len(modules))
	seen := map[runtime.ModuleID]bool{}
	for _, in := range modules {
		if in.Image.SourceKind != "prepared" {
			return p, errors.New("prepare and inspect images explicitly before configuration approval")
		}
		selector := in.Image.SourceRef
		if selector == "" {
			selector = in.Candidate.ImageDigest
		}
		if provision.ValidDigest(selector) {
			selector = "record:" + selector
		}
		binding, image, e := InspectPreparedBinding(ctx, id, selector)
		if e != nil {
			return p, e
		}
		if string(in.Candidate.ModuleID) != binding.ModuleID || seen[in.Candidate.ModuleID] {
			return p, errors.New("prepared module binding differs or is duplicated")
		}
		seen[in.Candidate.ModuleID] = true
		in.Candidate.ConfigRevision = binding.ConfigRevision
		in.Candidate.ApprovalRevision = binding.ApprovalRevision
		for _, old := range current.Images {
			if old.ModuleID == binding.ModuleID {
				in.Candidate.ConfigRevision = newID()
				in.Candidate.ApprovalRevision = newID()
			}
		}
		if image.SourceKind == "registry" {
			in.Candidate.ImageDigest = image.SourceRef
		} else {
			in.Candidate.ImageDigest = "record:" + image.ID
		}
		in.Image = provision.ApprovedImageInput{SourceKind: "prepared", SourceRef: image.ID, ModuleID: binding.ModuleID, ConfigRevision: in.Candidate.ConfigRevision, ApprovalRevision: in.Candidate.ApprovalRevision}
		p.Modules = append(p.Modules, in)
	}
	if !validID(p.PlanID) {
		return p, errors.New("entropy unavailable")
	}
	p.PlanDigest, e = ConfigurePlanDigest(p)
	return p, e
}

func validateConfigureHost(m host.InstallationManifest, c runtime.Config, current host.RevisionRecord) error {
	if current.BundleDigest != m.BundleDigest || current.DevelopmentWorker != nil {
		return errors.New("configuration requires the installed release bundle")
	}
	if c.Host.RuntimeInstallationID != m.RuntimeInstallationID || c.Host.BundleDigest != m.BundleDigest || c.Host.ManagementDirectory != filepath.Join(m.Paths.StorageRoot, "app") || c.Host.StorageRoot != m.Paths.StorageRoot || c.Host.IPCRoot != filepath.Join(m.Paths.RunRoot, "instances") {
		return errors.New("configuration differs from installed host paths or bundle")
	}
	return nil
}

// ConfigureWithInputs performs stopped explicit module approval and immutable
// revision cutover. Prepared records are data, never authority to launch alone.
func ConfigureWithInputs(ctx context.Context, p ApprovedConfigurePlan, approve func(context.Context, ModuleReview) (ApprovedModuleConfig, error), inputs func(context.Context, provision.ApprovedImageInput) (io.ReadCloser, io.ReadCloser, error)) (result host.RevisionRecord, retErr error) {
	if e := rootRequired(); e != nil {
		return result, e
	}
	sum, e := ConfigurePlanDigest(p)
	if e != nil || sum != p.PlanDigest || !validID(p.PlanID) || !validID(p.ExpectedActiveRevision) {
		return result, errors.New("invalid configuration approval digest or identity")
	}
	if len(p.Modules) > 0 && approve == nil {
		return result, errors.New("explicit module approval callback required")
	}
	s, e := maintenance(ctx, p.InstallationID)
	if e != nil {
		return result, e
	}
	defer func() { retErr = errors.Join(retErr, closeMaintenance(s)) }()
	cutoverStarted := false
	defer func() {
		if retErr != nil && cutoverStarted {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			retErr = errors.Join(retErr, s.store.RequireRecovery(cleanup, "configuration cutover incomplete"))
		}
	}()
	m := s.manifest
	if m.DesiredRunState != "STOPPED" || (m.State != "READY" && m.State != "RECOVERY_REQUIRED") {
		return result, errors.New("configuration requires stopped installation")
	}
	if e = s.store.AssertRemovable(ctx); e != nil {
		return result, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return result, e
	}
	newTransaction := false
	transaction, e := s.store.ManagementPlan(ctx, "configure", p.PlanID)
	if e != nil {
		if m.ActiveRevision != p.ExpectedActiveRevision || m.PendingRevision != "" || m.State != "READY" {
			return result, errors.New("configuration base revision changed")
		}
		transaction = host.ManagementPlanRecord{Kind: "configure", ID: p.PlanID, Digest: p.PlanDigest, Plan: raw, Phase: "APPROVED"}
		newTransaction = true
	} else if transaction.Digest != p.PlanDigest || !bytes.Equal(transaction.Plan, raw) {
		return result, errors.New("configuration differs from durable approved transaction")
	}
	if transaction.Phase == "COMMITTED" {
		var saved configurationReceipt
		if e = gvxcontract.DecodeStrict(transaction.State, 1<<20, 32, &saved); e != nil {
			return result, e
		}
		if m.ActiveRevision != saved.RevisionID {
			return result, errors.New("completed configuration is no longer the active revision")
		}
		return s.store.Revision(ctx, saved.RevisionID)
	}
	current, e := s.store.Revision(ctx, p.ExpectedActiveRevision)
	if e != nil {
		return result, e
	}
	cfg, e := runtime.DecodeConfig(p.BaseConfig)
	if e != nil {
		return result, e
	}
	if len(cfg.Modules) != 0 {
		return result, errors.New("configuration plan base must not contain unreviewed modules")
	}
	if e = validateConfigureHost(m, cfg, current); e != nil {
		return result, e
	}
	if e = host.VerifyNetworkPrerequisites(ctx, networkPlanConfig(cfg), p.NetworkPrerequisites); e != nil {
		return result, e
	}
	secret, e := configureSecretObject(p, m.Paths.Secrets)
	if e != nil {
		return result, e
	}
	if e = validateSecretBindings(cfg, p.SecretSources); e != nil {
		return result, e
	}
	if e = validateSecretSourceObservations(p.SecretSources, p.SecretObservations); e != nil {
		return result, e
	}
	anchors, e := reviewNetworkAnchors(ctx, m.Paths, p.Objects, cfg, "configure", p.PlanID, p.PlanDigest)
	if e != nil {
		return result, e
	}
	var receipt configurationReceipt
	if transaction.Phase == "APPROVED" {
		observation, existingDigest, e := secretDescriptorObservation(m.Paths.Secrets)
		if e != nil {
			return result, e
		}
		observationDigest, e := ObjectObservationDigest(observation)
		if e != nil || observationDigest != secret.ObservationDigest {
			return result, errors.New("secret descriptor changed after plan approval")
		}
		desired, e := jsonSecrets(p.SecretSources)
		if e != nil {
			return result, e
		}
		if (secret.Action == "reuse") != (existingDigest == provision.Digest(desired)) {
			return result, errors.New("secret descriptor action differs from exact approved sources")
		}
		if newTransaction {
			if e = s.store.BeginManagementPlan(ctx, transaction); e != nil {
				return result, e
			}
		}
		if m.PendingRevision != "" {
			result, e = s.store.Revision(ctx, m.PendingRevision)
			if e != nil {
				return result, e
			}
			if result.BundleDigest != m.BundleDigest || result.DevelopmentWorker != nil {
				return result, errors.New("configuration pending release changed")
			}
		} else {
			modules := make([]runtime.ModuleSpec, 0, len(p.Modules))
			bindings := make([]host.ApprovedImageBinding, 0, len(p.Modules))
			for _, in := range p.Modules {
				if in.Image.SourceKind != "prepared" {
					return result, errors.New("configuration requires committed prepared image records")
				}
				recordID := strings.TrimPrefix(in.Image.SourceRef, "record:")
				binding, e := s.store.PreparedImageBinding(ctx, recordID)
				if e != nil {
					return result, e
				}
				image, e := s.store.Image(ctx, recordID)
				if e != nil {
					return result, e
				}
				if binding.ModuleID != string(in.Candidate.ModuleID) || in.Image.ModuleID != binding.ModuleID || in.Image.ConfigRevision != in.Candidate.ConfigRevision || in.Image.ApprovalRevision != in.Candidate.ApprovalRevision {
					return result, errors.New("configuration preparation binding changed")
				}
				selector := "record:" + image.ID
				if image.SourceKind == "registry" {
					selector = image.SourceRef
				}
				if in.Candidate.ImageDigest != selector {
					return result, errors.New("configuration selector differs from inspected record")
				}
				review := ModuleReview{PlanID: p.PlanID, Candidate: in.Candidate, Image: image, HostLimits: reviewLimits(cfg, in.Candidate)}
				review.ReviewDigest, e = ModuleReviewDigest(review)
				if e != nil {
					return result, e
				}
				approved, e := approve(ctx, review)
				if e != nil {
					return result, e
				}
				if e = ValidateModuleApproval(review, approved); e != nil {
					return result, e
				}
				if e = runtime.ValidatePreparedApproval(cfg, approved.Module, image.Declaration); e != nil {
					return result, e
				}
				modules = append(modules, approved.Module)
				bindings = append(bindings, host.ApprovedImageBinding{ModuleID: binding.ModuleID, ImageSelector: selector, ImageRecordID: image.ID, ConfigRevision: approved.Module.ConfigRevision, ApprovalRevision: approved.Module.ApprovalRevision})
			}
			config, e := exactConfig(p.BaseConfig, modules)
			if e != nil {
				return result, e
			}
			policies, e := launchPolicies(ctx, s.store, config, bindings)
			if e != nil {
				return result, e
			}
			if e = validateAppBudget(cfg, m.Budget, policies); e != nil {
				return result, e
			}
			result = host.RevisionRecord{ID: newID(), ConfigDigest: provision.Digest(config), BundleDigest: m.BundleDigest, Config: config, Images: bindings, LaunchPolicies: policies, PublicProfile: profile(cfg)}
		}
		previous, e := updateFileRecord(ctx, s.store, m.Paths.Config)
		if e != nil {
			return result, e
		}
		receipt = configurationReceipt{RevisionID: result.ID, Previous: previous}
		if secret.Action == "replace" {
			receipt.PreviousSecret, e = currentSecretRecord(ctx, s.store, m.Paths.Secrets)
			if e != nil {
				return result, e
			}
		}
		if e = s.store.SetPendingRevision(ctx, result); e != nil {
			return result, e
		}
		m.PendingRevision = result.ID
		cutoverStarted = true
		state, e := json.Marshal(receipt)
		if e != nil {
			return result, e
		}
		if e = s.store.AdvanceManagementPlanState(ctx, "configure", p.PlanID, p.PlanDigest, "APPROVED", "PREPARED", state); e != nil {
			return result, e
		}
	} else if transaction.Phase == "PREPARED" {
		if e = gvxcontract.DecodeStrict(transaction.State, 1<<20, 32, &receipt); e != nil {
			return result, e
		}
		result, e = s.store.Revision(ctx, receipt.RevisionID)
		if e != nil {
			return result, e
		}
		cutoverStarted = m.ActiveRevision != result.ID
	} else {
		return result, errors.New("unsupported configuration transaction phase")
	}
	if m.ActiveRevision != p.ExpectedActiveRevision && m.ActiveRevision != result.ID {
		return result, errors.New("configuration base revision changed")
	}
	if e = provisionNetworkAnchors(ctx, s.store, anchors, "configure", p.PlanID, p.PlanDigest); e != nil {
		return result, e
	}
	proof, e := configurationEvidence(ctx, s)
	if e != nil {
		return result, e
	}
	if m.ActiveRevision != result.ID {
		if m.PendingRevision != result.ID {
			return result, errors.New("prepared configuration pending revision changed")
		}
		if e = replaceApprovedFile(ctx, s, receipt.Previous, result.Config, 0600, p.PlanID, proof); e != nil {
			return result, e
		}
		if secret.Action == "replace" {
			desired, e := jsonSecrets(p.SecretSources)
			if e != nil {
				return result, e
			}
			if e = replaceApprovedFile(ctx, s, receipt.PreviousSecret, desired, 0600, p.PlanID, proof); e != nil {
				return result, e
			}
		} else {
			observation, _, e := secretDescriptorObservation(m.Paths.Secrets)
			if e != nil {
				return result, e
			}
			sum, e := ObjectObservationDigest(observation)
			if e != nil || sum != secret.ObservationDigest {
				return result, errors.New("unchanged secret descriptor identity drifted")
			}
		}
		if e = s.store.ActivateRevision(ctx, result.ID, proof); e != nil {
			return result, e
		}
	}
	if e = s.store.CompleteManagementPlan(ctx, "configure", p.PlanID, p.PlanDigest, "PREPARED", proof); e != nil {
		return result, e
	}
	return result, nil
}

type configurationReceipt struct {
	RevisionID     string               `json:"revision_id"`
	Previous       host.ProvisionRecord `json:"previous"`
	PreviousSecret host.ProvisionRecord `json:"previous_secret"`
}

func configurationEvidence(ctx context.Context, s *ownedSession) (proof host.CleanupEvidence, retErr error) {
	if e := host.AttachBacking(ctx, s.manifest, s.store, s.systemd); e != nil {
		return proof, e
	}
	storage, e := host.NewStorage(ctx, supervisorConfig(s.manifest, s.config), s.store, s.systemd)
	if e != nil {
		return proof, e
	}
	defer func() {
		retErr = errors.Join(retErr, storage.Close())
		if retErr != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			retErr = errors.Join(retErr, s.store.RequireRecovery(cleanup, "configuration storage cleanup incomplete"))
		}
	}()
	quota, e := storage.ReclaimEvidence(ctx)
	if e != nil {
		return proof, e
	}
	if e = storage.Close(); e != nil {
		return proof, e
	}
	proof, e = s.systemd.SettleHelpers(ctx)
	if e != nil {
		return proof, e
	}
	proof.QuotaReclaimed = quota.QuotaReclaimed
	if e = host.DetachBacking(ctx, s.manifest, s.store, s.systemd, proof); e != nil {
		return proof, e
	}
	return proof, completeEvidence(ctx, s.manifest, &proof)
}
