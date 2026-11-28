//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Update(ctx context.Context, id RuntimeInstallationID, a ApprovedUpdatePlan) (report CleanupReport, retErr error) {
	report = CleanupReport{InstallationID: id, DesiredRunState: "STOPPED"}
	if a.InstallationID != id || !validID(a.PlanID) || !validID(a.BackupID) || a.CandidateRevision.DevelopmentWorker != nil {
		return report, errors.New("invalid release update approval")
	}
	sum, e := UpdatePlanDigest(a)
	if e != nil || sum != a.PlanDigest {
		return report, errors.New("update approval digest mismatch")
	}
	if e = validateObjects(a.Objects, false); e != nil {
		return report, e
	}
	if e = rootRequired(); e != nil {
		return report, e
	}
	probe, _, e := openInstallation(ctx, id)
	if e != nil {
		return report, e
	}
	transaction, lookup := probe.ManagementPlan(ctx, "update", a.PlanID)
	initial, initialErr := probe.Installation(ctx)
	probe.Close()
	resuming := lookup == nil
	if lookup != nil && !errors.Is(lookup, sql.ErrNoRows) {
		return report, lookup
	}
	if initialErr != nil {
		return report, initialErr
	}
	if !resuming && initial.State != "READY" {
		return report, errors.New("release update requires explicit recovery before approval execution")
	}
	var s *ownedSession
	if resuming {
		approved, marshalErr := json.Marshal(a)
		if marshalErr != nil || transaction.Digest != a.PlanDigest || !bytes.Equal(transaction.Plan, approved) {
			return report, errors.New("update transaction differs from persisted approval")
		}
		s, e = maintenance(ctx, id)
	} else {
		report, e = Stop(ctx, id)
		if e != nil || !report.Complete {
			return report, errors.Join(e, host.ErrCleanupIncomplete)
		}
		s, e = cleanupLocked(ctx, id)
	}
	if e != nil {
		return report, e
	}
	defer closeMaintenance(s)
	report.Complete = false
	current, e := s.store.Installation(ctx)
	if e != nil {
		return report, e
	}
	s.manifest = current
	if resuming {
		s.manifest = transaction.Snapshot
	}
	m := s.manifest
	if m.ActiveRevision != a.ExpectedActiveRevision || a.CandidateRevision.BundleDigest != a.CandidateBundleDigest || a.CandidateRevision.ID == m.ActiveRevision || current.PendingRevision != "" && current.PendingRevision != a.CandidateRevision.ID || current.ActiveRevision != m.ActiveRevision && current.ActiveRevision != a.CandidateRevision.ID || current.DesiredRunState != "STOPPED" {
		return report, errors.New("update revision, run intent or bundle changed")
	}
	source, e := configuredSource()
	if e != nil {
		return report, e
	}
	raw, e := source.Manifest()
	if e != nil {
		return report, e
	}
	manifest, e := bundle.VerifyManifest(raw)
	if e != nil || manifest.Digest != a.CandidateBundleDigest {
		return report, errors.New("candidate bundle differs from executing launcher's verified source")
	}
	if !compatibleBundle(manifest, m) {
		return report, errors.New("candidate bundle does not declare installed data/schema/hostfs compatibility")
	}
	config, e := runtime.DecodeConfig(a.CandidateRevision.Config)
	if e != nil {
		return report, e
	}
	if e = validateUpdateConfig(m, config, a.CandidateRevision); e != nil {
		return report, e
	}
	if _, e = cleanupTimeout(config); e != nil {
		return report, e
	}
	previous, e := s.store.Revision(ctx, a.ExpectedActiveRevision)
	if e != nil {
		return report, e
	}
	explicit := a.ReacquiredPreparations
	if explicit == nil {
		explicit = []ReacquiredPreparation{}
	}
	_, replacements, e := selectUpdateReacquisitions(ctx, s.store, id, previous, a.CandidateBundleDigest, explicit)
	if e != nil {
		return report, e
	}
	if e = validateReacquiredCandidate(previous, a.CandidateRevision, replacements); e != nil {
		return report, e
	}
	policies, e := launchPolicies(ctx, s.store, a.CandidateRevision.Config, a.CandidateRevision.Images)
	if e != nil {
		return report, e
	}
	candidate := a.CandidateRevision
	candidate.LaunchPolicies = policies
	candidate.PublicProfile = profile(config)
	anchors, e := reviewNetworkAnchors(ctx, m.Paths, a.Objects, config, "update", a.PlanID, a.PlanDigest)
	if e != nil {
		return report, e
	}
	if !resuming {
		if e = validateUpdateScope(ctx, s, a); e != nil {
			return report, e
		}
	}
	if e = s.store.AssertRemovable(ctx); e != nil {
		return report, e
	}
	self, e := os.Executable()
	if e != nil {
		return report, e
	}
	launcher, e := readProtected(self, 1<<30)
	if e != nil {
		return report, e
	}
	var state updateTransactionState
	if resuming {
		if e = gvxcontract.DecodeStrict(transaction.State, 1<<20, 16, &state); e != nil {
			return report, e
		}
		if state.LauncherDigest != provision.Digest(launcher) {
			return report, errors.New("resumed update requires the exact approved candidate launcher")
		}
	} else {
		state.Config, e = updateFileRecord(ctx, s.store, m.Paths.Config)
		if e != nil {
			return report, e
		}
		state.Launcher, e = updateFileRecord(ctx, s.store, m.Paths.Launcher)
		if e != nil {
			return report, e
		}
		state.LauncherDigest = provision.Digest(launcher)
		approved, marshalErr := json.Marshal(a)
		if marshalErr != nil {
			return report, marshalErr
		}
		snapshot, marshalErr := json.Marshal(state)
		if marshalErr != nil {
			return report, marshalErr
		}
		transaction = legacyhost.ManagementPlanRecord{Kind: "update", ID: a.PlanID, Digest: a.PlanDigest, Plan: approved, Snapshot: m, Phase: "APPROVED", State: snapshot}
		if e = s.store.BeginManagementPlan(ctx, transaction); e != nil {
			return report, e
		}
	}
	if e = validateUpdateFiles(ctx, s, a, state, launcher); e != nil {
		return report, e
	}
	if transaction.Phase == "APPROVED" {
		e = backupInstallation(ctx, s, a.BackupID)
	} else {
		e = verifyUpdateBackup(ctx, s, a.BackupID)
	}
	if e != nil {
		return report, e
	}
	if transaction.Phase == "COMMITTED" {
		if current.ActiveRevision != candidate.ID || current.PendingRevision != "" || current.State != "READY" && current.State != "RECOVERY_REQUIRED" {
			return report, errors.New("completed update no longer names the active release")
		}
		if _, e = installedBundle(ctx, current); e != nil {
			return report, e
		}
		if e = verifyUpdateReplacement(ctx, s.store, state.Config, candidate.Config, a.PlanID); e != nil {
			return report, e
		}
		if e = verifyUpdateReplacement(ctx, s.store, state.Launcher, launcher, a.PlanID); e != nil {
			return report, e
		}
	}
	if e = advanceUpdate(ctx, s.store, &transaction, "BACKED_UP"); e != nil {
		return report, e
	}
	mutated := true
	defer func() {
		if retErr != nil && mutated {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			retErr = errors.Join(retErr, s.store.RequireRecovery(cleanup, "release update cutover incomplete"))
			report.Complete = false
			report.Failures = append(report.Failures, OperationFailure{Phase: "update", Code: "RECOVERY_REQUIRED", Message: retErr.Error()})
		}
	}()
	if transaction.Phase != "COMMITTED" {
		if e = provisionNetworkAnchors(ctx, s.store, anchors, "update", a.PlanID, a.PlanDigest); e != nil {
			return report, e
		}
	}
	verified, e := publishUpdateBundle(ctx, s, source, manifest)
	if e != nil {
		return report, e
	}
	if e = advanceUpdate(ctx, s.store, &transaction, "PUBLISHED"); e != nil {
		return report, e
	}
	candidateSystemd, e := legacyhost.NewSystemd(ctx, verified)
	if e != nil {
		return report, e
	}
	defer candidateSystemd.Close()
	if e = candidateSystemd.BindStore(s.store); e != nil {
		return report, e
	}
	candidateOwner := s.owner
	if e = candidateSystemd.BindOwner(ctx, candidateOwner); e != nil {
		return report, e
	}
	if e = legacyhost.AttachBacking(ctx, m, s.store, candidateSystemd); e != nil {
		return report, e
	}
	storage, e := legacyhost.NewStorage(ctx, supervisorConfig(m, s.config), s.store, candidateSystemd)
	if e != nil {
		return report, e
	}
	defer storage.Close()
	images, e := legacyhost.NewImageManager(imageConfig(m, verified, candidateOwner, nil), s.store, candidateSystemd, storage)
	if e != nil {
		return report, e
	}
	defer func() {
		if retErr == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		failure := images.Recover(cleanup)
		quota, qe := storage.ReclaimEvidence(cleanup)
		failure = errors.Join(failure, qe, storage.Close())
		proof, pe := candidateSystemd.SettleHelpers(cleanup)
		failure = errors.Join(failure, pe)
		proof.QuotaReclaimed = quota.QuotaReclaimed
		if failure == nil {
			failure = legacyhost.DetachBacking(cleanup, m, s.store, candidateSystemd, proof)
		}
		retErr = errors.Join(retErr, failure)
	}()
	if e = verifyReacquiredCaches(ctx, images, replacements); e != nil {
		return report, e
	}
	if transaction.Phase == "PUBLISHED" {
		for _, binding := range candidate.Images {
			replacement := false
			for _, selected := range replacements {
				if binding.ImageRecordID == selected.receipt.ImageID {
					replacement = true
					break
				}
			}
			if !replacement {
				if e = images.RebuildCache(ctx, binding.ImageRecordID); e != nil {
					return report, e
				}
			}
		}
	} else if e = images.VerifyReleaseCaches(ctx, candidate); e != nil {
		return report, e
	}
	// Retain every rebuilt compatible cache atomically before the cutover's
	// reconciliation and storage-reclamation barrier.
	if e = advanceUpdate(ctx, s.store, &transaction, "CACHES_READY"); e != nil {
		return report, e
	}
	if e = images.Recover(ctx); e != nil {
		return report, e
	}
	quota, e := storage.ReclaimEvidence(ctx)
	if e != nil {
		return report, e
	}
	if e = storage.Close(); e != nil {
		return report, e
	}
	proof, e := candidateSystemd.SettleHelpers(ctx)
	if e != nil {
		return report, e
	}
	proof.QuotaReclaimed = quota.QuotaReclaimed
	if e = legacyhost.DetachBacking(ctx, m, s.store, candidateSystemd, proof); e != nil {
		return report, e
	}
	if e = completeEvidence(ctx, m, &proof); e != nil {
		return report, e
	}
	if transaction.Phase == "COMMITTED" {
		if current.State == "RECOVERY_REQUIRED" {
			if e = s.store.CompleteRecovery(ctx, proof); e != nil {
				return report, e
			}
		}
		report.Complete, report.ObservedState = true, "stopped"
		return report, nil
	}
	if e = s.store.SetPendingRevision(ctx, candidate); e != nil {
		return report, e
	}
	if e = advanceUpdate(ctx, s.store, &transaction, "PENDING"); e != nil {
		return report, e
	}
	if e = replaceApprovedFile(ctx, s, state.Config, candidate.Config, 0600, a.PlanID, proof); e != nil {
		return report, e
	}
	if e = advanceUpdate(ctx, s.store, &transaction, "CONFIG_REPLACED"); e != nil {
		return report, e
	}
	if e = replaceApprovedFile(ctx, s, state.Launcher, launcher, 0755, a.PlanID, proof); e != nil {
		return report, e
	}
	if e = advanceUpdate(ctx, s.store, &transaction, "LAUNCHER_REPLACED"); e != nil {
		return report, e
	}
	if e = s.store.ActivateRevision(ctx, candidate.ID, proof); e != nil {
		return report, e
	}
	if e = advanceUpdate(ctx, s.store, &transaction, "ACTIVATED"); e != nil {
		return report, e
	}
	if e = s.store.CompleteManagementPlan(ctx, "update", a.PlanID, a.PlanDigest, transaction.Phase, proof); e != nil {
		return report, e
	}
	report.Complete = true
	report.ObservedState = "stopped"
	report.DesiredRunState = "STOPPED"
	return report, nil
}
func validateUpdateConfig(m legacyhost.InstallationManifest, c runtime.Config, r legacyhost.RevisionRecord) error {
	if provision.Digest(r.Config) != r.ConfigDigest || c.Host.RuntimeInstallationID != m.RuntimeInstallationID || c.Host.BundleDigest != r.BundleDigest || c.Host.ManagementDirectory != filepath.Join(m.Paths.StorageRoot, "app") || c.Host.StorageRoot != m.Paths.StorageRoot || c.Host.IPCRoot != filepath.Join(m.Paths.RunRoot, "instances") {
		return errors.New("candidate changes installation identity or protected paths")
	}
	raw, e := readProtected(m.Paths.Secrets, WorkerSecretMaxBytes)
	if e != nil {
		return e
	}
	var sources []SecretSource
	if e = gvxcontract.DecodeStrict(raw, WorkerSecretMaxBytes, 8, &sources); e != nil {
		return e
	}
	return validateSecretBindings(c, sources)
}
func validateUpdateScope(ctx context.Context, s *ownedSession, a ApprovedUpdatePlan) error {
	base := filepath.Join(s.manifest.Paths.Installation, "backup-"+a.BackupID)
	required := map[string]string{"config:" + base + ".json": "create", "config:" + base + ".sqlite": "create", "backing:" + base + ".xfs": "create", "config:" + s.manifest.Paths.Config: "replace", "config:" + s.manifest.Paths.Launcher: "replace"}
	if a.CandidateBundleDigest != s.manifest.BundleDigest {
		destination := filepath.Join(s.manifest.Paths.EngineRoot, strings.TrimPrefix(a.CandidateBundleDigest, "sha256:"))
		action := "create"
		record, e := ownedRecord(ctx, s.store, "bundle", destination)
		if e == nil {
			action = "reuse"
			if e = matchRecord(record); e != nil {
				return e
			}
		}
		required["bundle:"+destination] = action
	}
	for _, object := range a.Objects {
		key := object.Kind + ":" + object.Identity
		action, ok := required[key]
		if !ok {
			continue
		}
		if action != object.Action {
			return errors.New("update object action does not match cutover")
		}
		if action == "replace" {
			record, e := updateFileRecord(ctx, s.store, object.Identity)
			if e != nil {
				return e
			}
			if e = matchRecord(record); e != nil {
				return e
			}
			sum, e := ObjectObservationDigest(record.Observed)
			if e != nil || sum != object.ObservationDigest {
				return errors.New("update approved object changed")
			}
		}
		delete(required, key)
	}
	if len(required) != 0 {
		return errors.New("update plan omits backup/code/config object approval")
	}
	return nil
}
func replaceApprovedFile(ctx context.Context, s *ownedSession, previous legacyhost.ProvisionRecord, raw []byte, mode uint32, planID string, evidence legacyhost.CleanupEvidence) error {
	kind := previous.Kind
	if kind != "config" && kind != "secret" {
		return errors.New("replacement requires an approved configuration or secret descriptor")
	}
	path := previous.Identity
	next := updateStagePath(path, planID)
	p := legacyhost.ProvisionProperties{Path: path, Source: next, Digest: provision.Digest(raw), Mode: mode, Revision: previous.ID, ProductCreated: true}
	records, e := s.store.ObjectProvisions(ctx, kind, path)
	if e != nil {
		return e
	}
	intent := ""
	for _, r := range records {
		if string(r.Desired) != string(provisionJSON(p)) {
			continue
		}
		if r.CleanupState == "COMPLETE" {
			return errors.New("retired replacement cannot be recreated")
		}
		intent = r.ID
		if r.State == "OBSERVED" {
			if e = matchRecord(r); e != nil {
				return e
			}
			return errors.Join(completeUpdateStage(ctx, s.store, next, evidence), s.store.CompleteProvisionCleanup(ctx, previous.ID, evidence))
		}
	}
	if intent == "" {
		if e = matchRecord(previous); e != nil {
			return e
		}
		intent, e = recordIntent(ctx, s.store, kind, path, p, false)
		if e != nil {
			return e
		}
	}
	// A previous rename may have succeeded before its final observation. Only
	// the exact durable staging inode and hash authorize recognizing that case.
	stages, e := s.store.ObjectProvisions(ctx, "config", next)
	if e != nil {
		return e
	}
	var stage legacyhost.ProvisionRecord
	for _, r := range stages {
		if r.CleanupState == "COMPLETE" {
			return errors.New("retired update staging object")
		}
		stage = r
	}
	if stage.State == "OBSERVED" && updateStageAt(stage, path) == nil {
		if e = observePath(ctx, s.store, intent, path, p); e != nil {
			return e
		}
		return errors.Join(completeUpdateStage(ctx, s.store, next, evidence), s.store.CompleteProvisionCleanup(ctx, previous.ID, evidence))
	}
	if e = matchRecord(previous); e != nil {
		return e
	}
	if _, e = updateStagedFile(ctx, s.store, next, raw, mode); e != nil {
		return e
	}
	if e = os.Rename(next, path); e != nil {
		return e
	}
	if e = syncDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	if e = observePath(ctx, s.store, intent, path, p); e != nil {
		return e
	}
	return errors.Join(completeUpdateStage(ctx, s.store, next, evidence), s.store.CompleteProvisionCleanup(ctx, previous.ID, evidence))
}
func publishUpdateBundle(ctx context.Context, s *ownedSession, source bundle.Source, manifest bundle.Manifest) (bundle.Verified, error) {
	if manifest.Digest == s.manifest.BundleDigest {
		return installedBundle(ctx, s.manifest)
	}
	destination := filepath.Join(s.manifest.Paths.EngineRoot, strings.TrimPrefix(manifest.Digest, "sha256:"))
	records, e := s.store.ObjectProvisions(ctx, "bundle", destination)
	if e != nil {
		return bundle.Verified{}, e
	}
	intent := ""
	for _, record := range records {
		if record.CleanupState == "COMPLETE" {
			return bundle.Verified{}, errors.New("retired bundle generation cannot be recreated")
		}
		if !record.ProductCreated || record.ExistedBefore {
			return bundle.Verified{}, errors.New("candidate bundle has different ownership")
		}
		var p legacyhost.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &p); e != nil {
			return bundle.Verified{}, e
		}
		if p.Digest != manifest.Digest || p.Path != destination {
			return bundle.Verified{}, errors.New("candidate bundle intent differs")
		}
		if record.State == "OBSERVED" {
			if e = matchRecord(record); e != nil {
				return bundle.Verified{}, e
			}
			return bundle.VerifyDirectory(ctx, destination, manifest)
		}
		intent = record.ID
	}
	if intent == "" {
		if _, e = os.Lstat(destination); e == nil {
			return bundle.Verified{}, errors.New("existing unowned bundle generation cannot be adopted")
		} else if !os.IsNotExist(e) {
			return bundle.Verified{}, e
		}
		intent, e = recordIntent(ctx, s.store, "bundle", destination, legacyhost.ProvisionProperties{Path: destination, Digest: manifest.Digest, ProductCreated: true}, false)
		if e != nil {
			return bundle.Verified{}, e
		}
	}
	verified, e := publishBundle(ctx, s.store, source, s.manifest.Paths.EngineRoot)
	if e != nil {
		return bundle.Verified{}, e
	}
	e = observeBundle(ctx, s.store, intent, destination, verified)
	return verified, e
}
