//go:build linux

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

type updateReacquisitionMetadata struct {
	plans       []host.ManagementPlanRecord
	plan        ApprovedPreparationPlan
	image       provision.ImageRecord
	binding     host.ApprovedImageBinding
	cache       host.CacheGeneration
	publication host.ProvisionRecord
	spaceRecord host.ProvisionRecord
	old         host.ApprovedImageBinding
	quarantine  host.LegacyAcquisitionQuarantineRecord
	proofErr    error
}

func (m *updateReacquisitionMetadata) Image(context.Context, string) (provision.ImageRecord, error) {
	return m.image, nil
}
func (m *updateReacquisitionMetadata) PreparedImageBinding(context.Context, string) (host.ApprovedImageBinding, error) {
	return m.binding, nil
}
func (m *updateReacquisitionMetadata) ImagePreparationInput(context.Context, string) (provision.ApprovedImageInput, error) {
	return m.plan.Input, nil
}
func (m *updateReacquisitionMetadata) CacheForImage(context.Context, string, string) (host.CacheGeneration, error) {
	return m.cache, nil
}
func (m *updateReacquisitionMetadata) ObjectProvisions(context.Context, string, string) ([]host.ProvisionRecord, error) {
	return []host.ProvisionRecord{m.publication}, nil
}
func (m *updateReacquisitionMetadata) PendingProvisions(context.Context) ([]host.ProvisionRecord, error) {
	raw, _ := json.Marshal(host.ProvisionProperties{Digest: m.old.ImageRecordID})
	return []host.ProvisionRecord{{Kind: "image", Identity: "legacy-job", State: "OBSERVED", Observed: host.ObjectObservation{Attributes: raw}}}, nil
}
func (m *updateReacquisitionMetadata) Provision(context.Context, string) (host.ProvisionRecord, error) {
	return m.spaceRecord, nil
}
func (m *updateReacquisitionMetadata) StorageGeneration(_ context.Context, claim string) (string, error) {
	if strings.HasSuffix(claim, ":source") {
		return m.image.ID, nil
	}
	return m.cache.ID, nil
}
func (m *updateReacquisitionMetadata) RequirePreparationWriterDomain(context.Context, host.ImageSpace) error {
	return m.proofErr
}
func (m *updateReacquisitionMetadata) LegacyAcquisitionQuarantine(context.Context, string, string) (host.LegacyAcquisitionQuarantineRecord, bool, error) {
	return m.quarantine, true, nil
}
func (m *updateReacquisitionMetadata) ManagementPlans(context.Context, string) ([]host.ManagementPlanRecord, error) {
	return m.plans, nil
}

func updateReacquisitionFixture(t *testing.T) (*updateReacquisitionMetadata, host.RevisionRecord) {
	t.Helper()
	m := &updateReacquisitionMetadata{}
	m.old = host.ApprovedImageBinding{ModuleID: "module", ImageRecordID: provision.Digest([]byte("legacy-image")), ImageSelector: "record:" + provision.Digest([]byte("legacy-image")), ConfigRevision: "old-config", ApprovalRevision: "old-approval"}
	m.quarantine = host.LegacyAcquisitionQuarantineRecord{PlanID: "quarantine-plan", PlanDigest: provision.Digest([]byte("quarantine-plan")), QuarantineSetDigest: provision.Digest([]byte("quarantine-set")), Lineage: host.LegacyAcquisitionLineage{Kind: "image", JobID: "legacy-job", ImageRecordID: m.old.ImageRecordID}}
	m.plan = ApprovedPreparationPlan{PlanID: strings.Repeat("1", 32), InstallationID: "installation", ExpectedActiveRevision: "original-revision", PreparationBundleDigest: provision.Digest([]byte("bundle-B")), Reacquisition: &host.OperatorReacquisition{Version: 1, ExpectedState: "RECOVERY_REQUIRED", QuarantineSetDigest: m.quarantine.QuarantineSetDigest, RequiredWriterDomainVersion: gvxcontract.PreparationWriterDomainVersion, ReplacesImageRecordID: m.old.ImageRecordID}, Input: provision.ApprovedImageInput{JobID: "fresh-job", ModuleID: "module", ConfigRevision: "fresh-config", ApprovalRevision: "fresh-approval", SourceKind: "oci-archive", SourceRef: "reviewed-archive", ArchiveDigest: provision.Digest([]byte("archive")), Platform: "linux/amd64", Limits: provision.PrepareLimits{NanoCPUs: 1e9, MemoryBytes: 64 << 20, Tasks: 16, InputBytes: 4096, ExpandedBytes: 4096, OutputBytes: 4096, Inodes: 32, JSONBytes: 4096, DescriptorCount: 32, IndexDepth: 8, Deadline: time.Minute}}}
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Labels":{"org.chatanium.flexmodule.manifest.v2":"{\"protocolMajor\":2}"}},"rootfs":{"type":"layers","diff_ids":[]}}`)
	manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": provision.Digest(config), "size": len(config)}, "layers": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	declaration := []byte(`{"protocolMajor":2}`)
	m.image = provision.ImageRecord{Version: provision.ImageRecordVersion, Revision: provision.Revision(m.plan.Input), SourceKind: m.plan.Input.SourceKind, SourceRef: m.plan.Input.SourceRef, SourceDigest: m.plan.Input.ArchiveDigest, Original: manifest, OriginalDigest: provision.Digest(manifest), Manifest: manifest, ManifestDigest: provision.Digest(manifest), Config: config, ConfigDigest: provision.Digest(config), Declaration: declaration, DeclarationDigest: provision.Digest(declaration), CanonicalArchiveDigest: provision.Digest([]byte("canonical")), ExecutionRef: provision.ExecutionRef(provision.Digest(manifest))}
	m.image.ID = provision.RecordID(m.image)
	if err = provision.ValidateRecord(m.image, m.plan.Input.Limits); err != nil {
		t.Fatal(err)
	}
	m.binding = host.ApprovedImageBinding{ModuleID: m.plan.Input.ModuleID, ImageRecordID: m.image.ID, ImageSelector: "record:" + m.image.ID, ConfigRevision: m.plan.Input.ConfigRevision, ApprovalRevision: m.plan.Input.ApprovalRevision}
	m.cache = host.CacheGeneration{ID: provision.Digest([]byte("fresh-cache-B")), State: "READY", BundleDigest: m.plan.PreparationBundleDigest, ImageRecordID: m.image.ID, ManifestDigest: m.image.ManifestDigest, CanonicalArchiveDigest: m.image.CanonicalArchiveDigest, Directory: "/prepared/fresh-job/generation"}
	space := host.ImageSpace{JobID: m.plan.Input.JobID, ProvisionID: "fresh-space", Source: "/images/fresh-job", Cache: "/prepared/fresh-job", Work: "/preparation/fresh-job"}
	desired, _ := json.Marshal(host.ProvisionProperties{ApprovedImageInput: &m.plan.Input, PrepareLimits: &m.plan.Input.Limits, Revision: m.plan.PreparationBundleDigest})
	published, _ := json.Marshal(host.ProvisionProperties{Digest: m.image.ID, Revision: m.cache.ID, ImageSpace: &space})
	m.publication = host.ProvisionRecord{Kind: "image", Identity: m.plan.Input.JobID, State: "OBSERVED", ProductCreated: true, Desired: desired, Observed: host.ObjectObservation{Attributes: published}}
	space.Committed = true
	committed, _ := json.Marshal(host.ProvisionProperties{ImageSpace: &space})
	m.spaceRecord = host.ProvisionRecord{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + space.JobID, State: "OBSERVED", Observed: host.ObjectObservation{Attributes: committed}}
	m.plans = []host.ManagementPlanRecord{updateReacquisitionRecord(t, m.plan, m.image.ID, m.cache.ID)}
	previous := host.RevisionRecord{ID: m.plan.ExpectedActiveRevision, BundleDigest: provision.Digest([]byte("bundle-A")), Images: []host.ApprovedImageBinding{m.old}, Config: []byte(`{"host":{"bundle_digest":"old","protected":"unchanged"},"modules":[{"module_id":"module","image":"old","config_revision":"old-config","approval_revision":"old-approval","uid":123,"approval":{"grants":"unchanged"},"config":{"secret":"opaque-reference"}}]}`)}
	return m, previous
}

func updateReacquisitionRecord(t *testing.T, plan ApprovedPreparationPlan, imageID, cacheID string) host.ManagementPlanRecord {
	t.Helper()
	var err error
	plan.PlanDigest, err = PreparationPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(plan)
	state, _ := json.Marshal(operatorPreparationReceipt{ImageID: imageID, CacheID: cacheID, PreparationBundleDigest: plan.PreparationBundleDigest})
	return host.ManagementPlanRecord{Kind: "operator-preparation", ID: plan.PlanID, Digest: plan.PlanDigest, Plan: raw, Phase: "COMMITTED", State: state}
}

func TestUpdateSelectsExactCommittedReacquisition(t *testing.T) {
	m, previous := updateReacquisitionFixture(t)
	refs, selected, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].PreparationPlanID != m.plan.PlanID || refs[0].PreviousImageRecordID != m.old.ImageRecordID || len(selected) != 1 || selected[0].receipt.CacheID != m.cache.ID {
		t.Fatal("selection lost exact plan, previous image or cache identity")
	}
	candidate := previous
	candidate.Images = applyReacquiredBindings(previous.Images, selected)
	candidate.BundleDigest = m.plan.PreparationBundleDigest
	candidate.Config, err = reacquiredUpdateConfig(previous.Config, candidate.BundleDigest, selected)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateReacquiredCandidate(previous, candidate, selected); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*host.RevisionRecord){
		func(r *host.RevisionRecord) { r.Images = nil },
		func(r *host.RevisionRecord) { r.Images = []host.ApprovedImageBinding{m.old} },
		func(r *host.RevisionRecord) {
			r.Config = []byte(strings.Replace(string(r.Config), `"uid":123`, `"uid":0`, 1))
		},
		func(r *host.RevisionRecord) {
			r.Config = []byte(strings.Replace(string(r.Config), `"opaque-reference"`, `"other-secret"`, 1))
		},
	} {
		changed := candidate
		change(&changed)
		if err = validateReacquiredCandidate(previous, changed, selected); err == nil {
			t.Fatal("accepted module removal, legacy binding or changed authority")
		}
	}
}

func TestUpdateRejectsReacquisitionAmbiguityAndRevalidatesExplicitPlan(t *testing.T) {
	m, previous := updateReacquisitionFixture(t)
	other := m.plan
	other.PlanID = strings.Repeat("2", 32)
	m.plans = append(m.plans, updateReacquisitionRecord(t, other, m.image.ID, m.cache.ID))
	if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, nil); err == nil {
		t.Fatal("selected latest or first ambiguous preparation")
	}
	explicit := []ReacquiredPreparation{{ModuleID: m.old.ModuleID, PreviousImageRecordID: m.old.ImageRecordID, PreparationPlanID: m.plans[0].ID, PreparationPlanDigest: m.plans[0].Digest}}
	if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, explicit); err != nil {
		t.Fatal(err)
	}
	m.plans = m.plans[1:]
	if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, explicit); err == nil {
		t.Fatal("substituted a different committed plan on replay")
	}
	if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, []ReacquiredPreparation{}); err == nil {
		t.Fatal("accepted missing explicit replacement")
	}
}

func TestUpdateRejectsReacquisitionTupleAndReceiptSubstitution(t *testing.T) {
	for name, change := range map[string]func(*updateReacquisitionMetadata){
		"old revision": func(m *updateReacquisitionMetadata) { m.plan.ExpectedActiveRevision = "later-active-revision" },
		"old image": func(m *updateReacquisitionMetadata) {
			q := *m.plan.Reacquisition
			q.ReplacesImageRecordID = provision.Digest(nil)
			m.plan.Reacquisition = &q
		},
		"module": func(m *updateReacquisitionMetadata) { m.plan.Input.ModuleID = "other-module" },
		"quarantine": func(m *updateReacquisitionMetadata) {
			q := *m.plan.Reacquisition
			q.QuarantineSetDigest = provision.Digest(nil)
			m.plan.Reacquisition = &q
		},
		"candidate bundle":                func(m *updateReacquisitionMetadata) { m.plan.PreparationBundleDigest = provision.Digest(nil) },
		"cache identity":                  func(m *updateReacquisitionMetadata) { m.cache.ID = provision.Digest(nil) },
		"new load without original proof": func(m *updateReacquisitionMetadata) { m.proofErr = errors.New("original writer proof missing") },
		"approval provenance":             func(m *updateReacquisitionMetadata) { m.binding.ApprovalRevision = "other-approval" },
	} {
		t.Run(name, func(t *testing.T) {
			m, previous := updateReacquisitionFixture(t)
			bundleDigest, imageID, cacheID := m.plan.PreparationBundleDigest, m.image.ID, m.cache.ID
			change(m)
			m.plans = []host.ManagementPlanRecord{updateReacquisitionRecord(t, m.plan, imageID, cacheID)}
			if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, bundleDigest, nil); err == nil {
				t.Fatal("accepted changed exact tuple, cache or original proof")
			}
		})
	}
}

type selectedCacheLookup struct {
	image provision.ImageRecord
	cache host.CacheGeneration
	found bool
	input provision.ApprovedImageInput
}

func (l *selectedCacheLookup) LookupPreparedImage(_ context.Context, input provision.ApprovedImageInput) (provision.ImageRecord, host.CacheGeneration, bool, error) {
	l.input = input
	return l.image, l.cache, l.found, nil
}

func TestUpdatePhaseReplayPinsOriginalSelectedCache(t *testing.T) {
	m, previous := updateReacquisitionFixture(t)
	refs, selected, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"PUBLISHED", "CACHES_READY", "PENDING", "CONFIG_REPLACED", "LAUNCHER_REPLACED", "ACTIVATED", "COMMITTED"} {
		t.Run(phase, func(t *testing.T) {
			// The old immutable base and exact references remain the authority even
			// after the installation's active revision has become candidate B.
			if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, refs); err != nil {
				t.Fatal(err)
			}
			lookup := &selectedCacheLookup{image: m.image, cache: m.cache, found: true}
			if err := verifyReacquiredCaches(context.Background(), lookup, selected); err != nil {
				t.Fatal(err)
			}
			if lookup.input != m.plan.Input {
				t.Fatal("phase replay lost full original input approval")
			}
			lookup.cache.ID = provision.Digest(nil)
			if err := verifyReacquiredCaches(context.Background(), lookup, selected); err == nil {
				t.Fatal("later phase accepted another cache for same image and bundle")
			}
			lookup.found = false
			if err := verifyReacquiredCaches(context.Background(), lookup, selected); err == nil {
				t.Fatal("missing replacement cache permitted rebuild fallback")
			}
		})
	}
}

func TestUpdateRequiresCommittedValidPreparationApproval(t *testing.T) {
	for _, phase := range []string{"APPROVED", "PREPARED", "FAILED_CLEAN"} {
		t.Run(phase, func(t *testing.T) {
			m, previous := updateReacquisitionFixture(t)
			m.plans[0].Phase = phase
			if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, nil); err == nil {
				t.Fatal("uncommitted preparation conferred update activation authority")
			}
		})
	}
	m, previous := updateReacquisitionFixture(t)
	m.plans[0].Digest = provision.Digest(nil)
	if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, nil); err == nil {
		t.Fatal("changed durable preparation digest accepted")
	}
	plan := ApprovedUpdatePlan{ReacquiredPreparations: []ReacquiredPreparation{{ModuleID: "module", PreviousImageRecordID: m.old.ImageRecordID, PreparationPlanID: m.plan.PlanID, PreparationPlanDigest: m.plans[0].Digest}}}
	before, err := UpdatePlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.ReacquiredPreparations[0].PreparationPlanID = "other-plan"
	after, err := UpdatePlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("update approval digest omitted exact replacement selection")
	}
}

func TestUpdateSelectsSuccessfulReacquisitionAfterCommittedFailure(t *testing.T) {
	m, previous := updateReacquisitionFixture(t)
	success := m.plans[0]
	failedPlan := m.plan
	failedPlan.PlanID = strings.Repeat("2", 32)
	failedPlan.Input.JobID = "failed-job"
	failedPlan.Input.ConfigRevision = "failed-config"
	failedPlan.Input.ApprovalRevision = "failed-approval"
	failed := updateReacquisitionRecord(t, failedPlan, "", "")
	receipt := operatorPreparationReceipt{PreparationBundleDigest: failedPlan.PreparationBundleDigest, Failure: "PREPARATION_FAILED"}
	var err error
	failed.State, err = json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	m.plans = []host.ManagementPlanRecord{failed, success}
	successRef := ReacquiredPreparation{ModuleID: m.old.ModuleID, PreviousImageRecordID: m.old.ImageRecordID, PreparationPlanID: success.ID, PreparationPlanDigest: success.Digest}
	for _, explicit := range [][]ReacquiredPreparation{nil, {successRef}} {
		refs, selected, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, explicit)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0] != successRef || len(selected) != 1 || selected[0].receipt.CacheID != m.cache.ID {
			t.Fatal("terminal failed preparation blocked or replaced the exact successful selection")
		}
	}
	failedRef := successRef
	failedRef.PreparationPlanID, failedRef.PreparationPlanDigest = failed.ID, failed.Digest
	if _, _, err = selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, []ReacquiredPreparation{failedRef}); err == nil {
		t.Fatal("explicit failed preparation selected or silently substituted by successful preparation")
	}
	m.plans = []host.ManagementPlanRecord{failed}
	if _, _, err = selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, nil); err == nil {
		t.Fatal("terminal failure without outputs supplied replacement authority")
	}
	for name, change := range map[string]func(*operatorPreparationReceipt){
		"image output":                    func(r *operatorPreparationReceipt) { r.ImageID = m.image.ID },
		"cache output":                    func(r *operatorPreparationReceipt) { r.CacheID = m.cache.ID },
		"bundle mismatch":                 func(r *operatorPreparationReceipt) { r.PreparationBundleDigest = provision.Digest(nil) },
		"missing outputs without failure": func(r *operatorPreparationReceipt) { r.Failure = "" },
	} {
		t.Run(name, func(t *testing.T) {
			malformed := receipt
			change(&malformed)
			record := failed
			record.State, err = json.Marshal(malformed)
			if err != nil {
				t.Fatal(err)
			}
			m.plans = []host.ManagementPlanRecord{record, success}
			if _, _, err := selectUpdateReacquisitions(context.Background(), m, m.plan.InstallationID, previous, m.plan.PreparationBundleDigest, nil); err == nil {
				t.Fatal("malformed terminal failure receipt was silently excluded")
			}
		})
	}
}
