//go:build linux

package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxstage"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

type legacyQuarantineFixture struct {
	Store     *Store
	Plan      ManagementPlanRecord
	Space     ImageSpace
	ImageID   string
	CacheID   string
	Input     provision.ApprovedImageInput
	Binding   ApprovedImageBinding
	HelperIDs []string
}

func quarantineTestJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func quarantineTestLedger(t *testing.T, s *Store, r ProvisionRecord) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), "INSERT INTO provisioning_ledger VALUES(?,?,?,?)", r.ID, r.Kind, r.Identity, quarantineTestJSON(t, r)); err != nil {
		t.Fatal(err)
	}
}
func quarantineTestInput(job string) provision.ApprovedImageInput {
	return provision.ApprovedImageInput{JobID: job, SourceKind: "registry", SourceRef: "registry.example/module@sha256:" + strings.Repeat("d", 64), ModuleID: "module", ConfigRevision: "config-old", ApprovalRevision: "approval-old", Platform: "linux/amd64", Limits: provision.PrepareLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Tasks: 8, InputBytes: 1 << 20, ExpandedBytes: 2 << 20, OutputBytes: 1 << 20, Inodes: 1024, JSONBytes: 1 << 20, DescriptorCount: 64, IndexDepth: 8, Deadline: time.Minute}}
}
func quarantineTestPlan(t *testing.T, s *Store, id string, input provision.ApprovedImageInput, bundle string, q *OperatorReacquisition) ManagementPlanRecord {
	t.Helper()
	m, err := s.Installation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"plan_id": id, "installation_id": s.productID, "expected_active_revision": m.ActiveRevision, "input": input, "preparation_bundle_digest": bundle}
	if q != nil {
		fields["reacquisition"] = q
	}
	digest := provision.DomainDigest("chatanium-operator-preparation-plan-v1", quarantineTestJSON(t, fields))
	fields["plan_digest"] = digest
	return ManagementPlanRecord{Kind: "operator-preparation", ID: id, Digest: digest, Plan: quarantineTestJSON(t, fields), Phase: "APPROVED", Snapshot: m}
}

// These are persisted pre-upgrade histories, not current-protocol evidence and
// not native cleanup simulations. Production admission creates the quarantine.
func newUnadmittedLegacyQuarantineFixture(t *testing.T) *legacyQuarantineFixture {
	t.Helper()
	ctx := context.Background()
	s := testImagePreparationStore(t)
	m, err := s.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := quarantineTestInput(strings.Repeat("2", 32))
	image := provision.ImageRecord{Version: 1, Revision: provision.Revision(input), SourceKind: input.SourceKind, SourceRef: input.SourceRef, ManifestDigest: provision.Digest([]byte("manifest")), CanonicalArchiveDigest: provision.Digest([]byte("archive")), ConfigDigest: provision.Digest([]byte("config")), DeclarationDigest: provision.Digest([]byte("declaration"))}
	image.ID = provision.RecordID(image)
	cacheID := provision.Digest([]byte("legacy-cache"))
	projects := map[string]uint32{}
	for _, kind := range []string{"source", "cache", "preparation"} {
		project, e := s.ReserveStorage(ctx, input.JobID+":"+kind, kind, 4096, 16)
		if e != nil {
			t.Fatal(e)
		}
		projects[kind] = project
	}
	for kind, generation := range map[string]string{"source": image.ID, "cache": cacheID, "preparation": "image-preparation:" + input.JobID} {
		if err = s.BindStorageGeneration(ctx, input.JobID+":"+kind, generation); err != nil {
			t.Fatal(err)
		}
	}
	space := ImageSpace{JobID: input.JobID, ProvisionID: strings.Repeat("b", 32), Committed: true, Source: filepath.Join(m.Paths.StorageRoot, "images", input.JobID), Cache: filepath.Join(m.Paths.StorageRoot, "prepared", input.JobID), Work: filepath.Join(m.Paths.StorageRoot, "preparation", input.JobID), SourceProject: projects["source"], CacheProject: projects["cache"], WorkProject: projects["preparation"]}
	spaceProps := quarantineTestJSON(t, ProvisionProperties{Name: "image-space", ImageSpace: &space, ProductCreated: true})
	quarantineTestLedger(t, s, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + input.JobID, ProductCreated: true, Desired: spaceProps}, Observed: ObjectObservation{Identity: "image-space:" + input.JobID, Attributes: spaceProps}, State: "OBSERVED", CleanupState: "PENDING"})
	desired := ProvisionProperties{Name: input.JobID, Path: space.Source, Target: space.Cache, Source: space.Work, Revision: m.BundleDigest, ImageSpace: &space, PrepareLimits: &input.Limits, ApprovedImageInput: &input, ProductCreated: true}
	observed := desired
	observed.Digest = image.ID
	observed.Revision = cacheID
	quarantineTestLedger(t, s, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: strings.Repeat("3", 32), Kind: "image", Identity: input.JobID, ProductCreated: true, Desired: quarantineTestJSON(t, desired)}, Observed: ObjectObservation{Identity: input.JobID, Attributes: quarantineTestJSON(t, observed)}, State: "OBSERVED", CleanupState: "PENDING"})
	cache := CacheGeneration{ID: cacheID, ImageRecordID: image.ID, BundleDigest: m.BundleDigest, State: "READY", Directory: filepath.Join(space.Cache, "generation"), ManifestDigest: image.ManifestDigest, CanonicalArchiveDigest: image.CanonicalArchiveDigest}
	if _, err = s.db.ExecContext(ctx, "INSERT INTO image_records VALUES(?,?)", image.ID, quarantineTestJSON(t, image)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, "INSERT INTO cache_generations VALUES(?,?,?)", cacheID, image.ID, quarantineTestJSON(t, cache)); err != nil {
		t.Fatal(err)
	}
	f := &legacyQuarantineFixture{Store: s, Space: space, ImageID: image.ID, CacheID: cacheID, Input: input}
	for index, program := range []string{"preparer", "rungv"} {
		generation := strings.Repeat(string(rune('5'+index)), 32)
		unit := sharedhost.UnitIdentity{Name: "chatanium-image-" + program + "-" + generation + ".service", Generation: generation, BootID: "old-boot", InvocationID: strings.Repeat("7", 32), CgroupPath: "/system.slice/legacy", MainPID: 100 + index, StartTime: 1000 + uint64(index), ExecutableDigest: provision.Digest([]byte(program)), ResourceFingerprint: provision.Digest([]byte("limits"))}
		properties := ProvisionProperties{Name: unit.Name, Source: input.JobID, Unit: &unit, ProductCreated: true}
		internal := properties
		internal.Source = program
		for id, p := range map[string]ProvisionProperties{generation: properties, "systemd-" + generation: internal} {
			raw := quarantineTestJSON(t, p)
			quarantineTestLedger(t, s, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: id, Kind: "unit", Identity: unit.Name, ProductCreated: true, Desired: raw}, Observed: ObjectObservation{Identity: unit.Name, Attributes: raw}, State: "OBSERVED", CleanupState: "COMPLETE"})
			f.HelperIDs = append(f.HelperIDs, id)
		}
	}
	binding := ApprovedImageBinding{ModuleID: input.ModuleID, ImageSelector: input.SourceRef, ImageRecordID: image.ID, ConfigRevision: input.ConfigRevision, ApprovalRevision: input.ApprovalRevision}
	policy := sharedhost.LaunchSpec{ModuleID: binding.ModuleID, ImageDigest: binding.ImageSelector, ConfigRevision: binding.ConfigRevision, ApprovalRevision: binding.ApprovalRevision, InitialEgress: sharedhost.EgressNone, Entrypoint: []string{"/module"}, UID: 1001, GID: 1001, Resources: sharedhost.ResourceLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Pids: 64, PersistentBytes: 1 << 20, PersistentInodes: 1024, ScratchBytes: 1 << 20, ScratchInodes: 1024, ControlMessageMaxBytes: 65536, LogBufferBytes: 1 << 20, LogFileMaxBytes: 1 << 20, LogRetainedFiles: 2}}
	revision := RevisionRecord{ID: "legacy-base", BundleDigest: m.BundleDigest, Images: []ApprovedImageBinding{binding}, LaunchPolicies: []sharedhost.LaunchSpec{policy}}
	if _, err = s.db.ExecContext(ctx, "INSERT INTO revisions VALUES(?,?)", revision.ID, quarantineTestJSON(t, revision)); err != nil {
		t.Fatal(err)
	}
	m.ActiveRevision = revision.ID
	m.State = "RECOVERY_REQUIRED"
	if _, err = s.db.ExecContext(ctx, "UPDATE runtime_installations SET manifest=? WHERE id=?", quarantineTestJSON(t, m), s.productID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, "INSERT INTO approved_image_candidates VALUES(?,?,?,?,?,?)", revision.ID, binding.ModuleID, binding.ImageSelector, image.ID, quarantineTestJSON(t, binding), quarantineTestJSON(t, policy)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{image.ID, cacheID, m.BundleDigest} {
		if err = s.RetainGeneration(ctx, "recovery", id, "candidate:"+revision.ID+":"+binding.ModuleID+":"+image.ID); err != nil {
			t.Fatal(err)
		}
	}
	set, err := s.LegacyAcquisitionQuarantineSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fresh := input
	fresh.JobID = strings.Repeat("f", 32)
	fresh.ConfigRevision = "config-fresh"
	fresh.ApprovalRevision = "approval-fresh"
	f.Plan = quarantineTestPlan(t, s, "reacquisition-plan", fresh, provision.Digest([]byte("staged-B")), &OperatorReacquisition{Version: 1, ExpectedState: m.State, QuarantineSetDigest: set.Digest, RequiredWriterDomainVersion: gvxcontract.PreparationWriterDomainVersion, ReplacesImageRecordID: image.ID})
	f.Binding = binding
	return f
}
func newLegacyQuarantineFixture(t *testing.T) *legacyQuarantineFixture {
	t.Helper()
	f := newUnadmittedLegacyQuarantineFixture(t)
	if err := f.Store.BeginOperatorReacquisition(context.Background(), f.Plan); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLegacyQuarantineAtomicAdmissionAndExactResumedReplay(t *testing.T) {
	ctx := context.Background()
	f := newUnadmittedLegacyQuarantineFixture(t)
	var err error
	var oldRows [][]byte
	for _, id := range f.HelperIDs {
		var raw []byte
		if err = f.Store.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		oldRows = append(oldRows, raw)
	}
	if err = f.Store.BeginOperatorReacquisition(ctx, f.Plan); err != nil {
		t.Fatal(err)
	}
	if err = f.Store.AdvanceManagementPlanState(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "APPROVED", "PREPARED", []byte(`{"image_id":"new-output"}`)); err != nil {
		t.Fatal(err)
	}
	// Its own fresh job history is not a new admission; replay authenticates the
	// frozen approval and original receipt, not unused-job/current-state tests.
	a, err := operatorPreparationApproval(f.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Store.ReserveStorage(ctx, a.Input.JobID+":source", "source", 4096, 16); err != nil {
		t.Fatal(err)
	}
	if err = f.Store.BeginOperatorReacquisition(ctx, f.Plan); err != nil {
		t.Fatal(err)
	}
	for i, id := range f.HelperIDs {
		var raw []byte
		if err = f.Store.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", id).Scan(&raw); err != nil || !bytes.Equal(raw, oldRows[i]) {
			t.Fatalf("COMPLETE helper history changed: %v", err)
		}
	}
	var candidates, archives, held int
	if err = f.Store.db.QueryRowContext(ctx, "SELECT count(*) FROM approved_image_candidates").Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if err = f.Store.db.QueryRowContext(ctx, "SELECT count(*) FROM metadata WHERE key LIKE 'legacy_quarantined_candidate:%'").Scan(&archives); err != nil {
		t.Fatal(err)
	}
	if err = f.Store.db.QueryRowContext(ctx, "SELECT count(*) FROM generation_references WHERE claim LIKE 'candidate:%'").Scan(&held); err != nil {
		t.Fatal(err)
	}
	if candidates != 0 || archives != 1 || held != 3 {
		t.Fatalf("non-atomic candidate archive/retention: %d %d %d", candidates, archives, held)
	}
	changed := f.Plan
	changed.Plan = append(append([]byte(nil), changed.Plan...), ' ')
	if err = f.Store.BeginOperatorReacquisition(ctx, changed); err == nil {
		t.Fatal("replay accepted changed exact approved bytes")
	}
}

func TestLegacyQuarantineRejectsChangedSetAndLeavesNoPartialAdmission(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"membership", "fresh-claim", "unfinished-helper", "wrong-replacement", "changed-complete-authority"} {
		t.Run(change, func(t *testing.T) {
			f := newUnadmittedLegacyQuarantineFixture(t)
			a, err := operatorPreparationApproval(f.Plan)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "membership":
				a.Reacquisition.QuarantineSetDigest = provision.Digest([]byte("different-set"))
				f.Plan = quarantineTestPlan(t, f.Store, f.Plan.ID, a.Input, a.BundleDigest, a.Reacquisition)
			case "fresh-claim":
				if _, err = f.Store.ReserveStorage(ctx, a.Input.JobID+":source", "source", 4096, 16); err != nil {
					t.Fatal(err)
				}
			case "unfinished-helper":
				r, err := f.Store.Provision(ctx, f.HelperIDs[0])
				if err != nil {
					t.Fatal(err)
				}
				r.CleanupState = "PENDING"
				if _, err = f.Store.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", quarantineTestJSON(t, r), r.ID); err != nil {
					t.Fatal(err)
				}
			case "wrong-replacement":
				a.Reacquisition.ReplacesImageRecordID = provision.Digest([]byte("other-image"))
				f.Plan = quarantineTestPlan(t, f.Store, f.Plan.ID, a.Input, a.BundleDigest, a.Reacquisition)
			case "changed-complete-authority":
				addLegacyQuarantineHelper(t, f.Store, f.Space.JobID, strings.Repeat("0", 32), "rungv")
			}
			if err = f.Store.BeginOperatorReacquisition(ctx, f.Plan); err == nil {
				t.Fatal("changed admission authority accepted")
			}
			var mutations int
			if err = f.Store.db.QueryRowContext(ctx, "SELECT count(*) FROM metadata WHERE key='management_active' OR key LIKE 'legacy_acquisition_quarantine:%' OR key LIKE 'quarantined_generation:%' OR key LIKE 'legacy_quarantined_candidate:%'").Scan(&mutations); err != nil || mutations != 0 {
				t.Fatalf("failed admission leaked authority: %d %v", mutations, err)
			}
			var candidates int
			if err = f.Store.db.QueryRowContext(ctx, "SELECT count(*) FROM approved_image_candidates").Scan(&candidates); err != nil || candidates != 1 {
				t.Fatalf("failed admission removed candidate: %d %v", candidates, err)
			}
		})
	}
}

func TestLegacyQuarantineDeniesUseButPreservesRetentionOnlyRecovery(t *testing.T) {
	ctx := context.Background()
	f := newLegacyQuarantineFixture(t)
	for _, id := range []string{f.ImageID, f.CacheID, "image-preparation:" + f.Space.JobID} {
		if err := f.Store.CheckGenerationAvailable(ctx, id); err == nil {
			t.Fatal("quarantined generation remained usable")
		}
		for _, kind := range []string{"live", "preparation"} {
			if err := f.Store.RetainGeneration(ctx, kind, id, "new-use"); err == nil {
				t.Fatalf("quarantine admitted %s reference", kind)
			}
		}
		if err := f.Store.RetainGeneration(ctx, "recovery", id, "retention-only"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.Store.ResolveApprovedImage(ctx, f.Binding.ImageSelector); err == nil {
		t.Fatal("quarantined selector remained usable")
	}
	if _, err := f.Store.CacheForImage(ctx, f.ImageID, f.Plan.Snapshot.BundleDigest); err == nil {
		t.Fatal("quarantined cache remained ready")
	}
	if _, err := f.Store.PreparedImageBinding(ctx, f.ImageID); err == nil {
		t.Fatal("quarantined prepared binding remained usable")
	}
	if _, err := f.Store.Image(ctx, f.ImageID); err != nil {
		t.Fatal("raw image history disappeared", err)
	}
	if _, err := (&MetadataReader{store: f.Store}).Cache(ctx, f.CacheID); err != nil {
		t.Fatal("retained raw cache history disappeared", err)
	}
	receipt, found, err := f.Store.LegacyAcquisitionQuarantine(ctx, "image", f.Space.JobID)
	if err != nil || !found || receipt.Lineage.ProvisionID != f.Space.ProvisionID {
		t.Fatalf("missing exact quarantine receipt: %+v %v", receipt, err)
	}
	if err = f.Store.CompleteRecovery(ctx, quarantineTestCleanup(t)); err != nil {
		t.Fatal("quarantine blocked retention-only explicit recovery", err)
	}
	if err = f.Store.CompleteManagementPlan(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "APPROVED", quarantineTestCleanup(t)); err != nil {
		t.Fatal(err)
	}
	m, err := f.Store.Installation(ctx)
	if err != nil || m.State != "READY" {
		t.Fatalf("explicit recovery failed: %+v %v", m, err)
	}
	if err = f.Store.SetDesired(ctx, "RUNNING", strings.Repeat("a", 32)); err == nil {
		t.Fatal("active quarantine gained RUNNING authority")
	}
}

func quarantineTestCleanup(t *testing.T) CleanupEvidence {
	t.Helper()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	return CleanupEvidence{BootID: strings.TrimSpace(string(boot)), JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, QuotaReclaimed: true}
}
func TestReacquisitionCompletionPreservesRecoveryRequired(t *testing.T) {
	ctx := context.Background()
	f := newLegacyQuarantineFixture(t)
	if err := f.Store.AdvanceManagementPlan(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "APPROVED", "FAILED_CLEAN"); err != nil {
		t.Fatal(err)
	}
	incomplete := quarantineTestCleanup(t)
	incomplete.MountsAbsent = false
	if err := f.Store.CompleteManagementPlan(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "FAILED_CLEAN", incomplete); err == nil {
		t.Fatal("tag bypassed actual cleanup evidence")
	}
	if err := f.Store.CompleteManagementPlan(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "FAILED_CLEAN", quarantineTestCleanup(t)); err != nil {
		t.Fatal(err)
	}
	m, err := f.Store.Installation(ctx)
	if err != nil || m.State != "RECOVERY_REQUIRED" || m.BundleDigest != f.Plan.Snapshot.BundleDigest || m.ActiveRevision != f.Plan.Snapshot.ActiveRevision {
		t.Fatalf("completion activated or recovered installation: %+v %v", m, err)
	}
	var active int
	if err = f.Store.db.QueryRowContext(ctx, "SELECT count(*) FROM metadata WHERE key='management_active'").Scan(&active); err != nil || active != 0 {
		t.Fatalf("own management marker remained: %d %v", active, err)
	}
	if err = f.Store.BeginOperatorReacquisition(ctx, f.Plan); err != nil {
		t.Fatal("committed replay rejected original authority", err)
	}
}

func TestStagedPreparationBundleAdmissionBindsExactReviewedJob(t *testing.T) {
	ctx := context.Background()
	f := newLegacyQuarantineFixture(t)
	a, err := operatorPreparationApproval(f.Plan)
	if err != nil {
		t.Fatal(err)
	}
	space := f.Space
	space.JobID = a.Input.JobID
	space.ProvisionID = strings.Repeat("c", 32)
	space.Source = filepath.Join(f.Plan.Snapshot.Paths.StorageRoot, "images", space.JobID)
	space.Cache = filepath.Join(f.Plan.Snapshot.Paths.StorageRoot, "prepared", space.JobID)
	space.Work = filepath.Join(f.Plan.Snapshot.Paths.StorageRoot, "preparation", space.JobID)
	space.Committed = false
	p := ProvisionProperties{Name: space.JobID, ImageSpace: &space, ApprovedImageInput: &a.Input, Revision: a.BundleDigest}
	quarantineTestLedger(t, f.Store, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: strings.Repeat("e", 32), Kind: "image", Identity: space.JobID, ProductCreated: true, Desired: quarantineTestJSON(t, p)}, State: "INTENT", CleanupState: "PENDING"})
	launch := PreparationWriterLaunch{BundleDigest: a.BundleDigest, JobID: space.JobID, ProvisionID: space.ProvisionID}
	check := func(l PreparationWriterLaunch, s ImageSpace) error {
		tx, e := f.Store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			return e
		}
		defer tx.Rollback()
		return validatePreparationLaunchBundleTx(ctx, tx, f.Store.productID, l, s)
	}
	if err = check(launch, space); err != nil {
		t.Fatal("exact reviewed staged helper rejected", err)
	}
	changed := launch
	changed.BundleDigest = provision.Digest([]byte("unreviewed-B"))
	if err = check(changed, space); err == nil {
		t.Fatal("arbitrary staged helper accepted")
	}
	changed = launch
	changed.JobID = strings.Repeat("9", 32)
	if err = check(changed, space); err == nil {
		t.Fatal("reviewed bundle authorized another job")
	}
	changedSpace := space
	changedSpace.Source = filepath.Join(f.Plan.Snapshot.Paths.StorageRoot, "images", "other")
	if err = check(launch, changedSpace); err == nil {
		t.Fatal("reviewed helper authorized another source")
	}
}

// Fresh current-protocol metadata is separate from the immutable legacy rows.
// Native identities are deterministic state-validation fixtures, not host proof.
func addReviewedPreparationOutput(t *testing.T, f *legacyQuarantineFixture) (ApprovedImageBinding, CacheGeneration) {
	t.Helper()
	ctx := context.Background()
	a, err := operatorPreparationApproval(f.Plan)
	if err != nil {
		t.Fatal(err)
	}
	m, err := f.Store.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	projects := map[string]uint32{}
	for _, kind := range []string{"source", "cache", "preparation"} {
		project, e := f.Store.ReserveStorage(ctx, a.Input.JobID+":"+kind, kind, 4096, 16)
		if e != nil {
			t.Fatal(e)
		}
		projects[kind] = project
	}
	space := ImageSpace{JobID: a.Input.JobID, ProvisionID: strings.Repeat("c", 32), Source: filepath.Join(m.Paths.StorageRoot, "images", a.Input.JobID), Cache: filepath.Join(m.Paths.StorageRoot, "prepared", a.Input.JobID), Work: filepath.Join(m.Paths.StorageRoot, "preparation", a.Input.JobID), SourceProject: projects["source"], CacheProject: projects["cache"], WorkProject: projects["preparation"]}
	spaceDesired := quarantineTestJSON(t, ProvisionProperties{Name: "image-space", ImageSpace: &space, ProductCreated: true})
	committed := space
	committed.Committed = true
	spaceObserved := quarantineTestJSON(t, ProvisionProperties{Name: "image-space", ImageSpace: &committed, ProductCreated: true})
	quarantineTestLedger(t, f.Store, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + space.JobID, ProductCreated: true, Desired: spaceDesired}, Observed: ObjectObservation{Identity: "image-space:" + space.JobID, Attributes: spaceObserved}, State: "OBSERVED", CleanupState: "PENDING"})
	image := provision.ImageRecord{Version: 1, Revision: provision.Revision(a.Input), SourceKind: a.Input.SourceKind, SourceRef: a.Input.SourceRef, ManifestDigest: provision.Digest([]byte("fresh-manifest")), CanonicalArchiveDigest: provision.Digest([]byte("fresh-archive")), ConfigDigest: provision.Digest([]byte("fresh-config")), DeclarationDigest: provision.Digest([]byte("fresh-declaration"))}
	image.ID = provision.RecordID(image)
	cache := CacheGeneration{ID: provision.Digest([]byte("fresh-staged-cache")), ImageRecordID: image.ID, BundleDigest: a.BundleDigest, State: "READY", Directory: filepath.Join(space.Cache, "generation"), ManifestDigest: image.ManifestDigest, CanonicalArchiveDigest: image.CanonicalArchiveDigest}
	for kind, generation := range map[string]string{"source": image.ID, "cache": cache.ID, "preparation": "image-preparation:" + space.JobID} {
		if err = f.Store.BindStorageGeneration(ctx, space.JobID+":"+kind, generation); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = f.Store.db.ExecContext(ctx, "INSERT INTO image_records VALUES(?,?)", image.ID, quarantineTestJSON(t, image)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Store.db.ExecContext(ctx, "INSERT INTO cache_generations VALUES(?,?,?)", cache.ID, image.ID, quarantineTestJSON(t, cache)); err != nil {
		t.Fatal(err)
	}
	desired := ProvisionProperties{
		Name: space.JobID, Path: space.Source, Target: space.Cache, Source: space.Work,
		ImageSpace: &space, Revision: a.BundleDigest, PrepareLimits: &a.Input.Limits,
		ApprovedImageInput: &a.Input, ProductCreated: true,
	}
	observed := desired
	observed.Digest = image.ID
	observed.Revision = cache.ID
	if err := validateImageAcquisitionProperties(desired); err != nil {
		t.Fatalf("invalid original acquisition intent fixture: %v", err)
	}
	if err := validateImageAcquisitionProperties(observed); err != nil {
		t.Fatalf("invalid committed acquisition receipt fixture: %v", err)
	}
	quarantineTestLedger(t, f.Store, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: strings.Repeat("e", 32), Kind: "image", Identity: space.JobID, ProductCreated: true, Desired: quarantineTestJSON(t, desired)}, Observed: ObjectObservation{Identity: space.JobID, Attributes: quarantineTestJSON(t, observed)}, State: "OBSERVED", CleanupState: "PENDING"})
	for index, program := range []string{"preparer", "rungv"} {
		generation := strings.Repeat(string(rune('8'+index)), 32)
		unit := sharedhost.UnitIdentity{Name: "chatanium-image-" + program + "-" + generation + ".service", Generation: generation, BootID: "fixture-boot", InvocationID: strings.Repeat("a", 32), CgroupPath: "/system.slice/" + program, MainPID: 200 + index, StartTime: 2000 + uint64(index), ExecutableDigest: provision.Digest([]byte("stage")), ResourceFingerprint: provision.Digest([]byte("limits"))}
		sourcePool := NativeRootIdentity{RootID: "source-pool", HostPath: filepath.Join(m.Paths.StorageRoot, "images"), Dev: 1, Ino: 100, Mode: 0700}
		source := NativeRootIdentity{RootID: "source", HostPath: space.Source, Dev: 1, Ino: 103, Project: space.SourceProject, UID: 1001, GID: 1002, Mode: 0700}
		cacheRoot := NativeRootIdentity{RootID: "cache-barrier", HostPath: space.Cache, Dev: 1, Ino: 102, Mode: 0700, Project: space.CacheProject}
		cacheData := NativeRootIdentity{RootID: "cache", HostPath: cache.Directory, Dev: 1, Ino: 105, UID: 1001, GID: 1002, Mode: 0700, Project: space.CacheProject}
		workPool := NativeRootIdentity{RootID: "work-pool", HostPath: filepath.Join(m.Paths.StorageRoot, "preparation"), Dev: 1, Ino: 101, Mode: 0700}
		work := NativeRootIdentity{RootID: "work", HostPath: space.Work, Dev: 1, Ino: 104, UID: 1001, GID: 1002, Mode: 0700, Project: space.WorkProject}
		purpose := gvxstage.PreparationPurpose
		if program == "rungv" {
			purpose = gvxstage.LoadPurpose
			source.UID = 0
			source.Mode = 0550
		}
		digest := provision.Digest([]byte("stage"))
		launch := PreparationWriterLaunch{Version: gvxcontract.PreparationWriterDomainVersion, ProtocolVersion: gvxcontract.PreparationWriterProtocolVersion, InstallationID: f.Store.productID, JobID: space.JobID, ProvisionID: space.ProvisionID, UnitName: unit.Name, Generation: generation, BootID: unit.BootID, Purpose: purpose, BundleDigest: a.BundleDigest, StageDigest: digest, TargetDigest: provision.Digest([]byte(program)), StagePath: "/chatanium/base/gvx-stage", TargetPath: "/chatanium/base/target", ArgumentDigest: digest, DeclarationDigest: digest, PreparerUID: 1001, PreparerGID: 1002, Layout: PreparationStorageView{Version: 1, JobID: space.JobID, ProvisionID: space.ProvisionID, Source: PreparationStorageRoot{Barrier: sourcePool, Data: source, ReadOnly: program == "rungv"}, Cache: PreparationStorageRoot{Barrier: cacheRoot, Data: cacheData}, Work: PreparationStorageRoot{Barrier: workPool, Data: work}}}
		launch.FilterVersion = gvxcontract.PreparationWriterFilterVersion
		writer := testPreparationWriterRecord(t, launch, unit)
		pipes := []string{"pipe:[201]", "pipe:[202]", "pipe:[203]"}
		details := quarantineTestJSON(t, UnitAbsenceDetails{UnitAbsent: true, CgroupEmpty: true, TransportPipes: pipes, WriterUserNamespace: &writer.Birth.UserNamespace, WriterUserNamespaceAbsent: true})
		absence := CleanupEvidence{BootID: unit.BootID, Units: []sharedhost.UnitIdentity{unit}, JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, Details: details}
		properties := ProvisionProperties{Name: unit.Name, Source: space.JobID, Unit: &unit, Writer: &writer, Limits: &sharedhost.ResourceLimits{Pids: 8}, MountNamespace: &writer.Birth.MountNamespace, MountNamespaceDisposition: NamespacePrivate, TransportPipes: pipes, CgroupEmpty: true, Exit: &sharedhost.ProcessExit{Kind: "exit", Value: 0}, Absence: &absence}
		internal := properties
		internal.Source = program
		for id, p := range map[string]ProvisionProperties{generation: properties, "systemd-" + generation: internal} {
			dispatch := p
			dispatch.Writer = nil
			dispatch.Absence = nil
			if strings.HasPrefix(id, "systemd-") {
				dispatch.Writer = &PreparationWriterRecord{Launch: launch}
			}
			quarantineTestLedger(t, f.Store, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: id, Kind: "unit", Identity: unit.Name, ProductCreated: true, Desired: quarantineTestJSON(t, dispatch)}, Observed: ObjectObservation{Identity: unit.Name, Attributes: quarantineTestJSON(t, p)}, State: "OBSERVED", CleanupState: "COMPLETE"})
		}
	}
	return ApprovedImageBinding{ModuleID: a.Input.ModuleID, ConfigRevision: a.Input.ConfigRevision, ApprovalRevision: a.Input.ApprovalRevision, ImageRecordID: image.ID, ImageSelector: image.SourceRef}, cache
}

func TestBindPreparedImageRetainsExactReviewedStagedBundleAndCache(t *testing.T) {
	ctx := context.Background()
	for _, reacquisition := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal-new-operator-plan", true: "reacquisition"}[reacquisition], func(t *testing.T) {
			var f *legacyQuarantineFixture
			if reacquisition {
				f = newLegacyQuarantineFixture(t)
			} else {
				f = newUnadmittedLegacyQuarantineFixture(t)
				a, err := operatorPreparationApproval(f.Plan)
				if err != nil {
					t.Fatal(err)
				}
				m := f.Plan.Snapshot
				m.State = "READY"
				if _, err = f.Store.db.ExecContext(ctx, "UPDATE runtime_installations SET manifest=? WHERE id=?", quarantineTestJSON(t, m), f.Store.productID); err != nil {
					t.Fatal(err)
				}
				f.Plan = quarantineTestPlan(t, f.Store, "normal-plan", a.Input, a.BundleDigest, nil)
				if err = f.Store.BeginManagementPlan(ctx, f.Plan); err != nil {
					t.Fatal(err)
				}
			}
			binding, cache := addReviewedPreparationOutput(t, f)
			// A compatible-looking installed-A cache must never replace reviewed B.
			installed := cache
			installed.ID = provision.Digest([]byte("installed-A-substitute"))
			installed.BundleDigest = f.Plan.Snapshot.BundleDigest
			if _, err := f.Store.db.ExecContext(ctx, "INSERT INTO cache_generations VALUES(?,?,?)", installed.ID, binding.ImageRecordID, quarantineTestJSON(t, installed)); err != nil {
				t.Fatal(err)
			}
			if err := f.Store.BindPreparedImage(ctx, binding); err != nil {
				t.Fatal(err)
			}
			var receiptRaw []byte
			if err := f.Store.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "prepared_image_receipt:"+binding.ImageRecordID).Scan(&receiptRaw); err != nil {
				t.Fatal(err)
			}
			var receipt preparedImageReceipt
			if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.CacheID != cache.ID || receipt.PreparationBundleDigest != cache.BundleDigest {
				t.Fatalf("installed digest/cache substituted for reviewed staged output: %+v", receipt)
			}
			for _, id := range []string{binding.ImageRecordID, cache.ID, cache.BundleDigest} {
				var held int
				if err := f.Store.db.QueryRowContext(ctx, "SELECT count(*) FROM generation_references WHERE kind='recovery' AND id=? AND claim=?", id, "prepared-image:"+binding.ImageRecordID).Scan(&held); err != nil || held != 1 {
					t.Fatalf("selected output/bundle not retained: %s %d %v", id, held, err)
				}
			}
			state := quarantineTestJSON(t, map[string]string{"image_id": binding.ImageRecordID, "cache_id": cache.ID, "preparation_bundle_digest": cache.BundleDigest})
			if err := f.Store.AdvanceManagementPlanState(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "APPROVED", "PREPARED", state); err != nil {
				t.Fatal(err)
			}
			if err := f.Store.BindPreparedImage(ctx, binding); err != nil {
				t.Fatal("exact prepared receipt replay failed", err)
			}
		})
	}
}

func TestBindPreparedImageRejectsMissingChangedAndAmbiguousSelectedAuthority(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"missing-staged-cache", "changed-receipt", "ambiguous-plan", "changed-input", "changed-cache-attributes"} {
		t.Run(change, func(t *testing.T) {
			f := newLegacyQuarantineFixture(t)
			binding, cache := addReviewedPreparationOutput(t, f)
			switch change {
			case "missing-staged-cache":
				installed := cache
				installed.ID = provision.Digest([]byte("installed-only"))
				installed.BundleDigest = f.Plan.Snapshot.BundleDigest
				if _, err := f.Store.db.ExecContext(ctx, "INSERT INTO cache_generations VALUES(?,?,?)", installed.ID, binding.ImageRecordID, quarantineTestJSON(t, installed)); err != nil {
					t.Fatal(err)
				}
				if _, err := f.Store.db.ExecContext(ctx, "DELETE FROM cache_generations WHERE id=?", cache.ID); err != nil {
					t.Fatal(err)
				}
			case "changed-receipt":
				state := quarantineTestJSON(t, map[string]string{"image_id": binding.ImageRecordID, "cache_id": provision.Digest([]byte("other-cache")), "preparation_bundle_digest": cache.BundleDigest})
				if err := f.Store.AdvanceManagementPlanState(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "APPROVED", "PREPARED", state); err != nil {
					t.Fatal(err)
				}
			case "ambiguous-plan":
				a, err := operatorPreparationApproval(f.Plan)
				if err != nil {
					t.Fatal(err)
				}
				other := quarantineTestPlan(t, f.Store, "another-plan", a.Input, a.BundleDigest, a.Reacquisition)
				key, _ := managementKey(other.Kind, other.ID)
				if _, err = f.Store.db.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?)", key, quarantineTestJSON(t, other)); err != nil {
					t.Fatal(err)
				}
			case "changed-input":
				r, err := f.Store.Provision(ctx, strings.Repeat("e", 32))
				if err != nil {
					t.Fatal(err)
				}
				var observed ProvisionProperties
				if err = json.Unmarshal(r.Observed.Attributes, &observed); err != nil {
					t.Fatal(err)
				}
				observed.ApprovedImageInput.CredentialRef = "changed-credential"
				r.Observed.Attributes = quarantineTestJSON(t, observed)
				if _, err = f.Store.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", quarantineTestJSON(t, r), r.ID); err != nil {
					t.Fatal(err)
				}
			case "changed-cache-attributes":
				cache.ManifestDigest = provision.Digest([]byte("other-manifest"))
				if _, err := f.Store.db.ExecContext(ctx, "UPDATE cache_generations SET record=? WHERE id=?", quarantineTestJSON(t, cache), cache.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Store.BindPreparedImage(ctx, binding); err == nil {
				t.Fatal("changed selected cache/receipt/input authority was accepted")
			}
			var saved int
			if err := f.Store.db.QueryRowContext(ctx, "SELECT count(*) FROM metadata WHERE key=?", "prepared_image:"+binding.ImageRecordID).Scan(&saved); err != nil || saved != 0 {
				t.Fatalf("failed binding leaked provenance: %d %v", saved, err)
			}
		})
	}
}

func addLegacyQuarantineHelper(t *testing.T, s *Store, job, generation, program string) {
	t.Helper()
	unit := sharedhost.UnitIdentity{Name: "chatanium-image-" + program + "-" + generation + ".service", Generation: generation, BootID: "legacy-boot", InvocationID: strings.Repeat("7", 32), CgroupPath: "/system.slice/legacy", MainPID: 123, StartTime: 456, ExecutableDigest: provision.Digest([]byte(program)), ResourceFingerprint: provision.Digest([]byte("limits"))}
	outer := ProvisionProperties{Name: unit.Name, Source: job, Unit: &unit, ProductCreated: true}
	internal := outer
	internal.Source = program
	for id, p := range map[string]ProvisionProperties{generation: outer, "systemd-" + generation: internal} {
		raw := quarantineTestJSON(t, p)
		quarantineTestLedger(t, s, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: id, Kind: "unit", Identity: unit.Name, ProductCreated: true, Desired: raw}, Observed: ObjectObservation{Identity: unit.Name, Attributes: raw}, State: "OBSERVED", CleanupState: "COMPLETE"})
	}
}

func TestLegacyQuarantineDerivedCacheResolvesOnlyExactOriginalReceipt(t *testing.T) {
	ctx := context.Background()
	f := newUnadmittedLegacyQuarantineFixture(t)
	m, err := f.Store.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	job := strings.Repeat("4", 32)
	cacheProject, err := f.Store.ReserveStorage(ctx, job+":cache", "cache", 4096, 16)
	if err != nil {
		t.Fatal(err)
	}
	workProject, err := f.Store.ReserveStorage(ctx, job+":preparation", "preparation", 4096, 16)
	if err != nil {
		t.Fatal(err)
	}
	space := ImageSpace{JobID: job, ProvisionID: strings.Repeat("d", 32), Committed: true, ReusedSource: true, SourceGenerationID: f.ImageID, Source: f.Space.Source, SourceProject: f.Space.SourceProject, Cache: filepath.Join(m.Paths.StorageRoot, "prepared", job), CacheProject: cacheProject, Work: filepath.Join(m.Paths.StorageRoot, "preparation", job), WorkProject: workProject}
	p := ProvisionProperties{Name: "image-space", ImageSpace: &space}
	raw := quarantineTestJSON(t, p)
	quarantineTestLedger(t, f.Store, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + job, ProductCreated: true, Desired: raw}, Observed: ObjectObservation{Identity: "image-space:" + job, Attributes: raw}, State: "OBSERVED", CleanupState: "PENDING"})
	cache := CacheGeneration{ID: provision.Digest([]byte("derived-cache")), ImageRecordID: f.ImageID, BundleDigest: provision.Digest([]byte("legacy-derived-bundle")), State: "READY", Directory: filepath.Join(space.Cache, "generation")}
	image, err := f.Store.Image(ctx, f.ImageID)
	if err != nil {
		t.Fatal(err)
	}
	cache.CanonicalArchiveDigest = image.CanonicalArchiveDigest
	cache.ManifestDigest = image.ManifestDigest
	if err = f.Store.BindStorageGeneration(ctx, job+":cache", cache.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Store.db.ExecContext(ctx, "INSERT INTO cache_generations VALUES(?,?,?)", cache.ID, f.ImageID, quarantineTestJSON(t, cache)); err != nil {
		t.Fatal(err)
	}
	desired := ProvisionProperties{Name: job, ImageSpace: &space, Digest: f.ImageID, Revision: cache.BundleDigest}
	observed := desired
	observed.Revision = cache.ID
	quarantineTestLedger(t, f.Store, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: strings.Repeat("a", 32), Kind: "image", Identity: job, ProductCreated: true, Desired: quarantineTestJSON(t, desired)}, Observed: ObjectObservation{Identity: job, Attributes: quarantineTestJSON(t, observed)}, State: "OBSERVED", CleanupState: "PENDING"})
	addLegacyQuarantineHelper(t, f.Store, job, strings.Repeat("0", 32), "rungv")
	set, err := f.Store.LegacyAcquisitionQuarantineSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Lineages) != 1 || len(set.Lineages[0].CacheIDs) != 2 || len(set.Lineages[0].DerivedJobIDs) != 1 || set.Lineages[0].DerivedJobIDs[0] != job || set.Lineages[0].DerivedProvisionIDs[0] != space.ProvisionID {
		t.Fatalf("derived cache was inferred/lost: %+v", set)
	}
	a, err := operatorPreparationApproval(f.Plan)
	if err != nil {
		t.Fatal(err)
	}
	a.Reacquisition.QuarantineSetDigest = set.Digest
	f.Plan = quarantineTestPlan(t, f.Store, f.Plan.ID, a.Input, a.BundleDigest, a.Reacquisition)
	if err = f.Store.BeginOperatorReacquisition(ctx, f.Plan); err != nil {
		t.Fatal(err)
	}
	receipt, found, err := f.Store.LegacyAcquisitionQuarantine(ctx, "image", job)
	if err != nil || !found || receipt.Lineage.JobID != f.Space.JobID || receipt.Lineage.ProvisionID != f.Space.ProvisionID {
		t.Fatalf("derived receipt did not resolve original acquisition: %+v %v", receipt, err)
	}
	if err = f.Store.CheckGenerationAvailable(ctx, cache.ID); err == nil {
		t.Fatal("derived quarantined cache remained usable")
	}
	r, err := f.Store.Provision(ctx, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	var changed ProvisionProperties
	if err = json.Unmarshal(r.Observed.Attributes, &changed); err != nil {
		t.Fatal(err)
	}
	changed.ImageSpace.SourceGenerationID = provision.Digest([]byte("unrelated-source"))
	r.Observed.Attributes = quarantineTestJSON(t, changed)
	if _, err = f.Store.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", quarantineTestJSON(t, r), r.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.Store.LegacyAcquisitionQuarantine(ctx, "image", job); err == nil {
		t.Fatal("changed derived authority remained accepted")
	}
}

func TestLegacyQuarantineDevelopmentLineageRetainsHistoryWithoutUse(t *testing.T) {
	ctx := context.Background()
	f := newUnadmittedLegacyQuarantineFixture(t)
	m, err := f.Store.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	job := strings.Repeat("a", 32)
	projects := map[string]uint32{}
	for _, kind := range []string{"source", "cache", "preparation"} {
		project, e := f.Store.ReserveStorage(ctx, job+":"+kind, kind, 4096, 16)
		if e != nil {
			t.Fatal(e)
		}
		projects[kind] = project
	}
	generation := "development-worker:" + job
	for _, kind := range []string{"source", "cache"} {
		if err = f.Store.BindStorageGeneration(ctx, job+":"+kind, generation); err != nil {
			t.Fatal(err)
		}
	}
	space := ImageSpace{JobID: job, ProvisionID: strings.Repeat("d", 32), Committed: true, Source: filepath.Join(m.Paths.StorageRoot, "images", job), Cache: filepath.Join(m.Paths.StorageRoot, "prepared", job), Work: filepath.Join(m.Paths.StorageRoot, "preparation", job), SourceProject: projects["source"], CacheProject: projects["cache"], WorkProject: projects["preparation"]}
	spaceRaw := quarantineTestJSON(t, ProvisionProperties{Name: "image-space", ImageSpace: &space})
	quarantineTestLedger(t, f.Store, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + job, ProductCreated: true, Desired: spaceRaw}, Observed: ObjectObservation{Identity: "image-space:" + job, Attributes: spaceRaw}, State: "OBSERVED", CleanupState: "PENDING"})
	properties := ProvisionProperties{Name: job, ImageSpace: &space, Digest: provision.Digest([]byte("development-artifact")), Revision: m.ActiveRevision}
	raw := quarantineTestJSON(t, properties)
	quarantineTestLedger(t, f.Store, ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: strings.Repeat("e", 32), Kind: "development-worker", Identity: job, ProductCreated: true, Desired: raw}, Observed: ObjectObservation{Identity: job, Attributes: raw}, State: "OBSERVED", CleanupState: "PENDING"})
	addLegacyQuarantineHelper(t, f.Store, job, strings.Repeat("0", 32), "preparer")
	set, err := f.Store.LegacyAcquisitionQuarantineSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Lineages) != 2 || set.Lineages[0].Kind != "development-worker" {
		t.Fatalf("development membership not canonical: %+v", set)
	}
	a, err := operatorPreparationApproval(f.Plan)
	if err != nil {
		t.Fatal(err)
	}
	a.Reacquisition.QuarantineSetDigest = set.Digest
	f.Plan = quarantineTestPlan(t, f.Store, f.Plan.ID, a.Input, a.BundleDigest, a.Reacquisition)
	if err = f.Store.BeginOperatorReacquisition(ctx, f.Plan); err != nil {
		t.Fatal(err)
	}
	if _, found, err := (&MetadataReader{store: f.Store}).LegacyAcquisitionQuarantine(ctx, "development-worker", job); err != nil || !found {
		t.Fatalf("missing passive development quarantine receipt: %v", err)
	}
	if err = f.Store.RetainGeneration(ctx, "preparation", generation, "new-development-use"); err == nil {
		t.Fatal("quarantined development artifact was admitted")
	}
	if err = f.Store.RetainGeneration(ctx, "recovery", generation, "old-development-retention"); err != nil {
		t.Fatal(err)
	}
	history, err := f.Store.ObjectProvisions(ctx, "development-worker", job)
	if err != nil || len(history) != 1 || history[0].State != "OBSERVED" {
		t.Fatalf("development history lost: %+v %v", history, err)
	}
}

func TestLegacyQuarantineAcceptsOnlyExactCompleteUnsupportedFilterV1(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"exact-v1", "wrong-filter-digest", "partial-v1", "pending-v1"} {
		t.Run(change, func(t *testing.T) {
			f := newUnadmittedLegacyQuarantineFixture(t)
			binding, cache := addReviewedPreparationOutput(t, f)
			a, err := operatorPreparationApproval(f.Plan)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := f.Store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			history, err := quarantineHistoryTx(ctx, tx)
			tx.Rollback()
			if err != nil {
				t.Fatal(err)
			}
			var outputSpace ImageSpace
			for _, r := range history {
				if r.Kind != "unit" {
					continue
				}
				var observed, desired ProvisionProperties
				if err = json.Unmarshal(r.Observed.Attributes, &observed); err != nil {
					t.Fatal(err)
				}
				if observed.Writer == nil || observed.Writer.Launch.JobID != a.Input.JobID {
					continue
				}
				// Persisted v1 predates the launch filter-version declaration.
				observed.Writer.Launch.FilterVersion = 0
				observed.Writer.Evidence.FilterVersion = 1
				observed.Writer.Evidence.FilterDigest = preparationUnsupportedFilterV1Digest
				switch change {
				case "wrong-filter-digest":
					observed.Writer.Evidence.FilterDigest = provision.Digest([]byte("not-the-original-fixed-filter"))
				case "partial-v1":
					observed.Writer.Evidence = nil
					observed.Writer.StartIntent = false
				case "pending-v1":
					r.CleanupState = "PENDING"
				}
				if err = json.Unmarshal(r.Desired, &desired); err != nil {
					t.Fatal(err)
				}
				if desired.Writer != nil {
					desired.Writer.Launch.FilterVersion = 0
				}
				r.Desired = quarantineTestJSON(t, desired)
				r.Observed.Attributes = quarantineTestJSON(t, observed)
				if _, err = f.Store.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", quarantineTestJSON(t, r), r.ID); err != nil {
					t.Fatal(err)
				}
			}
			acquisition, err := f.Store.Provision(ctx, strings.Repeat("e", 32))
			if err != nil {
				t.Fatal(err)
			}
			var observed ProvisionProperties
			if err = json.Unmarshal(acquisition.Observed.Attributes, &observed); err != nil {
				t.Fatal(err)
			}
			outputSpace = *observed.ImageSpace
			if err = f.Store.RequirePreparationWriterDomain(ctx, outputSpace); err == nil {
				t.Fatal("unsupported v1 supplied current writer-domain readiness")
			}
			set, err := f.Store.LegacyAcquisitionQuarantineSet(ctx)
			if change != "exact-v1" {
				if err == nil {
					t.Fatal("corrupt, partial, or pending v1 became quarantine authority")
				}
				return
			}
			if err != nil {
				t.Fatal("exact immutable COMPLETE v1 was stranded", err)
			}
			member := false
			for _, l := range set.Lineages {
				member = member || l.ImageRecordID == binding.ImageRecordID && len(l.CacheIDs) == 1 && l.CacheIDs[0] == cache.ID
			}
			if !member {
				t.Fatalf("exact v1 missing from bounded lineage: %+v", set)
			}
			fresh := a.Input
			fresh.JobID = strings.Repeat("7", 32)
			a.Reacquisition.QuarantineSetDigest = set.Digest
			f.Plan = quarantineTestPlan(t, f.Store, "v1-reacquisition", fresh, a.BundleDigest, a.Reacquisition)
			if err = f.Store.BeginOperatorReacquisition(ctx, f.Plan); err != nil {
				t.Fatal(err)
			}
			if _, found, err := f.Store.LegacyAcquisitionQuarantine(ctx, "image", outputSpace.JobID); err != nil || !found {
				t.Fatalf("exact COMPLETE v1 lacks quarantine-only receipt: %v", err)
			}
			if err = f.Store.CheckGenerationAvailable(ctx, binding.ImageRecordID); err == nil {
				t.Fatal("quarantined v1 regained use authority")
			}
		})
	}
}

func newUpdatePreparationReplayFixture(t *testing.T, phase, state, mutation string) (*Store, ManagementPlanRecord, ProvisionProperties, PreparationWriterRecord) {
	t.Helper()
	ctx := context.Background()
	f := newUnadmittedLegacyQuarantineFixture(t)
	approval, err := operatorPreparationApproval(f.Plan)
	if err != nil {
		t.Fatal(err)
	}
	m := f.Plan.Snapshot
	m.State = "READY"
	if _, err = f.Store.db.ExecContext(ctx, "UPDATE runtime_installations SET manifest=? WHERE id=?", quarantineTestJSON(t, m), f.Store.productID); err != nil {
		t.Fatal(err)
	}
	f.Plan = quarantineTestPlan(t, f.Store, "source-preparation", approval.Input, approval.BundleDigest, nil)
	if err = f.Store.BeginManagementPlan(ctx, f.Plan); err != nil {
		t.Fatal(err)
	}
	binding, cache := addReviewedPreparationOutput(t, f)
	if err = f.Store.BindPreparedImage(ctx, binding); err != nil {
		t.Fatal(err)
	}
	receipt := quarantineTestJSON(t, map[string]string{"image_id": binding.ImageRecordID, "cache_id": cache.ID, "preparation_bundle_digest": cache.BundleDigest})
	if err = f.Store.AdvanceManagementPlanState(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "APPROVED", "PREPARED", receipt); err != nil {
		t.Fatal(err)
	}
	if err = f.Store.CompleteManagementPlan(ctx, f.Plan.Kind, f.Plan.ID, f.Plan.Digest, "PREPARED", quarantineTestCleanup(t)); err != nil {
		t.Fatal(err)
	}
	sourceWriter, err := f.Store.PreparationWriter(ctx, "systemd-"+strings.Repeat("9", 32))
	if err != nil {
		t.Fatal(err)
	}
	base, err := f.Store.Revision(ctx, m.ActiveRevision)
	if err != nil {
		t.Fatal(err)
	}
	candidate := base
	candidate.ID = "update-candidate"
	candidate.BundleDigest = provision.Digest([]byte("update-candidate-C"))
	candidate.Config = []byte(`{}`)
	candidate.ConfigDigest = provision.Digest(candidate.Config)
	policy := base.LaunchPolicies[0]
	policy.ModuleID, policy.ImageDigest = binding.ModuleID, binding.ImageSelector
	policy.ConfigRevision, policy.ApprovalRevision = binding.ConfigRevision, binding.ApprovalRevision
	candidate.Images = []ApprovedImageBinding{binding}
	candidate.LaunchPolicies = []sharedhost.LaunchSpec{policy}
	if mutation == "unreviewed-source" {
		candidate.Images = base.Images
		candidate.LaunchPolicies = base.LaunchPolicies
	}
	fields := map[string]any{
		"plan_id": "update-replay", "installation_id": f.Store.productID,
		"expected_active_revision": m.ActiveRevision, "candidate_bundle_digest": candidate.BundleDigest,
		"candidate_revision": candidate, "backup_id": strings.Repeat("4", 32), "objects": []any{},
	}
	digest := provision.DomainDigest("chatanium-update-plan-v1", quarantineTestJSON(t, fields))
	fields["plan_digest"] = digest
	plan := ManagementPlanRecord{Kind: "update", ID: "update-replay", Digest: digest, Plan: quarantineTestJSON(t, fields), Snapshot: m, Phase: "APPROVED"}
	if err = f.Store.BeginManagementPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	currentPhase := "APPROVED"
	for _, next := range []string{"BACKED_UP", "PUBLISHED", "REBUILT"} {
		if currentPhase == phase {
			break
		}
		if err = f.Store.AdvanceManagementPlan(ctx, plan.Kind, plan.ID, plan.Digest, currentPhase, next); err != nil {
			t.Fatal(err)
		}
		currentPhase = next
	}
	if state == "RECOVERY_REQUIRED" {
		// This is the same durable failure transition used by Update's defer.
		if err = f.Store.RequireRecovery(ctx, "release update cutover incomplete"); err != nil {
			t.Fatal(err)
		}
	}
	job := strings.Repeat("7", 32)
	cacheProject, err := f.Store.ReserveStorage(ctx, job+":cache", "cache", 4096, 16)
	if err != nil {
		t.Fatal(err)
	}
	workProject, err := f.Store.ReserveStorage(ctx, job+":preparation", "preparation", 4096, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Store.BindStorageGeneration(ctx, job+":preparation", "image-preparation:"+job); err != nil {
		t.Fatal(err)
	}
	space := ImageSpace{
		JobID: job, ProvisionID: strings.Repeat("d", 32), ReusedSource: true,
		SourceGenerationID: binding.ImageRecordID, Source: sourceWriter.Launch.Layout.Source.Data.HostPath,
		SourceProject: sourceWriter.Launch.Layout.Source.Data.Project,
		Cache:         filepath.Join(m.Paths.StorageRoot, "prepared", job), CacheProject: cacheProject,
		Work: filepath.Join(m.Paths.StorageRoot, "preparation", job), WorkProject: workProject,
	}
	spaceProperties := ProvisionProperties{Name: "image-space", ImageSpace: &space, ProductCreated: true}
	if err = f.Store.BeginProvision(ctx, ProvisionIntent{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + job, ProductCreated: true, Desired: quarantineTestJSON(t, spaceProperties)}); err != nil {
		t.Fatal(err)
	}
	acquisition := ProvisionProperties{
		Name: job, Path: space.Source, Source: space.Work, Target: space.Cache,
		ImageSpace: &space, Digest: binding.ImageRecordID, Revision: candidate.BundleDigest,
		PrepareLimits: &approval.Input.Limits, ProductCreated: true,
	}
	if err = f.Store.BeginProvision(ctx, ProvisionIntent{ID: strings.Repeat("a", 32), Kind: "image", Identity: job, ProductCreated: true, Desired: quarantineTestJSON(t, acquisition)}); err != nil {
		t.Fatal(err)
	}
	for _, generation := range []string{binding.ImageRecordID, "image-preparation:" + job} {
		if err = f.Store.RetainGeneration(ctx, "preparation", generation, job); err != nil {
			t.Fatal(err)
		}
	}
	launch := sourceWriter.Launch
	launch.JobID, launch.ProvisionID = job, space.ProvisionID
	launch.Generation = strings.Repeat("0", 32)
	launch.UnitName = "chatanium-image-rungv-" + launch.Generation + ".service"
	launch.BundleDigest = candidate.BundleDigest
	launch.BootID = quarantineTestCleanup(t).BootID
	launch.Layout.JobID, launch.Layout.ProvisionID = job, space.ProvisionID
	launch.Layout.Cache.Barrier.HostPath, launch.Layout.Cache.Barrier.Project, launch.Layout.Cache.Barrier.Ino = space.Cache, cacheProject, 202
	launch.Layout.Cache.Data.HostPath, launch.Layout.Cache.Data.Project, launch.Layout.Cache.Data.Ino = filepath.Join(space.Cache, "generation"), cacheProject, 203
	launch.Layout.Work.Data.HostPath, launch.Layout.Work.Data.Project, launch.Layout.Work.Data.Ino = space.Work, workProject, 204
	unit := sourceWriter.Birth.Unit
	unit.Name, unit.Generation, unit.BootID = launch.UnitName, launch.Generation, launch.BootID
	unit.InvocationID, unit.CgroupPath = strings.Repeat("b", 32), "/system.slice/"+launch.UnitName
	unit.MainPID, unit.StartTime = 301, 3001
	writer := testPreparationWriterRecord(t, launch, unit)
	proposed := sharedhost.UnitIdentity{Name: launch.UnitName, Generation: launch.Generation, BootID: launch.BootID}
	properties := ProvisionProperties{Name: proposed.Name, Source: "rungv", Unit: &proposed, Limits: &sharedhost.ResourceLimits{NanoCPUs: approval.Input.Limits.NanoCPUs, MemoryBytes: approval.Input.Limits.MemoryBytes, Pids: approval.Input.Limits.Tasks}, Writer: &PreparationWriterRecord{Launch: launch}, ProductCreated: true}
	if mutation == "foreign-pending" || mutation == "changed-base" || mutation == "running" {
		if err = f.Store.updateInstallation(ctx, func(manifest *InstallationManifest, _ *sql.Tx) error {
			switch mutation {
			case "foreign-pending":
				manifest.PendingRevision = "foreign-candidate"
			case "changed-base":
				manifest.ActiveRevision = "foreign-base"
			case "running":
				manifest.DesiredRunState = "RUNNING"
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if mutation == "missing-active" {
		if _, err = f.Store.db.ExecContext(ctx, "DELETE FROM metadata WHERE key='management_active'"); err != nil {
			t.Fatal(err)
		}
	}
	if mutation == "wrong-bundle" {
		properties.Writer.Launch.BundleDigest = provision.Digest([]byte("unapproved-update-bundle"))
	}
	return f.Store, plan, properties, writer
}

func TestStagedUpdatePreparationGateRequiresExactPublishedReplay(t *testing.T) {
	for _, test := range []struct {
		name, phase, state, mutation string
		allow                        bool
	}{
		{name: "published-recovery-replay", phase: "PUBLISHED", state: "RECOVERY_REQUIRED", allow: true},
		{name: "published-ready", phase: "PUBLISHED", state: "READY", allow: true},
		{name: "unpublished-recovery", phase: "BACKED_UP", state: "RECOVERY_REQUIRED"},
		{name: "rebuilt-recovery", phase: "REBUILT", state: "RECOVERY_REQUIRED"},
		{name: "unpublished-ready", phase: "BACKED_UP", state: "READY"},
		{name: "foreign-pending", phase: "PUBLISHED", state: "RECOVERY_REQUIRED", mutation: "foreign-pending"},
		{name: "changed-base", phase: "PUBLISHED", state: "RECOVERY_REQUIRED", mutation: "changed-base"},
		{name: "running", phase: "PUBLISHED", state: "RECOVERY_REQUIRED", mutation: "running"},
		{name: "missing-active", phase: "PUBLISHED", state: "RECOVERY_REQUIRED", mutation: "missing-active"},
		{name: "wrong-bundle", phase: "PUBLISHED", state: "RECOVERY_REQUIRED", mutation: "wrong-bundle"},
		{name: "unreviewed-source", phase: "PUBLISHED", state: "RECOVERY_REQUIRED", mutation: "unreviewed-source"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store, plan, properties, writer := newUpdatePreparationReplayFixture(t, test.phase, test.state, test.mutation)
			id := "systemd-" + writer.Launch.Generation
			err := store.BeginProvision(ctx, ProvisionIntent{ID: id, Kind: "unit", Identity: writer.Launch.UnitName, ProductCreated: true, Desired: quarantineTestJSON(t, properties)})
			if !test.allow {
				if err == nil {
					t.Fatal("staged update helper admitted changed phase/base/bundle/source authority")
				}
				var count int
				if err = store.db.QueryRowContext(ctx, "SELECT count(*) FROM provisioning_ledger WHERE id=?", id).Scan(&count); err != nil || count != 0 {
					t.Fatalf("failed stage admission leaked native dispatch intent: %d %v", count, err)
				}
				return
			}
			if err != nil {
				t.Fatal("exact PUBLISHED replay could not journal its required staged helper", err)
			}
			birth := writer
			birth.Evidence, birth.StartIntent = nil, false
			properties.Unit = &writer.Birth.Unit
			properties.Writer = &birth
			properties.MountNamespace = &writer.Birth.MountNamespace
			properties.MountNamespaceDisposition = NamespacePrivate
			properties.TransportPipes = []string{"pipe:[301]", "pipe:[302]", "pipe:[303]"}
			if err = store.ObserveProvision(ctx, id, ObjectObservation{Identity: writer.Launch.UnitName, Attributes: quarantineTestJSON(t, properties)}); err != nil {
				t.Fatal("exact replay birth was refused before ARM", err)
			}
			properties.Writer = &writer
			if err = store.ObserveProvision(ctx, id, ObjectObservation{Identity: writer.Launch.UnitName, Attributes: quarantineTestJSON(t, properties)}); err != nil {
				t.Fatal("exact replay full evidence/START was refused", err)
			}
			manifest, err := store.Installation(ctx)
			if err != nil || manifest.State != test.state || manifest.ActiveRevision != plan.Snapshot.ActiveRevision || manifest.BundleDigest != plan.Snapshot.BundleDigest || manifest.PendingRevision != "" {
				t.Fatalf("staged replay restored READY or changed the installed release: %+v %v", manifest, err)
			}
		})
	}
}
