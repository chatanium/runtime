//go:build linux

package bootstrap

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

func TestOperatorPreparationReplayPreservesApprovedIdentity(t *testing.T) {
	plan := ApprovedPreparationPlan{
		PlanID: "approved-plan", InstallationID: "installation", ExpectedActiveRevision: "active-revision",
		PreparationBundleDigest: provision.Digest([]byte("reviewed-helper-bundle")),
		Input: provision.ApprovedImageInput{
			JobID: "approved-job", ModuleID: "new-module", ConfigRevision: "reserved-config", ApprovalRevision: "reserved-approval",
			SourceKind: "registry", SourceRef: "example.invalid/module:reviewed", CredentialRef: "opaque-task-reference", Platform: "linux/amd64",
			Limits: provision.PrepareLimits{NanoCPUs: 1e9, MemoryBytes: 512 << 20, Tasks: 64, InputBytes: 4096, ExpandedBytes: 8192, OutputBytes: 4096, Inodes: 32, JSONBytes: 4096, DescriptorCount: 32, IndexDepth: 4, Deadline: time.Minute},
		},
	}
	if err := plan.Input.Validate(); err != nil {
		t.Fatal(err)
	}
	var err error
	plan.PlanDigest, err = PreparationPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(operatorPreparationReceipt{ImageID: provision.Digest([]byte("image")), CacheID: provision.Digest([]byte("cache")), PreparationBundleDigest: plan.PreparationBundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	record := host.ManagementPlanRecord{Kind: "operator-preparation", ID: plan.PlanID, Digest: plan.PlanDigest, Plan: raw, Phase: "COMMITTED", State: state}
	for _, request := range []provision.ApprovedImageInput{{JobID: plan.Input.JobID}, plan.Input} {
		saved, err := operatorPreparationReplayPlan([]host.ManagementPlanRecord{record}, request)
		if err != nil {
			t.Fatal(err)
		}
		if saved != plan || provision.Revision(saved.Input) != provision.Revision(plan.Input) {
			t.Fatal("same-job replay regenerated approved plan, credential, revision or limits")
		}
	}
	for name, mutate := range map[string]func(*provision.ApprovedImageInput){
		"module":            func(in *provision.ApprovedImageInput) { in.ModuleID = "other-module" },
		"source kind":       func(in *provision.ApprovedImageInput) { in.SourceKind = "oci-archive" },
		"source reference":  func(in *provision.ApprovedImageInput) { in.SourceRef = "example.invalid/module:other" },
		"archive digest":    func(in *provision.ApprovedImageInput) { in.ArchiveDigest = provision.Digest(nil) },
		"credential":        func(in *provision.ApprovedImageInput) { in.CredentialRef = "replacement-reference" },
		"config revision":   func(in *provision.ApprovedImageInput) { in.ConfigRevision = "other-config" },
		"approval revision": func(in *provision.ApprovedImageInput) { in.ApprovalRevision = "other-approval" },
		"platform":          func(in *provision.ApprovedImageInput) { in.Platform = "linux/arm64" },
		"limits":            func(in *provision.ApprovedImageInput) { in.Limits.OutputBytes += 4096 },
	} {
		t.Run(name, func(t *testing.T) {
			request := plan.Input
			mutate(&request)
			if _, err := operatorPreparationReplayPlan([]host.ManagementPlanRecord{record}, request); err == nil {
				t.Fatal("same-job replay accepted a changed acquisition approval")
			}
		})
	}
	if _, err := operatorPreparationReplayPlan(nil, provision.ApprovedImageInput{JobID: plan.Input.JobID}); err == nil {
		t.Fatal("unknown caller-selected job accepted as a fresh reservation")
	}
	if _, err := operatorPreparationReplayPlan([]host.ManagementPlanRecord{record, record}, plan.Input); err == nil {
		t.Fatal("ambiguous job approval accepted")
	}
	record.Digest = provision.Digest(nil)
	if _, err := operatorPreparationReplayPlan([]host.ManagementPlanRecord{record}, plan.Input); err == nil {
		t.Fatal("changed durable plan binding accepted")
	}
}

func TestOperatorReacquisitionPlanUsesExactActiveBinding(t *testing.T) {
	oldImage := provision.Digest([]byte("legacy-image"))
	otherImage := provision.Digest([]byte("other-image"))
	m := host.InstallationManifest{RuntimeInstallationID: "installation", ActiveRevision: "active-revision", State: "RECOVERY_REQUIRED", DesiredRunState: "STOPPED"}
	set := host.LegacyQuarantineSet{
		Version: 1, InstallationID: m.RuntimeInstallationID, ActiveRevision: m.ActiveRevision,
		Digest: provision.Digest([]byte("quarantine-set")), RequiredWriterDomainVersion: gvxcontract.PreparationWriterDomainVersion,
		Lineages: []host.LegacyAcquisitionLineage{{Kind: "image", JobID: "legacy-job", ImageRecordID: oldImage}},
	}
	revision := host.RevisionRecord{ID: m.ActiveRevision, Images: []host.ApprovedImageBinding{
		{ModuleID: "legacy-module", ImageRecordID: oldImage, ImageSelector: "shared-selector"},
		{ModuleID: "other-module", ImageRecordID: otherImage, ImageSelector: "shared-selector"},
	}}
	for _, module := range []string{"legacy-module", "other-module", "new-module"} {
		got, err := plannedOperatorReacquisition(m, set, revision, module)
		if err != nil {
			t.Fatal(err)
		}
		wantOldImage := ""
		if module == "legacy-module" {
			wantOldImage = oldImage
		}
		if got == nil || got.ExpectedState != m.State || got.QuarantineSetDigest != set.Digest || got.ReplacesImageRecordID != wantOldImage {
			t.Fatalf("module %s inferred or lost exact legacy replacement: %+v", module, got)
		}
	}
	for _, mutate := range []func(*host.LegacyQuarantineSet){
		func(s *host.LegacyQuarantineSet) { s.InstallationID = "another-installation" },
		func(s *host.LegacyQuarantineSet) { s.ActiveRevision = "another-revision" },
		func(s *host.LegacyQuarantineSet) { s.RequiredWriterDomainVersion++ },
		func(s *host.LegacyQuarantineSet) { s.Digest = "" },
	} {
		changed := set
		mutate(&changed)
		if _, err := plannedOperatorReacquisition(m, changed, revision, "legacy-module"); err == nil {
			t.Fatal("changed quarantine authority accepted")
		}
	}
	if _, err := plannedOperatorReacquisition(m, host.LegacyQuarantineSet{}, revision, "legacy-module"); err == nil {
		t.Fatal("recovery-required preparation accepted without exact legacy authority")
	}
	m.State = "READY"
	if got, err := plannedOperatorReacquisition(m, host.LegacyQuarantineSet{}, revision, "new-module"); err != nil || got != nil {
		t.Fatalf("ordinary preparation changed: %+v, %v", got, err)
	}
}

func TestOperatorPreparationReacquisitionReplayBindsReviewedAuthority(t *testing.T) {
	plan := ApprovedPreparationPlan{
		PlanID: "approved-plan", InstallationID: "installation", ExpectedActiveRevision: "active-revision",
		PreparationBundleDigest: provision.Digest([]byte("staged-bundle")),
		Reacquisition:           &host.OperatorReacquisition{Version: 1, ExpectedState: "RECOVERY_REQUIRED", QuarantineSetDigest: provision.Digest([]byte("quarantine")), RequiredWriterDomainVersion: gvxcontract.PreparationWriterDomainVersion, ReplacesImageRecordID: provision.Digest([]byte("old-image"))},
		Input: provision.ApprovedImageInput{
			JobID: "fresh-job", ModuleID: "module", ConfigRevision: "config", ApprovalRevision: "approval",
			SourceKind: "registry", SourceRef: "example.invalid/module:reviewed", Platform: "linux/amd64", CredentialRef: "opaque-credential",
			Limits: provision.PrepareLimits{NanoCPUs: 1e9, MemoryBytes: 512 << 20, Tasks: 64, InputBytes: 4096, ExpandedBytes: 8192, OutputBytes: 4096, Inodes: 32, JSONBytes: 4096, DescriptorCount: 32, IndexDepth: 4, Deadline: time.Minute},
		},
	}
	var err error
	plan.PlanDigest, err = PreparationPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateOperatorPreparationPlan(plan); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ApprovedPreparationPlan){
		"bundle": func(p *ApprovedPreparationPlan) {
			p.PreparationBundleDigest = provision.Digest([]byte("installed-bundle"))
		},
		"state": func(p *ApprovedPreparationPlan) { p.Reacquisition.ExpectedState = "READY" },
		"set": func(p *ApprovedPreparationPlan) {
			p.Reacquisition.QuarantineSetDigest = provision.Digest([]byte("different-quarantine"))
		},
		"replacement": func(p *ApprovedPreparationPlan) {
			p.Reacquisition.ReplacesImageRecordID = provision.Digest([]byte("different-image"))
		},
		"protocol": func(p *ApprovedPreparationPlan) { p.Reacquisition.RequiredWriterDomainVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := plan
			authority := *plan.Reacquisition
			changed.Reacquisition = &authority
			mutate(&changed)
			if err := validateOperatorPreparationPlan(changed); err == nil {
				t.Fatal("changed reviewed reacquisition authority accepted")
			}
		})
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"APPROVED", "PREPARED", "COMMITTED"} {
		record := host.ManagementPlanRecord{Kind: "operator-preparation", ID: plan.PlanID, Digest: plan.PlanDigest, Plan: raw, Phase: phase}
		if phase != "APPROVED" {
			record.State, err = json.Marshal(operatorPreparationReceipt{ImageID: provision.Digest([]byte("fresh-image")), CacheID: provision.Digest([]byte("selected-cache")), PreparationBundleDigest: plan.PreparationBundleDigest})
			if err != nil {
				t.Fatal(err)
			}
		}
		saved, err := operatorPreparationReplayPlan([]host.ManagementPlanRecord{record}, provision.ApprovedImageInput{JobID: plan.Input.JobID})
		if err != nil || !reflect.DeepEqual(saved, plan) {
			t.Fatalf("%s replay changed immutable authority: %+v, %v", phase, saved, err)
		}
		if phase == "APPROVED" {
			continue
		}
		for _, receipt := range []operatorPreparationReceipt{
			{ImageID: provision.Digest([]byte("fresh-image")), CacheID: provision.Digest([]byte("selected-cache"))},
			{ImageID: provision.Digest([]byte("fresh-image")), CacheID: provision.Digest([]byte("selected-cache")), PreparationBundleDigest: provision.Digest([]byte("installed-bundle"))},
			{ImageID: provision.Digest([]byte("fresh-image")), PreparationBundleDigest: plan.PreparationBundleDigest},
		} {
			record.State, err = json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = operatorPreparationReplayPlan([]host.ManagementPlanRecord{record}, plan.Input); err == nil {
				t.Fatal("replay accepted a missing or substituted committed receipt binding")
			}
		}
	}
}
