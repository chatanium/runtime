//go:build linux

package bootstrap

import (
	"testing"

	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

func TestPreparationDefaultsAdmitTwoDistinctRetainedImages(t *testing.T) {
	total := host.StorageBudget{
		SourceBytes: 8 << 30, SourceInodes: 1 << 20,
		CacheBytes: 8 << 30, CacheInodes: 1 << 20,
		PreparationBytes: 8 << 30, PreparationInodes: 1 << 20,
	}
	base := maximumPreparationLimits(host.InstallationManifest{Budget: total})
	available := total
	var first provision.ApprovedImageInput
	// Model the consumer's exact claims, not observed image size: source keeps
	// 2*InputBytes, cache keeps OutputBytes, and each keeps Inodes. Work is a
	// temporary ExpandedBytes+OutputBytes claim released after publication.
	for _, job := range []string{"first-image-job", "second-image-job"} {
		limits, err := FitPreparationLimits(base, total, available)
		if err != nil {
			t.Fatalf("%s defaults: %v", job, err)
		}
		input := provision.ApprovedImageInput{
			JobID: job, ModuleID: job, ConfigRevision: "config", ApprovalRevision: "approval",
			SourceKind: "registry", SourceRef: "example.invalid/" + job + ":approved", Platform: "linux/amd64", Limits: limits,
		}
		if err = input.Validate(); err != nil {
			t.Fatal(err)
		}
		if err = checkOperatorPreparationStorage(input.Limits, available); err != nil {
			t.Fatalf("%s cannot reserve its exact preparation peak: %v", job, err)
		}
		available.SourceBytes -= 2 * limits.InputBytes
		available.SourceInodes -= limits.Inodes
		available.CacheBytes -= limits.OutputBytes
		available.CacheInodes -= limits.Inodes
		available.PreparationBytes -= limits.ExpandedBytes + limits.OutputBytes
		available.PreparationInodes -= limits.Inodes
		if available.SourceBytes < 0 || available.SourceInodes < 0 || available.CacheBytes < 0 || available.CacheInodes < 0 || available.PreparationBytes < 0 || available.PreparationInodes < 0 {
			t.Fatalf("%s overcommitted source/cache/work reservations", job)
		}
		// Publication retains source/cache claims, never the temporary work peak.
		available.PreparationBytes += limits.ExpandedBytes + limits.OutputBytes
		available.PreparationInodes += limits.Inodes
		if first.JobID == "" {
			first = input
		} else if provision.Revision(first) == provision.Revision(input) {
			t.Fatal("distinct retained image jobs shared preparation identity")
		}
	}
	if available.SourceBytes != total.SourceBytes/2 || available.CacheBytes != total.CacheBytes/2 || available.SourceInodes != total.SourceInodes/2 || available.CacheInodes != total.CacheInodes/2 {
		t.Fatalf("two default publications did not preserve two more retained-image slots: %+v", available)
	}
	if available.PreparationBytes != total.PreparationBytes || available.PreparationInodes != total.PreparationInodes {
		t.Fatal("temporary work claims were retained after publication")
	}
}

func TestPreparationDefaultsCapActualAvailabilityWithoutDoubleDivision(t *testing.T) {
	total := host.StorageBudget{
		SourceBytes: 8 << 30, SourceInodes: 1 << 20,
		CacheBytes: 8 << 30, CacheInodes: 1 << 20,
		PreparationBytes: 8 << 30, PreparationInodes: 1 << 20,
	}
	base := maximumPreparationLimits(host.InstallationManifest{Budget: total})
	available := total
	available.SourceBytes /= 2
	available.CacheBytes /= 2
	available.SourceInodes /= 2
	available.CacheInodes /= 2
	limits, err := FitPreparationLimits(base, total, available)
	if err != nil {
		t.Fatal(err)
	}
	if limits.InputBytes != total.SourceBytes/8 || limits.OutputBytes != total.CacheBytes/4 || limits.Inodes != total.SourceInodes/4 {
		t.Fatalf("planned per-job availability was quartered a second time: %+v", limits)
	}
	available.SourceBytes = 2*4096 + 8191
	available.CacheBytes = 2*4096 + 4095
	available.PreparationBytes = 5*4096 + 4095
	available.SourceInodes, available.CacheInodes, available.PreparationInodes = 19, 17, 13
	limits, err = FitPreparationLimits(base, total, available)
	if err != nil {
		t.Fatal(err)
	}
	if err = checkOperatorPreparationStorage(limits, available); err != nil {
		t.Fatal(err)
	}
	if limits.InputBytes != 4096 || limits.OutputBytes != 8192 || limits.ExpandedBytes != 8192 || limits.Inodes != 13 {
		t.Fatalf("defaults did not round down against actual remaining claims: %+v", limits)
	}
	if limits.NanoCPUs != base.NanoCPUs || limits.MemoryBytes != base.MemoryBytes || limits.Tasks != base.Tasks || limits.JSONBytes != base.JSONBytes || limits.DescriptorCount != base.DescriptorCount || limits.IndexDepth != base.IndexDepth || limits.Deadline != base.Deadline {
		t.Fatal("storage fitting changed nonstorage authority")
	}
	available.SourceBytes = 8191
	if _, err = FitPreparationLimits(base, total, available); err == nil {
		t.Fatal("sub-block source peak accepted")
	}
}

func TestOperatorExplicitPreparationLimitsAreNotResized(t *testing.T) {
	total := host.StorageBudget{
		SourceBytes: 8 << 30, SourceInodes: 1 << 20,
		CacheBytes: 8 << 30, CacheInodes: 1 << 20,
		PreparationBytes: 8 << 30, PreparationInodes: 1 << 20,
	}
	limits := maximumPreparationLimits(host.InstallationManifest{Budget: total})
	limits.InputBytes, limits.OutputBytes, limits.ExpandedBytes = 2<<30, 3<<30, 4<<30
	before := limits
	if err := checkOperatorPreparationStorage(limits, total); err != nil {
		t.Fatal(err)
	}
	if limits != before {
		t.Fatal("explicit approved limits were resized to the default share")
	}
	limits.InputBytes++
	if err := checkOperatorPreparationStorage(limits, total); err == nil {
		t.Fatal("unaligned explicit limits silently rounded")
	}
}
