//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
	"path/filepath"
	"strings"
)

func openMetadata(ctx context.Context, id RuntimeInstallationID) (*host.MetadataReader, error) {
	if e := rootRequired(); e != nil {
		return nil, e
	}
	path, e := controlPath(id)
	if e != nil {
		return nil, e
	}
	gate, e := acquireManagementGuard(ctx)
	if e != nil {
		return nil, e
	}
	reader, e := host.OpenMetadata(ctx, path, string(id), gate)
	if e != nil {
		closeUnadoptedManagementGuard(gate)
		return nil, e
	}
	return reader, nil
}
func ReadInstalledConfig(ctx context.Context, id RuntimeInstallationID) ([]byte, error) {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return nil, e
	}
	defer metadata.Close()
	m, e := metadata.Installation(ctx)
	if e != nil {
		return nil, e
	}
	revision, e := metadata.Revision(ctx, m.ActiveRevision)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if e = unix.Lstat(m.Paths.Config, &st); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != 0 || st.Nlink != 1 {
		return nil, errors.New("installed configuration must remain private root0600")
	}
	raw, e := readProtected(m.Paths.Config, 16<<20)
	if e != nil {
		return nil, e
	}
	if provision.Digest(raw) != revision.ConfigDigest || !bytes.Equal(raw, revision.Config) {
		return nil, errors.New("installed configuration differs from active immutable approval")
	}
	return raw, nil
}
func InspectPreparedImage(ctx context.Context, id RuntimeInstallationID, selector string) (provision.ImageRecord, error) {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return provision.ImageRecord{}, e
	}
	defer metadata.Close()
	return inspectMetadataImage(ctx, metadata, selector)
}
func inspectMetadataImage(ctx context.Context, metadata *host.MetadataReader, selector string) (provision.ImageRecord, error) {
	var image provision.ImageRecord
	key := strings.TrimPrefix(selector, "record:")
	if provision.ValidDigest(key) {
		record, e := metadata.Image(ctx, key)
		if e != nil {
			return image, e
		}
		image = record
	} else {
		records, e := metadata.Images(ctx)
		if e != nil {
			return image, e
		}
		for _, record := range records {
			if record.SourceRef == selector || record.ExecutionRef == selector {
				if image.ID != "" && image.ID != record.ID {
					return image, errors.New("ambiguous prepared selector; use exact record:<ID>")
				}
				image = record
			}
		}
	}
	if image.ID == "" {
		return image, errors.New("committed prepared image not found")
	}
	m, e := metadata.Installation(ctx)
	if e != nil {
		return image, e
	}
	if e = provision.ValidateRecord(image, maximumPreparationLimits(m)); e != nil {
		return image, e
	}
	records, e := metadata.PendingProvisions(ctx)
	if e != nil {
		return image, e
	}
	committed := false
	for _, record := range records {
		if record.Kind != "image" || record.State != "OBSERVED" {
			continue
		}
		var p host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return image, e
		}
		if p.Digest != image.ID || p.Revision == "" {
			continue
		}
		cache, e := metadata.Cache(ctx, p.Revision)
		if e != nil {
			return image, e
		}
		if cache.State == "READY" && cache.BundleDigest == m.BundleDigest && cache.ImageRecordID == image.ID && cache.ManifestDigest == image.ManifestDigest && cache.CanonicalArchiveDigest == image.CanonicalArchiveDigest {
			committed = true
		}
	}
	if !committed {
		return image, errors.New("prepared image has no committed compatible cache metadata")
	}
	return image, nil
}
func PreparedImageBinding(ctx context.Context, id RuntimeInstallationID, recordID string) (host.ApprovedImageBinding, error) {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return host.ApprovedImageBinding{}, e
	}
	defer metadata.Close()
	if _, e = inspectMetadataImage(ctx, metadata, "record:"+recordID); e != nil {
		return host.ApprovedImageBinding{}, e
	}
	return metadata.PreparedImageBinding(ctx, recordID)
}
func preparedImageBinding(ctx context.Context, store *host.Store, recordID string) (host.ApprovedImageBinding, error) {
	return store.PreparedImageBinding(ctx, recordID)
}
func InspectPreparedBinding(ctx context.Context, id RuntimeInstallationID, selector string) (host.ApprovedImageBinding, provision.ImageRecord, error) {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return host.ApprovedImageBinding{}, provision.ImageRecord{}, e
	}
	defer metadata.Close()
	image, e := inspectMetadataImage(ctx, metadata, selector)
	if e != nil {
		return host.ApprovedImageBinding{}, image, e
	}
	binding, e := metadata.PreparedImageBinding(ctx, image.ID)
	return binding, image, e
}
func ImagePreparationInput(ctx context.Context, id RuntimeInstallationID, jobID string) (provision.ApprovedImageInput, error) {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return provision.ApprovedImageInput{}, e
	}
	defer metadata.Close()
	return metadata.ImagePreparationInput(ctx, jobID)
}

// inspectCandidatePreparation is private to reviewed update selection. Unlike
// installed-image lookup, it accepts only the exact selected B receipt, never a
// selector or an arbitrary bundle override for Configure.
func inspectCandidatePreparation(ctx context.Context, metadata reacquisitionMetadata, plan ApprovedPreparationPlan, receipt operatorPreparationReceipt, candidateBundle string) (host.ApprovedImageBinding, error) {
	var binding host.ApprovedImageBinding
	if plan.PreparationBundleDigest != candidateBundle || receipt.PreparationBundleDigest != candidateBundle {
		return binding, errors.New("preparation receipt is not for the verified candidate bundle")
	}
	input, err := metadata.ImagePreparationInput(ctx, plan.Input.JobID)
	if err != nil {
		return binding, err
	}
	if input != plan.Input {
		return binding, errors.New("selected preparation differs from original full acquisition input")
	}
	image, err := metadata.Image(ctx, receipt.ImageID)
	if err != nil {
		return binding, err
	}
	if err = provision.ValidateRecord(image, input.Limits); err != nil {
		return binding, err
	}
	if image.ID != receipt.ImageID || image.Revision != provision.Revision(input) || image.SourceKind != input.SourceKind || image.SourceRef != input.SourceRef || input.SourceKind != "registry" && image.SourceDigest != input.ArchiveDigest {
		return binding, errors.New("selected image differs from original acquisition revision")
	}
	binding, err = metadata.PreparedImageBinding(ctx, image.ID)
	if err != nil {
		return binding, err
	}
	selector := "record:" + image.ID
	if image.SourceKind == "registry" {
		selector = image.SourceRef
	}
	if binding != (host.ApprovedImageBinding{ModuleID: input.ModuleID, ImageSelector: selector, ImageRecordID: image.ID, ConfigRevision: input.ConfigRevision, ApprovalRevision: input.ApprovalRevision}) {
		return binding, errors.New("selected prepared binding differs from reviewed module and approval provenance")
	}
	cache, err := metadata.CacheForImage(ctx, image.ID, candidateBundle)
	if err != nil {
		return binding, err
	}
	if cache.ID != receipt.CacheID || cache.State != "READY" || cache.BundleDigest != candidateBundle || cache.ImageRecordID != image.ID || cache.ManifestDigest != image.ManifestDigest || cache.CanonicalArchiveDigest != image.CanonicalArchiveDigest {
		return binding, errors.New("selected preparation cache differs from immutable receipt")
	}
	history, err := metadata.ObjectProvisions(ctx, "image", input.JobID)
	if err != nil {
		return binding, err
	}
	if len(history) != 1 || history[0].State != "OBSERVED" || history[0].CleanupState == "COMPLETE" || !history[0].ProductCreated || history[0].ExistedBefore {
		return binding, errors.New("selected acquisition publication is missing, ambiguous or retired")
	}
	var desired, published host.ProvisionProperties
	if err = gvxcontract.DecodeStrict(history[0].Desired, 64<<10, 16, &desired); err != nil {
		return binding, err
	}
	if err = gvxcontract.DecodeStrict(history[0].Observed.Attributes, 64<<10, 16, &published); err != nil {
		return binding, err
	}
	if desired.ApprovedImageInput == nil || *desired.ApprovedImageInput != input || desired.Revision != candidateBundle || desired.PrepareLimits == nil || *desired.PrepareLimits != input.Limits || published.Digest != image.ID || published.Revision != receipt.CacheID || published.ImageSpace == nil {
		return binding, errors.New("selected receipt differs from original committed publication")
	}
	space := *published.ImageSpace
	if space.JobID != input.JobID || space.ReusedSource || cache.Directory != filepath.Join(space.Cache, "generation") {
		return binding, errors.New("replacement must be the exact fresh original acquisition")
	}
	record, err := metadata.Provision(ctx, space.ProvisionID)
	if err != nil {
		return binding, err
	}
	var committed host.ProvisionProperties
	if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &committed); err != nil {
		return binding, err
	}
	space.Committed = true
	if record.Kind != "image" || record.Identity != "image-space:"+input.JobID || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" || committed.ImageSpace == nil || *committed.ImageSpace != space {
		return binding, errors.New("selected acquisition has not committed its exact physical publication")
	}
	for _, claim := range []struct{ id, generation string }{{input.JobID + ":source", image.ID}, {input.JobID + ":cache", receipt.CacheID}} {
		generation, err := metadata.StorageGeneration(ctx, claim.id)
		if err != nil {
			return binding, err
		}
		if generation != claim.generation {
			return binding, errors.New("selected preparation storage generation is retired or rebound")
		}
	}
	if err = metadata.RequirePreparationWriterDomain(ctx, space); err != nil {
		return binding, err
	}
	return binding, nil
}
