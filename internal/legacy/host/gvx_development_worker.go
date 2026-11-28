//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

func developmentGeneration(job string) string { return "development-worker:" + job }
func (m *ImageManager) PrepareDevelopmentWorker(ctx context.Context, input bundle.DevelopmentWorkerInput, stream io.ReadCloser) (bundle.VerifiedDevelopmentWorker, error) {
	var zero bundle.VerifiedDevelopmentWorker
	if stream == nil {
		return zero, errors.New("development artifact stream required")
	}
	defer stream.Close()
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := provision.ValidateDevelopmentInput(input); e != nil {
		return zero, e
	}
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Limits.Deadline)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	if e := m.recover(ctx); e != nil {
		return zero, e
	}
	installation, e := m.store.Installation(ctx)
	if e != nil {
		return zero, e
	}
	if installation.BundleDigest != m.cfg.Bundle.Digest {
		return zero, errors.New("development preparation requires the active installed release base")
	}
	limits := m.cfg.Limits
	limits.InputBytes = input.ArchiveBytes
	limits.ExpandedBytes = input.ArchiveBytes
	limits.OutputBytes = input.ArchiveBytes
	limits.JSONBytes = min(limits.JSONBytes, int64(provision.DevelopmentMetadataMax))
	limits.Inodes = min(limits.Inodes, installation.Budget.SourceInodes, installation.Budget.CacheInodes, installation.Budget.PreparationInodes)
	limits.DescriptorCount = min(limits.DescriptorCount, 4096)
	for _, claim := range []struct {
		kind  string
		bytes int64
	}{{"source", 2 * input.ArchiveBytes}, {"cache", input.ArchiveBytes}, {"preparation", 2 * input.ArchiveBytes}} {
		available, inodes, e := m.store.AvailableStorage(ctx, claim.kind)
		if e != nil {
			return zero, e
		}
		if available < claim.bytes {
			return zero, errors.New("development artifact peak exceeds available installed quota")
		}
		limits.Inodes = min(limits.Inodes, inodes)
	}
	if e = limits.Validate(); e != nil {
		return zero, e
	}
	if limits.InputBytes > m.cfg.Limits.InputBytes || limits.ExpandedBytes > m.cfg.Limits.ExpandedBytes || limits.OutputBytes > m.cfg.Limits.OutputBytes {
		return zero, errors.New("development artifact exceeds installed preparation ceiling")
	}
	jobID := newID()
	space, e := m.storage.PrepareImageSpace(ctx, jobID, limits)
	if e != nil {
		return zero, e
	}
	properties := ProvisionProperties{Name: jobID, Path: space.Source, Source: space.Work, Target: space.Cache, Digest: input.ArchiveDigest, Revision: installation.ActiveRevision, ImageSpace: &space, PrepareLimits: &limits, ProductCreated: true}
	raw, _ := json.Marshal(properties)
	ledger := newID()
	if e = m.store.BeginProvision(ctx, ProvisionIntent{ID: ledger, Kind: "development-worker", Identity: jobID, ProductCreated: true, Desired: raw}); e != nil {
		return zero, e
	}
	generation := developmentGeneration(jobID)
	if e = m.store.RetainGeneration(ctx, "preparation", generation, "dev-upload:"+jobID); e != nil {
		return zero, e
	}
	if e = m.store.RetainGeneration(ctx, "preparation", "image-preparation:"+jobID, jobID); e != nil {
		return zero, e
	}
	task := provision.Task{DevelopmentWorker: &provision.DevelopmentWorkerTask{Input: input, Directory: preparationCache, BaseRoot: preparationBase, Limits: limits}}
	var envelope bytes.Buffer
	if e = provision.WriteTask(&envelope, task); e != nil {
		return zero, e
	}
	send := func(w io.Writer) error {
		if _, e := w.Write(envelope.Bytes()); e != nil {
			return e
		}
		source, e := os.OpenFile(filepath.Join(space.Source, "source.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(source, h, w), io.LimitReader(stream, input.ArchiveBytes+1))
		if e == nil && (n != input.ArchiveBytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != input.ArchiveDigest) {
			e = errors.New("development upload exact count/digest mismatch")
		}
		if e == nil {
			e = source.Sync()
		}
		return errors.Join(e, source.Close())
	}
	output, proof, e := m.runImageService(ctx, jobID, bundle.Preparer, []string{"gvx-preparer"}, space, limits, send, func() { stream.Close() }, provision.DevelopmentMetadataMax, true)
	if e != nil {
		return zero, e
	}
	manifest, e := bundle.VerifyDevelopmentWorkerManifest(output, m.cfg.Bundle.Manifest)
	if e != nil {
		return zero, e
	}
	if e = verifyExactImageFile(filepath.Join(space.Source, "source.tar"), input.ArchiveDigest, input.ArchiveBytes); e != nil {
		return zero, e
	}
	sourceFiles, e := os.ReadDir(space.Source)
	if e != nil || len(sourceFiles) != 1 {
		return zero, errors.New("development source has unexpected entries")
	}
	if _, e = freezeImageDirectory(space.Source, m.cfg.Preparer.GID, 2*input.ArchiveBytes, limits.Inodes); e != nil {
		return zero, e
	}
	verified, e := m.publishDevelopmentWorker(ctx, space, manifest, limits)
	if e != nil {
		return zero, e
	}
	properties.Digest = verified.Digest
	raw, _ = json.Marshal(properties)
	if e = m.store.ObserveProvision(ctx, ledger, ObjectObservation{Identity: jobID, Attributes: raw}); e != nil {
		return zero, e
	}
	proof, e = m.releasePreparation(ctx, space, proof)
	if e != nil {
		return zero, e
	}
	if e = m.storage.CommitImageSpace(ctx, space, proof); e != nil {
		return zero, e
	}
	if e = m.completeCommittedPreparationUnits(ctx, space); e != nil {
		return zero, e
	}
	return verified, nil
}
func (m *ImageManager) publishDevelopmentWorker(ctx context.Context, space ImageSpace, manifest bundle.DevelopmentWorkerManifest, limits provision.PrepareLimits) (bundle.VerifiedDevelopmentWorker, error) {
	var zero bundle.VerifiedDevelopmentWorker
	if e := m.requirePreparationUse(ctx, "development-worker", space); e != nil {
		return zero, e
	}
	final := filepath.Join(space.Cache, "generation")
	if e := normalizeDevelopmentDirectory(ctx, final, manifest, m.storage.installation.Identities.App.GID, limits); e != nil {
		return zero, e
	}
	generation := developmentGeneration(space.JobID)
	if e := m.store.BindStorageGeneration(ctx, space.JobID+":source", generation); e != nil {
		return zero, e
	}
	if e := m.store.BindStorageGeneration(ctx, space.JobID+":cache", generation); e != nil {
		return zero, e
	}
	return bundle.VerifyDevelopmentWorkerDirectory(ctx, final, manifest, m.cfg.Bundle)
}
func normalizeDevelopmentDirectory(ctx context.Context, root string, manifest bundle.DevelopmentWorkerManifest, gid uint32, limits provision.PrepareLimits) error {
	if e := checkImageDirectory(root); e != nil {
		return e
	}
	raw, e := readImageFile(filepath.Join(root, bundle.DevelopmentWorkerManifestPath), provision.DevelopmentMetadataMax)
	if e != nil {
		return e
	}
	expected := map[string]bundle.File{bundle.DevelopmentWorkerManifestPath: {Path: bundle.DevelopmentWorkerManifestPath, Digest: provision.Digest(raw), Size: int64(len(raw)), Mode: 0444}}
	directories := map[string]bool{".": true}
	for _, file := range manifest.Files {
		expected[file.Path] = file
		for dir := path.Dir(file.Path); dir != "."; dir = path.Dir(dir) {
			directories[dir] = true
		}
	}
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	inodes := int64(0)
	total := int64(0)
	var walk func(int, string) error
	walk = func(directory int, relative string) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		inodes++
		if inodes > limits.Inodes {
			return errors.New("development directory inode bound exceeded")
		}
		duplicate, e := unix.Dup(directory)
		if e != nil {
			return e
		}
		unix.CloseOnExec(duplicate)
		f := os.NewFile(uintptr(duplicate), relative)
		entries, e := f.ReadDir(bundle.MaxDevelopmentFiles + 2)
		closeErr := f.Close()
		if e != nil && !errors.Is(e, io.EOF) {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if len(entries) > bundle.MaxDevelopmentFiles+1 {
			return errors.New("development directory inventory bound exceeded")
		}
		for _, entry := range entries {
			child := entry.Name()
			if relative != "." {
				child = relative + "/" + entry.Name()
			}
			if entry.IsDir() {
				if !directories[child] {
					return errors.New("undeclared development directory")
				}
				childFD, e := unix.Openat(directory, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if e != nil {
					return e
				}
				e = walk(childFD, child)
				e = errors.Join(e, unix.Close(childFD))
				if e != nil {
					return e
				}
				continue
			}
			file, ok := expected[child]
			if !ok {
				return errors.New("unlisted development output member")
			}
			inodes++
			if inodes > limits.Inodes {
				return errors.New("development output inode bound exceeded")
			}
			childFD, e := unix.Openat(directory, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if e != nil {
				return e
			}
			handle := os.NewFile(uintptr(childFD), child)
			var stat unix.Stat_t
			e = unix.Fstat(childFD, &stat)
			if e == nil && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size != file.Size) {
				e = errors.New("development output type/link/size mismatch")
			}
			total += stat.Size
			if total > limits.OutputBytes {
				e = errors.New("development output exceeds quota bound")
			}
			hash := sha256.New()
			if e == nil {
				_, e = io.Copy(hash, handle)
			}
			if e == nil && "sha256:"+hex.EncodeToString(hash.Sum(nil)) != file.Digest {
				e = errors.New("development output hash mismatch")
			}
			if e == nil {
				e = unix.Fchown(childFD, 0, int(gid))
			}
			if e == nil {
				e = unix.Fchmod(childFD, file.Mode)
			}
			if e == nil {
				e = handle.Sync()
			}
			e = errors.Join(e, handle.Close())
			if e != nil {
				return e
			}
			delete(expected, child)
		}
		if e = unix.Fchown(directory, 0, int(gid)); e != nil {
			return e
		}
		mode := uint32(0555)
		if relative == "." {
			mode = 0550
		}
		if e = unix.Fchmod(directory, mode); e != nil {
			return e
		}
		return unix.Fsync(directory)
	}
	if e = walk(fd, "."); e != nil {
		return e
	}
	if len(expected) != 0 {
		return errors.New("development output inventory missing files")
	}
	return nil
}
func (m *ImageManager) DevelopmentWorker(ctx context.Context, jobID, digest string) (bundle.VerifiedDevelopmentWorker, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.developmentWorker(ctx, jobID, digest)
}
func (m *ImageManager) developmentWorker(ctx context.Context, jobID, digest string) (bundle.VerifiedDevelopmentWorker, error) {
	var zero bundle.VerifiedDevelopmentWorker
	if !safeID(jobID) || !provision.ValidDigest(digest) {
		return zero, errors.New("invalid development generation selector")
	}
	installation, e := m.store.Installation(ctx)
	if e != nil {
		return zero, e
	}
	records, e := m.store.PendingProvisions(ctx)
	if e != nil {
		return zero, e
	}
	var matched *ProvisionProperties
	for _, entry := range records {
		if entry.Kind != "development-worker" || entry.Identity != jobID || entry.State != "OBSERVED" {
			continue
		}
		var p ProvisionProperties
		if e = gvxcontract.DecodeStrict(entry.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return zero, e
		}
		if p.Digest != digest || p.Revision != installation.ActiveRevision || p.ImageSpace == nil {
			return zero, errors.New("development worker base/binding is stale")
		}
		if matched != nil {
			return zero, errors.New("ambiguous development generation")
		}
		matched = &p
	}
	if matched == nil {
		return zero, errors.New("development generation is not committed")
	}
	space := *matched.ImageSpace
	if e = m.validateDevelopmentSpace(space); e != nil {
		return zero, e
	}
	committed, e := committedImageSpace(records, space)
	if e != nil {
		return zero, e
	}
	if !committed {
		return zero, errors.New("development worker lacks its physical publication barriers")
	}
	if e = m.requirePreparationUse(ctx, "development-worker", space); e != nil {
		return zero, e
	}
	refs, e := m.store.GenerationReferences(ctx)
	if e != nil {
		return zero, e
	}
	retained := false
	for _, ref := range refs {
		if ref.ID == developmentGeneration(jobID) {
			retained = true
		}
	}
	if !retained {
		return zero, errors.New("development worker generation has been retired")
	}
	return m.verifyDevelopmentWorker(ctx, space, digest)
}

func (m *ImageManager) verifyDevelopmentWorker(ctx context.Context, space ImageSpace, digest string) (bundle.VerifiedDevelopmentWorker, error) {
	var zero bundle.VerifiedDevelopmentWorker
	root := filepath.Join(space.Cache, "generation")
	raw, e := readImageFile(filepath.Join(root, bundle.DevelopmentWorkerManifestPath), provision.DevelopmentMetadataMax)
	if e != nil {
		return zero, e
	}
	manifest, e := bundle.VerifyDevelopmentWorkerManifest(raw, m.cfg.Bundle.Manifest)
	if e != nil {
		return zero, e
	}
	if manifest.Digest != digest {
		return zero, errors.New("development manifest digest mismatch")
	}
	return bundle.VerifyDevelopmentWorkerDirectory(ctx, root, manifest, m.cfg.Bundle)
}
func (m *ImageManager) validateDevelopmentSpace(space ImageSpace) error {
	if !safeID(space.JobID) || space.ReusedSource || space.Source != filepath.Join(m.storage.config.StorageRoot, "images", space.JobID) || space.Cache != filepath.Join(m.storage.config.StorageRoot, "prepared", space.JobID) || space.Work != filepath.Join(m.storage.config.StorageRoot, "preparation", space.JobID) || space.SourceProject == 0 || space.CacheProject == 0 || space.WorkProject == 0 {
		return errors.New("development space is not the exact owned quota generation")
	}
	return nil
}
func (m *ImageManager) DiscardDevelopmentWorker(ctx context.Context, revisionID string) (CleanupEvidence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var empty CleanupEvidence
	revision, e := m.store.Revision(ctx, revisionID)
	if e != nil {
		return empty, e
	}
	if revision.DevelopmentWorker == nil {
		return empty, errors.New("only a development revision may be discarded")
	}
	binding := revision.DevelopmentWorker
	records, e := m.store.PendingProvisions(ctx)
	if e != nil {
		return empty, e
	}
	var job *ProvisionRecord
	var properties ProvisionProperties
	for _, entry := range records {
		if entry.Kind != "development-worker" || entry.Identity != binding.JobID {
			continue
		}
		if job != nil {
			return empty, errors.New("ambiguous development worker ledger")
		}
		copy := entry
		job = &copy
		raw := entry.Desired
		if entry.State == "OBSERVED" {
			raw = entry.Observed.Attributes
		}
		if e = gvxcontract.DecodeStrict(raw, 64<<10, 16, &properties); e != nil {
			return empty, e
		}
	}
	if job == nil {
		return empty, errors.New("development worker generation is absent or already retired")
	}
	if properties.ImageSpace == nil || properties.Digest != binding.ArtifactDigest || properties.Revision != binding.BaseRevision {
		return empty, errors.New("development discard binding mismatch")
	}
	space := *properties.ImageSpace
	if e = m.validateDevelopmentSpace(space); e != nil {
		return empty, e
	}
	generation := developmentGeneration(space.JobID)
	refs, e := m.store.GenerationReferences(ctx)
	if e != nil {
		return empty, e
	}
	for _, ref := range refs {
		if ref.ID == generation && (ref.Kind != "preparation" || ref.Claim != "dev-revision:"+revisionID) {
			return empty, sharedhost.ErrCleanupIncomplete
		}
	}
	settled, e := m.settlePreparationUnits(ctx, space)
	if e != nil {
		return empty, e
	}
	proof, e := m.releasePreparation(ctx, space, settled.Evidence)
	if e != nil {
		return empty, e
	}
	if e = m.store.ReleaseGeneration(ctx, "preparation", generation, "dev-revision:"+revisionID, proof); e != nil {
		return empty, e
	}
	proof, e = m.storage.ReleaseImageSpaceEvidence(ctx, space, proof)
	if e != nil {
		return empty, e
	}
	if e = m.completePreparationUnitLedgers(ctx, settled.Ledgers, proof); e != nil {
		return proof, e
	}
	if e = m.store.CompleteProvisionCleanup(ctx, job.ID, proof); e != nil {
		return proof, e
	}
	return proof, nil
}
func (m *ImageManager) recoverDevelopmentWorkers(ctx context.Context, records []ProvisionRecord) error {
	installation, e := m.store.Installation(ctx)
	if e != nil {
		return e
	}
	for _, job := range records {
		if job.Kind != "development-worker" {
			continue
		}
		var desired ProvisionProperties
		if e = gvxcontract.DecodeStrict(job.Desired, 64<<10, 16, &desired); e != nil {
			return e
		}
		if desired.ImageSpace == nil || desired.PrepareLimits == nil {
			return errors.New("development recovery intent is incomplete")
		}
		space := *desired.ImageSpace
		if e = m.validateDevelopmentSpace(space); e != nil {
			return e
		}
		refs, e := m.store.GenerationReferences(ctx)
		if e != nil {
			return e
		}
		retained := false
		for _, ref := range refs {
			if ref.ID == developmentGeneration(space.JobID) {
				retained = true
			}
		}
		committed, e := committedImageSpace(records, space)
		if e != nil {
			return e
		}
		quarantined, e := m.preparationQuarantined(ctx, "development-worker", space)
		if e != nil {
			return e
		}
		if quarantined && retained && committed && job.State == "OBSERVED" {
			continue
		}
		var observed ProvisionProperties
		if job.State == "OBSERVED" {
			if e = gvxcontract.DecodeStrict(job.Observed.Attributes, 64<<10, 16, &observed); e != nil {
				return e
			}
			if retained && committed {
				if desired.Revision == installation.ActiveRevision {
					if _, e = m.developmentWorker(ctx, space.JobID, observed.Digest); e != nil {
						return e
					}
				}
				if e = m.completeCommittedPreparationUnits(ctx, space); e != nil {
					return e
				}
				continue
			}
		}
		settled, e := m.settlePreparationUnits(ctx, space)
		if e != nil {
			return e
		}
		proof, e := m.releasePreparation(ctx, space, settled.Evidence)
		if e != nil {
			return e
		}
		if job.State == "OBSERVED" && retained {
			if desired.Revision == installation.ActiveRevision {
				if e = m.requirePreparationUse(ctx, "development-worker", space); e != nil {
					return e
				}
				if _, e = m.verifyDevelopmentWorker(ctx, space, observed.Digest); e != nil {
					return e
				}
			}
			if e = m.storage.CommitImageSpace(ctx, space, proof); e != nil {
				return e
			}
			if e = m.completePreparationUnitLedgers(ctx, settled.Ledgers, proof); e != nil {
				return e
			}
			continue
		}
		// No release trust is granted by mere output existence. Resume only the
		// exact helper's durable successful terminal result on the same base.
		if job.State != "OBSERVED" && settled.Succeeded[bundle.Preparer] && desired.Revision == installation.ActiveRevision {
			limits := *desired.PrepareLimits
			if e = verifyExactImageFile(filepath.Join(space.Source, "source.tar"), desired.Digest, limits.InputBytes); e != nil {
				return e
			}
			root := filepath.Join(space.Cache, "generation")
			raw, e := readImageFile(filepath.Join(root, bundle.DevelopmentWorkerManifestPath), provision.DevelopmentMetadataMax)
			if e != nil {
				return e
			}
			manifest, e := bundle.VerifyDevelopmentWorkerManifest(raw, m.cfg.Bundle.Manifest)
			if e != nil {
				return e
			}
			if _, e = freezeImageDirectory(space.Source, m.cfg.Preparer.GID, 2*limits.InputBytes, limits.Inodes); e != nil {
				return e
			}
			verified, e := m.publishDevelopmentWorker(ctx, space, manifest, limits)
			if e != nil {
				return e
			}
			desired.Digest = verified.Digest
			raw, _ = json.Marshal(desired)
			if e = m.store.ObserveProvision(ctx, job.ID, ObjectObservation{Identity: job.Identity, Attributes: raw}); e != nil {
				return e
			}
			if e = m.storage.CommitImageSpace(ctx, space, proof); e != nil {
				return e
			}
			if e = m.completePreparationUnitLedgers(ctx, settled.Ledgers, proof); e != nil {
				return e
			}
			continue
		}
		if e = m.store.ReleaseGeneration(ctx, "preparation", developmentGeneration(space.JobID), "dev-upload:"+space.JobID, proof); e != nil {
			return e
		}
		proof, e = m.storage.ReleaseImageSpaceEvidence(ctx, space, proof)
		if e != nil {
			return e
		}
		if e = m.completePreparationUnitLedgers(ctx, settled.Ledgers, proof); e != nil {
			return e
		}
		if e = m.store.CompleteProvisionCleanup(ctx, job.ID, proof); e != nil {
			return e
		}
	}
	return nil
}
