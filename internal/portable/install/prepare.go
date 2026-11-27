package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/preparehost"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

func DefaultPreparationLimits() images.Limits {
	return images.Limits{NanoCPUs: 1_000_000_000, MemoryBytes: 512 << 20, Tasks: 64, InputBytes: 512 << 20, ExpandedBytes: 2 << 30, OutputBytes: 512 << 20, Inodes: 100_000, JSONBytes: 1 << 20, DescriptorCount: 1024, IndexDepth: 8, Deadline: 5 * time.Minute}
}

type ImageInput struct {
	Source  images.Source
	Archive string
	Limits  images.Limits
}

func planImage(m Manifest, path string, request ImageInput) (imagePlan, error) {
	source, archive := request.Source, request.Archive
	if (source.Kind == "registry") != (archive == "") || archive != "" && (!filepath.IsAbs(archive) || filepath.Clean(archive) != archive || legacyPath(archive)) {
		return imagePlan{}, errors.New("offline sources require an explicit canonical absolute non-legacy archive path")
	}
	engine, engineErr := m.Bundle.Program(bundle.Rungv)
	preparer, prepErr := m.Bundle.Program(bundle.Preparer)
	compiler, compilerErr := m.Bundle.Program(bundle.GuestRungv)
	if err := errors.Join(engineErr, prepErr, compilerErr); err != nil {
		return imagePlan{}, err
	}
	p := images.Plan{Source: source, Architecture: m.Bundle.Target.Arch, EngineDigest: engine.Digest, CompilerDigest: compiler.Digest, PreparerDigest: preparer.Digest, Limits: request.Limits}
	imageDigest, err := p.Digest()
	if err != nil {
		return imagePlan{}, err
	}
	work, cache, err := p.DiskBounds()
	if err != nil {
		return imagePlan{}, err
	}
	plan := imagePlan{Format: Format, Installation: path, IPCFallback: m.IPCFallback, Limiter: m.BudgetBytes, BundleDigest: m.Bundle.Digest, ImagePlan: p, ImageDigest: imageDigest, Archive: archive, WorkBytes: work, CacheBytes: cache}
	plan.PlanDigest, err = planDigest(plan)
	return plan, err
}

func (i *Installation) program(id bundle.ProgramID) (bundle.File, string, error) {
	entry, err := i.Manifest.Bundle.Program(id)
	if err != nil {
		return bundle.File{}, "", err
	}
	if !fs.ValidPath(entry.Path) || entry.Path == "." {
		return bundle.File{}, "", errors.New("invalid pinned program path")
	}
	return entry, filepath.Join(i.Path, i.Manifest.CodeDir, filepath.FromSlash(entry.Path)), nil
}

type imagePlan struct {
	Format       string      `json:"format"`
	Installation string      `json:"installation_directory"`
	IPCFallback  string      `json:"private_ipc_fallback_parent"`
	Limiter      int64       `json:"maximum_installation_bytes"`
	BundleDigest string      `json:"bundle_digest"`
	ImagePlan    images.Plan `json:"image_plan"`
	ImageDigest  string      `json:"image_plan_digest"`
	Archive      string      `json:"archive_path,omitempty"`
	WorkBytes    int64       `json:"maximum_preparation_bytes"`
	CacheBytes   int64       `json:"maximum_cache_bytes"`
	PlanDigest   string      `json:"plan_digest,omitempty"`
}

type preparedReceipt struct {
	Acquisition imagePlan         `json:"acquisition"`
	Generation  images.Generation `json:"generation"`
}

func finishEpoch(ctx context.Context, db *store.Store, epoch string, result *error) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	*result = errors.Join(*result, db.EndEpoch(cleanup, epoch))
}

// PrepareImage completes a read-only generation but keeps it staged: it is not
// publishable to the runtime until Configure reviews a specific module/grant.
func PrepareImage(ctx context.Context, path string, request ImageInput, confirm Confirm) (images.Generation, error) {
	return prepareImage(ctx, path, request, confirm, "", "")
}

func prepareImage(ctx context.Context, path string, request ImageInput, confirm Confirm, initDigest, approvedImagePlan string) (_ images.Generation, resultErr error) {
	i, err := Lock(path)
	if err != nil {
		return images.Generation{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()
	return i.prepareImage(ctx, request, confirm, initDigest, approvedImagePlan)
}

func (i *Installation) prepareImage(ctx context.Context, request ImageInput, confirm Confirm, initDigest, approvedImagePlan string) (_ images.Generation, resultErr error) {
	if i.Manifest.State != store.Initializing && i.Manifest.State != store.Ready {
		return images.Generation{}, store.ErrState
	}
	if err := i.VerifyBundle(ctx); err != nil {
		return images.Generation{}, err
	}
	_, enginePath, engineErr := i.program(bundle.Rungv)
	_, preparerPath, prepErr := i.program(bundle.Preparer)
	_, compilerPath, compilerErr := i.program(bundle.GuestRungv)
	if err := errors.Join(engineErr, prepErr, compilerErr); err != nil {
		return images.Generation{}, err
	}
	plan, err := planImage(i.Manifest, i.Path, request)
	if err != nil {
		return images.Generation{}, err
	}
	p := plan.ImagePlan
	if approvedImagePlan == "" {
		if confirm == nil {
			return images.Generation{}, errors.New("preparation requires exact PlanDigest approval")
		}
		if err := confirm("Approve the bounded, isolated image source and staging paths (PlanDigest)", plan, plan.PlanDigest); err != nil {
			return images.Generation{}, err
		}
	} else if i.Manifest.PlanDigest != initDigest || plan.PlanDigest != approvedImagePlan {
		return images.Generation{}, store.ErrApprovalMismatch
	}
	db, err := i.Store(ctx)
	if err != nil {
		return images.Generation{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, db.Close()) }()
	if approvedImagePlan != "" {
		g, err := i.findStagedImage(ctx, db, plan)
		if err != nil || g.ID != "" {
			return g, err
		}
	}
	var input io.Reader
	if plan.Archive != "" {
		file, err := OpenInput(plan.Archive, false)
		if err != nil {
			return images.Generation{}, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || info.Size() == 0 || info.Size() > p.Limits.InputBytes {
			return images.Generation{}, errors.New("archive does not fit the approved input byte limit")
		}
		input = file
	}
	supervisor, err := os.Executable()
	if err != nil {
		return images.Generation{}, err
	}
	epoch, err := i.beginEpoch(ctx, db)
	if err != nil {
		return images.Generation{}, err
	}
	defer finishEpoch(ctx, db, epoch, &resultErr)
	if err := i.recoverAbandoned(ctx, db, epoch); err != nil {
		return images.Generation{}, err
	}
	preparation, err := db.ReservePreparation(ctx, epoch, plan.WorkBytes)
	if err != nil {
		return images.Generation{}, err
	}
	reserved, err := db.ReserveImage(ctx, epoch, preparation.ID, p.Source.Digest, plan.CacheBytes)
	if err != nil {
		return images.Generation{}, errors.Join(err, releasePreparation(ctx, db, epoch, preparation.ID))
	}
	preparerRun := images.Preparer{Root: i.Root, InstallationID: i.Manifest.ID, Epoch: epoch, PreparationID: preparation.ID, GenerationID: reserved.ID, Supervisor: supervisor, Engine: enginePath, GuestPreparer: preparerPath, GuestCompiler: compilerPath, Start: preparehost.Managed(i.OwnerLock)}
	generation, err := preparerRun.Prepare(ctx, p, input)
	if err != nil {
		if errors.Is(err, process.ErrUnobserved) || errors.Is(err, store.ErrCleanupPending) {
			return images.Generation{}, errors.Join(err, store.ErrCleanupPending)
		}
		return images.Generation{}, errors.Join(err, i.releaseFailedImage(ctx, db, epoch, preparation, reserved))
	}
	if filepath.ToSlash(generation.Directory) != reserved.Path || generation.ID != reserved.ID || generation.Epoch != epoch || generation.SourceDigest != reserved.Digest || generation.PlanDigest != plan.ImageDigest {
		return images.Generation{}, errors.Join(store.ErrApprovalMismatch, i.releaseFailedImage(ctx, db, epoch, preparation, reserved))
	}
	if _, err := generation.VerifiedLaunch(i.Root, epoch); err != nil {
		return images.Generation{}, errors.Join(err, i.releaseFailedImage(ctx, db, epoch, preparation, reserved))
	}
	if err := absent(i.Root, preparation.Path); err != nil {
		return images.Generation{}, err
	}
	document, err := json.Marshal(preparedReceipt{Acquisition: plan, Generation: generation})
	if err == nil && len(document) > maxDocument {
		err = errors.New("prepared generation receipt exceeds its bound")
	}
	if err == nil {
		err = checkMetadataBudget(i, int64(len(document)))
	}
	if err == nil {
		err = writeNew(i.Root, draftName(generation.ID), document)
	}
	if err != nil {
		return images.Generation{}, errors.Join(err, i.releaseFailedImage(ctx, db, epoch, preparation, reserved))
	}
	proof := store.PublishProof{WritersExited: true, Verified: true, ReadOnly: true, Synchronized: true}
	if err := db.StageImage(ctx, epoch, generation.ID, proof); err != nil {
		return images.Generation{}, err
	}
	if err := releasePreparation(ctx, db, epoch, preparation.ID); err != nil {
		return images.Generation{}, err
	}
	return generation, nil
}

func (i *Installation) findStagedImage(ctx context.Context, db *store.Store, plan imagePlan) (images.Generation, error) {
	staged, err := db.Images(ctx)
	if err != nil {
		return images.Generation{}, err
	}
	for _, row := range staged {
		if row.EngineDigest != i.Manifest.Bundle.Engine.ExecutableDigest || row.Digest != plan.ImagePlan.Source.Digest || row.State != store.Prepared && row.State != store.Published {
			continue
		}
		receipt, err := i.readReceipt(row.ID)
		if err != nil {
			return images.Generation{}, err
		}
		if receipt.Acquisition.PlanDigest != plan.PlanDigest {
			continue
		}
		generation := receipt.Generation
		if generation.Epoch != row.EpochID || filepath.ToSlash(generation.Directory) != row.Path {
			return images.Generation{}, store.ErrApprovalMismatch
		}
		if _, err := generation.VerifiedLaunch(i.Root, generation.Epoch); err != nil {
			return images.Generation{}, err
		}
		return generation, nil
	}
	return images.Generation{}, nil
}

func draftName(id string) string { return "draft-" + id + ".json" }

func (i *Installation) draft(id string) (images.Generation, error) {
	receipt, err := i.readReceipt(id)
	return receipt.Generation, err
}

func (i *Installation) readReceipt(id string) (preparedReceipt, error) {
	if !generationPattern.MatchString(id) {
		return preparedReceipt{}, errors.New("invalid prepared image ID")
	}
	data, err := readDocument(i.Root, draftName(id))
	if err != nil {
		return preparedReceipt{}, err
	}
	var receipt preparedReceipt
	if err := gvxcontract.DecodeStrict(data, maxDocument, 128, &receipt); err != nil {
		return preparedReceipt{}, err
	}
	generation := receipt.Generation
	if err := verifyAcquisition(i.Manifest, i.Path, generation, receipt.Acquisition); err != nil {
		return preparedReceipt{}, err
	}
	if generation.ID != id || !generationPattern.MatchString(generation.Epoch) || filepath.ToSlash(generation.Directory) != "images/"+generation.Epoch+"/"+id {
		return preparedReceipt{}, store.ErrApprovalMismatch
	}
	return receipt, nil
}

func verifyAcquisition(m Manifest, path string, generation images.Generation, approved imagePlan) error {
	request := ImageInput{Source: approved.ImagePlan.Source, Archive: approved.Archive, Limits: approved.ImagePlan.Limits}
	expected, err := planImage(m, path, request)
	if err != nil {
		return err
	}
	recorded := approved.PlanDigest
	approved.PlanDigest = ""
	actual, err := planDigest(approved)
	if err != nil {
		return err
	}
	if expected.PlanDigest != recorded || actual != recorded || generation.PlanDigest != expected.ImageDigest || generation.SourceDigest != expected.ImagePlan.Source.Digest || generation.Architecture != expected.ImagePlan.Architecture {
		return store.ErrApprovalMismatch
	}
	return nil
}

func absent(root *os.Root, name string) error {
	parent, leaf, closeParent, err := ownedParent(root, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer closeParent()
	_, err = parent.Lstat(leaf)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %s remains", store.ErrCleanupPending, name)
}

var removed = store.RemovalProof{WritersExited: true, FilesAbsent: true}

func releasePreparation(ctx context.Context, db *store.Store, epoch, id string) error {
	if err := db.MarkPreparationPending(ctx, epoch, id); err != nil {
		return err
	}
	return db.ReleasePreparation(ctx, epoch, id, removed)
}

func (i *Installation) releaseFailedImage(ctx context.Context, db *store.Store, epoch string, preparation store.Preparation, image store.Image) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := errors.Join(removeOwned(i.Root, image.Path), removeOwned(i.Root, preparation.Path), removeOwned(i.Root, draftName(image.ID)), removeOwned(i.Root, ".writing-"+draftName(image.ID))); err != nil {
		return errors.Join(err, store.ErrCleanupPending)
	}
	if err := db.MarkImagePending(cleanup, epoch, image.ID); err != nil {
		return err
	}
	if err := db.ReleaseImage(cleanup, epoch, image.ID, removed); err != nil {
		return err
	}
	return releasePreparation(cleanup, db, epoch, preparation.ID)
}
