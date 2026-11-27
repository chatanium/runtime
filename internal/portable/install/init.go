package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	discordbackend "github.com/thirdscam/chatanium/internal/backend/discord"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/releasepayload"
	"github.com/thirdscam/chatanium/internal/runtime"
	core "github.com/thirdscam/chatanium/shared/core-v2"
)

// Confirm displays and obtains explicit approval of the complete value and
// digest. The caller must return an error if approval is absent or mismatched.
type Confirm func(description string, plan any, digest string) error

const DefaultBudgetBytes int64 = 10 << 30

const reservedUploadBytes = int64(core.MaxUploadFileBytes)
const reservedDiscordBytes = int64(discordbackend.PortableOwnershipBudgetBytes)
const runtimeDiskBytes = 80 << 20 // finite per-instance logs and native control artifacts

func defaultConfig(id, bundleDigest, path string) ([]byte, error) {
	cfg := runtime.DefaultPortableConfig(id, bundleDigest, path, filepath.Join(path, "ipc"))
	cfg.Limits.UploadRecordsPerInstance = 1
	cfg.Limits.UploadRecordsPerHost = 1
	return runtime.EncodePortableConfig(cfg)
}

func planDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return hashBytes(raw), nil
}

// Doctor works without making any directory, lock, or ledger changes. Bundle
// evidence and untested capabilities are deliberately reported separately.
func Doctor(ctx context.Context) (_ map[string]any, resultErr error) {
	path, err := Directory()
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"format": Format, "installation_directory": path,
		"requires_active_check": []string{"write and exclusive lock at the approved location", "native GVX backend and guest capabilities", "image preparation and execution isolation"},
	}
	m, err := releasepayload.InspectPortable()
	if err != nil {
		result["bundle_error"] = err.Error()
		return result, err
	}
	result["verified_embedded_manifest"] = m.Digest
	result["bundle_target"] = m.Target
	result["pinned_engine"] = m.Engine
	fallback, err := ipcpath.FallbackBase()
	if err != nil {
		return result, err
	}
	result["checked_native_ipc_fallback_parent"] = fallback
	i, err := Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()

	result["installed_manifest_state"] = i.Manifest.State
	result["installed_bundle_digest"] = i.Manifest.Bundle.Digest
	const verification = "installed_bundle_verification"
	switch i.Manifest.State {
	case store.Initializing, store.Ready:
		if i.Manifest.Bundle.Digest != m.Digest {
			result[verification] = "DIFFERENT_LAUNCHER"
			return result, nil
		}
		if err := i.VerifyBundle(ctx); err != nil {
			result[verification] = "FAILED"
			return result, fmt.Errorf("installed bundle verification failed: %w", err)
		}
		result[verification] = "VERIFIED"
	default:
		result[verification] = "NOT_APPLICABLE"
	}
	return result, nil
}

type initPlan struct {
	Format        string                  `json:"format"`
	Owner         string                  `json:"owner"`
	Path          string                  `json:"installation_directory"`
	Staging       string                  `json:"initialization_staging_directory"`
	SharedParent  string                  `json:"shared_parent_retained_after_purge"`
	IPCFallback   string                  `json:"private_ipc_fallback_parent"`
	BudgetBytes   int64                   `json:"maximum_installation_bytes"`
	MetadataBytes int64                   `json:"maximum_code_and_metadata_bytes"`
	LogBytes      int64                   `json:"maximum_disk_logs_per_run_bytes"`
	UploadBytes   int64                   `json:"maximum_host_upload_bytes"`
	DiscordBytes  int64                   `json:"maximum_discord_ownership_bytes"`
	Bundle        bundle.PortableManifest `json:"bundle"`
	FirstModule   *firstModulePlan        `json:"initial_module,omitempty"`
	PlanDigest    string                  `json:"plan_digest,omitempty"`
}

func initStaging(path string) string {
	return filepath.Join(filepath.Dir(path), ".init-"+filepath.Base(path))
}

type FirstModule struct {
	Image  ImageInput
	Module GenerateOptions
}

type firstModulePlan struct {
	Image        imagePlan            `json:"image"`
	ModuleID     string               `json:"module_id"`
	UID          uint32               `json:"uid"`
	GID          uint32               `json:"gid"`
	ConfigDigest string               `json:"module_config_digest"`
	GrantDigest  string               `json:"grant_digest"`
	Network      store.NetworkProfile `json:"proposed_network"`
}

func planFirstModule(p initPlan, first FirstModule) (*firstModulePlan, error) {
	m := first.Module
	if m.ImageID != "" || !modulePattern.MatchString(m.ModuleID) || m.UID == 0 || m.GID == 0 {
		return nil, errors.New("initial module requires its stable ID and nonroot guest UID/GID")
	}
	var value any
	if err := gvxcontract.DecodeStrict(m.ModuleConfig, 64<<10, 64, &value); err != nil {
		return nil, errors.New("invalid bounded initial module config JSON")
	}
	if err := gvxcontract.DecodeStrict(m.Grant, 1<<20, 64, &value); err != nil {
		return nil, errors.New("invalid bounded initial module grant JSON")
	}
	image, err := planImage(Manifest{Bundle: p.Bundle, BudgetBytes: p.BudgetBytes, IPCFallback: p.IPCFallback}, p.Path, first.Image)
	if err != nil {
		return nil, err
	}
	left := p.BudgetBytes - p.MetadataBytes
	if image.WorkBytes > left || image.CacheBytes > left-image.WorkBytes {
		return nil, fmt.Errorf("%w: initial image preparation and cache exceed the approved installation maximum", store.ErrBudgetExceeded)
	}
	return &firstModulePlan{Image: image, ModuleID: m.ModuleID, UID: m.UID, GID: m.GID, ConfigDigest: hashBytes(m.ModuleConfig), GrantDigest: hashBytes(m.Grant), Network: m.Network}, nil
}

func bundleBytes(m bundle.PortableManifest) (int64, error) {
	var total int64
	for _, file := range m.Files {
		if file.Size < 0 || file.Size > math.MaxInt64-total {
			return 0, errors.New("bundle has an invalid byte bound")
		}
		total += file.Size
	}
	return total, nil
}

// Init creates a stopped installation. A complete initial module request
// combines setup, bounded staging, and module review without executing it.
// An empty request leaves the installation INITIALIZING for later setup.
func Init(ctx context.Context, budget int64, first *FirstModule, confirm Confirm) (Manifest, error) {
	path, err := Directory()
	if err != nil {
		return Manifest{}, err
	}
	b, err := releasepayload.InspectPortable()
	if err != nil {
		return Manifest{}, err
	}
	p, err := planInit(path, b, budget, first)
	if err != nil {
		return Manifest{}, err
	}
	if confirm == nil {
		return Manifest{}, errors.New("initialization requires exact PlanDigest approval")
	}
	if err := confirm("Approve the exact portable installation paths, bundle and byte budget (PlanDigest)", p, p.PlanDigest); err != nil {
		return Manifest{}, err
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	m, err := initialize(ctx, p)
	if err != nil {
		return m, err
	}
	return completeInit(ctx, p, m, first, confirm)
}

func planInit(path string, b bundle.PortableManifest, budget int64, first *FirstModule) (initPlan, error) {
	owner, err := process.OwnerIdentity()
	if err != nil {
		return initPlan{}, err
	}
	fallback, err := ipcpath.FallbackBase()
	if err != nil {
		return initPlan{}, err
	}
	codeBytes, err := bundleBytes(b)
	const metadataBase = 4 * (reservedUploadBytes + reservedDiscordBytes + 64<<20)
	if err != nil || codeBytes > (math.MaxInt64-metadataBase-runtimeDiskBytes)/8 {
		return initPlan{}, errors.New("bundle cannot fit in the portable metadata bound")
	}
	// The store reserves at least one quarter for non-SQLite files. Budget
	// two code generations at peak, bounded manifests and the upload spool.
	metadata := 8*codeBytes + metadataBase
	if budget <= metadata+runtimeDiskBytes {
		return initPlan{}, fmt.Errorf("%w: budget must exceed %d bytes for this bundle, metadata and one runtime reservation", store.ErrBudgetExceeded, metadata+runtimeDiskBytes)
	}
	p := initPlan{Format: Format, Owner: owner, Path: path, Staging: initStaging(path), SharedParent: filepath.Dir(path), IPCFallback: fallback, BudgetBytes: budget, MetadataBytes: metadata, LogBytes: runtimeDiskBytes, UploadBytes: reservedUploadBytes, DiscordBytes: reservedDiscordBytes, Bundle: b}
	if first != nil {
		p.FirstModule, err = planFirstModule(p, *first)
		if err != nil {
			return initPlan{}, err
		}
	}
	p.PlanDigest, err = planDigest(p)
	return p, err
}

func completeInit(ctx context.Context, p initPlan, m Manifest, first *FirstModule, confirm Confirm) (Manifest, error) {
	if first == nil || m.State == store.Ready {
		return m, nil
	}
	return activateInitial(ctx, p.Path, m, first, p.FirstModule.Image.PlanDigest, confirm)
}

func initialize(ctx context.Context, p initPlan) (Manifest, error) {
	parent, err := anchor(p.Path, true)
	if err != nil {
		return Manifest{}, err
	}
	defer parent.Close()
	gate, err := process.Lock(filepath.Join(parent.Name(), anchorLock))
	if err != nil {
		return Manifest{}, err
	}
	defer gate.Close()
	return initializeLocked(ctx, parent, p)
}

// initializeLocked publishes a stopped installation with the management lock
// already held. Reset keeps this lock from approving deletion to publication.
func initializeLocked(ctx context.Context, parent *os.Root, p initPlan) (_ Manifest, resultErr error) {
	path := p.Path
	if p.Staging != initStaging(path) {
		return Manifest{}, store.ErrApprovalMismatch
	}
	if err := requireNoPurgeReceipt(parent, path); err != nil {
		return Manifest{}, err
	}
	runtimeName := filepath.Base(path)
	stageName := filepath.Base(p.Staging)
	if _, err := parent.Lstat(runtimeName); err == nil {
		i, err := lockInstallation(parent, path)
		if err != nil {
			return Manifest{}, err
		}
		defer i.Close()
		if i.Manifest.State != store.Ready && i.Manifest.State != store.Initializing {
			return Manifest{}, errors.New("installation is not available for initialization; retained portable data was not changed")
		}
		if i.Manifest.PlanDigest != p.PlanDigest {
			return Manifest{}, errors.New("installation already has a different approved plan")
		}
		if err := i.verifyInitializationLedger(ctx); err != nil {
			return Manifest{}, err
		}
		return i.Manifest, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, err
	}
	stage, err := privateChild(parent, stageName, true)
	if err != nil {
		return Manifest{}, err
	}
	i := &Installation{Path: p.Staging, Root: stage}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()
	m, err := initializeManifest(stage, p)
	if err != nil {
		return Manifest{}, err
	}
	i.Manifest = m
	i.OwnerLock, err = process.Lock(filepath.Join(p.Staging, ownerLock))
	if err != nil {
		return Manifest{}, err
	}
	if err := i.initializeLedger(ctx); err != nil {
		return Manifest{}, err
	}
	if err := i.installBundle(ctx, m.Bundle, m.CodeDir); err != nil {
		return Manifest{}, err
	}
	if err := provisionApp(stage); err != nil {
		return Manifest{}, err
	}
	if err := errors.Join(syncDirectory(stage), i.Close()); err != nil {
		return Manifest{}, err
	}
	if err := replaceFile(parent, stageName, runtimeName); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// initializeManifest runs under the parent lock. Once published, the staging
// manifest supplies the ID and exact configuration for every retry.
func initializeManifest(stage *os.Root, p initPlan) (Manifest, error) {
	m, err := decodeManifest(stage, manifestName, "")
	if err == nil {
		if m.PlanDigest != p.PlanDigest || m.Owner != p.Owner || m.IPCFallback != p.IPCFallback ||
			m.BudgetBytes != p.BudgetBytes || m.MetadataBytes != p.MetadataBytes || m.LogBytes != p.LogBytes ||
			!reflect.DeepEqual(m.Bundle, p.Bundle) || m.State != store.Initializing || len(m.Modules) != 0 || m.ConfigPlanDigest != "" {
			return Manifest{}, fmt.Errorf("%w: initialization staging belongs to a different plan", store.ErrApprovalMismatch)
		}
		if err := absent(stage, pendingName); err != nil {
			return Manifest{}, err
		}
		return m, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, err
	}
	if err := ensureFreshStaging(stage); err != nil {
		return Manifest{}, err
	}
	var random [16]byte
	rand.Read(random[:])
	id := hex.EncodeToString(random[:])
	config, err := defaultConfig(id, p.Bundle.Digest, p.Path)
	if err != nil {
		return Manifest{}, err
	}
	m = Manifest{ID: id, Format: Format, State: store.Initializing, CodeDir: codeDirectory(p.Bundle.Digest), PlanDigest: p.PlanDigest, Owner: p.Owner, IPCFallback: p.IPCFallback, BudgetBytes: p.BudgetBytes, MetadataBytes: p.MetadataBytes, LogBytes: p.LogBytes, Bundle: p.Bundle, Config: config, Modules: []Module{}}
	if err := writeManifest(stage, manifestName, m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (i *Installation) verifyInitializationLedger(ctx context.Context) (resultErr error) {
	db, err := i.Store(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, db.Close()) }()
	record, err := db.Installation(ctx)
	if err != nil {
		return err
	}
	if record.State != i.Manifest.State {
		return store.ErrApprovalMismatch
	}
	return matchMaintenanceManifest(record, i.Manifest)
}

// Create SQLite in an unpublished owned work directory so an interrupted
// header/schema creation never leaves the final portable ledger half written.
func (i *Installation) initializeLedger(ctx context.Context) error {
	const building = ".creating-ledger"
	if _, err := i.Root.Lstat(store.DatabaseName); err == nil {
		if err := i.verifyInitializationLedger(ctx); err != nil {
		}
		return removeOwned(i.Root, building)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := removeOwned(i.Root, building); err != nil {
		return err
	}
	scratch, err := privateChild(i.Root, building, true)
	if err != nil {
		return err
	}
	staging := filepath.Join(i.Path, building)
	m := i.Manifest
	db, err := store.Create(ctx, staging, store.Installation{InstallationIdentity: identity(m), PlanDigest: m.PlanDigest, BudgetBytes: m.BudgetBytes, MetadataBytes: m.MetadataBytes, LogBytes: m.LogBytes})
	if err != nil {
		return errors.Join(err, scratch.Close())
	}
	if err := errors.Join(db.Close(), syncDirectory(scratch)); err != nil {
		return errors.Join(err, scratch.Close())
	}
	if err := scratch.Close(); err != nil {
		return err
	}
	if err := replaceFile(i.Root, filepath.Join(building, store.DatabaseName), store.DatabaseName); err != nil {
		return err
	}
	return removeOwned(i.Root, building)
}

func ensureFreshStaging(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	names, err := file.Readdirnames(-1)
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	for _, name := range names {
		if name != ".writing-"+manifestName {
			return fmt.Errorf("unrecognized file in markerless portable initialization staging: %q", name)
		}
	}
	return nil
}

func provisionApp(root *os.Root) error {
	app, err := privateChild(root, "app", true)
	if err != nil {
		return err
	}
	defer app.Close()
	for _, name := range []string{"uploads", "discord"} {
		child, err := privateChild(app, name, true)
		if err != nil {
			return err
		}
		if err := child.Close(); err != nil {
			return err
		}
	}
	ipc, err := privateChild(root, "ipc", true)
	if err != nil {
		return err
	}
	if err := ipc.Close(); err != nil {
		return err
	}
	return errors.Join(syncDirectory(app), syncDirectory(root))
}

func (i *Installation) installBundle(ctx context.Context, expected bundle.PortableManifest, name string) error {
	if existing, err := openChild(i.Root, name); err == nil {
		got, verifyErr := releasepayload.VerifyPortable(ctx, existing)
		if err := existing.Close(); err != nil {
			return err
		}
		if verifyErr == nil && got.Digest == expected.Digest {
			return nil
		}
		if err := removeOwned(i.Root, name); err != nil {
			return errors.Join(verifyErr, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if name != codeDirectory(expected.Digest) || strings.ContainsAny(name, `/\`) {
		return errors.New("invalid portable bundle directory")
	}
	root, err := privateChild(i.Root, name, true)
	if err != nil {
		return err
	}
	got, extractErr := releasepayload.ExtractPortable(ctx, root)
	if extractErr == nil && got.Digest != expected.Digest {
		extractErr = store.ErrApprovalMismatch
	}
	if err := errors.Join(extractErr, root.Close()); err != nil {
		return errors.Join(err, removeOwned(i.Root, name))
	}
	return syncDirectory(i.Root)
}
