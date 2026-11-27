package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/releasepayload"
	"github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

// ResetPlan binds the complete purge inventory and its standard PurgeDigest
// to the exact replacement setup. Further module approval is separate.
type ResetPlan struct {
	Purge       purgeScope `json:"purge"`
	PurgeDigest string     `json:"purge_digest"`
	Replacement initPlan   `json:"replacement"`
}

// Reinitialize replaces the identified stopped installation, including any
// data retained by uninstall. Refusal does not reconcile or change the old
// ledger. An interrupted deletion must be completed with standalone Purge.
func Reinitialize(ctx context.Context, path, expectedID string, budget int64, first *FirstModule, confirm Confirm, confirmReset Confirm) (Manifest, error) {
	if err := validateDirectory(path); err != nil {
		return Manifest{}, err
	}
	if !generationPattern.MatchString(expectedID) {
		return Manifest{}, fmt.Errorf("%w: reset requires the observed installation ID", store.ErrApprovalMismatch)
	}
	if confirmReset == nil {
		return Manifest{}, errors.New("reset requires approval of the exact purge and replacement plans")
	}
	if first != nil {
		if confirm == nil {
			return Manifest{}, errors.New("initial module setup requires separate module approval")
		}
		// The interactive confirmation cannot change the requested inputs.
		request := *first
		request.Module.ModuleConfig = slices.Clone(first.Module.ModuleConfig)
		request.Module.Grant = slices.Clone(first.Module.Grant)
		request.Module.Network.DNSServers = slices.Clone(first.Module.Network.DNSServers)
		request.Module.Network.ExcludedAddresses = slices.Clone(first.Module.Network.ExcludedAddresses)
		request.Image.Source.RedirectHosts = slices.Clone(first.Image.Source.RedirectHosts)
		first = &request
	}
	b, err := releasepayload.InspectPortable()
	if err != nil {
		return Manifest{}, err
	}
	p, err := planInit(path, b, budget, first)
	if err != nil {
		return Manifest{}, err
	}
	if first != nil {
		if err := validateResetModule(p, expectedID, first.Module); err != nil {
			return Manifest{}, err
		}
	}
	m, err := replaceInstallation(ctx, p, expectedID, confirmReset)
	if err != nil {
		return m, err
	}
	return completeInit(ctx, p, m, first, confirm)
}

func replaceInstallation(ctx context.Context, p initPlan, expectedID string, confirm Confirm) (_ Manifest, resultErr error) {
	parent, err := anchor(p.Path, false)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.Close()) }()
	if err := checkMaintenanceFile(parent, anchorLock); err != nil {
		return Manifest{}, err
	}
	gate, err := process.Lock(filepath.Join(parent.Name(), anchorLock))
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, gate.Close()) }()
	if err := checkResetAnchor(parent, p); err != nil {
		return Manifest{}, err
	}
	if err := requireDownloadedLauncher(p.Path); err != nil {
		return Manifest{}, err
	}
	if err := purgeLocked(ctx, parent, p.Path, expectedID, func(scope purgeScope) error {
		// Verify every embedded payload member before erasing the old code.
		if _, err := bundle.ValidatePortableArchive(ctx, releasepayload.Source(), goruntime.GOOS, goruntime.GOARCH); err != nil {
			return err
		}
		purgeDigest, err := planDigest(scope)
		if err != nil {
			return err
		}
		plan := ResetPlan{Purge: scope, PurgeDigest: purgeDigest, Replacement: p}
		digest, err := planDigest(plan)
		if err != nil {
			return err
		}
		if err := confirm("Permanently delete the listed installation and retained data, then create the proposed replacement (ResetDigest)", plan, digest); err != nil {
			return err
		}
		if current, err := planDigest(plan); err != nil || current != digest {
			return errors.Join(store.ErrApprovalMismatch, err)
		}
		if err := checkResetAnchor(parent, p); err != nil {
			return err
		}
		return validateResetArchive(ctx, parent, p)
	}); err != nil {
		return Manifest{}, err
	}
	if err := checkResetAnchor(parent, p); err != nil {
		return Manifest{}, err
	}
	if err := absent(parent, filepath.Base(p.Path)); err != nil {
		return Manifest{}, err
	}
	return initializeLocked(ctx, parent, p)
}

func checkResetAnchor(parent *os.Root, p initPlan) error {
	current, err := anchor(p.Path, false)
	if err != nil {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	opened, err := current.Stat(".")
	if err := errors.Join(err, current.Close()); err != nil {
		return err
	}
	pinned, err := parent.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(opened, pinned) {
		return store.ErrApprovalMismatch
	}
	if err := requireNoPurgeReceipt(parent, p.Path); err != nil {
		return err
	}
	if err := absent(parent, filepath.Base(p.Staging)); err != nil {
		return fmt.Errorf("reset will not reuse initialization staging: %w", err)
	}
	return nil
}

func lockResetInstallation(parent *os.Root, path, expectedID string) (*Installation, error) {
	i, err := openInstallation(parent, path)
	if err != nil {
		return nil, err
	}
	// Unlike the ordinary offline lock path, do not reconcile a pending
	// manifest or create a missing owner lock before confirmation.
	if i.Manifest.ID != expectedID {
		err = store.ErrApprovalMismatch
	} else if err = checkMaintenanceFile(i.Root, ownerLock); err == nil {
		i.OwnerLock, err = process.Lock(filepath.Join(path, ownerLock))
		if err == nil {
			err = checkResetContents(i.Root)
		}
	}
	if err != nil {
		return nil, errors.Join(err, i.Close())
	}
	return i, nil
}

func pendingResetPurge() error {
	return fmt.Errorf("%w: installation has a pending purge; finish it with standalone purge", store.ErrCleanupPending)
}

func checkResetContents(root *os.Root) error {
	for _, name := range []string{purgeIntent, ".writing-" + purgeIntent} {
		if err := absent(root, name); err != nil {
			if errors.Is(err, store.ErrCleanupPending) {
				return pendingResetPurge()
			}
			return err
		}
	}
	// Opening SQLite with a hot journal could change the ledger even on
	// denial. Pending manifest reconciliation is likewise explicitly offline.
	for _, name := range []string{pendingName, store.DatabaseName + "-journal", store.DatabaseName + "-wal", store.DatabaseName + "-shm"} {
		if err := absent(root, name); err != nil {
			return fmt.Errorf("recover the interrupted installation operation before resetting: %w", err)
		}
	}
	return nil
}

func resetFinalizeFiles(root *os.Root) (files [3]os.FileInfo, err error) {
	for n, name := range [...]string{manifestName, store.DatabaseName, ownerLock} {
		files[n], err = root.Lstat(name)
		if err != nil {
			return files, err
		}
		if !ownedFile(files[n]) || !safeEntry(files[n]) {
			return files, fmt.Errorf("refusing unowned reset file %q", name)
		}
	}
	return files, nil
}

func validateResetModule(p initPlan, expectedID string, m GenerateOptions) error {
	grant := new(wire.Grants)
	if err := protojson.Unmarshal(m.Grant, grant); err != nil || grant.ResourceLimits == nil {
		return errors.New("grant needs explicit core-v2 resource limits and egress policy")
	}
	r := grant.ResourceLimits
	cfg := runtime.DefaultPortableConfig(expectedID, p.Bundle.Digest, p.Path, filepath.Join(p.Path, "ipc"))
	class := "general"
	if grant.ResourceClass == wire.ResourceClass_RESOURCE_CLASS_MEDIA {
		class = "media"
	}
	cfg.ResourceProfiles[class] = runtime.ResourceProfile{CPUMillicores: r.CpuMillicores, MemoryBytes: r.MemoryBytes, MaxPids: r.MaxPids, PersistentBytes: r.PersistentBytes, ScratchBytes: r.ScratchBytes}
	egress := host.EgressNone
	if grant.EgressPolicy == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		cfg.Host.Network.Profile = host.NetworkPublicV4
		egress = host.EgressPublicInternet
	} else if m.Network.Mode == "" {
		m.Network.Mode = store.NetworkNone
	}
	// Check all operator inputs with the runtime's validation rules. The
	// prepared image will supply its actual entrypoint and declaration later.
	spec := runtime.ModuleSpec{ModuleID: runtime.ModuleID(m.ModuleID), ImageDigest: "record:" + p.FirstModule.Image.ImagePlan.Source.Digest, Entrypoint: []string{"/module"}, UID: m.UID, GID: m.GID, Config: &wire.JSONValue{Json: m.ModuleConfig}, Approval: grant}
	cfg.Modules = []runtime.ModuleSpec{spec}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if _, err := reviewNetwork(spec, egress, m.Network); err != nil {
		return err
	}
	left := p.BudgetBytes - p.MetadataBytes - p.FirstModule.Image.CacheBytes
	for _, charge := range [...]int64{int64(r.PersistentBytes), int64(r.ScratchBytes), p.LogBytes} {
		if charge > left {
			return fmt.Errorf("%w: replacement module cannot run under the proposed budget", store.ErrBudgetExceeded)
		}
		left -= charge
	}
	return nil
}

func validateResetArchive(ctx context.Context, parent *os.Root, p initPlan) (resultErr error) {
	if p.FirstModule == nil || p.FirstModule.Image.Archive == "" {
		return nil
	}
	image := p.FirstModule.Image
	f, err := OpenInput(image.Archive, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	root, err := parent.Lstat(filepath.Base(p.Path))
	if err != nil {
		return err
	}
	// Compare native identities, allowing for case-insensitive filesystems.
	for dir := filepath.Dir(image.Archive); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if os.SameFile(root, info) {
			return errors.New("replacement image archive must be outside the installation being removed")
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 || info.Size() > image.ImagePlan.Limits.InputBytes {
		return errors.New("archive does not fit the approved input byte limit")
	}
	return verifyMaintenanceFile(ctx, f, info.Size(), image.ImagePlan.Source.Digest, 0)
}
