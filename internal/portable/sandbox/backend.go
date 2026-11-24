// Package sandbox is the supervisor-owned portable module backend. The worker
// supplies only an instance ID and AutoMTLS bootstrapping data; the installed
// review and the ledger determine every engine argument and host path.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxipc"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/session"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/provision"
)

// Module is the installed configuration's exact worker projection, reviewed
// generation, and authoritative SQLite approval. It is never received by RPC.
type Module struct {
	Spec     host.LaunchSpec
	Image    images.Generation
	Approval store.Approval
}

type Options struct {
	Store                                        *store.Store
	Root                                         *os.Root
	InstallationID, Epoch, ConfigRevision        string
	SupervisorExecutable, EnginePath, BridgePath string
	Target                                       engine.Target
	Modules                                      []Module
	OwnerLock                                    *process.OwnerLock
	StartupTimeout, CleanupTimeout               time.Duration
	// Diagnostics is an owner-only startup error sink, never a worker channel.
	Diagnostics io.Writer
}

type Backend struct {
	opts          Options
	epoch         store.Epoch
	modules       map[string]Module
	manifests     map[string][]byte
	diagnosticsMu sync.Mutex

	mu      sync.Mutex
	closing bool
	live    map[string]*instance
}

func New(opts Options) (*Backend, error) {
	if opts.Store == nil || opts.Root == nil || opts.OwnerLock == nil || opts.InstallationID == "" || opts.Epoch == "" || opts.ConfigRevision == "" || opts.StartupTimeout <= 0 {
		return nil, errors.New("missing portable sandbox owner, installation, or startup budget")
	}
	if opts.CleanupTimeout <= 0 {
		opts.CleanupTimeout = 10 * time.Second
	}
	if opts.Target.OS != runtime.GOOS || opts.Target.Arch != runtime.GOARCH {
		return nil, fmt.Errorf("%w: portable engine must match the native host", engine.ErrUnsupportedTarget)
	}
	for _, path := range []string{opts.SupervisorExecutable, opts.EnginePath, opts.BridgePath, opts.Root.Name()} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("portable sandbox requires verified absolute paths")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.StartupTimeout)
	defer cancel()
	install, err := opts.Store.Installation(ctx)
	if err != nil {
		return nil, err
	}
	if install.ID != opts.InstallationID || install.EpochID != opts.Epoch || install.State != store.Ready || install.ConfigRevision != opts.ConfigRevision {
		return nil, store.ErrIdentity
	}
	epoch, err := opts.Store.Epoch(ctx, opts.Epoch)
	if err != nil {
		return nil, err
	}
	boot, err := process.BootIdentity()
	if err != nil {
		return nil, err
	}
	if epoch.BootID != boot {
		return nil, store.ErrIdentity
	}
	config, err := opts.Store.Configuration(ctx)
	if err != nil {
		return nil, err
	}
	if config.Revision != opts.ConfigRevision || len(config.Approvals) != len(opts.Modules) {
		return nil, store.ErrApprovalMismatch
	}
	approvals := make(map[string]store.Approval, len(config.Approvals))
	for _, approval := range config.Approvals {
		approvals[approval.ModuleID] = approval
	}
	b := &Backend{opts: opts, epoch: epoch, modules: make(map[string]Module, len(opts.Modules)), manifests: make(map[string][]byte), live: make(map[string]*instance)}
	for _, module := range opts.Modules {
		if _, exists := b.modules[module.Spec.ModuleID]; exists || !reflect.DeepEqual(approvals[module.Spec.ModuleID], module.Approval) {
			return nil, store.ErrApprovalMismatch
		}
		if err := validateModule(module, opts.Target.Arch, opts.Diagnostics != nil); err != nil {
			return nil, fmt.Errorf("module %s: %w", module.Spec.ModuleID, err)
		}
		image := &module.Image
		if declaration, exists := b.manifests[module.Spec.ImageDigest]; exists && !bytes.Equal(declaration, image.Declaration) {
			return nil, store.ErrApprovalMismatch
		}
		// The service's installed values are immutable after registration. Own
		// the declaration and launch vectors used across worker requests.
		image.Declaration = bytes.Clone(image.Declaration)
		image.ImageEnv = slices.Clone(image.ImageEnv)
		image.Entrypoint = slices.Clone(image.Entrypoint)
		image.Cmd = slices.Clone(image.Cmd)
		image.Files = slices.Clone(image.Files)
		module.Spec.Entrypoint = slices.Clone(module.Spec.Entrypoint)
		module.Spec.Args = slices.Clone(module.Spec.Args)
		module.Approval.Network.DNSServers = slices.Clone(module.Approval.Network.DNSServers)
		module.Approval.Network.ExcludedAddresses = slices.Clone(module.Approval.Network.ExcludedAddresses)
		b.modules[module.Spec.ModuleID] = module
		b.manifests[module.Spec.ImageDigest] = image.Declaration
	}
	b.opts.Modules = nil
	return b, nil
}

func validateModule(module Module, arch string, ownerDiagnostics bool) error {
	s, a, img := module.Spec, module.Approval, module.Image
	r := s.Resources
	if s.ModuleID == "" || s.ModuleID != a.ModuleID || s.InstanceID != "" || len(s.Entrypoint) == 0 ||
		s.ImageDigest != "record:"+img.Digest || !provision.ValidDigest(img.Digest) ||
		a.ImageDigest != img.SourceDigest || a.ImageGeneration != img.ID || img.Architecture != arch ||
		a.DeclarationDigest != img.DeclarationDigest || provision.Digest(img.Declaration) != a.DeclarationDigest ||
		a.ResourceFormat != store.VolumeResourceFormat || !provision.ValidDigest(a.ReviewDigest) ||
		s.UID != a.UID || s.GID != a.GID || s.UID == 0 || s.GID == 0 ||
		r.NanoCPUs <= 0 || r.NanoCPUs%1_000_000 != 0 || r.NanoCPUs/1_000_000 != a.CPUMillicores ||
		r.MemoryBytes != a.MemoryBytes || r.Pids != a.MaxPIDs || r.PersistentBytes != a.PersistentBytes || r.ScratchBytes != a.ScratchBytes ||
		r.PersistentInodes != 0 || r.ScratchInodes != 0 || r.LogFileMaxBytes <= 0 || r.LogRetainedFiles <= 0 ||
		r.ControlMessageMaxBytes <= 0 || int64(len(img.Declaration)) > r.ControlMessageMaxBytes {
		return store.ErrApprovalMismatch
	}
	switch a.Network.Mode {
	case store.NetworkNone:
		if s.InitialEgress != host.EgressNone {
			return store.ErrApprovalMismatch
		}
	case store.NetworkPublic:
		if s.InitialEgress != host.EgressPublicInternet {
			return store.ErrApprovalMismatch
		}
	default:
		return store.ErrApprovalMismatch
	}
	logBuffer := r.LogBufferBytes
	if ownerDiagnostics {
		logBuffer -= startupLogBytes
	}
	return gvxipc.Workspace(gvxipc.Limits{ControlMessageMaxBytes: r.ControlMessageMaxBytes, LogBufferBytes: logBuffer})
}

func sameLaunch(approved, requested host.LaunchSpec) bool {
	return approved.ModuleID == requested.ModuleID && approved.ImageDigest == requested.ImageDigest &&
		approved.InitialEgress == requested.InitialEgress && approved.UID == requested.UID && approved.GID == requested.GID &&
		approved.Resources == requested.Resources && approved.ConfigRevision == requested.ConfigRevision && approved.ApprovalRevision == requested.ApprovalRevision &&
		slices.Equal(approved.Entrypoint, requested.Entrypoint) && slices.Equal(approved.Args, requested.Args)
}

func (b *Backend) Manifest(ctx context.Context, digest string) (_ []byte, retErr error) {
	defer annotateRPCError(&retErr)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if declaration, ok := b.manifests[digest]; ok {
		return bytes.Clone(declaration), nil
	}
	return nil, store.ErrApprovalMismatch
}

func (b *Backend) Acquire(ctx context.Context, req host.LaunchSpec) (_ host.Lease, retErr error) {
	defer annotateRPCError(&retErr)
	module, ok := b.modules[req.ModuleID]
	if !ok || !sameLaunch(module.Spec, req) {
		return host.Lease{}, store.ErrApprovalMismatch
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing {
		return host.Lease{}, errors.New("portable sandbox supervisor is stopping")
	}
	if _, exists := b.live[req.InstanceID]; exists {
		return host.Lease{}, store.ErrVolumeBusy
	}
	run, err := b.opts.Store.AdmitRun(ctx, store.RunRequest{EpochID: b.opts.Epoch, InstanceID: req.InstanceID, ModuleID: req.ModuleID, ConfigRevision: b.opts.ConfigRevision, ReviewDigest: module.Approval.ReviewDigest})
	if err != nil {
		return host.Lease{}, err
	}
	if run.InstanceID != req.InstanceID || run.Key.EpochID != b.opts.Epoch || run.ConfigRevision != b.opts.ConfigRevision ||
		!reflect.DeepEqual(run.Approval, module.Approval) || run.Image.ID != module.Image.ID || run.Image.EpochID != module.Image.Epoch ||
		run.Image.Digest != module.Image.SourceDigest || filepath.FromSlash(run.Image.Path) != filepath.FromSlash(module.Image.Directory) ||
		run.Persistent.MaxBytes < module.Approval.PersistentBytes || run.EgressState != store.EgressClosed {
		cleanup, cancel := context.WithTimeout(context.Background(), b.opts.CleanupTimeout)
		defer cancel()
		return host.Lease{}, errors.Join(store.ErrApprovalMismatch, b.opts.Store.CancelRun(cleanup, b.opts.Epoch, run.Key))
	}
	actual := module.Spec
	actual.InstanceID = req.InstanceID
	lease := host.Lease{
		Ownership: host.Ownership{RuntimeInstallationID: b.opts.InstallationID, InstallationID: b.opts.InstallationID, EpochID: b.opts.Epoch, InstanceID: run.InstanceID},
		Spec:      actual, ImageRecordID: module.Image.ID, CacheGenerationID: module.Image.ID, NetworkGeneration: run.EgressGeneration,
		Topology: host.NetworkNone, SandboxUID: actual.UID, SandboxGID: actual.GID,
	}
	if module.Approval.Network.Mode == store.NetworkPublic {
		lease.Topology = host.NetworkPublicV4
	}
	i := b.newInstance(module, run)
	b.live[run.InstanceID] = i
	lease.Spec.Entrypoint = slices.Clone(actual.Entrypoint)
	lease.Spec.Args = slices.Clone(actual.Args)
	return lease, nil
}

func (b *Backend) lookup(id string) (*instance, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := b.live[id]
	if i == nil {
		return nil, store.ErrNotFound
	}
	return i, nil
}

func networkGrant(p store.NetworkProfile) (engine.NetworkGrant, error) {
	grant := engine.NetworkGrant{Mode: engine.NetworkMode(p.Mode), Family: engine.AddressFamily(p.AddressFamily), TXBPS: p.NetTXBPS, RXBPS: p.NetRXBPS, AllowUnlimitedTX: p.AllowUnlimitedTX, AllowUnlimitedRX: p.AllowUnlimitedRX}
	for _, value := range p.DNSServers {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return grant, err
		}
		grant.DNS = append(grant.DNS, addr)
	}
	for _, value := range p.ExcludedAddresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return grant, err
		}
		grant.Excluded = append(grant.Excluded, prefix)
	}
	if grant.Mode == engine.NetworkPublicInternet {
		local, err := engine.HostIPv4Exclusions()
		if err != nil {
			return grant, err
		}
		for _, host := range local {
			covered := false
			for _, approved := range grant.Excluded {
				if approved.Bits() <= host.Bits() && approved.Contains(host.Addr()) {
					covered = true
					break
				}
			}
			if !covered {
				return grant, fmt.Errorf("%w: host address %s is missing from reviewed NAT exclusions", store.ErrApprovalMismatch, host)
			}
		}
	}
	return grant, nil
}

var _ session.Backend = (*Backend)(nil)
