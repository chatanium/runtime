package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"regexp"
	goruntime "runtime"
	"slices"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

var modulePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Candidate is the writable operator document emitted by generate-config. It
// conveys proposed configuration and grants, not an approval to execute.
type Candidate struct {
	Format   string                          `json:"format"`
	Config   json.RawMessage                 `json:"config"`
	Prepared map[string]string               `json:"prepared_images"`
	Network  map[string]store.NetworkProfile `json:"network_profiles"`
}

type GenerateOptions struct {
	ModuleID, ImageID   string
	UID, GID            uint32
	ModuleConfig, Grant []byte
	Network             store.NetworkProfile
}

func GenerateConfig(path string, options GenerateOptions) (Candidate, error) {
	i, err := Open(path)
	if err != nil {
		return Candidate{}, err
	}
	defer i.Close()
	return i.generateConfig(options)
}

func (i *Installation) generateConfig(options GenerateOptions) (Candidate, error) {
	if i.Manifest.State != store.Initializing && i.Manifest.State != store.Ready {
		return Candidate{}, store.ErrState
	}
	if !modulePattern.MatchString(options.ModuleID) || options.UID == 0 || options.GID == 0 {
		return Candidate{}, errors.New("module ID and nonroot guest UID/GID are required")
	}
	g, err := i.draft(options.ImageID)
	if err != nil {
		return Candidate{}, fmt.Errorf("read staged image: %w", err)
	}
	if _, err := g.VerifiedLaunch(i.Root, g.Epoch); err != nil {
		return Candidate{}, err
	}
	cfg, err := runtime.DecodeConfig(i.Manifest.Config)
	if err != nil {
		return Candidate{}, err
	}
	var value any
	if err := gvxcontract.DecodeStrict(options.ModuleConfig, cfg.Limits.ConfigMaxBytes, 64, &value); err != nil {
		return Candidate{}, errors.New("invalid bounded module config JSON")
	}
	if err := gvxcontract.DecodeStrict(options.Grant, cfg.Limits.ControlMessageMaxBytes, 64, &value); err != nil {
		return Candidate{}, errors.New("invalid bounded grant JSON")
	}
	grant := new(wire.Grants)
	if err := protojson.Unmarshal(options.Grant, grant); err != nil || grant.ResourceLimits == nil {
		return Candidate{}, errors.New("grant needs explicit core-v2 resource limits and egress policy")
	}
	profile := grant.ResourceLimits
	class := "general"
	if grant.ResourceClass == wire.ResourceClass_RESOURCE_CLASS_MEDIA {
		class = "media"
	}
	cfg.ResourceProfiles[class] = runtime.ResourceProfile{CPUMillicores: profile.CpuMillicores, MemoryBytes: profile.MemoryBytes, MaxPids: profile.MaxPids, PersistentBytes: profile.PersistentBytes, ScratchBytes: profile.ScratchBytes}
	entrypoint, args := g.Entrypoint, g.Cmd
	if len(entrypoint) == 0 {
		entrypoint, args = args, nil
	}
	configDoc, err := canonicalJSON(options.ModuleConfig)
	if err != nil {
		return Candidate{}, err
	}
	grantDoc, err := canonicalJSON(options.Grant)
	if err != nil {
		return Candidate{}, err
	}
	spec := runtime.ModuleSpec{ModuleID: runtime.ModuleID(options.ModuleID), ImageDigest: "record:" + g.Digest, Entrypoint: entrypoint, Args: args, UID: options.UID, GID: options.GID, Config: &wire.JSONValue{Json: configDoc}, Approval: grant, ConfigRevision: hashBytes(configDoc), ApprovalRevision: hashBytes(grantDoc)}
	index := slices.IndexFunc(cfg.Modules, func(old runtime.ModuleSpec) bool { return old.ModuleID == spec.ModuleID })
	if index == -1 {
		cfg.Modules = append(cfg.Modules, spec)
	} else {
		spec.CredentialBindings = cfg.Modules[index].CredentialBindings
		cfg.Modules[index] = spec
	}
	p := Candidate{Format: Format, Prepared: make(map[string]string), Network: make(map[string]store.NetworkProfile)}
	for _, old := range i.Manifest.Modules {
		p.Prepared[old.ID] = old.Generation.ID
		p.Network[old.ID] = old.Approval.Network
	}
	p.Prepared[options.ModuleID] = g.ID
	if options.Network.Mode == "" && grant.EgressPolicy == wire.EgressPolicy_EGRESS_POLICY_NONE {
		options.Network.Mode = store.NetworkNone
	}
	p.Network[options.ModuleID] = options.Network
	cfg.Host.Network.Profile = host.NetworkNone
	for _, spec := range cfg.Modules {
		if spec.Approval.EgressPolicy == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
			cfg.Host.Network.Profile = host.NetworkPublicV4
		}
	}
	p.Config, err = runtime.EncodePortableConfig(cfg)
	return p, err
}

func DecodeCandidate(data []byte) (Candidate, error) {
	var p Candidate
	if err := gvxcontract.DecodeStrict(data, maxDocument, 128, &p); err != nil {
		return Candidate{}, err
	}
	if p.Format != Format {
		return Candidate{}, ErrLegacy
	}
	return p, nil
}

type moduleReview struct {
	InstallationID        string               `json:"installation_id"`
	BundleDigest          string               `json:"bundle_digest"`
	EngineDigest          string               `json:"engine_digest"`
	ConfigDigest          string               `json:"config_digest"`
	AcquisitionPlanDigest string               `json:"acquisition_plan_digest"`
	Launch                host.LaunchSpec      `json:"launch"`
	Grant                 json.RawMessage      `json:"grant"`
	ModuleConfig          json.RawMessage      `json:"module_config"`
	Network               store.NetworkProfile `json:"network"`
}

func (i *Installation) verifyCandidateConfig(p Candidate) (runtime.Config, error) {
	cfg, err := runtime.DecodeConfig(p.Config)
	if err != nil {
		return runtime.Config{}, err
	}
	h := cfg.Host
	if h.Format != Format || h.RuntimeInstallationID != i.Manifest.ID || h.BundleDigest != i.Manifest.Bundle.Digest ||
		h.StorageRoot != i.Path || h.ManagementDirectory != filepath.Join(i.Path, "app") || h.IPCRoot != filepath.Join(i.Path, "ipc") ||
		cfg.Limits.UploadRecordsPerHost != 1 || cfg.Limits.UploadRecordsPerInstance != 1 {
		return runtime.Config{}, errors.New("candidate changes approved installation identity, paths or upload bounds")
	}
	if len(p.Prepared) != len(cfg.Modules) || len(p.Network) != len(cfg.Modules) {
		return runtime.Config{}, errors.New("candidate needs an exact prepared image and network profile for each module")
	}
	if len(cfg.Modules) == 0 {
		if i.Manifest.State != store.Initializing || i.Manifest.Revision != "" || len(i.Manifest.Modules) != 0 {
			return runtime.Config{}, store.ErrState
		}
		if err := verifyDefaultConfig(i.Manifest, i.Path, p.Config); err != nil {
			return runtime.Config{}, err
		}
		return cfg, nil
	}
	if backend, ok := cfg.Backends["discord"]; ok {
		var config struct {
			OwnershipDirectory string `json:"ownership_directory"`
		}
		if backend.Major != 2 || json.Unmarshal(backend.Config, &config) != nil || config.OwnershipDirectory != filepath.Join(h.ManagementDirectory, "discord") {
			return runtime.Config{}, errors.New("portable Discord requires its approved installation-owned app/discord path")
		}
	}
	for _, backend := range cfg.Backends {
		for _, source := range backend.SecretSources {
			path, ok := strings.CutPrefix(source, "file:")
			if !ok || !filepath.IsAbs(path) || filepath.Clean(path) != path || legacyPath(path) {
				return runtime.Config{}, errors.New("portable backend secret must be an explicit canonical file:/absolute/path source")
			}
		}
	}
	return cfg, nil
}

type configurationPlan struct {
	Format, Installation, BundleDigest, ConfigDigest, Revision, PlanDigest string
	BudgetBytes                                                            int64
	Reviews                                                                []string
}

func planConfiguration(path string, m Manifest, configDigest string, approvals []store.Approval) (store.Configuration, configurationPlan, error) {
	configuration := store.Configuration{ConfigDigest: configDigest, Approvals: approvals}
	var err error
	configuration.Revision, err = planDigest(configuration)
	if err != nil {
		return store.Configuration{}, configurationPlan{}, err
	}
	plan := configurationPlan{Format: Format, Installation: path, BundleDigest: m.Bundle.Digest, ConfigDigest: configDigest, Revision: configuration.Revision, BudgetBytes: m.BudgetBytes, Reviews: make([]string, len(approvals))}
	for index, approval := range approvals {
		plan.Reviews[index] = approval.ReviewDigest
	}
	plan.PlanDigest, err = planDigest(plan)
	return configuration, plan, err
}

func verifyDefaultConfig(m Manifest, path string, configDoc []byte) error {
	expected, err := defaultConfig(m.ID, m.Bundle.Digest, path)
	if err != nil || !bytes.Equal(configDoc, expected) {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	return nil
}

// Configure publishes approved staged generations and activates a stopped
// configuration only after both PlanDigest and every ReviewDigest match.
func Configure(ctx context.Context, path string, p Candidate, confirm Confirm) (_ Manifest, resultErr error) {
	i, err := Lock(path)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()
	return i.configure(ctx, p, confirm)
}

func (i *Installation) configure(ctx context.Context, p Candidate, confirm Confirm) (_ Manifest, resultErr error) {
	if i.Manifest.State != store.Initializing && i.Manifest.State != store.Ready {
		return Manifest{}, store.ErrState
	}
	if err := i.VerifyBundle(ctx); err != nil {
		return Manifest{}, err
	}
	if p.Format != Format {
		return Manifest{}, ErrLegacy
	}
	configDoc, err := canonicalJSON(p.Config)
	if err != nil {
		return Manifest{}, err
	}
	p.Config = configDoc
	cfg, err := i.verifyCandidateConfig(p)
	if err != nil {
		return Manifest{}, err
	}
	configDigest := hashBytes(configDoc)
	m := i.Manifest
	m.Config = configDoc
	m.State = store.Ready
	m.Modules = make([]Module, 0, len(cfg.Modules))
	for _, spec := range cfg.Modules {
		module, err := i.reviewModule(cfg, spec, p.Prepared[string(spec.ModuleID)], p.Network[string(spec.ModuleID)], configDigest)
		if err != nil {
			return Manifest{}, fmt.Errorf("review module %q: %w", spec.ModuleID, err)
		}
		m.Modules = append(m.Modules, module)
	}
	approvals := make([]store.Approval, len(m.Modules))
	for index, module := range m.Modules {
		approvals[index] = module.Approval
	}
	configuration, plan, err := planConfiguration(i.Path, m, configDigest, approvals)
	if err != nil {
		return Manifest{}, err
	}
	m.Revision = configuration.Revision
	m.ConfigPlanDigest = plan.PlanDigest
	if confirm == nil {
		return Manifest{}, errors.New("configure requires exact PlanDigest and per-module ReviewDigest approval")
	}
	if err := confirm("Approve publishing this stopped configuration revision (PlanDigest)", struct {
		Plan   any             `json:"plan"`
		Config json.RawMessage `json:"config"`
	}{plan, configDoc}, plan.PlanDigest); err != nil {
		return Manifest{}, err
	}
	for _, module := range m.Modules {
		value := struct {
			Module       string          `json:"module_id"`
			Source       string          `json:"source_digest"`
			Image        string          `json:"image_manifest_digest"`
			Acquisition  json.RawMessage `json:"approved_acquisition"`
			Declaration  json.RawMessage `json:"image_declaration"`
			Review       json.RawMessage `json:"review"`
			ReviewDigest string          `json:"review_digest"`
		}{module.ID, module.Generation.SourceDigest, module.Generation.ManifestDigest, module.AcquisitionJSON, module.Generation.Declaration, module.ReviewJSON, module.Approval.ReviewDigest}
		if err := confirm("Approve exact launch, grants, resources and network for "+module.ID+" (ReviewDigest)", value, module.Approval.ReviewDigest); err != nil {
			return Manifest{}, err
		}
	}
	db, err := i.Store(ctx)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, db.Close()) }()
	previous, err := db.Installation(ctx)
	if err != nil {
		return Manifest{}, err
	}
	if previous.State != i.Manifest.State {
		return Manifest{}, store.ErrApprovalMismatch
	}
	if err := matchMaintenanceManifest(previous, i.Manifest); err != nil {
		return Manifest{}, err
	}
	epoch, err := i.beginEpoch(ctx, db)
	if err != nil {
		return Manifest{}, err
	}
	defer finishEpoch(ctx, db, epoch, &resultErr)
	if err := i.recoverAbandoned(ctx, db, epoch); err != nil {
		return Manifest{}, err
	}
	runs, err := db.Runs(ctx)
	if err != nil {
		return Manifest{}, err
	}
	if len(runs) != 0 {
		return Manifest{}, store.ErrCleanupPending
	}
	if err := checkRuntimeBudget(ctx, db, m.LogBytes, approvals); err != nil {
		return Manifest{}, err
	}
	if err := i.stageManifest(m); err != nil {
		return Manifest{}, err
	}
	if err := i.publishReviewed(ctx, db, epoch, m.Modules); err != nil {
		return Manifest{}, err
	}
	if err := db.Configure(ctx, epoch, previous.ConfigRevision, configuration); err != nil {
		return Manifest{}, err
	}
	if err := db.Activate(ctx, epoch, m.PlanDigest, m.Revision); err != nil {
		return Manifest{}, err
	}
	if err := i.commitManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func checkRuntimeBudget(ctx context.Context, db *store.Store, logBytes int64, approvals []store.Approval) error {
	usage, err := db.Usage(ctx)
	if err != nil {
		return err
	}
	left := usage.BudgetBytes
	for _, charge := range [...]int64{usage.MetadataBytes, usage.PersistentBytes, usage.ScratchBytes, usage.PreparationBytes, usage.CacheBytes, usage.LogBytes, usage.BackupBytes} {
		if charge < 0 || charge > left {
			return store.ErrBudgetExceeded
		}
		left -= charge
	}
	if len(approvals) == 0 {
		return nil
	}
	volumes, err := db.Volumes(ctx)
	if err != nil {
		return err
	}
	retained := make(map[string]int64, len(volumes))
	for _, volume := range volumes {
		retained[volume.ModuleID] = volume.MaxBytes
	}
	for _, a := range approvals {
		for _, charge := range [...]int64{max(a.PersistentBytes-retained[a.ModuleID], 0), a.ScratchBytes, logBytes} {
			if charge < 0 || charge > left {
				return fmt.Errorf("%w: configured modules cannot run together under the approved installation budget", store.ErrBudgetExceeded)
			}
			left -= charge
		}
	}
	return nil
}

func (i *Installation) stageManifest(m Manifest) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(raw) > maxDocument {
		return errors.New("installation manifest exceeds its bound")
	}
	if err := checkMetadataBudget(i, int64(len(raw))); err != nil {
		return err
	}
	return writeNew(i.Root, pendingName, raw)
}

func (i *Installation) publishReviewed(ctx context.Context, db *store.Store, epoch string, modules []Module) error {
	if len(modules) == 0 {
		return nil
	}
	imagesList, err := db.Images(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]store.Image, len(imagesList))
	for _, image := range imagesList {
		byID[image.ID] = image
	}
	for _, module := range modules {
		generation := module.Generation
		image, ok := byID[generation.ID]
		if !ok || image.Digest != generation.SourceDigest || image.Path != filepath.ToSlash(generation.Directory) || image.EpochID != generation.Epoch || image.EngineDigest != i.Manifest.Bundle.Engine.ExecutableDigest {
			return store.ErrApprovalMismatch
		}
		switch image.State {
		case store.Prepared:
			if _, err := generation.VerifiedLaunch(i.Root, generation.Epoch); err != nil {
				return err
			}
			proof := store.PublishProof{WritersExited: true, Verified: true, ReadOnly: true, Synchronized: true}
			if err := db.PublishImage(ctx, epoch, image.ID, proof); err != nil {
				return err
			}
			image.State = store.Published
			byID[image.ID] = image
		case store.Published:
		default:
			return store.ErrCleanupPending
		}
	}
	return nil
}

func (i *Installation) reviewModule(cfg runtime.Config, spec runtime.ModuleSpec, imageID string, network store.NetworkProfile, configDigest string) (Module, error) {
	id := string(spec.ModuleID)
	if !modulePattern.MatchString(id) {
		return Module{}, errors.New("invalid portable module ID")
	}
	receipt, err := i.readReceipt(imageID)
	if err != nil {
		return Module{}, err
	}
	g := receipt.Generation
	if spec.ImageDigest != "record:"+g.Digest {
		return Module{}, store.ErrApprovalMismatch
	}
	if _, err := g.VerifiedLaunch(i.Root, g.Epoch); err != nil {
		return Module{}, err
	}
	launch, err := runtime.ApprovedPortableLaunchPolicy(cfg, spec, g.Declaration)
	if err != nil {
		return Module{}, err
	}
	network, err = reviewNetwork(spec, launch.InitialEgress, network)
	if err != nil {
		return Module{}, err
	}
	acquisition, err := json.Marshal(receipt.Acquisition)
	if err != nil {
		return Module{}, err
	}
	review, approval, err := moduleReviewBytes(i.Manifest, spec, g, launch, network, configDigest, receipt.Acquisition.PlanDigest)
	if err != nil {
		return Module{}, err
	}
	return Module{ID: id, Generation: g, Approval: approval, AcquisitionJSON: acquisition, ReviewJSON: review}, nil
}

func moduleReviewBytes(m Manifest, spec runtime.ModuleSpec, g images.Generation, launch host.LaunchSpec, network store.NetworkProfile, configDigest, acquisitionDigest string) ([]byte, store.Approval, error) {
	grant, err := protojson.Marshal(spec.Approval)
	if err != nil {
		return nil, store.Approval{}, err
	}
	review, err := json.Marshal(moduleReview{InstallationID: m.ID, BundleDigest: m.Bundle.Digest, EngineDigest: m.Bundle.Engine.ExecutableDigest, ConfigDigest: configDigest, AcquisitionPlanDigest: acquisitionDigest, Launch: launch, Grant: grant, ModuleConfig: spec.Config.Json, Network: network})
	if err != nil {
		return nil, store.Approval{}, err
	}
	digest, err := g.ReviewDigest(json.RawMessage(review))
	if err != nil {
		return nil, store.Approval{}, err
	}
	limits := spec.Approval.ResourceLimits
	approval := store.Approval{ModuleID: string(spec.ModuleID), ReviewDigest: digest, ImageDigest: g.SourceDigest, ImageGeneration: g.ID, ResourceFormat: Format, DeclarationDigest: g.DeclarationDigest, UID: spec.UID, GID: spec.GID, CPUMillicores: int64(limits.CpuMillicores), MemoryBytes: int64(limits.MemoryBytes), MaxPIDs: int64(limits.MaxPids), PersistentBytes: int64(limits.PersistentBytes), ScratchBytes: int64(limits.ScratchBytes), Network: network}
	return review, approval, nil
}

func verifyStoredReviews(m Manifest, path string) error {
	cfg, err := runtime.DecodeConfig(m.Config)
	if err != nil {
		return store.ErrApprovalMismatch
	}
	h := cfg.Host
	if h.Format != Format || h.RuntimeInstallationID != m.ID || h.BundleDigest != m.Bundle.Digest ||
		h.StorageRoot != path || h.ManagementDirectory != filepath.Join(path, "app") || h.IPCRoot != filepath.Join(path, "ipc") || len(cfg.Modules) != len(m.Modules) {
		return store.ErrApprovalMismatch
	}
	if len(m.Modules) == 0 {
		configDoc, err := canonicalJSON(m.Config)
		if err != nil {
			return err
		}
		if err := verifyDefaultConfig(m, path, configDoc); err != nil {
			return err
		}
		if m.Revision == "" {
			if m.State == store.Ready || m.ConfigPlanDigest != "" {
				return store.ErrApprovalMismatch
			}
			return nil
		}
		// A module-free revision has no individual reviews to bind the config
		// or plan. Recompute both digests over the canonical default.
		configuration, plan, err := planConfiguration(path, m, hashBytes(configDoc), []store.Approval{})
		if err != nil {
			return err
		}
		if m.State == store.Initializing || m.Revision != configuration.Revision || m.ConfigPlanDigest != plan.PlanDigest {
			return store.ErrApprovalMismatch
		}
		return nil
	}
	if !digestPattern.MatchString(m.Revision) || !digestPattern.MatchString(m.ConfigPlanDigest) {
		return store.ErrApprovalMismatch
	}
	configDigest, err := documentDigest(m.Config)
	if err != nil {
		return err
	}
	for n, module := range m.Modules {
		spec := cfg.Modules[n]
		generation := module.Generation
		if string(spec.ModuleID) != module.ID || spec.ImageDigest != "record:"+generation.Digest {
			return store.ErrApprovalMismatch
		}
		var acquisition imagePlan
		if err := gvxcontract.DecodeStrict(module.AcquisitionJSON, maxDocument, 64, &acquisition); err != nil {
			return err
		}
		if err := verifyAcquisition(m, path, generation, acquisition); err != nil {
			return err
		}
		launch, err := runtime.ApprovedPortableLaunchPolicy(cfg, spec, generation.Declaration)
		if err != nil {
			return err
		}
		expected, approval, err := moduleReviewBytes(m, spec, generation, launch, module.Approval.Network, configDigest, acquisition.PlanDigest)
		if err != nil {
			return err
		}
		if !bytes.Equal(expected, module.ReviewJSON) || !reflect.DeepEqual(approval, module.Approval) {
			return fmt.Errorf("%w: module %s", store.ErrApprovalMismatch, module.ID)
		}
	}
	return nil
}

func reviewNetwork(spec runtime.ModuleSpec, effectiveEgress host.EgressPolicy, p store.NetworkProfile) (store.NetworkProfile, error) {
	public := spec.Approval.EgressPolicy == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET
	if public != (effectiveEgress == host.EgressPublicInternet) || public && p.Mode != store.NetworkPublic || !public && p.Mode != store.NetworkNone {
		return p, errors.New("negotiated worker egress grant and engine network mode must match")
	}
	if len(p.DNSServers) > 64 {
		return p, errors.New("portable network profile allows at most 64 approved DNS servers")
	}
	grant := engine.NetworkGrant{Mode: engine.NetworkMode(p.Mode), Family: engine.AddressFamily(p.AddressFamily), TXBPS: p.NetTXBPS, RXBPS: p.NetRXBPS, AllowUnlimitedTX: p.AllowUnlimitedTX, AllowUnlimitedRX: p.AllowUnlimitedRX}
	for _, server := range p.DNSServers {
		addr, err := netip.ParseAddr(server)
		if err != nil || addr.Zone() != "" {
			return p, errors.New("invalid approved numeric DNS address")
		}
		grant.DNS = append(grant.DNS, addr)
	}
	for _, raw := range p.ExcludedAddresses {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, err := netip.ParseAddr(raw)
			if err != nil || addr.Zone() != "" {
				return p, errors.New("invalid approved exclusion")
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		grant.Excluded = append(grant.Excluded, prefix)
	}
	if p.Mode == store.NetworkPublic {
		excluded, err := engine.HostIPv4Exclusions()
		if err != nil {
			return p, err
		}
		grant.Excluded = append(grant.Excluded, excluded...)
		p.ExcludedAddresses = make([]string, len(grant.Excluded))
		for index, exclusion := range grant.Excluded {
			p.ExcludedAddresses[index] = exclusion.String()
		}
		slices.Sort(p.ExcludedAddresses)
		p.ExcludedAddresses = slices.Compact(p.ExcludedAddresses)
	}
	limits := spec.Approval.ResourceLimits
	target := engine.Target{OS: goruntime.GOOS, Arch: goruntime.GOARCH, HostCPUs: goruntime.NumCPU()}
	resources := engine.ResourceLimits{CPUMillicores: int64(limits.CpuMillicores), MemoryBytes: int64(limits.MemoryBytes), MaxPIDs: int64(limits.MaxPids)}
	if err := engine.ValidateResourceLimits(target, resources); err != nil {
		return p, err
	}
	effective, err := engine.NetworkPolicyDigest(grant)
	if err != nil {
		return p, err
	}
	if effective != "" {
		p.PolicyDigest = "sha256:" + strings.TrimPrefix(effective, "sha256:")
	} else {
		p.PolicyDigest = ""
	}
	return p, nil
}
