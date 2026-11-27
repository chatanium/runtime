package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/releasepayload"
	"github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

// ModuleInstallInfo contains only verified declaration data and nonsecret host settings.
type ModuleInstallInfo struct {
	Declaration    *wire.ModuleManifest
	DiscordStarter bool
	Discord        *DiscordProfile
}

type ModuleInstallSettings struct {
	GuildID, ChannelID string
	Discord            *DiscordSetup
}

type ModuleInstallOptions struct {
	Archive     string
	BudgetBytes int64
	Limits      images.Limits
	Module      GenerateOptions
	Settings    func(ModuleInstallInfo) (ModuleInstallSettings, error)
}

type moduleInstallApproval struct {
	Configuration configurationApproval `json:"configuration"`
	Module        moduleApproval        `json:"module"`
	AddedDiscord  bool                  `json:"added_discord_backend"`
}

// InstallModule reviews and adds exactly one module without starting the runtime.
func InstallModule(ctx context.Context, o ModuleInstallOptions, confirm Confirm) (_ Manifest, resultErr error) {
	if confirm == nil || o.Settings == nil {
		return Manifest{}, errors.New("module install requires an operator settings and approval callback")
	}
	if o.Module.UID == 0 || o.Module.GID == 0 {
		return Manifest{}, errors.New("module install requires nonroot guest UID and GID")
	}
	if o.Module.ModuleID != "" && !modulePattern.MatchString(o.Module.ModuleID) {
		return Manifest{}, errors.New("invalid module ID")
	}
	path, err := Directory()
	if err != nil {
		return Manifest{}, err
	}
	current, err := InstalledManifest(path)
	if err != nil {
		return Manifest{}, err
	}
	archivePath, err := filepath.Abs(o.Archive)
	if err != nil {
		return Manifest{}, err
	}
	if err := o.Limits.Validate(); err != nil {
		return Manifest{}, err
	}
	if o.Limits.InputBytes > 1<<40 {
		return Manifest{}, errors.New("preparation input limit exceeds portable runtime bounds")
	}
	file, err := OpenInput(archivePath, false)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	if err := checkArchiveSize(file, o.Limits.InputBytes); err != nil {
		return Manifest{}, err
	}
	// Verify before the owner lock's reconciliation can mutate durable state.
	var checkedBundle string
	check := func(locked *Installation) error {
		if current != nil && locked.Manifest.ID != current.ID {
			return store.ErrIdentity
		}
		if locked.Manifest.State != store.Initializing && locked.Manifest.State != store.Ready {
			return store.ErrState
		}
		if err := locked.VerifyBundle(ctx); err != nil {
			return err
		}
		checkedBundle = locked.Manifest.Bundle.Digest
		return nil
	}
	var i *Installation
	if current == nil {
		i, err = initializeForModule(ctx, path, o.BudgetBytes, confirm, check)
	} else {
		i, err = lockPath(path, check)
	}
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()
	if i.Manifest.Bundle.Digest != checkedBundle {
		return Manifest{}, store.ErrApprovalMismatch
	}
	if i.Manifest.State != store.Initializing && i.Manifest.State != store.Ready {
		return Manifest{}, store.ErrState
	}
	cfg, err := runtime.DecodeConfig(i.Manifest.Config)
	if err != nil {
		return Manifest{}, err
	}
	if o.Module.ModuleID != "" {
		for _, old := range i.Manifest.Modules {
			if old.ID == o.Module.ModuleID {
				return Manifest{}, fmt.Errorf("module %q is already installed", old.ID)
			}
		}
	}
	digest, err := digestArchive(ctx, file, o.Limits.InputBytes)
	if err != nil {
		return Manifest{}, err
	}
	plan, err := planImage(i.Manifest, path, ImageInput{Archive: archivePath, Limits: o.Limits, Source: images.Source{Kind: "oci-archive", Digest: digest}})
	if err != nil {
		return Manifest{}, err
	}
	// Invocation authorizes bounded local inspection only. The guest checks the
	// streamed archive digest again; review, not acquisition, grants authority.
	g, err := i.prepareImagePlan(ctx, plan, file, true)
	if err != nil {
		return Manifest{}, err
	}
	declaration, err := decodeInstallDeclaration(g.Declaration, cfg.Limits.ControlMessageMaxBytes)
	if err != nil {
		return Manifest{}, err
	}
	for _, old := range i.Manifest.Modules {
		var installed wire.ModuleManifest
		if err := protojson.Unmarshal(old.Generation.Declaration, &installed); err != nil {
			return Manifest{}, store.ErrApprovalMismatch
		}
		if installed.Name == declaration.Name {
			return Manifest{}, fmt.Errorf("module %q is already installed", declaration.Name)
		}
	}
	if o.Module.ModuleID == "" {
		o.Module.ModuleID = declaration.Name
	}
	if !modulePattern.MatchString(o.Module.ModuleID) {
		return Manifest{}, errors.New("declaration name cannot be used as a module ID; provide --module-id")
	}
	for _, old := range i.Manifest.Modules {
		if old.ID == o.Module.ModuleID {
			return Manifest{}, fmt.Errorf("module %q is already installed", old.ID)
		}
	}
	info := ModuleInstallInfo{Declaration: declaration, DiscordStarter: isDiscordStarter(declaration)}
	if backend, ok := cfg.Backends["discord"]; info.DiscordStarter && ok {
		profile, err := compatibleDiscordProfile(backend)
		if err != nil {
			return Manifest{}, err
		}
		info.Discord = &profile
	}
	settings, err := o.Settings(info)
	if err != nil {
		return Manifest{}, err
	}
	if settings.Discord != nil {
		defer clear(settings.Discord.Token)
	}
	options, err := installModuleOptions(cfg, info.DiscordStarter, declaration, o.Module, settings)
	if err != nil {
		return Manifest{}, err
	}
	var publishCredential func() error
	if settings.Discord != nil {
		if !info.DiscordStarter || info.Discord != nil {
			return Manifest{}, errors.New("install cannot replace or configure an unrelated Discord backend")
		}
		backend, publish, err := i.proposeDiscordBackend(*settings.Discord, cfg.Backends)
		if err != nil {
			return Manifest{}, err
		}
		cfg.Backends["discord"] = backend
		publishCredential = publish
	}
	candidate, err := i.candidateForModule(cfg, g, options, true)
	if err != nil {
		return Manifest{}, err
	}
	return i.configureCandidate(ctx, candidate, func(config configurationApproval, modules []Module) error {
		value := moduleInstallApproval{Configuration: config, Module: approvalForModule(modules[len(modules)-1]), AddedDiscord: publishCredential != nil}
		return confirm("Approve installing this module and publishing the stopped configuration (PlanDigest)", value, config.Plan.PlanDigest)
	}, publishCredential)
}

func initializeForModule(ctx context.Context, path string, budget int64, confirm Confirm, check func(*Installation) error) (*Installation, error) {
	bundle, err := releasepayload.InspectPortable()
	if err != nil {
		return nil, err
	}
	p, err := planInit(path, bundle, budget, nil)
	if err != nil {
		return nil, err
	}
	if err := confirm("Approve the exact portable installation paths, bundle and byte budget (PlanDigest)", p, p.PlanDigest); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parent, err := anchor(path, true)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	gate, err := process.Lock(filepath.Join(parent.Name(), anchorLock))
	if err != nil {
		return nil, err
	}
	defer gate.Close()
	if _, err := parent.Lstat(filepath.Base(path)); err == nil {
		return nil, errors.New("an installation appeared during setup; run module install again")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if _, err := initializeLocked(ctx, parent, p); err != nil {
		return nil, err
	}
	return lockInstallationChecked(parent, path, check)
}

func checkArchiveSize(file *os.File, maximum int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() <= 0 || info.Size() > maximum {
		return errors.New("archive does not fit the input byte limit")
	}
	return nil
}

func digestArchive(ctx context.Context, file *os.File, maxBytes int64) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return "", errors.New("archive does not fit the input byte limit")
	}
	h := sha256.New()
	n, err := io.Copy(h, maintenanceReader{ctx, io.LimitReader(file, maxBytes+1)})
	if err != nil {
		return "", err
	}
	if n != info.Size() {
		return "", errors.New("archive size changed while reading")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func decodeInstallDeclaration(raw []byte, maximum int) (*wire.ModuleManifest, error) {
	m := new(wire.ModuleManifest)
	if len(raw) > maximum || (protojson.UnmarshalOptions{RecursionLimit: 64}).Unmarshal(raw, m) != nil || m.ProtocolMajor != 2 || m.Name == "" || m.Version == "" {
		return nil, errors.New("image needs a bounded core-v2 declaration with name and version")
	}
	return m, nil
}

func installModuleOptions(cfg runtime.Config, starter bool, m *wire.ModuleManifest, options GenerateOptions, s ModuleInstallSettings) (GenerateOptions, error) {
	grant := new(wire.Grants)
	if len(options.Grant) != 0 {
		if starter {
			return GenerateOptions{}, errors.New("use --discord-guild-id and --discord-channel-id to grant the Discord starter one channel")
		}
		if err := protojson.Unmarshal(options.Grant, grant); err != nil {
			return GenerateOptions{}, errors.New("invalid grants JSON")
		}
	} else {
		profile := cfg.ResourceProfiles["general"]
		grant.ResourceClass = wire.ResourceClass_RESOURCE_CLASS_GENERAL
		grant.ResourceLimits = &wire.ResourceLimits{CpuMillicores: profile.CPUMillicores, MemoryBytes: profile.MemoryBytes, MaxPids: profile.MaxPids, PersistentBytes: profile.PersistentBytes, ScratchBytes: profile.ScratchBytes}
		grant.EgressPolicy = wire.EgressPolicy_EGRESS_POLICY_NONE
		if !starter && len(m.BackendRequirements) != 0 {
			return GenerateOptions{}, errors.New("module declares backend requirements; provide --approval and --module-config using a compatible configured backend")
		}
		for _, request := range m.RequiredCapabilities {
			if !configReadRequest(request) {
				return GenerateOptions{}, errors.New("module declares additional required core capabilities; provide --approval and --module-config")
			}
			grant.CoreCapabilities = append(grant.CoreCapabilities, &wire.CapabilityGrant{Name: request.Name, ResourceScopes: request.ResourceScopes})
		}
	}
	if grant.EgressPolicy != wire.EgressPolicy_EGRESS_POLICY_NONE || options.Network.Mode != "" && options.Network.Mode != store.NetworkNone {
		return GenerateOptions{}, errors.New("module install permits only NONE module egress")
	}
	if starter {
		if len(options.ModuleConfig) != 0 {
			return GenerateOptions{}, errors.New("use --discord-guild-id and --discord-channel-id to set the Discord starter configuration")
		}
		var err error
		options.ModuleConfig, grant.Backends, err = discordStarterSettings(s)
		if err != nil {
			return GenerateOptions{}, err
		}
	} else if len(options.ModuleConfig) == 0 {
		if len(m.RequiredCapabilities)+len(m.OptionalCapabilities)+len(m.BackendRequirements) != 0 || len(options.Grant) != 0 {
			return GenerateOptions{}, errors.New("module settings are not declared by the image; provide --module-config (use {} if no settings are needed)")
		}
		options.ModuleConfig = json.RawMessage(`{}`)
	}
	if len(options.Grant) == 0 {
		var err error
		options.Grant, err = protojson.Marshal(grant)
		if err != nil {
			return GenerateOptions{}, err
		}
	}
	return options, nil
}

func configReadRequest(request *wire.CapabilityRequest) bool {
	return request.GetName() == "core.config.read" && len(request.GetResourceScopes()) == 1 && request.ResourceScopes[0].GetSelector() != nil && len(request.ResourceScopes[0].GetSelector().ResourceIds) == 0
}
