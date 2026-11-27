//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
	"github.com/thirdscam/chatanium/internal/runtime/upload"
	"golang.org/x/sys/unix"
)

// ProduceInitPlan observes the host and embedded release without changing either.
// The returned digest must be explicitly approved before InitializeWithInputs.
func ProduceInitPlan(ctx context.Context, draft *ApprovedInitPlan) (ApprovedInitPlan, error) {
	var p ApprovedInitPlan
	if e := rootRequired(); e != nil {
		return p, e
	}
	if e := ctx.Err(); e != nil {
		return p, e
	}
	if draft != nil {
		raw, e := json.Marshal(draft)
		if e != nil {
			return p, e
		}
		if e = gvxcontract.DecodeStrict(raw, 32<<20, 64, &p); e != nil {
			return p, e
		}
	}
	source, e := configuredSource()
	if e != nil {
		return p, e
	}
	raw, e := source.Manifest()
	if e != nil {
		return p, e
	}
	manifest, e := bundle.VerifyManifest(raw)
	if e != nil {
		return p, e
	}
	if p.InstallationID != "" {
		control, e := controlPath(p.InstallationID)
		if e != nil {
			return p, e
		}
		gate, e := acquireManagementGuard(ctx)
		if e != nil {
			return p, e
		}
		reader, e := host.OpenMetadata(ctx, control, string(p.InstallationID), gate)
		if e != nil {
			closeUnadoptedManagementGuard(gate)
			return p, e
		}
		defer reader.Close()
		plans, e := reader.ManagementPlans(ctx, "init")
		if e != nil {
			return p, e
		}
		if len(plans) != 1 {
			return p, errors.New("installation has no unique durable initialization approval")
		}
		var saved ApprovedInitPlan
		if e = gvxcontract.DecodeStrict(plans[0].Plan, 32<<20, 64, &saved); e != nil {
			return p, e
		}
		if saved.InstallationID != p.InstallationID || saved.BundleDigest != manifest.Digest || plans[0].Digest != saved.PlanDigest {
			return p, errors.New("saved initialization differs from executing bundle or identity")
		}
		return saved, validateInit(saved)
	}
	p.PlanID = newID()
	p.InstallationID = RuntimeInstallationID(newID())
	if p.PlanID == "" || p.InstallationID == "" {
		return p, errors.New("entropy unavailable")
	}
	p.BundleDigest = manifest.Digest
	control, e := controlPath(p.InstallationID)
	if e != nil {
		return p, e
	}
	root := filepath.Dir(control)
	p.Paths.Control = control
	p.Paths.Installation = root
	defaults := host.InstallationPaths{Launcher: "/usr/local/bin/chatanium", Config: filepath.Join(root, "config.json"), Secrets: filepath.Join(root, "secrets.json"), BackingFile: filepath.Join(root, "backing.xfs"), EngineRoot: filepath.Join(root, "engine"), StorageRoot: filepath.Join(root, "storage"), RunRoot: "/run/chatanium-" + string(p.InstallationID)}
	if p.Paths.Launcher == "" {
		p.Paths.Launcher = defaults.Launcher
	}
	if p.Paths.Config == "" {
		p.Paths.Config = defaults.Config
	}
	if p.Paths.Secrets == "" {
		p.Paths.Secrets = defaults.Secrets
	}
	if p.Paths.BackingFile == "" {
		p.Paths.BackingFile = defaults.BackingFile
	}
	if p.Paths.EngineRoot == "" {
		p.Paths.EngineRoot = defaults.EngineRoot
	}
	if p.Paths.StorageRoot == "" {
		p.Paths.StorageRoot = defaults.StorageRoot
	}
	if p.Paths.RunRoot == "" {
		p.Paths.RunRoot = defaults.RunRoot
	}
	if p.Budget == (host.StorageBudget{}) {
		p.Budget = host.StorageBudget{DataBytes: 32 << 30, DataInodes: 1 << 20, SourceBytes: 8 << 30, SourceInodes: 1 << 18, CacheBytes: 8 << 30, CacheInodes: 1 << 18, PreparationBytes: 8 << 30, PreparationInodes: 1 << 18, MetadataHeadroomBytes: 1 << 30, MetadataHeadroomInodes: 1 << 16}
	}
	if p.Budget.AppBytes == 0 {
		p.Budget.AppBytes = 10 << 30
	}
	if p.Budget.AppInodes == 0 {
		p.Budget.AppInodes = 65536
	}
	identities := []*host.NumericIdentity{&p.Identities.App, &p.Identities.Sandbox, &p.Identities.Preparer}
	roles := []string{"app", "sandbox", "preparer"}
	used := map[uint32]bool{}
	for index, identity := range identities {
		if identity.Name == "" {
			identity.Name = "ctn-" + roles[index] + "-" + string(p.InstallationID)[:8]
		}
		u, lookup := user.Lookup(identity.Name)
		if lookup == nil {
			uid, ue := strconv.ParseUint(u.Uid, 10, 32)
			gid, ge := strconv.ParseUint(u.Gid, 10, 32)
			if ue != nil || ge != nil {
				return p, errors.New("invalid existing account IDs")
			}
			identity.UID = uint32(uid)
			identity.GID = uint32(gid)
			identity.ProductCreated = false
			if e = validateAccount(*identity); e != nil {
				return p, e
			}
		} else {
			if _, ok := lookup.(user.UnknownUserError); !ok {
				return p, lookup
			}
			if _, ge := user.LookupGroup(identity.Name); ge == nil {
				return p, errors.New("account name already has an unrelated group")
			} else if _, ok := ge.(user.UnknownGroupError); !ok {
				return p, ge
			}
			if identity.UID == 0 || identity.GID == 0 {
				found := false
				for id := uint32(60000); id < 65000; id++ {
					if used[id] {
						continue
					}
					_, ue := user.LookupId(strconv.FormatUint(uint64(id), 10))
					_, ge := user.LookupGroupId(strconv.FormatUint(uint64(id), 10))
					_, uAbsent := ue.(user.UnknownUserIdError)
					_, gAbsent := ge.(user.UnknownGroupIdError)
					if uAbsent && gAbsent {
						identity.UID = id
						identity.GID = id
						found = true
						break
					}
					if ue != nil && !uAbsent {
						return p, ue
					}
					if ge != nil && !gAbsent {
						return p, ge
					}
				}
				if !found {
					return p, errors.New("no free dedicated numeric identity")
				}
			}
			identity.ProductCreated = true
		}
		used[identity.UID] = true
		used[identity.GID] = true
	}
	base, e := runtime.DefaultInstallationConfig(string(p.InstallationID), p.BundleDigest, p.Paths)
	if e != nil {
		return p, e
	}
	if len(p.BaseConfig) > 0 {
		var supplied, mapDefault map[string]json.RawMessage
		if e = gvxcontract.DecodeStrict(p.BaseConfig, 16<<20, 64, &supplied); e != nil {
			return p, e
		}
		if e = json.Unmarshal(base, &mapDefault); e != nil {
			return p, e
		}
		var suppliedHost map[string]json.RawMessage
		if value, ok := supplied["host"]; ok {
			if e = gvxcontract.DecodeStrict(value, 1<<20, 16, &suppliedHost); e != nil {
				return p, e
			}
		}
		var defaultHost map[string]json.RawMessage
		if e = json.Unmarshal(mapDefault["host"], &defaultHost); e != nil {
			return p, e
		}
		if network, ok := suppliedHost["network"]; ok {
			defaultHost["network"] = network
		}
		mapDefault["host"], e = json.Marshal(defaultHost)
		if e != nil {
			return p, e
		}
		for key, value := range supplied {
			if key != "host" && key != "modules" {
				mapDefault[key] = value
			}
		}
		base, e = json.Marshal(mapDefault)
		if e != nil {
			return p, e
		}
	}
	p.BaseConfig = base
	cfg, e := runtime.DecodeConfig(base)
	if e != nil {
		return p, e
	}
	if e = validateAppBudget(cfg, p.Budget, nil); e != nil {
		return p, e
	}
	p.NetworkPrerequisites, e = host.ObserveNetworkPrerequisites(ctx, networkPlanConfig(cfg))
	if e != nil {
		return p, e
	}
	p.ManagementAnchor, e = host.ObserveManagementAnchor(ctx)
	if e != nil {
		return p, e
	}
	managementObject, e := initManagementAnchorObject(p.ManagementAnchor)
	if e != nil {
		return p, e
	}
	p.Objects = []ApprovedObject{managementObject}
	directories := []string{p.Paths.EngineRoot, p.Paths.StorageRoot, p.Paths.RunRoot, filepath.Join(p.Paths.RunRoot, "netns"), filepath.Join(p.Paths.RunRoot, "instances")}
	for _, path := range directories {
		p.Objects = append(p.Objects, ApprovedObject{Kind: "directory", Identity: path, Action: "create"})
	}
	for _, object := range []ApprovedObject{{Kind: "backing", Identity: p.Paths.BackingFile, Action: "create"}, {Kind: "bundle", Identity: p.Paths.EngineRoot, Action: "create"}, {Kind: "config", Identity: p.Paths.Config, Action: "create"}, {Kind: "secret", Identity: p.Paths.Secrets, Action: "create"}} {
		p.Objects = append(p.Objects, object)
	}
	p.Objects = append(p.Objects, ApprovedObject{Kind: "config", Identity: filepath.Join(p.Paths.Installation, "dev-watch.lock"), Action: "create"})
	launcher := ApprovedObject{Kind: "config", Identity: p.Paths.Launcher, Action: "create"}
	if _, e = os.Lstat(p.Paths.Launcher); e == nil {
		observation, e := launcherObservation(p.Paths.Launcher)
		if e != nil {
			return p, e
		}
		launcher.Action = "reuse"
		launcher.ObservationDigest, e = ObjectObservationDigest(observation)
		if e != nil {
			return p, e
		}
	} else if !os.IsNotExist(e) {
		return p, e
	}
	p.Objects = append(p.Objects, launcher)
	for _, identity := range identities {
		object := ApprovedObject{Kind: "account", Identity: identity.Name, Action: "create"}
		if !identity.ProductCreated {
			object.Action = "reuse"
			object.ObservationDigest, e = ObjectObservationDigest(host.ObjectObservation{Identity: identity.Name, Attributes: provisionJSON(host.ProvisionProperties{Name: identity.Name, UID: identity.UID, GID: identity.GID})})
			if e != nil {
				return p, e
			}
		}
		p.Objects = append(p.Objects, object)
	}
	if cfg.Host.Network.Profile != host.NetworkNone {
		anchors, e := host.InspectNetworkAnchors(ctx)
		if e != nil {
			return p, e
		}
		for _, anchor := range anchors {
			object := ApprovedObject{Kind: "shared-network-anchor", Identity: anchor.Path, Action: "create"}
			if anchor.Exists {
				object.Action = "reuse"
				object.ObservationDigest, e = NetworkAnchorObservationDigest(anchor)
				if e != nil {
					return p, e
				}
			}
			p.Objects = append(p.Objects, object)
		}
	}
	if e = initSecretObjects(&p, cfg); e != nil {
		return p, e
	}
	ceiling := maximumPreparationLimits(host.InstallationManifest{Budget: p.Budget})
	preparationDefaults := provision.PrepareLimits{}
	if count := int64(len(p.Modules)); count > 0 {
		available := p.Budget
		available.SourceBytes /= count
		available.CacheBytes /= count
		available.SourceInodes /= count
		available.CacheInodes /= count
		preparationDefaults, e = FitPreparationLimits(ceiling, p.Budget, available)
		if e != nil {
			return p, e
		}
	}
	remaining := p.Budget
	for index := range p.Modules {
		in := &p.Modules[index]
		in.Candidate.ConfigRevision = newID()
		in.Candidate.ApprovalRevision = newID()
		if in.Image.JobID == "" {
			in.Image.JobID = newID()
		}
		in.Image.ModuleID = string(in.Candidate.ModuleID)
		in.Image.ConfigRevision = in.Candidate.ConfigRevision
		in.Image.ApprovalRevision = in.Candidate.ApprovalRevision
		if in.Image.Platform == "" {
			in.Image.Platform = "linux/amd64"
		}
		if in.Image.Limits == (provision.PrepareLimits{}) {
			in.Image.Limits = preparationDefaults
		}
		if e = in.Image.Validate(); e != nil {
			return p, e
		}
		if e = checkPrepareLimits(in.Image.Limits, ceiling); e != nil {
			return p, e
		}
		limits := in.Image.Limits
		if limits.InputBytes > remaining.SourceBytes/2 || limits.OutputBytes > remaining.CacheBytes || limits.Inodes > remaining.SourceInodes || limits.Inodes > remaining.CacheInodes || limits.Inodes > p.Budget.PreparationInodes || limits.ExpandedBytes > p.Budget.PreparationBytes-limits.OutputBytes || limits.InputBytes%4096 != 0 || limits.OutputBytes%4096 != 0 || limits.ExpandedBytes%4096 != 0 {
			return p, errors.New("planned preparation exceeds exact source/cache/work peak reservation")
		}
		remaining.SourceBytes -= 2 * limits.InputBytes
		remaining.CacheBytes -= limits.OutputBytes
		remaining.SourceInodes -= limits.Inodes
		remaining.CacheInodes -= limits.Inodes
	}
	if e = inspectInitCreates(p); e != nil {
		return p, e
	}
	p.PlanDigest, e = InitPlanDigest(p)
	if e != nil {
		return p, e
	}
	return p, validateInit(p)
}

// launcherObservation permits only explicit reuse of the protected executing file.
func launcherObservation(path string) (host.ObjectObservation, error) {
	var observation host.ObjectObservation
	if e := trustedPath(path, false); e != nil {
		return observation, e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return observation, e
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st, executing unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return observation, e
	}
	if e = unix.Stat("/proc/self/exe", &executing); e != nil {
		return observation, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size <= 0 || st.Size > 1<<30 || st.Uid != 0 || st.Dev != executing.Dev || st.Ino != executing.Ino || st.Mode&07777 != 0755 {
		return observation, errors.New("launcher reuse requires the protected executing inode at mode 0755")
	}
	sum, e := streamDigest(file)
	if e != nil {
		return observation, e
	}
	p := host.ProvisionProperties{Path: path, Digest: sum, Dev: uint64(st.Dev), Ino: st.Ino, Mode: st.Mode & 07777, UID: st.Uid, GID: st.Gid, SizeBytes: st.Size, ProductCreated: false}
	return host.ObjectObservation{Identity: path, Attributes: provisionJSON(p)}, nil
}

// initIntent reuses only the same unfinished durable object intent.
func initIntent(ctx context.Context, s *host.Store, kind, identity string, p host.ProvisionProperties, existed bool) (string, error) {
	records, e := s.PendingProvisions(ctx)
	if e != nil {
		return "", e
	}
	desired := provisionJSON(p)
	for _, record := range records {
		if record.Kind != kind || record.Identity != identity {
			continue
		}
		if record.CleanupState == "COMPLETE" {
			return "", errors.New("initialization cannot recreate a retired object")
		}
		if record.ExistedBefore != existed || record.ProductCreated == existed || !bytes.Equal(record.Desired, desired) {
			return "", errors.New("durable object intent differs from approved initialization")
		}
		return record.ID, nil
	}
	return recordIntent(ctx, s, kind, identity, p, existed)
}

func installApprovedLauncher(ctx context.Context, s *host.Store, p ApprovedInitPlan) error {
	for _, object := range p.Objects {
		if object.Kind != "config" || object.Identity != p.Paths.Launcher || object.Action != "reuse" {
			continue
		}
		observation, e := launcherObservation(p.Paths.Launcher)
		if e != nil {
			return e
		}
		sum, e := ObjectObservationDigest(observation)
		if e != nil || sum != object.ObservationDigest {
			return errors.New("preinstalled launcher observation changed")
		}
		var properties host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(observation.Attributes, 64<<10, 16, &properties); e != nil {
			return e
		}
		id, e := initIntent(ctx, s, "config", p.Paths.Launcher, properties, true)
		if e != nil {
			return e
		}
		return s.ObserveProvision(ctx, id, observation)
	}
	return installLauncher(ctx, s, p.Paths.Launcher)
}

func inspectInitCreates(p ApprovedInitPlan) error {
	for _, object := range p.Objects {
		if object.Action != "create" {
			continue
		}
		if object.Kind == "account" {
			for _, identity := range []host.NumericIdentity{p.Identities.App, p.Identities.Sandbox, p.Identities.Preparer} {
				if identity.Name != object.Identity {
					continue
				}
				if _, e := user.Lookup(identity.Name); e == nil {
					return errors.New("new dedicated account already exists")
				} else if !unknownUser(e) {
					return e
				}
				if _, e := user.LookupGroup(identity.Name); e == nil {
					return errors.New("new dedicated group already exists")
				} else if !unknownGroup(e) {
					return e
				}
				if _, e := user.LookupId(strconv.FormatUint(uint64(identity.UID), 10)); e == nil {
					return errors.New("approved UID already allocated")
				} else if _, ok := e.(user.UnknownUserIdError); !ok {
					return e
				}
				if _, e := user.LookupGroupId(strconv.FormatUint(uint64(identity.GID), 10)); e == nil {
					return errors.New("approved GID already allocated")
				} else if _, ok := e.(user.UnknownGroupIdError); !ok {
					return e
				}
			}
			continue
		}
		switch object.Kind {
		case "directory", "config", "secret", "backing", "bundle":
			if _, e := os.Lstat(object.Identity); e == nil {
				return errors.New("approved new installation object already exists: " + object.Identity)
			} else if !os.IsNotExist(e) {
				return e
			}
		}
	}
	return nil
}

func validateAppBudget(c runtime.Config, b host.StorageBudget, policies []host.LaunchSpec) error {
	records := int64(c.Limits.UploadRecordsPerHost)
	uploadBytes := int64(upload.BytesPerHost)
	if uint64(records) <= upload.BytesPerHost/upload.MaxFileBytes {
		uploadBytes = records * int64(upload.MaxFileBytes)
	}
	files := int64(c.Limits.LogRetainedFiles) + 1
	if files <= 0 || c.Limits.LogFileMaxBytes <= 0 || files > math.MaxInt64/c.Limits.LogFileMaxBytes {
		return errors.New("app log reservation overflows")
	}
	logs := files * c.Limits.LogFileMaxBytes
	if logs > math.MaxInt64-uploadBytes-5*4096 || records > math.MaxInt64-files-6 {
		return errors.New("app storage requirement overflows")
	}
	if e := host.ValidateAppAllowance(b, uploadBytes+logs+5*4096, records+files+6); e != nil {
		return e
	}
	bytes, inodes := b.AppBytes, b.AppInodes
	for _, policy := range policies {
		for _, n := range []int64{policy.Resources.PersistentBytes, policy.Resources.ScratchBytes} {
			if n <= 0 || n > b.DataBytes-bytes {
				return errors.New("configured modules and app overcommit data pool")
			}
			bytes += n
		}
		for _, n := range []int64{policy.Resources.PersistentInodes, policy.Resources.ScratchInodes} {
			if n <= 0 || n > b.DataInodes-inodes {
				return errors.New("configured modules and app overcommit data inode pool")
			}
			inodes += n
		}
	}
	return nil
}

func provisionDevWatchLock(ctx context.Context, s *host.Store, m host.InstallationManifest) error {
	path := filepath.Join(m.Paths.Installation, "dev-watch.lock")
	properties := host.ProvisionProperties{Path: path, Mode: 0440, GID: m.Identities.App.GID, ProductCreated: true}
	id, e := initIntent(ctx, s, "config", path, properties, false)
	if e != nil {
		return e
	}
	records, e := s.ObjectProvisions(ctx, "config", path)
	if e != nil {
		return e
	}
	for _, record := range records {
		if record.ID != id || record.State != "OBSERVED" {
			continue
		}
		if e = matchRecord(record); e != nil {
			return e
		}
		var st unix.Stat_t
		if e = unix.Lstat(path, &st); e != nil {
			return e
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0440 || st.Uid != 0 || st.Gid != m.Identities.App.GID || st.Nlink != 1 || st.Size != 0 {
			return errors.New("watch coordination lock metadata changed")
		}
		return nil
	}
	if e = trustedPath(path, true); e != nil {
		return e
	}
	fd, e := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0440)
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(fd), path)
	e = unix.Fchown(fd, 0, int(m.Identities.App.GID))
	if e == nil {
		e = file.Chmod(0440)
	}
	if e == nil {
		e = file.Sync()
	}
	e = errors.Join(e, file.Close())
	if e != nil {
		return e
	}
	if e = syncDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	return observePath(ctx, s, id, path, properties)
}

func networkPlanConfig(c runtime.Config) host.NetworkConfig {
	network := c.Host.Network
	internal := make([]string, 0, len(network.InternalPrefixes)+len(network.InfrastructurePrefixes))
	internal = append(internal, network.InternalPrefixes...)
	internal = append(internal, network.InfrastructurePrefixes...)
	return host.NetworkConfig{Profile: network.Profile, IPv4Pool: network.IPv4Pool, IPv6Pool: network.IPv6Pool, InventoryRevision: network.InventoryRevision, Uplink4: network.Uplink4, Uplink6: network.Uplink6, Source4: network.Source4, Source6: network.Source6, Resolvers: network.Resolvers, HostPublicAddresses: network.HostPublicAddresses, InternalPrefixes: internal, MetadataPrefixes: network.MetadataDestinations, RunRoot: filepath.Dir(c.Host.IPCRoot), OperationTimeout: time.Duration(c.Limits.HostOperationDeadline)}
}

// recoverApprovedInitialization settles only this journal-bound initialization.
// The caller retains the same Store, lease and systemd owner for resumed work.
func recoverApprovedInitialization(ctx context.Context, s *host.Store, lease *host.InstallationLease, m host.InstallationManifest, p ApprovedInitPlan, config runtime.Config) (result *host.Systemd, owner host.UnitIdentity, manifest host.InstallationManifest, retErr error) {
	manifest = m
	if m.State != "RECOVERY_REQUIRED" || m.DesiredRunState != "STOPPED" || m.ActiveRevision != "" {
		return nil, owner, manifest, errors.New("initialization recovery requires a stopped unactivated installation")
	}
	record, e := ownedRecord(ctx, s, "bundle", p.Paths.EngineRoot)
	if e != nil {
		return nil, owner, manifest, e
	}
	if record.CleanupState == "COMPLETE" {
		return nil, owner, manifest, errors.New("initialization cannot recover with a retired bundle")
	}
	if e = matchRecord(record); e != nil {
		return nil, owner, manifest, e
	}
	var properties host.ProvisionProperties
	if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &properties); e != nil {
		return nil, owner, manifest, e
	}
	if properties.Digest != p.BundleDigest || properties.Path != filepath.Join(p.Paths.EngineRoot, p.BundleDigest[7:]) {
		return nil, owner, manifest, errors.New("initialization recovery bundle differs from its approved observation")
	}
	verified, e := installedBundle(ctx, m)
	if e != nil {
		return nil, owner, manifest, e
	}
	d, e := host.NewSystemd(ctx, verified)
	if e != nil {
		return nil, owner, manifest, e
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, d.Close())
		}
	}()
	owner, e = d.RegisterForegroundOwner(ctx, string(p.InstallationID))
	if e != nil {
		return nil, owner, manifest, e
	}
	if e = lease.BindOwner(ctx, owner); e != nil {
		return nil, owner, manifest, e
	}
	if e = d.BindStore(s); e != nil {
		return nil, owner, manifest, e
	}
	session := &ownedSession{id: p.InstallationID, manifest: m, store: s, lease: lease, systemd: d, owner: owner, config: config}
	evidence, e := recoverInitialization(ctx, session)
	if e != nil {
		return nil, owner, manifest, e
	}
	if e = s.ResumeInitialization(ctx, p.PlanID, p.PlanDigest, evidence); e != nil {
		return nil, owner, manifest, e
	}
	manifest, e = s.Installation(ctx)
	if e != nil {
		return nil, owner, manifest, e
	}
	return d, owner, manifest, nil
}

func initManagementAnchorObject(observation host.ManagementAnchorObservation) (ApprovedObject, error) {
	var object ApprovedObject
	if observation.Root.Path != "/var/lib/chatanium" || observation.Lock.Path != "/var/lib/chatanium/.management.lock" || observation.Marker != "chatanium-management-v1\n" || observation.Root.Absent && !observation.Lock.Absent {
		return object, errors.New("initialization requires the fixed retained management anchor")
	}
	object = ApprovedObject{Kind: "management-anchor", Identity: observation.Lock.Path, Action: "create"}
	if !observation.Lock.Absent {
		object.Action = "reuse"
		raw, e := json.Marshal(observation.Lock)
		if e != nil {
			return object, e
		}
		object.ObservationDigest, e = ObjectObservationDigest(host.ObjectObservation{Identity: observation.Lock.Path, Attributes: raw})
		if e != nil {
			return object, e
		}
	}
	return object, nil
}

func validateInitManagementPaths(p ApprovedInitPlan) error {
	root := p.ManagementAnchor.Root.Path
	for _, path := range []string{p.Paths.Installation, p.Paths.Control, p.Paths.Launcher, p.Paths.Config, p.Paths.Secrets, p.Paths.BackingFile, p.Paths.StorageRoot, p.Paths.EngineRoot, p.Paths.RunRoot} {
		if path == root || isAncestor(path, root) {
			return errors.New("installation paths cannot replace retained shared management infrastructure")
		}
		relative, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		first, _, _ := strings.Cut(relative, "/")
		if first == ".management.lock" || strings.HasPrefix(first, ".purge-terminal-") {
			return errors.New("installation paths overlap reserved terminal management authority")
		}
	}
	return nil
}

func verifyInitManagementAnchor(ctx context.Context, s *host.Store) error {
	saved, e := s.ManagementAnchor(ctx)
	if e != nil {
		return e
	}
	current, e := host.ObserveManagementAnchor(ctx)
	if e != nil {
		return e
	}
	// A shared directory's child count is not an immutable native identity.
	saved.Root.Links, current.Root.Links = 0, 0
	if saved != current || current.Root.Absent || current.Lock.Absent {
		return errors.New("initialization management anchor differs from its durable native identity")
	}
	return nil
}
