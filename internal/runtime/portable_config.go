package runtime

import (
	"encoding/json"
	"math"
	"path"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/host"
	"google.golang.org/protobuf/encoding/protojson"
)

// PortableFormat is an explicit opt-in; a legacy v1 installation never gains
// the ext4lite interpretation of persistent_bytes or scratch_bytes implicitly.
const PortableFormat = "portable-v2"

func DefaultPortableConfig(id, bundleDigest, storageRoot, ipcRoot string) Config {
	config := defaultConfig(id, bundleDigest, storageRoot, ipcRoot)
	config.Host.Format = PortableFormat
	config.Limits.UploadRecordsPerInstance = 1
	config.Limits.UploadRecordsPerHost = 1
	return config
}

func (c Config) validPortableHost() bool {
	h, l, d := c.Host, c.Limits, c.Defaults
	n := h.Network
	const maxDeadline = Duration(10 * time.Minute)
	return h.QuotaBackend == "" && l.PersistentInodeLimit == 0 && l.ScratchInodeLimit == 0 &&
		!strings.ContainsAny(h.RuntimeInstallationID, "\\\r\n") &&
		(n.Profile == host.NetworkNone || n.Profile == host.NetworkPublicV4) && !n.hasLegacySettings() &&
		len(c.Modules) <= 512 && l.UploadRecordsPerInstance == 1 && l.UploadRecordsPerHost == 1 &&
		l.ControlMessageMaxBytes <= 8<<20 && d.StartupDeadline <= maxDeadline &&
		d.DrainDeadline <= maxDeadline && l.TerminationDeadline <= maxDeadline && l.HostOperationDeadline <= maxDeadline &&
		l.HookRPCDeadline <= maxDeadline && l.UploadDeadline <= maxDeadline && l.CredentialRefMaxTTL <= Duration(24*time.Hour)
}

func (s ModuleSpec) validPortableTarget() bool {
	entry, id := s.Entrypoint[0], string(s.ModuleID)
	return recordImagePattern.MatchString(s.ImageDigest) && len(id) <= 256 && strings.TrimSpace(id) == id &&
		!strings.ContainsAny(id, "\x00\r\n") && s.UID != ^uint32(0) && s.GID != ^uint32(0) &&
		entry != "/" && path.IsAbs(entry) && path.Clean(entry) == entry && !strings.ContainsAny(entry, "\\\x00\r\n")
}

func (p ResourceProfile) validPortable() bool {
	// The worker cannot claim configurations the pinned parser cannot encode;
	// the supervisor also checks the actual target's CPU capacity.
	validVolume := func(size uint64) bool { return size >= 16<<20 && size <= 64<<40 && size%(16<<20) == 0 }
	return p.CPUMillicores >= 10 && p.MemoryBytes >= 6<<20 && float64(p.MemoryBytes) < float64(math.MaxInt64) &&
		uint64(float64(p.MemoryBytes)) == p.MemoryBytes && validVolume(p.PersistentBytes) && validVolume(p.ScratchBytes)
}

// EncodePortableConfig carries the module list and strict core-v2 approval
// representation expected by DecodeConfig. Raw secret values are separate.
func EncodePortableConfig(config Config) ([]byte, error) {
	if config.Host.Format != PortableFormat {
		return nil, invalidConfig()
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	modules := make([]moduleJSON, 0, len(config.Modules))
	for _, spec := range config.Modules {
		grants, err := protojson.Marshal(spec.Approval)
		if err != nil {
			return nil, invalidConfig()
		}
		modules = append(modules, moduleJSON{ModuleID: spec.ModuleID, Image: spec.ImageDigest, Entrypoint: spec.Entrypoint,
			Args: spec.Args, UID: spec.UID, GID: spec.GID, Config: spec.Config.Json, Approval: grants,
			CredentialBindings: spec.CredentialBindings, ConfigRevision: spec.ConfigRevision, ApprovalRevision: spec.ApprovalRevision, DiscordACLRequired: spec.DiscordACLRequired})
	}
	return json.Marshal(struct {
		Config
		Modules []moduleJSON `json:"modules"`
	}{config, modules})
}
