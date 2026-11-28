package runtime

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thirdscam/chatanium/internal/host"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(raw []byte) error {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return invalidConfig()
	}
	v, e := time.ParseDuration(s)
	if e != nil || v <= 0 {
		return invalidConfig()
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

type Defaults struct {
	StartupDeadline  Duration `json:"startup_deadline"`
	DrainDeadline    Duration `json:"drain_deadline"`
	EventQueueEvents int      `json:"event_queue_events"`
	EventQueueBytes  int64    `json:"event_queue_bytes"`
}
type Limits struct {
	TerminationDeadline       Duration `json:"termination_deadline"`
	HostOperationDeadline     Duration `json:"host_operation_deadline"`
	HookRPCDeadline           Duration `json:"hook_rpc_deadline"`
	ReadinessPollInterval     Duration `json:"readiness_poll_interval"`
	ControlMessageMaxBytes    int      `json:"control_message_max_bytes"`
	ConfigMaxBytes            int      `json:"config_max_bytes"`
	ControlRPCsPerInstance    int      `json:"control_rpcs_per_instance"`
	CredentialRefsPerInstance int      `json:"credential_refs_per_instance"`
	CredentialRefMaxTTL       Duration `json:"credential_ref_max_ttl"`
	PersistentInodeLimit      int64    `json:"persistent_inode_limit,omitempty"`
	ScratchInodeLimit         int64    `json:"scratch_inode_limit,omitempty"`
	LogBufferBytes            int64    `json:"log_buffer_bytes"`
	LogFileMaxBytes           int64    `json:"log_file_max_bytes"`
	LogRetainedFiles          int      `json:"log_retained_files"`
	UploadRecordsPerInstance  int      `json:"upload_records_per_instance"`
	UploadRecordsPerHost      int      `json:"upload_records_per_host"`
	UploadFileNameMaxBytes    int      `json:"upload_file_name_max_bytes"`
	UploadContentTypeMaxBytes int      `json:"upload_content_type_max_bytes"`
	UploadDeadline            Duration `json:"upload_deadline"`
}
type NetworkConfig struct {
	Profile                host.NetworkProfile `json:"profile"`
	FirewallBackend        string              `json:"firewall_backend"`
	IPv4Pool               string              `json:"ipv4_pool"`
	IPv6Pool               string              `json:"ipv6_pool"`
	InventoryRevision      string              `json:"inventory_revision"`
	Uplink4                string              `json:"uplink4"`
	Uplink6                string              `json:"uplink6"`
	Source4                string              `json:"source4"`
	Source6                string              `json:"source6"`
	IPv4                   bool                `json:"ipv4"`
	IPv6                   bool                `json:"ipv6"`
	Resolvers              []string            `json:"resolvers"`
	HostPublicAddresses    []string            `json:"host_public_addresses"`
	InternalPrefixes       []string            `json:"internal_prefixes"`
	InfrastructurePrefixes []string            `json:"infrastructure_prefixes"`
	MetadataDestinations   []string            `json:"metadata_destinations"`
}
type HostConfig struct {
	Format                string        `json:"format,omitempty"`
	RuntimeInstallationID string        `json:"runtime_installation_id"`
	BundleDigest          string        `json:"bundle_digest"`
	ManagementDirectory   string        `json:"management_directory"`
	StorageRoot           string        `json:"storage_root"`
	IPCRoot               string        `json:"ipc_root"`
	QuotaBackend          string        `json:"quota_backend,omitempty"`
	Network               NetworkConfig `json:"network"`
}
type BackendConfig struct {
	Major         uint32            `json:"major"`
	Config        json.RawMessage   `json:"config"`
	SecretSources map[string]string `json:"secret_sources"`
}
type ResourceProfile struct {
	CPUMillicores   uint32 `json:"cpu_millicores"`
	MemoryBytes     uint64 `json:"memory_bytes"`
	MaxPids         uint32 `json:"max_pids"`
	PersistentBytes uint64 `json:"persistent_bytes"`
	ScratchBytes    uint64 `json:"scratch_bytes"`
}

func (p ResourceProfile) wire() *wire.ResourceLimits {
	return &wire.ResourceLimits{CpuMillicores: p.CPUMillicores, MemoryBytes: p.MemoryBytes, MaxPids: p.MaxPids, PersistentBytes: p.PersistentBytes, ScratchBytes: p.ScratchBytes}
}
func (p ResourceProfile) valid() bool {
	return p.CPUMillicores > 0 && p.MemoryBytes > 0 && p.MaxPids > 0 && p.PersistentBytes > 0 && p.ScratchBytes > 0 && p.MemoryBytes <= math.MaxInt64 && p.PersistentBytes <= math.MaxInt64 && p.ScratchBytes <= math.MaxInt64 && p.PersistentBytes%512 == 0 && p.ScratchBytes%512 == 0
}

type Config struct {
	SchemaVersion    int                        `json:"schema_version"`
	Host             HostConfig                 `json:"host"`
	Backends         map[string]BackendConfig   `json:"backends"`
	ResourceProfiles map[string]ResourceProfile `json:"resource_profiles"`
	Defaults         Defaults                   `json:"defaults"`
	Limits           Limits                     `json:"limits"`
	Modules          []ModuleSpec               `json:"-"`
}
type moduleJSON struct {
	ModuleID           ModuleID                       `json:"module_id"`
	Image              string                         `json:"image"`
	Entrypoint         []string                       `json:"entrypoint"`
	Args               []string                       `json:"args"`
	UID                uint32                         `json:"uid"`
	GID                uint32                         `json:"gid"`
	Config             json.RawMessage                `json:"config"`
	Approval           json.RawMessage                `json:"approval"`
	CredentialBindings []ProvisionedCredentialBinding `json:"credential_bindings"`
	ConfigRevision     string                         `json:"config_revision"`
	ApprovalRevision   string                         `json:"approval_revision"`
	DiscordACLRequired bool                           `json:"discord_acl_required,omitempty"`
}

// DecodeConfig rejects unknown and duplicate fields; module JSON bytes are kept exact.
// The caller bounds the host document while reading it; no secret source is expanded.
func DecodeConfig(raw []byte) (Config, error) {
	if !utf8.Valid(raw) || rejectDuplicates(raw) != nil {
		return Config{}, invalidConfig()
	}
	var doc struct {
		SchemaVersion    int                        `json:"schema_version"`
		Host             HostConfig                 `json:"host"`
		Backends         map[string]BackendConfig   `json:"backends"`
		ResourceProfiles map[string]ResourceProfile `json:"resource_profiles"`
		Defaults         Defaults                   `json:"defaults"`
		Limits           Limits                     `json:"limits"`
		Modules          []moduleJSON               `json:"modules"`
	}
	doc.Defaults = Defaults{StartupDeadline: Duration(30 * time.Second), DrainDeadline: Duration(10 * time.Second), EventQueueEvents: 256, EventQueueBytes: 32 << 20}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&doc) != nil {
		return Config{}, invalidConfig()
	}
	if d.Decode(new(any)) != io.EOF {
		return Config{}, invalidConfig()
	}
	if doc.Modules == nil || doc.Defaults.StartupDeadline <= 0 || doc.Defaults.DrainDeadline <= 0 || doc.Defaults.EventQueueEvents <= 0 || doc.Defaults.EventQueueBytes <= 0 {
		return Config{}, invalidConfig()
	}
	c := Config{SchemaVersion: doc.SchemaVersion, Host: doc.Host, Backends: doc.Backends, ResourceProfiles: doc.ResourceProfiles, Defaults: doc.Defaults, Limits: doc.Limits}
	c.applyDefaults()
	c.Modules = make([]ModuleSpec, 0, len(doc.Modules))
	for _, m := range doc.Modules {
		grants := new(wire.Grants)
		if protojson.Unmarshal(m.Approval, grants) != nil {
			return Config{}, invalidConfig()
		}
		c.Modules = append(c.Modules, ModuleSpec{ModuleID: m.ModuleID, ImageDigest: m.Image, Entrypoint: m.Entrypoint, Args: m.Args, UID: m.UID, GID: m.GID, Config: &wire.JSONValue{Json: bytes.Clone(m.Config)}, Approval: grants, CredentialBindings: m.CredentialBindings, ConfigRevision: m.ConfigRevision, ApprovalRevision: m.ApprovalRevision, DiscordACLRequired: m.DiscordACLRequired})
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
func (c *Config) applyDefaults() {
	if c.Defaults.StartupDeadline == 0 {
		c.Defaults.StartupDeadline = Duration(30 * time.Second)
	}
	if c.Defaults.DrainDeadline == 0 {
		c.Defaults.DrainDeadline = Duration(10 * time.Second)
	}
	if c.Defaults.EventQueueEvents == 0 {
		c.Defaults.EventQueueEvents = 256
	}
	if c.Defaults.EventQueueBytes == 0 {
		c.Defaults.EventQueueBytes = 32 << 20
	}
	if c.ResourceProfiles == nil {
		c.ResourceProfiles = make(map[string]ResourceProfile)
	}
	if _, ok := c.ResourceProfiles["general"]; !ok {
		c.ResourceProfiles["general"] = ResourceProfile{500, 256 << 20, 64, 1 << 30, 256 << 20}
	}
	if _, ok := c.ResourceProfiles["media"]; !ok {
		c.ResourceProfiles["media"] = ResourceProfile{2000, 1 << 30, 128, 5 << 30, 2 << 30}
	}
}

func defaultConfig(id, bundleDigest, storageRoot, ipcRoot string) Config {
	config := Config{
		SchemaVersion: 2,
		Host: HostConfig{RuntimeInstallationID: id, BundleDigest: bundleDigest,
			ManagementDirectory: filepath.Join(storageRoot, "app"), StorageRoot: storageRoot, IPCRoot: ipcRoot,
			Network: NetworkConfig{Profile: host.NetworkNone}},
		Backends: map[string]BackendConfig{},
		Limits: Limits{TerminationDeadline: Duration(15 * time.Second), HostOperationDeadline: Duration(10 * time.Second),
			HookRPCDeadline: Duration(5 * time.Second), ReadinessPollInterval: Duration(100 * time.Millisecond),
			ControlMessageMaxBytes: 1 << 20, ConfigMaxBytes: 64 << 10, ControlRPCsPerInstance: 32,
			CredentialRefsPerInstance: 128, CredentialRefMaxTTL: Duration(10 * time.Minute), LogBufferBytes: 8 << 20,
			LogFileMaxBytes: 16 << 20, LogRetainedFiles: 4,
			UploadFileNameMaxBytes: 256, UploadContentTypeMaxBytes: 256, UploadDeadline: Duration(time.Minute)},
		Modules: []ModuleSpec{},
	}
	config.applyDefaults()
	return config
}

func (n NetworkConfig) hasLegacySettings() bool {
	return n.IPv4 || n.IPv6 || n.FirewallBackend != "" || n.IPv4Pool != "" || n.IPv6Pool != "" ||
		n.InventoryRevision != "" || n.Uplink4 != "" || n.Uplink6 != "" || n.Source4 != "" || n.Source6 != "" ||
		len(n.Resolvers)+len(n.HostPublicAddresses)+len(n.InternalPrefixes)+len(n.InfrastructurePrefixes)+len(n.MetadataDestinations) != 0
}

var recordImagePattern = regexp.MustCompile(`^record:sha256:[a-f0-9]{64}$`)
var bundleDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func cleanAbsolute(s string) bool {
	return s != "/" && filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsRune(s, 0)
}
func (c Config) Validate() error {
	l := c.Limits
	h := c.Host
	d := c.Defaults
	if c.SchemaVersion != 2 || c.Backends == nil || l.TerminationDeadline <= 0 || l.HostOperationDeadline <= 0 || l.HookRPCDeadline <= 0 || l.ReadinessPollInterval <= 0 || l.CredentialRefMaxTTL <= 0 || l.ControlMessageMaxBytes <= 0 || l.ConfigMaxBytes <= 0 || l.ControlRPCsPerInstance <= 0 || l.CredentialRefsPerInstance <= 0 || l.LogBufferBytes <= 0 || l.LogFileMaxBytes <= 0 || l.LogRetainedFiles <= 0 || l.UploadRecordsPerInstance <= 0 || l.UploadRecordsPerHost <= 0 {
		return invalidConfig()
	}
	if l.UploadFileNameMaxBytes <= 0 || l.UploadContentTypeMaxBytes <= 0 || l.UploadDeadline <= 0 || l.UploadFileNameMaxBytes > math.MaxInt32 || l.UploadContentTypeMaxBytes > math.MaxInt32 {
		return invalidConfig()
	}
	if d.StartupDeadline <= 0 || d.DrainDeadline <= 0 || d.EventQueueEvents <= 0 || d.EventQueueBytes <= 0 || l.ReadinessPollInterval >= d.StartupDeadline || l.LogBufferBytes < int64(l.ControlMessageMaxBytes) || l.ConfigMaxBytes >= l.ControlMessageMaxBytes || l.UploadRecordsPerInstance > l.UploadRecordsPerHost {
		return invalidConfig()
	}
	// Protobuf framing is included without allocating a maximum chunk buffer.
	chunkBody := protowire.SizeTag(1) + protowire.SizeVarint(math.MaxUint64) + protowire.SizeTag(2) + protowire.SizeBytes(core.MaxUploadChunkBytes)
	chunkSize := protowire.SizeTag(2) + protowire.SizeBytes(chunkBody)
	if l.ControlMessageMaxBytes > math.MaxInt32 || l.ControlRPCsPerInstance > math.MaxInt32 || l.ControlMessageMaxBytes < chunkSize || l.ConfigMaxBytes > math.MaxInt32 || protowire.SizeTag(1)+protowire.SizeBytes(l.ConfigMaxBytes) > l.ControlMessageMaxBytes {
		return invalidConfig()
	}
	uploadMetadataBody := protowire.SizeTag(1) + protowire.SizeBytes(l.UploadFileNameMaxBytes) + protowire.SizeTag(2) + protowire.SizeBytes(l.UploadContentTypeMaxBytes) + protowire.SizeTag(3) + protowire.SizeVarint(core.MaxUploadFileBytes)
	if protowire.SizeTag(1)+protowire.SizeBytes(uploadMetadataBody) > l.ControlMessageMaxBytes {
		return invalidConfig()
	}
	// Collector workspaces, go-plugin's scanner and framed DATA buffers must
	// fit simultaneously before an output slab can be admitted.
	if l.LogBufferBytes <= 3*int64(l.ControlMessageMaxBytes)+65536+4096+256 {
		return invalidConfig()
	}
	if h.RuntimeInstallationID == "" || strings.TrimSpace(h.RuntimeInstallationID) != h.RuntimeInstallationID || strings.ContainsAny(h.RuntimeInstallationID, "/\x00") || !bundleDigestPattern.MatchString(h.BundleDigest) {
		return invalidConfig()
	}
	if h.ManagementDirectory != h.AppDirectory() {
		return invalidConfig()
	}
	paths := []string{h.ManagementDirectory, h.StorageRoot, h.IPCRoot}
	for _, p := range paths {
		if !cleanAbsolute(p) {
			return invalidConfig()
		}
	}
	for a, p := range paths {
		for b, q := range paths {
			if a != b && p == q {
				return invalidConfig()
			}
		}
	}
	switch h.Format {
	case "":
		if !c.validLegacyHost() {
			return invalidConfig()
		}
	case PortableFormat:
		if !c.validPortableHost() {
			return invalidConfig()
		}
	default:
		return invalidConfig()
	}
	for id, b := range c.Backends {
		if id == "" || b.Major == 0 || !utf8.Valid(b.Config) || !json.Valid(b.Config) || len(bytes.TrimSpace(b.Config)) == 0 || bytes.TrimSpace(b.Config)[0] != '{' {
			return invalidConfig()
		}
		for name, source := range b.SecretSources {
			if name == "" || source == "" {
				return invalidConfig()
			}
		}
	}
	for name, p := range c.ResourceProfiles {
		if name == "" || !p.valid() || h.Format == PortableFormat && !p.validPortable() {
			return invalidConfig()
		}
	}
	seen := map[ModuleID]bool{}
	for _, s := range c.Modules {
		if seen[s.ModuleID] {
			return invalidConfig()
		}
		seen[s.ModuleID] = true
		if err := c.validateSpec(s); err != nil {
			return err
		}
	}
	return nil
}
func (c Config) validateSpec(s ModuleSpec) error {
	if strings.TrimSpace(string(s.ModuleID)) == "" || s.UID == 0 || s.GID == 0 || len(s.Entrypoint) == 0 || s.Approval == nil {
		return invalidConfig()
	}
	if c.Host.Format == PortableFormat {
		if !s.validPortableTarget() {
			return invalidConfig()
		}
	} else if !s.validLegacyTarget() {
		return invalidConfig()
	}
	if s.DiscordACLRequired {
		if backend, present := c.Backends["discord"]; c.Host.Format != PortableFormat || !present || backend.Major != 2 || backendGrant(s.Approval, "discord") == nil {
			return invalidConfig()
		}
	}
	if c.Host.Network.Profile == host.NetworkNone && s.Approval.EgressPolicy == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		return invalidConfig()
	}
	for _, arguments := range [][]string{s.Entrypoint, s.Args} {
		for _, v := range arguments {
			if strings.ContainsRune(v, 0) {
				return invalidConfig()
			}
		}
	}
	if core.ValidateConfigJSON(s.Config, core.JSONLimits{MaxBytes: c.Limits.ConfigMaxBytes, MaxDepth: c.Limits.ConfigMaxBytes}) != nil {
		return invalidConfig()
	}
	if err := validateGrants(s.Approval); err != nil {
		return err
	}
	class := "general"
	if s.Approval.ResourceClass == wire.ResourceClass_RESOURCE_CLASS_MEDIA {
		class = "media"
	} else if s.Approval.ResourceClass != wire.ResourceClass_RESOURCE_CLASS_GENERAL {
		return invalidConfig()
	}
	p, ok := c.ResourceProfiles[class]
	if !ok || !proto.Equal(s.Approval.ResourceLimits, p.wire()) {
		return invalidConfig()
	}
	seen := map[string]bool{}
	for _, b := range s.CredentialBindings {
		if b.Name == "" || b.BackendID == "" || b.SecretID == "" || b.Purpose == "" || b.Resource == nil || seen[b.Name] {
			return invalidConfig()
		}
		if _, ok := c.Backends[b.BackendID]; !ok {
			return invalidConfig()
		}
		seen[b.Name] = true
	}
	return nil
}
func cloneSpec(s ModuleSpec) ModuleSpec {
	s.Entrypoint = append([]string(nil), s.Entrypoint...)
	s.Args = append([]string(nil), s.Args...)
	s.Config = proto.Clone(s.Config).(*wire.JSONValue)
	s.Approval = proto.Clone(s.Approval).(*wire.Grants)
	s.CredentialBindings = cloneCredentialBindings(s.CredentialBindings)
	return s
}
func cloneCredentialBindings(bindings []ProvisionedCredentialBinding) []ProvisionedCredentialBinding {
	result := append([]ProvisionedCredentialBinding(nil), bindings...)
	for n := range result {
		if result[n].Resource != nil {
			result[n].Resource = proto.Clone(result[n].Resource).(*wire.ResourceSelector)
		}
	}
	return result
}
func rejectDuplicates(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var scan func() error
	scan = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		del, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if del != '{' && del != '[' {
			return invalidConfig()
		}
		keys := map[string]bool{}
		for d.More() {
			if del == '{' {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || keys[s] {
					return invalidConfig()
				}
				keys[s] = true
			}
			if e := scan(); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	}
	if e := scan(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return invalidConfig()
	}
	return nil
}
