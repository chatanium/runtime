package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/host"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

func gvxConfigFixture() Config {
	c := Config{
		SchemaVersion: 2,
		Host:          HostConfig{RuntimeInstallationID: strings.Repeat("a", 32), BundleDigest: "sha256:" + strings.Repeat("b", 64), ManagementDirectory: "/var/lib/chatanium/storage/app", StorageRoot: "/var/lib/chatanium/storage", IPCRoot: "/run/chatanium/instances", QuotaBackend: "xfs-project", Network: NetworkConfig{Profile: host.NetworkPublicV4, FirewallBackend: "iptables", IPv4: true, IPv4Pool: "10.240.0.0/16", InventoryRevision: "inventory-one", Uplink4: "eth0", Source4: "1.1.1.2", Resolvers: []string{"1.1.1.1"}, HostPublicAddresses: []string{"1.1.1.2"}, InternalPrefixes: []string{}, InfrastructurePrefixes: []string{}, MetadataDestinations: []string{"169.254.169.254"}}},
		Backends:      map[string]BackendConfig{},
		Limits:        Limits{TerminationDeadline: Duration(time.Second), HostOperationDeadline: Duration(time.Second), HookRPCDeadline: Duration(time.Second), ReadinessPollInterval: Duration(time.Millisecond), ControlMessageMaxBytes: 1 << 20, ConfigMaxBytes: 64 << 10, ControlRPCsPerInstance: 16, CredentialRefsPerInstance: 16, CredentialRefMaxTTL: Duration(time.Minute), PersistentInodeLimit: 1000, ScratchInodeLimit: 1000, LogBufferBytes: 8 << 20, LogFileMaxBytes: 1 << 20, LogRetainedFiles: 2, UploadRecordsPerInstance: 4, UploadRecordsPerHost: 8, UploadFileNameMaxBytes: 256, UploadContentTypeMaxBytes: 128, UploadDeadline: Duration(time.Second)},
	}
	c.applyDefaults()
	return c
}

func TestGvxFixedFamilyConfiguration(t *testing.T) {
	v4 := gvxConfigFixture()
	if err := v4.Validate(); err != nil {
		t.Fatalf("explicit IPv4-only profile rejected: %v", err)
	}
	dual := gvxConfigFixture()
	dual.Host.Network.Profile = host.NetworkPublicDual
	dual.Host.Network.IPv6 = true
	dual.Host.Network.IPv6Pool = "fd42:1234::/64"
	dual.Host.Network.Uplink6 = "eth0"
	dual.Host.Network.Source6 = "2606:4700::2"
	dual.Host.Network.Resolvers = append(dual.Host.Network.Resolvers, "2606:4700:4700::1111")
	if err := dual.Validate(); err != nil {
		t.Fatalf("explicit dual-stack profile rejected: %v", err)
	}
	dual.Host.Network.Resolvers = []string{"1.1.1.1"}
	if dual.Validate() == nil {
		t.Fatal("dual-stack silently downgraded with no IPv6 resolver")
	}
	v4.Host.Network.Resolvers = append(v4.Host.Network.Resolvers, "2606:4700:4700::1111")
	if v4.Validate() == nil {
		t.Fatal("IPv4-only profile accepted an IPv6 resolver")
	}
	none := gvxConfigFixture()
	none.Host.Network = NetworkConfig{Profile: host.NetworkNone}
	if err := none.Validate(); err != nil {
		t.Fatalf("NONE required invented network prerequisites: %v", err)
	}
	none.Host.Network.IPv4Pool = "10.240.0.0/16"
	if none.Validate() == nil {
		t.Fatal("NONE accepted latent public topology policy")
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Limits.HostOperationDeadline = 0 },
		func(c *Config) { c.Host.RuntimeInstallationID = "" },
		func(c *Config) { c.Host.BundleDigest = "mutable" },
		func(c *Config) { c.Host.Network.IPv4Pool = "10.240.0.1/16" },
		func(c *Config) { c.Host.Network.Source4 = "::1" },
		func(c *Config) { c.Host.Network.IPv6Pool = "fd42::/64" },
	} {
		c := gvxConfigFixture()
		change(&c)
		if c.Validate() == nil {
			t.Fatal("invalid fixed runtime policy accepted")
		}
	}
}

func TestGvxOfflineSelectorRequiresOrdinaryApproval(t *testing.T) {
	c := gvxConfigFixture()
	spec := ModuleSpec{ModuleID: "offline", ImageDigest: "record:sha256:" + strings.Repeat("c", 64), Entrypoint: []string{"/module"}, UID: 1001, GID: 1002, Config: &wire.JSONValue{Json: []byte(`{}`)}, Approval: &wire.Grants{ResourceClass: wire.ResourceClass_RESOURCE_CLASS_GENERAL, ResourceLimits: c.ResourceProfiles["general"].wire(), EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_NONE}}
	if err := c.validateSpec(spec); err != nil {
		t.Fatalf("prepared offline identity with ordinary approval rejected: %v", err)
	}
	spec.ImageDigest = "record:sha256:" + strings.Repeat("C", 64)
	if c.validateSpec(spec) == nil {
		t.Fatal("noncanonical prepared record identity accepted")
	}
	spec.ImageDigest = "record:sha256:" + strings.Repeat("c", 64)
	spec.Approval.ResourceLimits.MemoryBytes++
	if c.validateSpec(spec) == nil {
		t.Fatal("offline identity bypassed installed resource profile")
	}
}
