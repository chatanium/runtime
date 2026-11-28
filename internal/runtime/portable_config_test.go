package runtime

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/host"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

func TestPortableConfigCarriesExt4liteApprovalsWithoutLegacyLimits(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultPortableConfig("portable-owner", "sha256:"+strings.Repeat("b", 64), filepath.Join(root, "storage"), filepath.Join(root, "ipc"))
	cfg.Modules = []ModuleSpec{{ModuleID: "module", ImageDigest: "record:sha256:" + strings.Repeat("c", 64), Entrypoint: []string{"/guest/bin/module"},
		UID: 1001, GID: 1002, Config: &wire.JSONValue{Json: []byte(`{"number":9007199254740993}`)},
		Approval: &wire.Grants{ResourceClass: wire.ResourceClass_RESOURCE_CLASS_GENERAL, ResourceLimits: cfg.ResourceProfiles["general"].wire(), EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_NONE}}}
	raw, err := EncodePortableConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("inode_limit")) || bytes.Contains(raw, []byte("quota_backend")) {
		t.Fatal("portable configuration includes legacy quota fields")
	}
	decoded, err := DecodeConfig(raw)
	if err != nil || decoded.Host.Format != PortableFormat || len(decoded.Modules) != 1 || decoded.Modules[0].Entrypoint[0] != "/guest/bin/module" || decoded.Modules[0].Approval.ResourceLimits.MaxPids != 64 {
		t.Fatalf("portable configuration changed its Linux guest path or wire limits: %v", err)
	}
	launch, err := ApprovedPortableLaunchPolicy(decoded, decoded.Modules[0], []byte(`{"protocolMajor":2}`))
	if err != nil || launch.Resources.PersistentBytes != 1<<30 || launch.Resources.ScratchBytes != 256<<20 || launch.Resources.PersistentInodes != 0 || launch.Resources.ScratchInodes != 0 || launch.InstanceID != "" {
		t.Fatalf("portable launch policy changed granted image maximums or minted a lease: %+v (%v)", launch, err)
	}
	public := decoded
	public.Host.Network.Profile = host.NetworkPublicV4
	if _, err := EncodePortableConfig(public); err != nil {
		t.Fatalf("portable public profile required legacy network settings: %v", err)
	}
	for _, bad := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"legacy format", func(c *Config) { c.Host.Format = "" }},
		{"legacy quota", func(c *Config) { c.Host.QuotaBackend = "xfs-project" }},
		{"legacy inode limit", func(c *Config) { c.Limits.ScratchInodeLimit = 4 }},
		{"legacy uplink pin", func(c *Config) { c.Host.Network.Profile = host.NetworkPublicV4; c.Host.Network.Uplink4 = "eth0" }},
		{"unverified dual stack", func(c *Config) { c.Host.Network.Profile = host.NetworkPublicDual }},
		{"unreserved uploads", func(c *Config) { c.Limits.UploadRecordsPerHost = 2 }},
		{"noncanonical image", func(c *Config) {
			c.Modules[0].ImageDigest = "registry.example/module@sha256:" + strings.Repeat("c", 64)
		}},
		{"misaligned image bytes", func(c *Config) {
			p := c.ResourceProfiles["general"]
			p.ScratchBytes += 512
			c.ResourceProfiles["general"] = p
			c.Modules[0].Approval.ResourceLimits = p.wire()
		}},
	} {
		t.Run(bad.name, func(t *testing.T) {
			c, err := DecodeConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			bad.mutate(&c)
			if c.Validate() == nil {
				t.Fatal("accepted incompatible portable configuration")
			}
		})
	}
}
