package configgen

import (
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

func preparedConfigInputs(t *testing.T) ([]byte, GenerateConfigOptions, host.ApprovedImageBinding, provision.ImageRecord, []byte) {
	t.Helper()
	base, err := runtime.DefaultInstallationConfig(strings.Repeat("a", 32), "sha256:"+strings.Repeat("b", 64), host.InstallationPaths{Installation: "/var/lib/chatanium", StorageRoot: "/var/lib/chatanium/storage", RunRoot: "/run/chatanium/installation"})
	if err != nil {
		t.Fatal(err)
	}
	record := provision.ImageRecord{ID: "sha256:" + strings.Repeat("c", 64), Declaration: []byte(`{"protocolMajor":2}`), Entrypoint: []string{"/module"}, Cmd: []string{"--image-argument"}}
	binding := host.ApprovedImageBinding{ModuleID: "offline", ImageSelector: "record:" + record.ID, ImageRecordID: record.ID, ConfigRevision: "root-config", ApprovalRevision: "root-approval"}
	approval, err := protojson.Marshal(&wire.Grants{ResourceClass: wire.ResourceClass_RESOURCE_CLASS_GENERAL, ResourceLimits: &wire.ResourceLimits{CpuMillicores: 500, MemoryBytes: 256 << 20, MaxPids: 64, PersistentBytes: 1 << 30, ScratchBytes: 256 << 20}, EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_NONE})
	if err != nil {
		t.Fatal(err)
	}
	return base, GenerateConfigOptions{UID: 1001, GID: 1002}, binding, record, approval
}
func TestGvxPreparedConfigDerivesOfflineSelectorAndRevisions(t *testing.T) {
	base, options, binding, record, approval := preparedConfigInputs(t)
	output, err := preparedConfig(base, options, binding, record, []byte(`{}`), approval)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := runtime.DecodeConfig(output)
	if err != nil {
		t.Fatal(err)
	}
	module := decoded.Modules[0]
	if module.ImageDigest != binding.ImageSelector || module.ConfigRevision != binding.ConfigRevision || module.ApprovalRevision != binding.ApprovalRevision || string(module.ModuleID) != binding.ModuleID {
		t.Fatal("owner-derived binding was not used")
	}
	if len(module.Args) != 1 || module.Args[0] != "--image-argument" {
		t.Fatal("inspected default argv was not retained")
	}
	options.ConfigRevision = "operator-guessed"
	if _, err := preparedConfig(base, options, binding, record, []byte(`{}`), approval); err == nil {
		t.Fatal("operator guessed revision replaced root binding")
	}
}
func TestGvxPreparedConfigPreservesModulesAndRequiresExplicitGrants(t *testing.T) {
	base, options, binding, record, approval := preparedConfigInputs(t)
	first, err := preparedConfig(base, options, binding, record, []byte(`{}`), approval)
	if err != nil {
		t.Fatal(err)
	}
	record.ID = "sha256:" + strings.Repeat("d", 64)
	binding.ModuleID = "second"
	binding.ImageRecordID = record.ID
	binding.ImageSelector = "record:" + record.ID
	second, err := preparedConfig(first, options, binding, record, []byte(`{}`), approval)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := runtime.DecodeConfig(second)
	if err != nil || len(decoded.Modules) != 2 || decoded.Modules[0].ModuleID != "offline" {
		t.Fatal("adding a prepared module discarded installed modules")
	}
	record.Declaration = []byte(`{"protocolMajor":2,"requiredCapabilities":[{"name":"core.config.read","resourceScopes":[{"selector":{}}]}]}`)
	if _, err := preparedConfig(base, options, binding, record, []byte(`{}`), approval); err == nil {
		t.Fatal("declaration request became an automatic grant")
	}
}
