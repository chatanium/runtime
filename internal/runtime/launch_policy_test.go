package runtime

import (
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestGvxLaunchPolicyCannotPromoteOptionalEgress(t *testing.T) {
	config := gvxConfigFixture()
	spec := ModuleSpec{ModuleID: "prepared", ImageDigest: "registry.example/module@sha256:" + strings.Repeat("c", 64), Entrypoint: []string{"/module"}, UID: 1001, GID: 1002, Config: &wire.JSONValue{Json: []byte(`{}`)}, Approval: &wire.Grants{ResourceClass: wire.ResourceClass_RESOURCE_CLASS_GENERAL, ResourceLimits: config.ResourceProfiles["general"].wire(), EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET}}
	declaration, err := protojson.Marshal(&wire.ModuleManifest{ProtocolMajor: 2, OptionalCapabilities: []*wire.CapabilityRequest{{Name: core.CapabilityPublicEgress, ResourceScopes: []*wire.ResourceScope{regressionScope()}}}})
	if err != nil {
		t.Fatal(err)
	}
	record := provision.ImageRecord{Declaration: declaration}
	policy, err := ApprovedLaunchPolicy(config, spec, record)
	if err != nil {
		t.Fatal(err)
	}
	if policy.InitialEgress != host.EgressNone {
		t.Fatal("public approval enum bypassed negotiated capability")
	}
	if policy.InstanceID != "" {
		t.Fatal("installation approval allocated a worker instance")
	}
	spec.Entrypoint[0] = "/changed"
	if policy.Entrypoint[0] != "/module" {
		t.Fatal("approved argv snapshot retained mutable caller input")
	}
	spec.Entrypoint[0] = "/module"
	spec.Approval.CoreCapabilities = []*wire.CapabilityGrant{{Name: core.CapabilityPublicEgress, ResourceScopes: []*wire.ResourceScope{regressionScope()}}}
	policy, err = ApprovedLaunchPolicy(config, spec, record)
	if err != nil {
		t.Fatal(err)
	}
	if policy.InitialEgress != host.EgressPublicInternet {
		t.Fatal("explicit negotiated public approval rejected")
	}
	if policy.Resources.NanoCPUs != 500_000_000 || policy.Resources.Pids != 64 {
		t.Fatal("root policy changed approved host resource conversion")
	}
}
