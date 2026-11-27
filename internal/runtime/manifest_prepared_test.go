package runtime

import (
	"strings"
	"testing"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestGvxPreparedApprovalDoesNotGrantDeclarationRequests(t *testing.T) {
	config := gvxConfigFixture()
	spec := ModuleSpec{ModuleID: "prepared", ImageDigest: "record:sha256:" + strings.Repeat("c", 64), Entrypoint: []string{"/module"}, UID: 1001, GID: 1002, Config: &wire.JSONValue{Json: []byte(`{}`)}, Approval: &wire.Grants{ResourceClass: wire.ResourceClass_RESOURCE_CLASS_GENERAL, ResourceLimits: config.ResourceProfiles["general"].wire(), EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_NONE}}
	declaration, err := protojson.Marshal(&wire.ModuleManifest{ProtocolMajor: 2, RequiredCapabilities: []*wire.CapabilityRequest{{Name: "core.config.read", ResourceScopes: []*wire.ResourceScope{regressionScope()}}}})
	if err != nil {
		t.Fatal(err)
	}
	if ValidatePreparedApproval(config, spec, declaration) == nil {
		t.Fatal("required declaration capability became an implicit approval")
	}
	spec.Approval.CoreCapabilities = []*wire.CapabilityGrant{{Name: "core.config.read", ResourceScopes: []*wire.ResourceScope{regressionScope()}}}
	if err := ValidatePreparedApproval(config, spec, declaration); err != nil {
		t.Fatalf("explicit matching prepared approval rejected: %v", err)
	}
	spec.Approval.ResourceLimits.MemoryBytes++
	if ValidatePreparedApproval(config, spec, declaration) == nil {
		t.Fatal("prepared image bypassed installed finite resource profile")
	}
}
