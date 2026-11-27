package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/spf13/cobra"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

func TestGvxModuleApprovalDisplaysDecodedConfiguration(t *testing.T) {
	module := runtime.ModuleSpec{ModuleID: "reviewed", Config: &wire.JSONValue{Json: []byte(`{"guild_id":"operator-selected","nested":{"enabled":true}}`)}, Approval: &wire.Grants{ResourceClass: wire.ResourceClass_RESOURCE_CLASS_GENERAL, ResourceLimits: &wire.ResourceLimits{CpuMillicores: 500, MemoryBytes: 256 << 20, MaxPids: 64, PersistentBytes: 1 << 30, ScratchBytes: 256 << 20}, EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_NONE}}
	raw, err := moduleChoice(module)
	if err != nil {
		t.Fatal(err)
	}
	var displayed struct {
		Config   map[string]json.RawMessage `json:"config"`
		Approval map[string]json.RawMessage `json:"approval"`
	}
	if err := json.Unmarshal(raw, &displayed); err != nil {
		t.Fatal("module configuration remained an opaque base64 string")
	}
	if string(displayed.Config["guild_id"]) != `"operator-selected"` || string(displayed.Approval["resourceClass"]) != `"RESOURCE_CLASS_GENERAL"` {
		t.Fatal("operator choices or grant class hidden from approval")
	}
}

func TestGvxNetworkApprovalDisplaysDecodedInventory(t *testing.T) {
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetErr(&output)
	if err := displayNetworkInventory(command, nil); err == nil || output.Len() != 0 {
		t.Fatal("missing inventory accepted as an implicit NONE observation")
	}
	if err := displayNetworkInventory(command, []byte(`{"source":"observed","forwarding":true}`)); err != nil {
		t.Fatal(err)
	}
	var displayed struct {
		Inventory map[string]json.RawMessage `json:"network_prerequisite_inventory"`
	}
	if err := json.Unmarshal(output.Bytes(), &displayed); err != nil || string(displayed.Inventory["source"]) != `"observed"` {
		t.Fatal("network inventory remained opaque base64")
	}
	output.Reset()
	if err := displayNetworkInventory(command, []byte(`{"source":"first","source":"other"}`)); err == nil || output.Len() != 0 {
		t.Fatal("ambiguous network inventory was displayed for approval")
	}
}
