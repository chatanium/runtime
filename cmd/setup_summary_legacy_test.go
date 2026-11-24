package cmd

import (
	"encoding/json"
	"errors"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"google.golang.org/protobuf/encoding/protojson"
)

func moduleChoice(module runtime.ModuleSpec) (json.RawMessage, error) {
	if module.Config == nil || module.Approval == nil || !json.Valid(module.Config.Json) {
		return nil, errors.New("plan module configuration or approval is invalid")
	}
	approval, err := protojson.Marshal(module.Approval)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ModuleID           runtime.ModuleID                       `json:"module_id"`
		Image              string                                 `json:"image"`
		Entrypoint         []string                               `json:"entrypoint"`
		Args               []string                               `json:"args"`
		UID                uint32                                 `json:"uid"`
		GID                uint32                                 `json:"gid"`
		Config             json.RawMessage                        `json:"config"`
		Approval           json.RawMessage                        `json:"approval"`
		CredentialBindings []runtime.ProvisionedCredentialBinding `json:"credential_bindings"`
		ConfigRevision     string                                 `json:"config_revision"`
		ApprovalRevision   string                                 `json:"approval_revision"`
	}{module.ModuleID, module.ImageDigest, module.Entrypoint, module.Args, module.UID, module.GID, module.Config.Json, approval, module.CredentialBindings, module.ConfigRevision, module.ApprovalRevision})
}

// Inventory is an observation to display, not a permission decision. The host
// verifies the closed observation and its current kernel binding before effects.
func displayNetworkInventory(cmd *cobra.Command, raw []byte) error {
	if len(raw) == 0 {
		return errors.New("plan network prerequisite inventory is missing")
	}
	var inventory json.RawMessage
	// Use the host's canonical semantic-inventory bounds. NONE is still an
	// explicit nonempty profile with empty public-fact arrays, never a fallback.
	if err := gvxcontract.DecodeStrict(raw, host.NetworkPrerequisiteInventoryMaxBytes, host.NetworkPrerequisiteInventoryMaxDepth, &inventory); err != nil {
		return errors.New("plan network prerequisite inventory is invalid")
	}
	return json.NewEncoder(cmd.ErrOrStderr()).Encode(struct {
		Inventory json.RawMessage `json:"network_prerequisite_inventory"`
	}{inventory})
}
