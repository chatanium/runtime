package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/thirdscam/chatanium/internal/host"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

type GenerateConfigOptions struct {
	Base               string
	ModuleConfig       string
	Approval           string
	Image              string
	ModuleID           string
	Entrypoint         string
	UID                uint
	GID                uint
	ConfigRevision     string
	ApprovalRevision   string
	SupervisorSocket   string
	SupervisorUID      int64
	SupervisorMaxBytes int
}

// GenerateConfig fills only an explicitly approved installation. Host settings,
// finite limits and approvals remain operator inputs. The complete output is
// checked by the production validator before any bytes are emitted.
func GenerateConfig(ctx context.Context, options GenerateConfigOptions) error {
	if options.UID == 0 || options.GID == 0 || uint64(options.UID) > 1<<32-1 || uint64(options.GID) > 1<<32-1 || !canonicalPath(options.SupervisorSocket) || options.SupervisorUID < 0 || options.SupervisorUID > 1<<32-1 || options.SupervisorMaxBytes <= 0 {
		return errors.New("invalid config generation arguments")
	}
	raw, err := readOperatorFile(options.Base)
	if err != nil {
		return err
	}
	decoded, err := runtime.DecodeConfig(raw)
	if err != nil || len(decoded.Modules) != 0 {
		return errors.New("base must be a valid host configuration with no installed modules")
	}
	configRaw, err := readOperatorFile(options.ModuleConfig)
	if err != nil {
		return err
	}
	approvalRaw, err := readOperatorFile(options.Approval)
	if err != nil {
		return err
	}
	if rejectDuplicateJSON(configRaw) != nil || rejectDuplicateJSON(approvalRaw) != nil {
		return errors.New("invalid module config or approval JSON")
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil {
		return errors.New("invalid base document")
	}
	module := struct {
		ModuleID           string                                 `json:"module_id"`
		Image              string                                 `json:"image"`
		Entrypoint         []string                               `json:"entrypoint"`
		Args               []string                               `json:"args"`
		UID                uint                                   `json:"uid"`
		GID                uint                                   `json:"gid"`
		Config             json.RawMessage                        `json:"config"`
		Approval           json.RawMessage                        `json:"approval"`
		CredentialBindings []runtime.ProvisionedCredentialBinding `json:"credential_bindings"`
		ConfigRevision     string                                 `json:"config_revision"`
		ApprovalRevision   string                                 `json:"approval_revision"`
	}{options.ModuleID, options.Image, []string{options.Entrypoint}, []string{}, options.UID, options.GID, configRaw, approvalRaw, []runtime.ProvisionedCredentialBinding{}, options.ConfigRevision, options.ApprovalRevision}
	document["modules"], err = json.Marshal([]any{module})
	if err != nil {
		return errors.New("config generation failed")
	}
	output, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return errors.New("config generation failed")
	}
	if _, err = runtime.DecodeConfig(output); err != nil {
		return errors.New("generated installation rejected: real digest, nonzero IDs, exact approval profile and finite host limits required")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(decoded.Limits.DockerAPIDeadline))
	defer cancel()
	client, err := host.Dial(ctx, host.ClientConfig{SocketPath: options.SupervisorSocket, SupervisorUID: uint32(options.SupervisorUID), MaxMessageBytes: options.SupervisorMaxBytes, OperationTimeout: time.Duration(decoded.Limits.DockerAPIDeadline)})
	if err != nil {
		return errors.New("image verification supervisor unavailable")
	}
	defer client.Close()
	declaration, err := client.ImageManifest(ctx, options.Image)
	if err != nil {
		return errors.New("exact immutable image declaration unavailable")
	}
	manifest := new(wire.ModuleManifest)
	if protojson.Unmarshal(declaration, manifest) != nil || manifest.ProtocolMajor != 2 {
		return errors.New("image has no strict canonical v2 manifest")
	}
	if _, err = os.Stdout.Write(append(output, '\n')); err != nil {
		return errors.New("config output failed")
	}
	return nil
}
