// Package configgen generates configuration from committed image metadata only.
// It must remain independent of native backend and voice packages.
package configgen

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/thirdscam/chatanium/internal/bootstrap"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"golang.org/x/sys/unix"
)

type GenerateConfigOptions struct {
	Base, ModuleConfig, Approval, Image, ModuleID, Entrypoint string
	UID, GID                                                  uint
	ConfigRevision, ApprovalRevision                          string
	InstallationID                                            string
}

// ReadOperatorFile opens bounded protected input without following symlinks.
func ReadOperatorFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("canonical absolute operator path required")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, errors.New("operator input cannot be opened without symlinks")
	}
	f := os.NewFile(uintptr(fd), "operator-input")
	defer f.Close()
	var stat unix.Stat_t
	const max = 16 << 20
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Size <= 0 || stat.Size > max {
		return nil, errors.New("operator input must be a bounded protected regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || len(raw) > max {
		return nil, errors.New("operator input read failed")
	}
	return raw, nil
}

func GenerateConfig(ctx context.Context, options GenerateConfigOptions) error {
	var raw []byte
	var err error
	if options.Base != "" {
		raw, err = ReadOperatorFile(options.Base)
	} else if options.InstallationID != "" {
		raw, err = bootstrap.ReadInstalledConfig(ctx, bootstrap.RuntimeInstallationID(options.InstallationID))
	} else {
		return errors.New("an installed identity or protected base configuration is required")
	}
	if err != nil {
		return err
	}
	base, err := runtime.DecodeConfig(raw)
	if err != nil {
		return errors.New("invalid base configuration")
	}
	if options.InstallationID != "" && options.InstallationID != base.Host.RuntimeInstallationID {
		return errors.New("base installation identity mismatch")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(base.Limits.HostOperationDeadline))
	defer cancel()
	// Inspection precedes final configuration validation: offline selectors and
	// reserved revision IDs are owner-authored outputs, not operator guesses.
	binding, record, err := bootstrap.InspectPreparedBinding(bounded, bootstrap.RuntimeInstallationID(base.Host.RuntimeInstallationID), options.Image)
	if err != nil {
		return errors.New("committed immutable image unavailable; prepare it explicitly first")
	}
	config, err := ReadOperatorFile(options.ModuleConfig)
	if err != nil {
		return err
	}
	approval, err := ReadOperatorFile(options.Approval)
	if err != nil {
		return err
	}
	output, err := preparedConfig(raw, options, binding, record, config, approval)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(output, '\n'))
	return err
}

func preparedConfig(raw []byte, options GenerateConfigOptions, binding host.ApprovedImageBinding, record provision.ImageRecord, config, approval []byte) ([]byte, error) {
	if options.UID == 0 || options.GID == 0 || uint64(options.UID) > 1<<32-1 || uint64(options.GID) > 1<<32-1 {
		return nil, errors.New("invalid config generation identity")
	}
	if binding.ModuleID == "" || binding.ImageSelector == "" || binding.ImageRecordID != record.ID || binding.ConfigRevision == "" || binding.ApprovalRevision == "" {
		return nil, errors.New("prepared image has no complete owner-authored binding")
	}
	if options.ModuleID != "" && options.ModuleID != binding.ModuleID || options.ConfigRevision != "" && options.ConfigRevision != binding.ConfigRevision || options.ApprovalRevision != "" && options.ApprovalRevision != binding.ApprovalRevision {
		return nil, errors.New("operator identity or revision differs from prepared binding")
	}
	base, err := runtime.DecodeConfig(raw)
	if err != nil {
		return nil, errors.New("invalid base configuration")
	}
	var value any
	if gvxcontract.DecodeStrict(config, base.Limits.ConfigMaxBytes, 64, &value) != nil || gvxcontract.DecodeStrict(approval, base.Limits.ControlMessageMaxBytes, 64, &value) != nil {
		return nil, errors.New("invalid module configuration or grant JSON")
	}
	index := -1
	credentialBindings := []runtime.ProvisionedCredentialBinding{}
	for i, installed := range base.Modules {
		if string(installed.ModuleID) == binding.ModuleID {
			index = i
			credentialBindings = installed.CredentialBindings
			break
		}
	}
	entrypoint, args := record.Entrypoint, record.Cmd
	if options.Entrypoint != "" {
		entrypoint, args = []string{options.Entrypoint}, []string{}
	} else if len(entrypoint) == 0 {
		entrypoint, args = args, []string{}
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
	}{binding.ModuleID, binding.ImageSelector, entrypoint, args, options.UID, options.GID, config, approval, credentialBindings, binding.ConfigRevision, binding.ApprovalRevision}
	moduleRaw, err := json.Marshal(module)
	if err != nil {
		return nil, err
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil {
		return nil, errors.New("invalid base document")
	}
	var modules []json.RawMessage
	if json.Unmarshal(document["modules"], &modules) != nil {
		return nil, errors.New("invalid base modules")
	}
	if index < 0 {
		index = len(modules)
		modules = append(modules, moduleRaw)
	} else {
		modules[index] = moduleRaw
	}
	document["modules"], err = json.Marshal(modules)
	if err != nil {
		return nil, err
	}
	output, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	generated, err := runtime.DecodeConfig(output)
	if err != nil {
		return nil, errors.New("generated configuration rejected")
	}
	if err = runtime.ValidatePreparedApproval(generated, generated.Modules[index], record.Declaration); err != nil {
		return nil, errors.New("prepared image declaration does not satisfy approved configuration")
	}
	return output, nil
}
