package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
	"io"
)

func runIntent(mode RunMode, current string) (string, bool, error) {
	if current != "STOPPED" && current != "RUNNING" {
		return "", false, errors.New("unsupported durable run intent")
	}
	switch mode {
	case Foreground:
		return "RUNNING", true, nil
	case Service:
		return current, current == "RUNNING", nil
	default:
		return "", false, errors.New("unsupported run mode")
	}
}
func ObjectObservationDigest(observation legacyhost.ObjectObservation) (string, error) {
	return digest("chatanium-object-observation-v1", observation)
}
func removableProductObject(record legacyhost.ProvisionRecord) bool {
	return record.ProductCreated && !record.ExistedBefore && record.State == "OBSERVED" && !sharedNetworkObject(record.Kind, record.Identity)
}
func uninstallRemovable(record legacyhost.ProvisionRecord, m legacyhost.InstallationManifest) bool {
	return removableProductObject(record) && (record.Kind == "unit" && record.Identity == servicePath(RuntimeInstallationID(m.RuntimeInstallationID)) || record.Kind == "config" && record.Identity == m.Paths.Launcher)
}
func authorizeRemoval(record legacyhost.ProvisionRecord, approval ApprovedObject) error {
	if approval.Action != "remove" || record.Kind != approval.Kind || record.Identity != approval.Identity {
		return errors.New("removal approval targets another object")
	}
	if !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
		return errors.New("removal requires observed product-created ownership")
	}
	expected, e := ObjectObservationDigest(record.Observed)
	if e != nil {
		return e
	}
	if expected != approval.ObservationDigest {
		return errors.New("removal observation differs from approval")
	}
	return nil
}
func streamDigest(r io.Reader) (string, error) {
	h := sha256.New()
	if _, e := io.Copy(h, r); e != nil {
		return "", e
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func launchPolicies(ctx context.Context, s interface {
	Image(context.Context, string) (provision.ImageRecord, error)
}, raw []byte, bindings []legacyhost.ApprovedImageBinding) ([]host.LaunchSpec, error) {
	cfg, e := runtime.DecodeConfig(raw)
	if e != nil {
		return nil, e
	}
	policies := make([]host.LaunchSpec, 0, len(bindings))
	if len(bindings) != len(cfg.Modules) {
		return nil, errors.New("module/image binding cardinality mismatch")
	}
	for _, binding := range bindings {
		var module *runtime.ModuleSpec
		for index := range cfg.Modules {
			candidate := &cfg.Modules[index]
			if string(candidate.ModuleID) == binding.ModuleID {
				if module != nil {
					return nil, errors.New("duplicate module policy")
				}
				module = candidate
			}
		}
		if module == nil || module.ImageDigest != binding.ImageSelector || module.ConfigRevision != binding.ConfigRevision || module.ApprovalRevision != binding.ApprovalRevision {
			return nil, errors.New("image binding differs from exact protected configuration")
		}
		record, e := s.Image(ctx, binding.ImageRecordID)
		if e != nil {
			return nil, e
		}
		if record.SourceKind == "registry" {
			if binding.ImageSelector != record.SourceRef {
				return nil, errors.New("registry selector differs from prepared provenance")
			}
		} else if binding.ImageSelector != "record:"+record.ID {
			return nil, errors.New("offline selector differs from prepared record")
		}
		policy, e := runtime.ApprovedLaunchPolicy(cfg, *module, record)
		if e != nil {
			return nil, e
		}
		policies = append(policies, policy)
	}
	return policies, nil
}
