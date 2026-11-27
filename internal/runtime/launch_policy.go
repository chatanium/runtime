package runtime

import (
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

// ApprovedLaunchPolicy is a pure projection for the root installation owner.
// The image must already have passed ImageRecord verification and exact binding;
// this function neither prepares images nor admits an instance.
func ApprovedLaunchPolicy(config Config, spec ModuleSpec, image provision.ImageRecord) (host.LaunchSpec, error) {
	if config.Host.Format != "" {
		return host.LaunchSpec{}, invalidConfig()
	}
	return approvedLaunchPolicy(config, spec, image.Declaration)
}

// ApprovedPortableLaunchPolicy validates the reviewed declaration against the
// worker's configuration using the same projection as the actual launch.
func ApprovedPortableLaunchPolicy(config Config, spec ModuleSpec, declaration []byte) (host.LaunchSpec, error) {
	if config.Host.Format != PortableFormat {
		return host.LaunchSpec{}, invalidConfig()
	}
	return approvedLaunchPolicy(config, spec, declaration)
}

func approvedLaunchPolicy(config Config, spec ModuleSpec, declaration []byte) (host.LaunchSpec, error) {
	manifest, err := preparedApprovalManifest(config, spec, declaration)
	if err != nil {
		return host.LaunchSpec{}, err
	}
	core, err := negotiateCore(manifest, spec.Approval)
	if err != nil {
		return host.LaunchSpec{}, err
	}
	policy := launchPolicy(config, spec, core.EgressPolicy)
	policy.Entrypoint = append([]string(nil), policy.Entrypoint...)
	policy.Args = append([]string(nil), policy.Args...)
	return policy, nil
}

// Both the worker's declaration path and root approval path use this exact
// conversion. InstanceID belongs to a subsequent fresh worker launch only.
func launchPolicy(config Config, spec ModuleSpec, egress wire.EgressPolicy) host.LaunchSpec {
	resources := spec.Approval.ResourceLimits
	limits := config.Limits
	policy := host.LaunchSpec{
		ModuleID: string(spec.ModuleID), ImageDigest: spec.ImageDigest,
		Entrypoint: spec.Entrypoint, Args: spec.Args,
		UID: spec.UID, GID: spec.GID, ConfigRevision: spec.ConfigRevision, ApprovalRevision: spec.ApprovalRevision,
		InitialEgress: host.EgressNone,
		Resources:     host.ResourceLimits{NanoCPUs: int64(resources.CpuMillicores) * 1_000_000, MemoryBytes: int64(resources.MemoryBytes), Pids: int64(resources.MaxPids), PersistentBytes: int64(resources.PersistentBytes), ScratchBytes: int64(resources.ScratchBytes), PersistentInodes: limits.PersistentInodeLimit, ScratchInodes: limits.ScratchInodeLimit, ControlMessageMaxBytes: int64(limits.ControlMessageMaxBytes), LogBufferBytes: limits.LogBufferBytes, LogFileMaxBytes: limits.LogFileMaxBytes, LogRetainedFiles: limits.LogRetainedFiles},
	}
	if egress == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		policy.InitialEgress = host.EgressPublicInternet
	}
	return policy
}
