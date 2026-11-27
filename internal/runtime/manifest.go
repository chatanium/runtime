package runtime

import (
	"unicode/utf8"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Image declarations are untrusted requirements. Parsing one never publishes
// grants, authenticates a principal or authorizes an external network flow.
func (m *Manager) parseImageManifest(raw []byte) (*wire.ModuleManifest, error) {
	if len(raw) == 0 || len(raw) > m.config.Limits.ControlMessageMaxBytes || !utf8.Valid(raw) {
		return nil, invalidConfig()
	}
	manifest := new(wire.ModuleManifest)
	decoder := protojson.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: m.config.Limits.ControlMessageMaxBytes}
	if err := decoder.Unmarshal(raw, manifest); err != nil {
		return nil, invalidConfig()
	}
	if err := m.validateManifest(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}
func (m *Manager) validateManifest(manifest *wire.ModuleManifest) error {
	if manifest == nil || manifest.ProtocolMajor != core.ProtocolMajor {
		return runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")
	}
	if proto.Size(manifest) > m.config.Limits.ControlMessageMaxBytes {
		return invalidConfig()
	}
	if err := validateManifestRequests(manifest.RequiredCapabilities, manifest.OptionalCapabilities, nil, true); err != nil {
		return err
	}
	seen := make(map[string]bool, len(manifest.BackendRequirements))
	for _, requirement := range manifest.BackendRequirements {
		if requirement == nil || requirement.BackendId == "" || requirement.ProtocolMajor == 0 || seen[requirement.BackendId] {
			return invalidConfig()
		}
		seen[requirement.BackendId] = true
		var registration *BackendRegistration
		if b, ok := m.backends[requirement.BackendId]; ok && b.Major == requirement.ProtocolMajor {
			registration = &b
		}
		if err := validateManifestRequests(requirement.RequiredCapabilities, requirement.OptionalCapabilities, registration, false); err != nil {
			return err
		}
	}
	return nil
}
func validateManifestRequests(required, optional []*wire.CapabilityRequest, backend *BackendRegistration, coreOnly bool) error {
	seen := make(map[string]bool, len(required)+len(optional))
	for _, requests := range [][]*wire.CapabilityRequest{required, optional} {
		for _, request := range requests {
			if request == nil || request.Name == "" || seen[request.Name] || len(request.ResourceScopes) == 0 {
				return invalidConfig()
			}
			seen[request.Name] = true
			for _, scope := range request.ResourceScopes {
				if !validScope(scope, true) {
					return invalidConfig()
				}
				if coreOnly {
					if scope.GetAllResources() || len(scope.GetSelector().ResourceIds) != 0 {
						return invalidConfig()
					}
				} else if backend != nil && !scope.GetAllResources() {
					if backend.ValidateSelector(scope.GetSelector()) != nil {
						return invalidConfig()
					}
					if len(scope.GetSelector().ResourceIds) == 0 && backend.supports(request.Name) {
						resourceFree := false
						for _, operation := range backend.Operations {
							if operation.Capability == request.Name && operation.ResourceFree {
								resourceFree = true
								break
							}
						}
						if !resourceFree {
							return invalidConfig()
						}
					}
				}
			}
		}
	}
	return nil
}

// ValidatePreparedApproval checks a non-executing declaration against the
// installation's finite profiles and explicit grant. Backend-specific adapter
// selectors/support are checked again by the composed Manager before launch;
// this function never constructs an adapter or grants runtime authority.
func ValidatePreparedApproval(config Config, spec ModuleSpec, declaration []byte) error {
	manifest, err := preparedApprovalManifest(config, spec, declaration)
	if err != nil {
		return err
	}
	_, err = negotiateCore(manifest, spec.Approval)
	return err
}

func preparedApprovalManifest(config Config, spec ModuleSpec, declaration []byte) (*wire.ModuleManifest, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := config.validateSpec(spec); err != nil {
		return nil, err
	}
	manager := &Manager{config: config}
	manifest, err := manager.parseImageManifest(declaration)
	if err != nil {
		return nil, err
	}
	for _, grant := range spec.Approval.Backends {
		configured, ok := config.Backends[grant.BackendId]
		if !ok || configured.Major != grant.ProtocolMajor {
			return nil, invalidConfig()
		}
	}
	for _, requirement := range manifest.BackendRequirements {
		configured, present := config.Backends[requirement.BackendId]
		approved := backendGrant(spec.Approval, requirement.BackendId)
		if !present || configured.Major != requirement.ProtocolMajor || approved == nil || approved.ProtocolMajor != requirement.ProtocolMajor {
			if requirement.Required || len(requirement.RequiredCapabilities) != 0 {
				return nil, runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")
			}
			continue
		}
		if _, err := negotiateCapabilities(requirement.RequiredCapabilities, requirement.OptionalCapabilities, approved.Capabilities, func(name string) bool { return capability(approved.Capabilities, name) != nil }); err != nil {
			return nil, err
		}
	}
	return manifest, nil
}
