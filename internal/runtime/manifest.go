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
