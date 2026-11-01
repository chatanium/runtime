package runtime

import (
	"context"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func validScope(s *wire.ResourceScope, resourceFree bool) bool {
	if s == nil {
		return false
	}
	switch k := s.SelectorKind.(type) {
	case *wire.ResourceScope_AllResources:
		return k.AllResources
	case *wire.ResourceScope_Selector:
		if k.Selector == nil {
			return false
		}
		if len(k.Selector.ResourceIds) == 0 {
			return resourceFree
		}
		for key, v := range k.Selector.ResourceIds {
			if key == "" || v == "" {
				return false
			}
		}
		return true
	}
	return false
}

// Selector conditions are AND, scope lists OR. A narrower selector carries all
// conditions of its ceiling; disjoint additional conditions may intersect.
func scopeContains(outer, inner *wire.ResourceScope) bool {
	if outer.GetAllResources() {
		return true
	}
	if inner.GetAllResources() {
		return false
	}
	a, b := outer.GetSelector(), inner.GetSelector()
	if a == nil || b == nil {
		return false
	}
	if len(a.ResourceIds) == 0 || len(b.ResourceIds) == 0 {
		return len(a.ResourceIds) == 0 && len(b.ResourceIds) == 0
	}
	for k, v := range a.ResourceIds {
		if b.ResourceIds[k] != v {
			return false
		}
	}
	return true
}
func intersectScope(a, b *wire.ResourceScope) *wire.ResourceScope {
	if a.GetAllResources() {
		return proto.Clone(b).(*wire.ResourceScope)
	}
	if b.GetAllResources() {
		return proto.Clone(a).(*wire.ResourceScope)
	}
	if a.GetSelector() == nil || b.GetSelector() == nil {
		return nil
	}
	if (len(a.GetSelector().ResourceIds) == 0) != (len(b.GetSelector().ResourceIds) == 0) {
		return nil
	}
	m := map[string]string{}
	for k, v := range a.GetSelector().ResourceIds {
		m[k] = v
	}
	for k, v := range b.GetSelector().ResourceIds {
		if x, ok := m[k]; ok && x != v {
			return nil
		}
		m[k] = v
	}
	return &wire.ResourceScope{SelectorKind: &wire.ResourceScope_Selector{Selector: &wire.ResourceSelector{ResourceIds: m}}}
}
func intersectScopes(a, b []*wire.ResourceScope) []*wire.ResourceScope {
	var out []*wire.ResourceScope
	for _, x := range a {
		for _, y := range b {
			if z := intersectScope(x, y); z != nil {
				duplicate := false
				for _, v := range out {
					if proto.Equal(v, z) {
						duplicate = true
						break
					}
				}
				if !duplicate {
					out = append(out, z)
				}
			}
		}
	}
	return out
}
func scopesSubset(a, b []*wire.ResourceScope) bool {
	for _, x := range a {
		covered := false
		for _, y := range b {
			if scopeContains(y, x) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}
func validateCapabilities(caps []*wire.CapabilityGrant, resourceFree bool) error {
	seen := map[string]bool{}
	for _, c := range caps {
		if c == nil || c.Name == "" || seen[c.Name] || len(c.ResourceScopes) == 0 {
			return invalidConfig()
		}
		seen[c.Name] = true
		for _, s := range c.ResourceScopes {
			if !validScope(s, resourceFree) {
				return invalidConfig()
			}
		}
	}
	return nil
}
func validateGrants(g *wire.Grants) error {
	if g == nil || g.ResourceLimits == nil || g.EgressPolicy != wire.EgressPolicy_EGRESS_POLICY_NONE && g.EgressPolicy != wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		return invalidConfig()
	}
	if validateCapabilities(g.CoreCapabilities, true) != nil {
		return invalidConfig()
	}
	for _, c := range g.CoreCapabilities {
		if !coreCapability(c.Name) || c.Constraints != nil {
			return invalidConfig()
		}
		for _, s := range c.ResourceScopes {
			if s.GetAllResources() || len(s.GetSelector().ResourceIds) != 0 {
				return invalidConfig()
			}
		}
	}
	seen := map[string]bool{}
	for _, b := range g.Backends {
		if b == nil || b.BackendId == "" || b.ProtocolMajor == 0 || seen[b.BackendId] || validateCapabilities(b.Capabilities, true) != nil {
			return invalidConfig()
		}
		seen[b.BackendId] = true
	}
	return nil
}
func coreCapability(s string) bool {
	return s == core.CapabilityConfigRead || s == core.CapabilityUpload || s == core.CapabilityPublicEgress
}
func capability(caps []*wire.CapabilityGrant, name string) *wire.CapabilityGrant {
	for _, c := range caps {
		if c.Name == name {
			return c
		}
	}
	return nil
}
func backendGrant(g *wire.Grants, id string) *wire.BackendGrant {
	for _, b := range g.Backends {
		if b.BackendId == id {
			return b
		}
	}
	return nil
}
func negotiateCapabilities(required, optional []*wire.CapabilityRequest, approved []*wire.CapabilityGrant, supported func(string) bool) ([]*wire.CapabilityGrant, error) {
	seen := map[string]bool{}
	var out []*wire.CapabilityGrant
	for group, requests := range [][]*wire.CapabilityRequest{required, optional} {
		for _, r := range requests {
			if r == nil || r.Name == "" || seen[r.Name] || len(r.ResourceScopes) == 0 {
				return nil, invalidConfig()
			}
			seen[r.Name] = true
			for _, s := range r.ResourceScopes {
				if !validScope(s, true) {
					return nil, invalidConfig()
				}
			}
			ceiling := capability(approved, r.Name)
			var scopes []*wire.ResourceScope
			if ceiling != nil && supported(r.Name) {
				scopes = intersectScopes(r.ResourceScopes, ceiling.ResourceScopes)
			}
			if group == 0 && !scopesSubset(r.ResourceScopes, scopes) {
				return nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
			}
			if len(scopes) > 0 {
				g := &wire.CapabilityGrant{Name: r.Name, ResourceScopes: scopes}
				if ceiling.Constraints != nil {
					g.Constraints = proto.Clone(ceiling.Constraints).(*anypb.Any)
				}
				out = append(out, g)
			}
		}
	}
	return out, nil
}

// negotiateCore is the single decision used both for closed initial topology
// and for final authenticated actual grants. It has no backend side effects.
func negotiateCore(manifest *wire.ModuleManifest, a *wire.Grants) (*wire.Grants, error) {
	if manifest == nil || manifest.ProtocolMajor != core.ProtocolMajor {
		return nil, runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")
	}
	caps, err := negotiateCapabilities(manifest.RequiredCapabilities, manifest.OptionalCapabilities, a.CoreCapabilities, coreCapability)
	if err != nil {
		return nil, err
	}
	for _, c := range caps {
		for _, s := range c.ResourceScopes {
			if s.GetAllResources() || len(s.GetSelector().ResourceIds) != 0 {
				return nil, invalidConfig()
			}
		}
	}
	g := &wire.Grants{CoreCapabilities: caps, ResourceClass: a.ResourceClass, ResourceLimits: proto.Clone(a.ResourceLimits).(*wire.ResourceLimits), EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_NONE}
	if capability(caps, core.CapabilityPublicEgress) != nil && a.EgressPolicy == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		g.EgressPolicy = wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET
	} else if capability(caps, core.CapabilityPublicEgress) != nil {
		for _, r := range manifest.RequiredCapabilities {
			if r.Name == core.CapabilityPublicEgress {
				return nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
			}
		}
		for n, c := range g.CoreCapabilities {
			if c.Name == core.CapabilityPublicEgress {
				g.CoreCapabilities = append(g.CoreCapabilities[:n], g.CoreCapabilities[n+1:]...)
				break
			}
		}
	}
	return g, nil
}

// Launch has validated this authenticated manifest and matched its declaration.
func (m *Manager) negotiate(ctx context.Context, i *Instance, manifest *wire.ModuleManifest) (*wire.Grants, error) {
	// Backend preparation deliberately occurs only after that equality check.
	a := i.spec.Approval
	g, err := negotiateCore(manifest, a)
	if err != nil {
		return nil, err
	}
	for _, r := range manifest.BackendRequirements {
		b, ok := m.backends[r.BackendId]
		approved := backendGrant(a, r.BackendId)
		if !ok || r.ProtocolMajor != b.Major || approved == nil || approved.ProtocolMajor != b.Major {
			if r.Required || len(r.RequiredCapabilities) > 0 {
				return nil, runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")
			}
			continue
		}
		candidate, err := negotiateCapabilities(r.RequiredCapabilities, r.OptionalCapabilities, approved.Capabilities, func(name string) bool { return b.supports(name) })
		if err != nil {
			return nil, err
		}
		narrowed := &wire.BackendGrant{BackendId: b.ID, ProtocolMajor: b.Major, Capabilities: candidate}
		if err := b.validateGrant(narrowed); err != nil {
			return nil, err
		}
		// Record partial Prepare ownership before invoking adapter code.
		i.mu.Lock()
		i.prepared = append(i.prepared, b)
		i.mu.Unlock()
		binding, err := b.Adapter.Prepare(ctx, i.principal, BackendPreparation{Requirement: proto.Clone(r).(*wire.BackendRequirement), Approved: proto.Clone(narrowed).(*wire.BackendGrant)})
		if err != nil {
			return nil, err
		}
		if binding == nil || binding.Grant == nil {
			return nil, runtimeError(codes.Internal, "BACKEND_BINDING_INVALID")
		}
		actual := binding.Grant
		if actual.BackendId != b.ID || actual.ProtocolMajor != b.Major || b.validateGrant(actual) != nil {
			return nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
		}
		for _, c := range actual.Capabilities {
			ceil := capability(candidate, c.Name)
			if ceil == nil || !scopesSubset(c.ResourceScopes, ceil.ResourceScopes) {
				return nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
			}
			if !proto.Equal(c.Constraints, ceil.Constraints) && (b.ValidateConstraintsSubset == nil || b.ValidateConstraintsSubset(c, ceil) != nil) {
				return nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
			}
		}
		for _, required := range r.RequiredCapabilities {
			have := capability(actual.Capabilities, required.Name)
			if have == nil || !scopesSubset(required.ResourceScopes, have.ResourceScopes) {
				return nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
			}
		}
		g.Backends = append(g.Backends, proto.Clone(actual).(*wire.BackendGrant))
	}
	return g, nil
}
func (b BackendRegistration) supports(name string) bool {
	for _, op := range b.Operations {
		if op.Capability == name {
			return true
		}
	}
	return false
}
func (b BackendRegistration) validateGrant(g *wire.BackendGrant) error {
	if validateCapabilities(g.Capabilities, true) != nil {
		return invalidConfig()
	}
	for _, c := range g.Capabilities {
		if !b.supports(c.Name) {
			return invalidConfig()
		}
		for _, s := range c.ResourceScopes {
			if !s.GetAllResources() {
				if b.ValidateSelector == nil || b.ValidateSelector(s.GetSelector()) != nil {
					return invalidConfig()
				}
			}
		}
		if c.Constraints != nil && (b.ValidateConstraints == nil || b.ValidateConstraints(c) != nil) {
			return invalidConfig()
		}
	}
	return nil
}

// IntersectResourceScopes returns fresh selectors, never aliases of input grants.
func IntersectResourceScopes(a, b []*wire.ResourceScope) []*wire.ResourceScope {
	return intersectScopes(a, b)
}
func ResourceScopesSubset(scopes, ceiling []*wire.ResourceScope) bool {
	return scopesSubset(scopes, ceiling)
}
func ValidateResourceScope(scope *wire.ResourceScope, resourceFree bool) error {
	if !validScope(scope, resourceFree) {
		return invalidConfig()
	}
	return nil
}
