package runtime

import (
	"context"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/discordacl"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type OperationClass uint8

const (
	FiniteOperation OperationClass = iota + 1
	LongLivedOperation
	OwnerCleanupOperation
)

type OperationPolicy struct {
	Backend      string
	Operation    string
	Capability   string
	InitSafe     bool
	ResourceFree bool
	DrainSafe    bool
	Class        OperationClass
}
type AccessRequest struct {
	Backend           string
	Operation         string
	Scopes            []*wire.ResourceScope
	DiscordUnscopable bool
	DiscordGuildWide  bool
}
type Authorizer struct{ instance *Instance }
type principalKey struct{}
type rpcCall struct {
	instance   *Instance
	admissions []*Admission
}

// Admission is an operation-scoped authority lease, never wire identity. Its
// context is canceled at expiry, drain expiry or terminal failure.
type Admission struct {
	instance      *Instance
	principal     InstancePrincipal
	policy        OperationPolicy
	ctx           context.Context
	cancel        context.CancelFunc
	stopWork      func() bool
	released      bool
	discordScopes []discordacl.Scope
}

func (a *Admission) Context() context.Context     { return a.ctx }
func (a *Admission) Principal() InstancePrincipal { return a.principal }

// CapabilityGrant returns the immutable actual operation grant, including
// registered backend constraints, only while this admission is still valid.
func (a *Admission) CapabilityGrant() (*wire.CapabilityGrant, error) {
	i := a.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	if !a.validLocked() {
		return nil, runtimeError(codes.FailedPrecondition, "INSTANCE_NOT_RUNNING")
	}
	var grant *wire.CapabilityGrant
	if a.policy.Backend == "" {
		grant = capability(i.grants.CoreCapabilities, a.policy.Capability)
	} else if b := backendGrant(i.grants, a.policy.Backend); b != nil {
		grant = capability(b.Capabilities, a.policy.Capability)
	}
	if grant == nil {
		return nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	}
	return proto.Clone(grant).(*wire.CapabilityGrant), nil
}
func (a *Admission) Release() {
	i := a.instance
	i.mu.Lock()
	if !a.released {
		a.released = true
		delete(i.admissions, a)
		a.cancel()
		if a.stopWork != nil {
			a.stopWork()
		}
		i.signalLocked()
	}
	i.mu.Unlock()
}

// AdmissionFromContext returns the last admitted operation in this real RPC.
func AdmissionFromContext(ctx context.Context) (*Admission, error) {
	call, ok := ctx.Value(principalKey{}).(*rpcCall)
	if !ok {
		return nil, runtimeError(codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
	}
	i := call.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(call.admissions) == 0 {
		return nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	}
	a := call.admissions[len(call.admissions)-1]
	if !a.validLocked() {
		return nil, runtimeError(codes.FailedPrecondition, "INSTANCE_NOT_RUNNING")
	}
	return a, nil
}
func (a *Admission) validLocked() bool {
	return !a.released && a.ctx.Err() == nil && a.instance.bound && a.instance.state != Failed && a.instance.state != Stopped
}
func PrincipalFromContext(ctx context.Context) (InstancePrincipal, error) {
	call, ok := ctx.Value(principalKey{}).(*rpcCall)
	if !ok || call == nil {
		return InstancePrincipal{}, runtimeError(codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
	}
	i := call.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.bound || i.state == Failed || i.state == Stopped || ctx.Err() != nil {
		return InstancePrincipal{}, runtimeError(codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
	}
	return i.principal, nil
}
func (a *Authorizer) operationLocked(ctx context.Context, backend, operation string) (*rpcCall, OperationPolicy, *wire.CapabilityGrant, error) {
	i := a.instance
	call, ok := ctx.Value(principalKey{}).(*rpcCall)
	if !ok || call == nil || call.instance != i || !i.bound {
		return nil, OperationPolicy{}, nil, runtimeError(codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
	}
	policy, ok := i.manager.operations[operationKey(backend, operation)]
	if !ok {
		return nil, policy, nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	}
	var grant *wire.CapabilityGrant
	if policy.Backend == "" {
		grant = capability(i.grants.CoreCapabilities, policy.Capability)
	} else if binding := backendGrant(i.grants, policy.Backend); binding != nil {
		grant = capability(binding.Capabilities, policy.Capability)
	}
	if grant == nil || len(grant.ResourceScopes) == 0 {
		return nil, policy, nil, runtimeError(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	}
	return call, policy, grant, nil
}

// Every target is required (AND); the actual grant's scopes remain alternatives
// (OR). All targets are checked while holding the one instance authority lock.
func (a *Authorizer) checkScopesLocked(policy OperationPolicy, grant *wire.CapabilityGrant, req *AccessRequest) error {
	scopes := req.Scopes
	if len(scopes) == 0 {
		return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
	}
	if policy.ResourceFree && len(scopes) != 1 {
		return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
	}
	acl := a.instance.discordACL
	if policy.Backend == discordBackend && acl != nil && req.DiscordUnscopable {
		return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
	}
	for _, scope := range scopes {
		if !validScope(scope, policy.ResourceFree) || scope.GetAllResources() {
			return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
		}
		if policy.ResourceFree && len(scope.GetSelector().ResourceIds) != 0 {
			return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
		}
		if policy.Backend != "" {
			registration := a.instance.manager.backends[policy.Backend]
			if registration.ValidateSelector == nil || registration.ValidateSelector(scope.GetSelector()) != nil {
				return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
			}
		}
		if policy.Backend == discordBackend && acl != nil {
			target := discordScope(scope)
			if req.DiscordGuildWide {
				target.ChannelID = ""
			}
			if !acl.Allows(target) {
				return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
			}
		}
		allowed := false
		for _, ceiling := range grant.ResourceScopes {
			if scopeContains(ceiling, scope) {
				allowed = true
				break
			}
		}
		if !allowed {
			return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
		}
	}
	return nil
}
func operationKey(backend, operation string) string { return backend + "\x00" + operation }

// eligibleLocked is the shared state and activation policy for both readonly
// relationship lookups and final resource admission. It returns with i.mu held,
// including on error. Gate waits temporarily release only that same lock.
func (a *Authorizer) eligibleLocked(ctx context.Context, backend, operation string, req *AccessRequest) (*rpcCall, OperationPolicy, error) {
	i := a.instance
	for {
		if ctx.Err() != nil {
			return nil, OperationPolicy{}, contextError(ctx)
		}
		call, policy, grant, err := a.operationLocked(ctx, backend, operation)
		if err != nil {
			return nil, policy, err
		}
		if req != nil {
			if err := a.checkScopesLocked(policy, grant, req); err != nil {
				return nil, policy, err
			}
		}
		if backend == discordBackend && i.discordACL != nil && (policy.ResourceFree || isDiscordNativeVoice(policy.Capability) || len(i.discordACL.Scopes) == 0) {
			return nil, policy, runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
		}
		if i.state == Ready && i.activating && !policy.InitSafe && policy.Class != OwnerCleanupOperation {
			gate, startup := i.gate, i.startup
			i.mu.Unlock()
			var waitErr error
			select {
			case <-ctx.Done():
				waitErr = contextError(ctx)
			case <-startup.Done():
				waitErr = contextError(startup)
			case <-gate:
			}
			i.mu.Lock()
			if ctx.Err() != nil {
				return nil, policy, contextError(ctx)
			}
			// Successful RUNNING commit closes the gate before canceling the
			// startup context. A simultaneous wake must recheck that commit.
			if waitErr != nil && i.state != Running {
				return nil, policy, waitErr
			}
			continue
		}
		allowed := false
		switch i.state {
		case Initializing, Ready:
			allowed = policy.InitSafe
		case Running:
			allowed = true
		case Draining:
			if i.drain != nil && i.drain.Err() == nil {
				if policy.Class == OwnerCleanupOperation {
					allowed = true
				} else if policy.Class == FiniteOperation && policy.DrainSafe {
					refs := metadata.ValueFromIncomingContext(ctx, core.WorkRefMetadata)
					allowed = len(refs) == 1 && refs[0] != "" && refs[0] == i.workRef && i.workContext != nil && i.workContext.Err() == nil
				}
			}
		}
		if !allowed {
			reason := "INSTANCE_NOT_RUNNING"
			if i.state == Draining {
				reason = "INSTANCE_DRAINING"
			}
			return nil, policy, runtimeError(codes.FailedPrecondition, reason)
		}
		if ctx.Err() != nil {
			return nil, policy, contextError(ctx)
		}
		return call, policy, nil
	}
}

// AwaitOperation permits only bounded, trusted, readonly relationship lookup.
// It cannot authorize a mutation or credential/file lease and creates neither
// an admission nor another control-RPC slot. Authorize must subsequently check
// the complete resolved target list and recheck current operation eligibility.
func (a *Authorizer) AwaitOperation(ctx context.Context, backend, operation string) (InstancePrincipal, error) {
	i := a.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, _, err := a.eligibleLocked(ctx, backend, operation, nil); err != nil {
		return InstancePrincipal{}, err
	}
	return i.principal, nil
}

func (a *Authorizer) Authorize(ctx context.Context, req AccessRequest) (InstancePrincipal, error) {
	i := a.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	call, policy, err := a.eligibleLocked(ctx, req.Backend, req.Operation, &req)
	if err != nil {
		return InstancePrincipal{}, err
	}
	// One RPC creates one admission, atomically covering every resolved target.
	if len(call.admissions) != 0 {
		return InstancePrincipal{}, runtimeError(codes.FailedPrecondition, "OPERATION_ALREADY_ADMITTED")
	}
	admitted, cancel := context.WithCancel(ctx)
	lease := &Admission{instance: i, principal: i.principal, policy: policy, ctx: admitted, cancel: cancel}
	if policy.Backend == discordBackend && !req.DiscordUnscopable {
		lease.discordScopes = make([]discordacl.Scope, 0, len(req.Scopes))
		for _, target := range req.Scopes {
			resolved := discordScope(target)
			if req.DiscordGuildWide {
				resolved.ChannelID = ""
			}
			lease.discordScopes = append(lease.discordScopes, resolved)
		}
	}
	i.admissions[lease] = struct{}{}
	call.admissions = append(call.admissions, lease)
	if i.state == Draining && policy.Class == FiniteOperation {
		lease.stopWork = context.AfterFunc(i.workContext, cancel)
	}
	return i.principal, nil
}
func (i *Instance) beginRPC(ctx context.Context) (context.Context, func(), error) {
	i.mu.Lock()
	if !i.bound || i.state == Failed || i.state == Stopped {
		i.mu.Unlock()
		return nil, nil, runtimeError(codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
	}
	if i.controls >= i.manager.config.Limits.ControlRPCsPerInstance {
		i.mu.Unlock()
		return nil, nil, runtimeError(codes.ResourceExhausted, "CONTROL_RPC_LIMIT")
	}
	i.controls++
	i.mu.Unlock()
	bounded, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(i.lifetime, cancel)
	call := &rpcCall{instance: i}
	bound := context.WithValue(bounded, principalKey{}, call)
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel()
			stop()
			i.mu.Lock()
			for _, a := range call.admissions {
				if !a.released {
					a.released = true
					a.cancel()
					if a.stopWork != nil {
						a.stopWork()
					}
					delete(i.admissions, a)
				}
			}
			i.controls--
			i.signalLocked()
			i.mu.Unlock()
		})
	}
	return bound, finish, nil
}
func (i *Instance) serverFactory(options []grpc.ServerOption) (*grpc.Server, error) {
	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, done, err := i.beginRPC(ctx)
		if err != nil {
			return nil, err
		}
		defer done()
		return handler(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		parent := ss.Context()
		if info.FullMethod == wire.FileTransfer_Upload_FullMethodName {
			bounded, cancel := context.WithTimeout(parent, time.Duration(i.manager.config.Limits.UploadDeadline))
			defer cancel()
			parent = bounded
		}
		ctx, done, err := i.beginRPC(parent)
		if err != nil {
			return err
		}
		bound := &boundStream{ServerStream: ss, ctx: ctx, finish: done}
		defer bound.finishHandler()
		return handler(srv, bound)
	}
	opts := append([]grpc.ServerOption(nil), options...)
	opts = append(opts, grpc.ChainUnaryInterceptor(unary), grpc.ChainStreamInterceptor(stream), grpc.MaxConcurrentStreams(uint32(i.manager.config.Limits.ControlRPCsPerInstance)))
	return grpc.NewServer(opts...), nil
}

type CoreServer struct {
	wire.UnimplementedCoreServer
	Authorizer *Authorizer
}

func (s *CoreServer) GetConfig(ctx context.Context, _ *emptypb.Empty) (*wire.JSONValue, error) {
	if _, err := s.Authorizer.Authorize(ctx, AccessRequest{Operation: "GetConfig", Scopes: []*wire.ResourceScope{resourceFreeScope()}}); err != nil {
		return nil, err
	}
	i := s.Authorizer.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	return proto.Clone(i.spec.Config).(*wire.JSONValue), nil
}
func resourceFreeScope() *wire.ResourceScope {
	return &wire.ResourceScope{SelectorKind: &wire.ResourceScope_Selector{Selector: &wire.ResourceSelector{}}}
}
