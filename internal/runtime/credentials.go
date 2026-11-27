package runtime

import (
	"context"
	"sync"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BackendCredentialHandle is implemented by a backend-private secret-store key.
// Raw strings and tokens cannot satisfy this interface.
type BackendCredentialHandle interface{ BackendCredentialHandle() }
type CredentialBinding struct {
	BackendID     string
	Purpose       string
	Resource      *wire.ResourceSelector
	ExpiresAt     time.Time
	BackendHandle BackendCredentialHandle
}
type CredentialRequirement struct {
	BackendID string
	Purpose   string
	Resource  *wire.ResourceSelector
}
type CredentialRegistry struct{ manager *Manager }
type credentialRecord struct {
	ref     *wire.CredentialRef
	handle  BackendCredentialHandle
	revoked bool
	leases  map[*CredentialLease]struct{}
	timer   *time.Timer
}
type CredentialLease struct {
	instance  *Instance
	admission *Admission
	record    *credentialRecord
	handle    BackendCredentialHandle
	ctx       context.Context
	cancel    context.CancelFunc
	once      sync.Once
}

func (l *CredentialLease) Context() context.Context { return l.ctx }

// Handle is host-only; canceled leases never reveal the backend key.
func (l *CredentialLease) Handle() (BackendCredentialHandle, error) {
	i := l.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	if l.ctx.Err() != nil || l.record.revoked || i.credentialsRevoked || !l.admission.validLocked() {
		return nil, credentialError()
	}
	if _, ok := l.record.leases[l]; !ok {
		return nil, credentialError()
	}
	return l.handle, nil
}
func (l *CredentialLease) Release() {
	l.once.Do(func() {
		l.cancel()
		i := l.instance
		i.mu.Lock()
		delete(l.record.leases, l)
		if l.record.revoked && len(l.record.leases) == 0 {
			delete(i.credentials, l.record.ref.OpaqueId)
			l.record.handle = nil
		}
		i.signalLocked()
		i.mu.Unlock()
	})
}
func credentialError() error {
	return runtimeError(codes.PermissionDenied, "CREDENTIAL_REFERENCE_INVALID")
}
func (v *CredentialRegistry) instance(p InstancePrincipal) (*Instance, error) {
	v.manager.mu.Lock()
	i := v.manager.instances[p.ModuleID]
	v.manager.mu.Unlock()
	if i == nil || i.principal != p {
		return nil, credentialError()
	}
	return i, nil
}
func (v *CredentialRegistry) Issue(ctx context.Context, owner InstancePrincipal, b CredentialBinding) (*wire.CredentialRef, error) {
	if ctx.Err() != nil {
		return nil, contextError(ctx)
	}
	i, err := v.instance(owner)
	if err != nil {
		return nil, err
	}
	if b.BackendID == "" || b.Purpose == "" || b.Resource == nil || b.BackendHandle == nil || !b.ExpiresAt.After(time.Now()) || !timestamppb.New(b.ExpiresAt).IsValid() {
		return nil, credentialError()
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.bound || i.credentialsRevoked || (i.state != Initializing && i.state != Running) || backendGrant(i.grants, b.BackendID) == nil {
		return nil, credentialError()
	}
	registration := v.manager.backends[b.BackendID]
	if registration.ValidateSelector == nil || registration.ValidateSelector(b.Resource) != nil {
		return nil, credentialError()
	}
	if b.BackendID == discordBackend && i.discordACL != nil && !i.discordACL.Allows(discordSelectorScope(b.Resource)) {
		return nil, credentialError()
	}
	if len(i.credentials) >= v.manager.config.Limits.CredentialRefsPerInstance {
		return nil, runtimeError(codes.ResourceExhausted, "CREDENTIAL_REFERENCE_LIMIT")
	}
	expires := b.ExpiresAt
	ceiling := time.Now().Add(time.Duration(v.manager.config.Limits.CredentialRefMaxTTL))
	if ceiling.Before(expires) {
		expires = ceiling
	}
	ref := &wire.CredentialRef{OpaqueId: id, BackendId: b.BackendID, Purpose: b.Purpose, ResourceScope: proto.Clone(b.Resource).(*wire.ResourceSelector), ExpiresAt: timestamppb.New(expires)}
	if !ref.ExpiresAt.IsValid() {
		return nil, credentialError()
	}
	r := &credentialRecord{ref: ref, handle: b.BackendHandle, leases: make(map[*CredentialLease]struct{})}
	if ctx.Err() != nil {
		return nil, contextError(ctx)
	}
	i.credentials[id] = r
	r.timer = time.AfterFunc(time.Until(expires), func() {
		i.mu.Lock()
		r.revoked = true
		for l := range r.leases {
			l.cancel()
		}
		if len(r.leases) == 0 {
			delete(i.credentials, id)
			r.handle = nil
		}
		i.signalLocked()
		i.mu.Unlock()
	})
	return proto.Clone(ref).(*wire.CredentialRef), nil
}
func (v *CredentialRegistry) Acquire(ctx context.Context, ref *wire.CredentialRef, want CredentialRequirement) (*CredentialLease, error) {
	admission, err := AdmissionFromContext(ctx)
	if err != nil {
		return nil, err
	}
	i := admission.instance
	if ref == nil || want.Resource == nil {
		return nil, credentialError()
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	r := i.credentials[ref.OpaqueId]
	if !admission.validLocked() || i.credentialsRevoked || r == nil || r.revoked || !proto.Equal(ref, r.ref) || !time.Now().Before(r.ref.ExpiresAt.AsTime()) || r.ref.BackendId != want.BackendID || r.ref.Purpose != want.Purpose || !proto.Equal(r.ref.ResourceScope, want.Resource) {
		return nil, credentialError()
	}
	if admission.policy.Backend != want.BackendID {
		return nil, credentialError()
	}
	if want.BackendID == discordBackend && i.discordACL != nil && !i.discordACL.Allows(discordSelectorScope(r.ref.ResourceScope)) {
		return nil, credentialError()
	}
	for lease := range r.leases {
		if lease.admission == admission {
			return nil, runtimeError(codes.ResourceExhausted, "CREDENTIAL_LEASE_ALREADY_ACQUIRED")
		}
	}
	leaseCtx, cancel := context.WithDeadline(admission.ctx, r.ref.ExpiresAt.AsTime())
	l := &CredentialLease{instance: i, record: r, handle: r.handle, ctx: leaseCtx, cancel: cancel, admission: admission}
	r.leases[l] = struct{}{}
	return l, nil
}
func (v *CredentialRegistry) RevokeInstance(ctx context.Context, owner InstancePrincipal) error {
	i, err := v.instance(owner)
	if err != nil {
		return nil
	}
	i.mu.Lock()
	revokeCredentialsLocked(i)
	for len(i.credentials) != 0 {
		changed := i.changed
		i.mu.Unlock()
		select {
		case <-ctx.Done():
			return contextError(ctx)
		case <-changed:
		}
		i.mu.Lock()
	}
	i.mu.Unlock()
	return nil
}
func revokeCredentialsLocked(i *Instance) {
	i.credentialsRevoked = true
	for id, r := range i.credentials {
		r.revoked = true
		if r.timer != nil {
			r.timer.Stop()
		}
		for l := range r.leases {
			l.cancel()
		}
		if len(r.leases) == 0 {
			delete(i.credentials, id)
			r.handle = nil
		}
	}
}
