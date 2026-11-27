package discordbackend

import (
	"context"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/protobuf/proto"
	"strconv"
	"strings"
	"time"
)

type vaultHandle struct{ id string }

func (vaultHandle) BackendCredentialHandle() {}

type callbackState uint8

const (
	callbackUnused callbackState = iota
	callbackInFlight
	callbackResponded
)

type vaultRecord struct {
	owner           runtime.InstancePrincipal
	secret, purpose string
	resource        *corewire.ResourceSelector
	expires         time.Time
	timer           *time.Timer
	callback        callbackState
	fileLimit       int64
	ref             *corewire.CredentialRef
	sourceMessageID string
	attachmentIDs   map[string]bool
	interactionType int32
	initialDeadline time.Time
}
type instanceEncoder struct {
	backend         *Backend
	services        runtime.InstanceServices
	fileLimit       int64
	sourceMessageID string
	attachmentIDs   map[string]bool
	interactionType int32
}

func (e instanceEncoder) EncodeCredential(ctx context.Context, binding core.CredentialBinding, secret string) (*corewire.CredentialRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b := e.backend
	if secret == "" || strings.TrimPrefix(secret, "Bot ") == strings.TrimPrefix(b.config.BotToken, "Bot ") || binding.BackendID != BackendID || (binding.Purpose != "discord.interaction" && binding.Purpose != "discord.webhook" && binding.Purpose != "discord.user.guilds.join") || validateSelector(binding.ResourceScope) != nil || len(binding.ResourceScope.ResourceIds) == 0 || !binding.ExpiresAt.After(time.Now()) {
		return nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	expiry := binding.ExpiresAt
	if max := time.Now().Add(b.config.CredentialTTL); max.Before(expiry) {
		expiry = max
	}
	if max := time.Now().Add(time.Duration(e.services.Limits.CredentialRefMaxTTL)); max.Before(expiry) {
		expiry = max
	}
	var initialDeadline time.Time
	if binding.Purpose == "discord.interaction" {
		if !snowflake(binding.ResourceScope.ResourceIds["user_id"]) {
			return nil, denied("CREDENTIAL_REFERENCE_INVALID")
		}
		var err error
		initialDeadline, err = initialCallbackDeadline(binding.ResourceScope.ResourceIds["interaction_id"])
		if err != nil {
			return nil, err
		}
		if e.interactionType < 1 || e.interactionType > 5 {
			return nil, denied("CREDENTIAL_REFERENCE_INVALID")
		}
	}
	// One source interaction has one callback state even if Discord repeats an
	// ingress event. Returning an existing handle never renews its original TTL.
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i := b.instances[e.services.Principal.InstanceID]
	if b.closed || i == nil || i.services.Principal != e.services.Principal || i.ctx.Err() != nil {
		return nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	if binding.Purpose == "discord.interaction" {
		for _, r := range b.vault {
			if r.owner == e.services.Principal && r.purpose == binding.Purpose && proto.Equal(r.resource, binding.ResourceScope) && r.secret == secret && time.Now().Before(r.expires) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return proto.Clone(r.ref).(*corewire.CredentialRef), nil
			}
		}
	}
	handle := &vaultHandle{}
	ref, err := e.services.Credentials.Issue(ctx, e.services.Principal, runtime.CredentialBinding{BackendID: BackendID, Purpose: binding.Purpose, Resource: binding.ResourceScope, ExpiresAt: expiry, BackendHandle: handle})
	if err != nil {
		return nil, err
	}
	handle.id = ref.OpaqueId
	r := &vaultRecord{owner: e.services.Principal, secret: secret, purpose: binding.Purpose, resource: copySelector(binding.ResourceScope), expires: ref.ExpiresAt.AsTime(), fileLimit: e.fileLimit, ref: proto.Clone(ref).(*corewire.CredentialRef), sourceMessageID: e.sourceMessageID, attachmentIDs: e.attachmentIDs, interactionType: e.interactionType, initialDeadline: initialDeadline}
	b.vault[handle.id] = r
	r.timer = time.AfterFunc(time.Until(r.expires), func() {
		b.mu.Lock()
		if b.vault[handle.id] == r {
			r.secret = ""
			delete(b.vault, handle.id)
		}
		b.mu.Unlock()
	})
	return ref, nil
}
func (b *Backend) projectionPolicy(ctx context.Context, t discordv2.CredentialTarget) (core.CredentialBinding, error) {
	if validateSelector(t.ResourceScope) != nil {
		return core.CredentialBinding{}, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	ids := t.ResourceScope.ResourceIds
	expiry := time.Now().Add(b.config.CredentialTTL)
	switch t.Purpose {
	case "discord.interaction":
		if !snowflake(ids["user_id"]) {
			return core.CredentialBinding{}, denied("CREDENTIAL_REFERENCE_INVALID")
		}
		id := ids["interaction_id"]
		n, e := strconv.ParseUint(id, 10, 64)
		if e != nil || n == 0 {
			return core.CredentialBinding{}, denied("CREDENTIAL_REFERENCE_INVALID")
		}
		created := time.UnixMilli(int64(n>>22) + 1420070400000)
		expiry = created.Add(b.config.InteractionTTL)
		if ids["application_id"] != b.config.ApplicationID {
			return core.CredentialBinding{}, denied("CREDENTIAL_REFERENCE_INVALID")
		}
	case "discord.webhook":
		if !snowflake(ids["webhook_id"]) {
			return core.CredentialBinding{}, denied("CREDENTIAL_REFERENCE_INVALID")
		}
	default:
		return core.CredentialBinding{}, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	if !expiry.After(time.Now()) {
		return core.CredentialBinding{}, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	return core.CredentialBinding{BackendID: BackendID, Purpose: t.Purpose, ResourceScope: copySelector(t.ResourceScope), ExpiresAt: expiry}, nil
}

type resolvedCredential struct {
	backend *Backend
	lease   *runtime.CredentialLease
	record  *vaultRecord
	initial bool
}

func (h *Helper) acquireCredential(ctx context.Context, op *OperationContext, use CredentialUse) (string, *resolvedCredential, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if use.Ref == nil || use.Resource == nil || use.Apply == nil || use.Purpose != use.Ref.Purpose || !proto.Equal(use.Resource, use.Ref.ResourceScope) {
		return "", nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	if err := op.validateCredentialScopes(use); err != nil {
		return "", nil, err
	}
	lease, err := h.services.Credentials.Acquire(ctx, use.Ref, runtime.CredentialRequirement{BackendID: BackendID, Purpose: use.Purpose, Resource: use.Resource})
	if err != nil {
		return "", nil, err
	}
	handle, err := lease.Handle()
	if err != nil {
		lease.Release()
		return "", nil, err
	}
	key, ok := handle.(*vaultHandle)
	if !ok {
		lease.Release()
		return "", nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	b := h.backend
	b.mu.Lock()
	r := b.vault[key.id]
	if r == nil || r.owner != op.Principal || r.purpose != use.Purpose || !proto.Equal(r.resource, use.Resource) || !time.Now().Before(r.expires) || r.secret == "" {
		b.mu.Unlock()
		lease.Release()
		return "", nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	if r.purpose == "discord.interaction" && r.callback == callbackUnused && !time.Now().Before(r.initialDeadline) {
		b.mu.Unlock()
		lease.Release()
		return "", nil, unavailable("INTERACTION_CALLBACK_EXPIRED")
	}
	if use.InitialCallback && r.callback != callbackUnused {
		b.mu.Unlock()
		lease.Release()
		return "", nil, unavailable("INTERACTION_CALLBACK_ALREADY_USED")
	}
	if use.InitialCallback {
		r.callback = callbackInFlight
	}
	secret := r.secret
	b.mu.Unlock()
	return secret, &resolvedCredential{backend: b, lease: lease, record: r, initial: use.InitialCallback}, nil
}
func (c *resolvedCredential) release(dispatched, responded bool) {
	if c == nil {
		return
	}
	c.backend.mu.Lock()
	if c.initial {
		if !dispatched {
			c.record.callback = callbackUnused
		} else if responded {
			c.record.callback = callbackResponded
		}
	}
	c.backend.mu.Unlock()
	c.lease.Release()
}
func (h *Helper) provisionedCredential(ctx context.Context, request proto.Message) (proto.Message, error) {
	req, ok := request.(*wire.GetProvisionedCredentialRefRequest)
	if !ok || req.BindingName == "" {
		return nil, invalid("CREDENTIAL_BINDING_INVALID")
	}
	var selected *runtime.ProvisionedCredentialBinding
	for _, binding := range h.services.CredentialBindings {
		if binding.Name == req.BindingName {
			value := binding
			selected = &value
			break
		}
	}
	if selected == nil || selected.BackendID != BackendID {
		return nil, denied("CREDENTIAL_BINDING_INVALID")
	}
	secret, ok := h.backend.config.Secrets[selected.SecretID]
	if !ok || secret.ModuleID != h.services.Principal.ModuleID || secret.Purpose != selected.Purpose || !proto.Equal(secret.Resource, selected.Resource) || !secret.ExpiresAt.After(time.Now()) {
		return nil, denied("CREDENTIAL_BINDING_INVALID")
	}
	targets := []ResourceTarget{}
	for k, id := range selected.Resource.ResourceIds {
		targets = append(targets, ResourceTarget{Kind: k, ID: id, GuildID: selected.Resource.ResourceIds["guild_id"], ApplicationID: selected.Resource.ResourceIds["application_id"]})
	}
	op, err := h.authorize(ctx, "GetProvisionedCredentialRef", &RESTPlan{Targets: targets})
	if err != nil {
		return nil, err
	}
	defer op.Admission.Release()
	return (instanceEncoder{backend: h.backend, services: h.services}).EncodeCredential(op.Context, core.CredentialBinding{BackendID: BackendID, Purpose: secret.Purpose, ResourceScope: secret.Resource, ExpiresAt: secret.ExpiresAt}, secret.Value)
}
