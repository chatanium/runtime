package discordbackend

import (
	"context"
	"errors"
	"testing"
	"time"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMutationRootCannotBeAuthorizedByReferencedDescendant(t *testing.T) {
	guild := scope(map[string]string{"guild_id": "1"})
	channel := scope(map[string]string{"guild_id": "1", "channel_id": "2"})
	for _, operation := range []string{"GuildEdit", "GuildEmbedEdit"} {
		t.Run(operation, func(t *testing.T) {
			complete := requiredScopes([]*corewire.ResourceScope{guild, channel}, []*corewire.ResourceScope{guild})
			channelOnly := &corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{channel}}
			if grantAllows(channelOnly, complete) {
				t.Fatal("referenced channel authorized guild-wide mutation")
			}
			if !grantAllows(&corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{guild}}, complete) {
				t.Fatal("guild authority did not cover mutation and referenced channel")
			}
		})
	}
	// A genuine leaf operation must not acquire a new guild-wide requirement.
	if !grantAllows(&corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{channel}}, requiredScopes([]*corewire.ResourceScope{guild, channel}, nil)) {
		t.Fatal("relationship ancestor became an independent mutation root")
	}
}

func TestRoleReplacementRequiresRemovedRolesAndGuildFence(t *testing.T) {
	h := &Helper{backend: &Backend{}}
	cache := &relationshipCache{max: 4096, entries: map[string][]byte{
		"/guilds/1/members/2": []byte(`{"user":{"id":"2"},"roles":["3"]}`),
		"/guilds/1/roles/3":   []byte(`{"id":"3"}`),
		"/guilds/1/roles/4":   []byte(`{"id":"4"}`),
	}}
	ctx := context.WithValue(context.Background(), relationshipCacheKey{}, cache)
	for _, submitted := range [][]string{nil, {"4"}} {
		targets, root, err := h.memberRoleReplacementTargets(ctx, runtime.InstancePrincipal{}, &MemberRoleReplacement{GuildID: "1", UserID: "2", RoleIDs: submitted})
		if err != nil {
			t.Fatal(err)
		}
		removed, added := false, len(submitted) == 0
		for _, target := range targets {
			removed = removed || target.GetSelector().ResourceIds["role_id"] == "3"
			added = added || target.GetSelector().ResourceIds["role_id"] == "4"
		}
		if !removed || !added {
			t.Fatalf("replacement omitted existing/selected roles: %v", targets)
		}
		member := scope(map[string]string{"guild_id": "1", "user_id": "2"})
		narrow := &corewire.CapabilityGrant{ResourceScopes: append([]*corewire.ResourceScope{member}, targets...)}
		complete := requiredScopes(append(targets, member), []*corewire.ResourceScope{root})
		if grantAllows(narrow, complete) {
			t.Fatal("enumerated snapshot was treated as an atomic fence for a role-scoped caller")
		}
		if !grantAllows(&corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{scope(map[string]string{"guild_id": "1"})}}, complete) {
			t.Fatal("guild-wide replacement authority rejected")
		}
	}
	// Absent roles are not a replacement and perform no member lookup.
	if targets, root, err := (*Helper)(nil).memberRoleReplacementTargets(context.Background(), runtime.InstancePrincipal{}, nil); err != nil || targets != nil || root != nil {
		t.Fatal("absent roles acquired replacement semantics")
	}
}

func TestWebhookThreadKeepsParentBindingThroughAllCredentialGates(t *testing.T) {
	p := runtime.InstancePrincipal{ModuleID: "module", InstanceID: "instance"}
	binding := &corewire.ResourceSelector{ResourceIds: map[string]string{"application_id": "100", "guild_id": "1", "channel_id": "2", "webhook_id": "3"}}
	expiry := time.Now().Add(time.Minute)
	ref := &corewire.CredentialRef{OpaqueId: "reference", BackendId: BackendID, Purpose: "discord.webhook", ResourceScope: binding, ExpiresAt: timestamppb.New(expiry)}
	b := &Backend{config: Config{ApplicationID: "100"}, vault: map[string]*vaultRecord{"reference": {owner: p, secret: "private", purpose: ref.Purpose, resource: copySelector(binding), expires: expiry, ref: proto.Clone(ref).(*corewire.CredentialRef)}}}
	h := &Helper{backend: b, services: runtime.InstanceServices{Principal: p}}
	cache := &relationshipCache{max: 4096, entries: map[string][]byte{
		"/channels/4": []byte(`{"id":"4","parent_id":"2","guild_id":"1","type":11}`),
		"/channels/5": []byte(`{"id":"5","parent_id":"9","guild_id":"1","type":11}`),
		"/channels/6": []byte(`{"id":"6","parent_id":"2","guild_id":"1","type":0}`),
	}}
	ctx := context.WithValue(context.Background(), relationshipCacheKey{}, cache)
	use := CredentialUse{Ref: ref, Purpose: ref.Purpose, Resource: binding, ThreadDestination: "4"}
	plan := &RESTPlan{Targets: []ResourceTarget{{Kind: "webhook_id", ID: "3"}, {Kind: "channel_id", ID: "4"}}, Credentials: []CredentialUse{use}}
	scopes, err := h.credentialTargets(ctx, plan, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.validateCredentialChannel(ctx, p, plan, "4"); err != nil {
		t.Fatal(err)
	}
	target, err := h.credentialTarget(plan, p, ResourceTarget{Kind: "webhook_id", ID: "3"})
	if err != nil {
		t.Fatal(err)
	}
	op := &OperationContext{Scopes: append(scopes, target), credentialDestinations: plan.credentialDestinations}
	if err = op.validateCredentialScopes(use); err != nil {
		t.Fatalf("lease gate rejected verified destination: %v", err)
	}
	if !grantAllows(&corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{scope(map[string]string{"guild_id": "1", "channel_id": "4"})}}, op.Scopes) {
		t.Fatal("actual thread destination was replaced by parent authority")
	}
	if binding.ResourceIds["channel_id"] != "2" || ref.ResourceScope.ResourceIds["channel_id"] != "2" {
		t.Fatal("immutable parent binding was rewritten")
	}
	withoutProof := &OperationContext{Scopes: op.Scopes}
	if withoutProof.validateCredentialScopes(use) == nil {
		t.Fatal("unverified channel substitution accepted at lease gate")
	}
	interaction := use
	interaction.Purpose = "discord.interaction"
	if op.validateCredentialScopes(interaction) == nil {
		t.Fatal("webhook proof weakened interaction channel binding")
	}
	for _, thread := range []string{"5", "6"} {
		bad := use
		bad.ThreadDestination = thread
		badPlan := &RESTPlan{Credentials: []CredentialUse{bad}}
		if _, err = h.credentialTargets(ctx, badPlan, p); err == nil {
			t.Fatal("unrelated parent or non-thread accepted")
		}
	}
}

func TestCanceledRESTProjectionCannotHandoffFreshCredential(t *testing.T) {
	b := &Backend{config: Config{ApplicationID: "100", BotToken: "bot-secret", CredentialTTL: time.Minute}, vault: make(map[string]*vaultRecord)}
	body := []byte(`{"id":"3","type":1,"guild_id":"1","channel_id":"2","application_id":"100","token":"webhook-secret"}`)
	for _, kind := range []string{"deadline", "lease"} {
		t.Run(kind, func(t *testing.T) {
			parent := context.Background()
			var bounded context.Context
			var cancel context.CancelFunc
			if kind == "deadline" {
				bounded, cancel = context.WithDeadline(parent, time.Now().Add(-time.Second))
			} else {
				bounded, cancel = context.WithCancel(parent)
				cancel()
			}
			defer cancel()
			// The successful HTTP bytes already exist and the original RPC is live;
			// projection must still use the canceled admitted-operation context.
			result, err := projectRESTResponse(withRESTProjectionContext(bounded, &RESTPlan{}), "WebhookWithToken", body, instanceEncoder{backend: b}, b.projectionPolicy)
			if !errors.Is(err, bounded.Err()) || result != nil {
				t.Fatalf("canceled operation handed off a result or lost cancellation: %v %v", result, err)
			}
			if parent.Err() != nil || len(b.vault) != 0 {
				t.Fatal("test canceled the original RPC or projection published a secret")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if ref, err := (instanceEncoder{}).EncodeCredential(canceled, core.CredentialBinding{}, "secret"); err == nil || ref != nil {
		t.Fatal("canceled encoder proceeded to publication")
	}
}
