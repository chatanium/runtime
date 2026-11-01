package discordbackend

import (
	"context"
	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/proto"
	"time"
)

// Reading stored, immutable credential metadata is not secret resolution. The
// registry lease still must be acquired after final complete resource admission.
func (h *Helper) credentialRecord(use CredentialUse, p runtime.InstancePrincipal) (*corewire.ResourceSelector, error) {
	if use.Ref == nil || use.Resource == nil || !proto.Equal(use.Resource, use.Ref.ResourceScope) || use.Ref.BackendId != BackendID || use.Ref.Purpose != use.Purpose {
		return nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	h.backend.mu.Lock()
	defer h.backend.mu.Unlock()
	r := h.backend.vault[use.Ref.OpaqueId]
	if r == nil || r.owner != p || !proto.Equal(r.ref, use.Ref) || r.purpose != use.Purpose || !time.Now().Before(r.expires) {
		return nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	if r.purpose == "discord.interaction" && !snowflake(r.resource.GetResourceIds()["user_id"]) {
		return nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	return copySelector(r.resource), nil
}
func (h *Helper) credentialTargets(ctx context.Context, plan *RESTPlan, p runtime.InstancePrincipal) ([]*corewire.ResourceScope, error) {
	var out []*corewire.ResourceScope
	plan.credentialDestinations = nil
	for _, use := range plan.Credentials {
		stored, e := h.credentialRecord(use, p)
		if e != nil {
			return nil, e
		}
		if stored.ResourceIds["application_id"] != "" && stored.ResourceIds["application_id"] != h.backend.config.ApplicationID {
			return nil, denied("CREDENTIAL_REFERENCE_INVALID")
		}
		if use.ThreadDestination != "" {
			proof, e := h.webhookDestination(ctx, p, use, stored)
			if e != nil {
				return nil, e
			}
			if prior, ok := plan.credentialDestinations[use.Ref.OpaqueId]; ok && !proto.Equal(prior.destination, proof.destination) {
				return nil, denied("CREDENTIAL_CHANNEL_MISMATCH")
			}
			if plan.credentialDestinations == nil {
				plan.credentialDestinations = make(map[string]credentialDestination, 1)
			}
			plan.credentialDestinations[use.Ref.OpaqueId] = proof
		}
		for _, t := range plan.Targets {
			kind, id := t.Kind, t.ID
			if id == "@me" {
				if kind == "application_id" {
					id = h.backend.config.ApplicationID
				} else if kind == "user_id" {
					id = h.backend.config.BotUserID
				}
			}
			if kind == "webhook_id" && use.Purpose == "discord.interaction" {
				kind = "application_id"
			}
			if expected, ok := stored.ResourceIds[kind]; ok && id != expected && !plan.credentialDestinations[use.Ref.OpaqueId].allows(use, kind, expected, id) {
				return nil, denied("CREDENTIAL_REFERENCE_INVALID")
			}
		}
		stored, e = plan.credentialResource(use, stored)
		if e != nil {
			return nil, e
		}
		if use.InitialCallback {
			h.backend.mu.Lock()
			r := h.backend.vault[use.Ref.OpaqueId]
			if r != nil && r.owner == p && r.sourceMessageID != "" {
				stored.ResourceIds["message_id"] = r.sourceMessageID
			}
			h.backend.mu.Unlock()
		}
		out = append(out, scope(stored.ResourceIds))
	}
	return out, nil
}
func (h *Helper) credentialTarget(plan *RESTPlan, p runtime.InstancePrincipal, t ResourceTarget) (*corewire.ResourceScope, error) {
	if len(plan.Credentials) != 1 {
		return nil, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	use := plan.Credentials[0]
	stored, e := h.credentialRecord(use, p)
	if e != nil {
		return nil, e
	}
	stored, e = plan.credentialResource(use, stored)
	if e != nil {
		return nil, e
	}
	ids := stored.ResourceIds
	if use.InitialCallback && t.Kind == "message_id" {
		h.backend.mu.Lock()
		r := h.backend.vault[use.Ref.OpaqueId]
		valid := r != nil && r.owner == p && r.sourceMessageID != "" && r.sourceMessageID == t.ID
		h.backend.mu.Unlock()
		if !valid {
			return nil, denied("CREDENTIAL_MESSAGE_MISMATCH")
		}
	}
	switch t.Kind {
	case "webhook_id":
		key := "webhook_id"
		if use.Purpose == "discord.interaction" {
			key = "application_id"
		}
		if ids[key] != t.ID {
			return nil, denied("CREDENTIAL_REFERENCE_INVALID")
		}
	case "interaction_id":
		if use.Purpose != "discord.interaction" || ids["interaction_id"] != t.ID {
			return nil, denied("CREDENTIAL_REFERENCE_INVALID")
		}
	case "message_id":
		if t.ID == "@original" {
			if use.Purpose != "discord.interaction" {
				return nil, denied("CREDENTIAL_REFERENCE_INVALID")
			}
		} else {
			if !snowflake(t.ID) {
				return nil, invalid("DISCORD_RESOURCE_INVALID")
			}
			ids["message_id"] = t.ID
		}
	default:
		return nil, invalid("DISCORD_RESOURCE_INVALID")
	}
	return scope(ids), nil
}
func (h *Helper) validateCredentialChannel(ctx context.Context, p runtime.InstancePrincipal, plan *RESTPlan, channelID string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	for _, use := range plan.Credentials {
		if use.Purpose != "discord.webhook" && use.Purpose != "discord.interaction" {
			continue
		}
		stored, e := h.credentialRecord(use, p)
		if e != nil {
			return e
		}
		effective, e := plan.credentialResource(use, stored)
		if e != nil {
			return e
		}
		if effective.ResourceIds["channel_id"] != channelID {
			return denied("CREDENTIAL_CHANNEL_MISMATCH")
		}
	}
	return nil
}

// A proof is minted only from a trusted relationship lookup. It never changes
// the registry/vault binding, which remains the original webhook parent.
type credentialDestination struct {
	binding     *corewire.ResourceSelector
	destination *corewire.ResourceSelector
}

func (d credentialDestination) matches(use CredentialUse) bool {
	return use.Purpose == "discord.webhook" && use.ThreadDestination != "" && d.binding != nil && d.destination != nil && proto.Equal(d.binding, use.Resource) && d.destination.ResourceIds["channel_id"] == use.ThreadDestination
}
func (d credentialDestination) allows(use CredentialUse, kind, expected, actual string) bool {
	return kind == "channel_id" && d.matches(use) && d.binding.ResourceIds[kind] == expected && d.destination.ResourceIds[kind] == actual
}
func (plan *RESTPlan) credentialResource(use CredentialUse, stored *corewire.ResourceSelector) (*corewire.ResourceSelector, error) {
	if use.ThreadDestination == "" {
		return stored, nil
	}
	proof := plan.credentialDestinations[use.Ref.OpaqueId]
	if !proof.matches(use) || !proto.Equal(stored, proof.binding) {
		return nil, denied("CREDENTIAL_CHANNEL_MISMATCH")
	}
	return copySelector(proof.destination), nil
}
func (h *Helper) webhookDestination(ctx context.Context, p runtime.InstancePrincipal, use CredentialUse, stored *corewire.ResourceSelector) (credentialDestination, error) {
	if use.Purpose != "discord.webhook" || !snowflake(use.ThreadDestination) || !snowflake(stored.ResourceIds["channel_id"]) {
		return credentialDestination{}, denied("CREDENTIAL_CHANNEL_MISMATCH")
	}
	var actual struct {
		ID       string                `json:"id"`
		ParentID string                `json:"parent_id"`
		GuildID  string                `json:"guild_id"`
		Type     discordgo.ChannelType `json:"type"`
	}
	if e := h.backend.readJSON(ctx, p, "/channels/"+use.ThreadDestination, &actual); e != nil {
		return credentialDestination{}, e
	}
	thread := actual.Type == discordgo.ChannelTypeGuildNewsThread || actual.Type == discordgo.ChannelTypeGuildPublicThread || actual.Type == discordgo.ChannelTypeGuildPrivateThread
	if !thread || actual.ID != use.ThreadDestination || actual.ParentID != stored.ResourceIds["channel_id"] || !snowflake(actual.GuildID) || (stored.ResourceIds["guild_id"] != "" && actual.GuildID != stored.ResourceIds["guild_id"]) {
		return credentialDestination{}, denied("CREDENTIAL_CHANNEL_MISMATCH")
	}
	destination := copySelector(stored)
	destination.ResourceIds["channel_id"] = actual.ID
	destination.ResourceIds["guild_id"] = actual.GuildID
	return credentialDestination{binding: copySelector(stored), destination: destination}, nil
}

// Secret resolution requires the admitted resource to retain every immutable
// credential relationship. The sole channel exception is a verified webhook
// thread destination; an interaction credential never receives this proof.
func (op *OperationContext) validateCredentialScopes(use CredentialUse) error {
	if use.Ref == nil || use.Resource == nil {
		return denied("CREDENTIAL_REFERENCE_INVALID")
	}
	for k, v := range use.Resource.ResourceIds {
		found := false
		for _, s := range op.Scopes {
			if actual, ok := s.GetSelector().ResourceIds[k]; ok {
				if actual != v && !op.credentialDestinations[use.Ref.OpaqueId].allows(use, k, v, actual) {
					return denied("CREDENTIAL_REFERENCE_INVALID")
				}
				found = true
			}
		}
		if !found {
			return denied("CREDENTIAL_REFERENCE_INVALID")
		}
	}
	return nil
}
