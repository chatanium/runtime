package discordbackend

import (
	"context"
	"encoding/json"
	"strings"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
)

type relationshipCacheKey struct{}
type relationshipCache struct {
	entries    map[string][]byte
	bytes, max int64
}
type readLocaleKey struct{}

func readLocale(ctx context.Context) *string {
	locale, _ := ctx.Value(readLocaleKey{}).(*string)
	return locale
}
func (b *Backend) resolveTag(ctx context.Context, p runtime.InstancePrincipal, t ResourceTarget) (*corewire.ResourceScope, error) {
	if !snowflake(t.ID) || !snowflake(t.ChannelID) {
		return nil, invalid("DISCORD_TAG_INVALID")
	}
	var channel struct {
		ID       string `json:"id"`
		GuildID  string `json:"guild_id"`
		ParentID string `json:"parent_id"`
		Tags     []struct {
			ID string `json:"id"`
		} `json:"available_tags"`
	}
	if e := b.readJSON(ctx, p, "/channels/"+t.ChannelID, &channel); e != nil {
		return nil, e
	}
	if channel.ID != t.ChannelID || (t.GuildID != "" && channel.GuildID != t.GuildID) {
		return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
	}
	source := channel
	if len(source.Tags) == 0 && channel.ParentID != "" {
		if e := b.readJSON(ctx, p, "/channels/"+channel.ParentID, &source); e != nil {
			return nil, e
		}
		if source.GuildID != channel.GuildID {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
	}
	for _, tag := range source.Tags {
		if tag.ID == t.ID {
			return scope(map[string]string{"channel_id": channel.ID, "guild_id": channel.GuildID}), nil
		}
	}
	return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
}
func (h *Helper) attachmentScope(ctx context.Context, p runtime.InstancePrincipal, plan *RESTPlan, t ResourceTarget) (*corewire.ResourceScope, error) {
	if !snowflake(t.ID) {
		return nil, invalid("DISCORD_ATTACHMENT_INVALID")
	}
	if len(plan.Credentials) > 0 {
		return h.credentialTarget(plan, p, ResourceTarget{Kind: "message_id", ID: t.MessageID})
	}
	if !snowflake(t.MessageID) || !snowflake(t.ChannelID) {
		return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
	}
	return h.backend.resolveTarget(ctx, p, ResourceTarget{Kind: "message_id", ID: t.MessageID, ChannelID: t.ChannelID, GuildID: t.GuildID})
}

// This lookup validates only requested existing IDs; it never reconstructs,
// appends to, or substitutes the caller's complete post-edit attachment list.
func (h *Helper) validateOwnedAttachments(ctx context.Context, plan *RESTPlan, op *OperationContext) error {
	var wanted []string
	channel, message := "", ""
	for _, t := range plan.Targets {
		if t.Kind == "attachment_id" {
			wanted = append(wanted, t.ID)
			if t.ChannelID != "" {
				channel = t.ChannelID
			}
			if t.MessageID != "" {
				message = t.MessageID
			}
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	if len(plan.Credentials) == 1 && plan.Credentials[0].InitialCallback {
		use := plan.Credentials[0]
		h.backend.mu.Lock()
		r := h.backend.vault[use.Ref.OpaqueId]
		valid := r != nil && r.owner == op.Principal && r.sourceMessageID != "" && (message == "" || r.sourceMessageID == message)
		if valid {
			for _, id := range wanted {
				valid = valid && r.attachmentIDs[id]
			}
		}
		h.backend.mu.Unlock()
		if !valid {
			return denied("DISCORD_ATTACHMENT_NOT_OWNED")
		}
		return nil
	}
	var actual struct {
		ID          string `json:"id"`
		ChannelID   string `json:"channel_id"`
		Attachments []struct {
			ID string `json:"id"`
		} `json:"attachments"`
	}
	if len(plan.Credentials) == 0 {
		if !snowflake(channel) || !snowflake(message) {
			return denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		if e := h.backend.readJSON(ctx, op.Principal, "/channels/"+channel+"/messages/"+message, &actual); e != nil {
			return e
		}
	} else {
		// The token has already been registry-leased after complete scope admission.
		// Reuse the fixed message route, never an arbitrary module-supplied URL.
		request := plan.Request
		request.Method = "GET"
		request.JSON = nil
		request.Files = nil
		request.AuditReason = nil
		request.Owner = string(op.Principal.InstanceID)
		request.Authorization = "Bot " + strings.TrimPrefix(h.backend.config.BotToken, "Bot ")
		request.MaxBodyBytes = h.backend.config.RequestMaxBytes
		if !strings.Contains(request.Path, "/messages/") {
			return denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		response, e := h.backend.transport.Do(ctx, request)
		if e != nil {
			return httpTransportError(e, response.Dispatched)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return discordHTTPError(response.StatusCode, response.Body)
		}
		if json.Unmarshal(response.Body, &actual) != nil {
			return unavailable("DISCORD_RESPONSE_INVALID")
		}
	}
	if message != "@original" && actual.ID != message {
		return denied("RESOURCE_RELATIONSHIP_DENIED")
	}
	if channel != "" && actual.ChannelID != channel {
		return denied("RESOURCE_RELATIONSHIP_DENIED")
	}
	have := make(map[string]bool, len(actual.Attachments))
	for _, a := range actual.Attachments {
		have[a.ID] = true
	}
	for _, id := range wanted {
		if !have[id] {
			return denied("DISCORD_ATTACHMENT_NOT_OWNED")
		}
	}
	return nil
}
