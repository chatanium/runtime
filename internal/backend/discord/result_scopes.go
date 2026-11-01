package discordbackend

import (
	"encoding/json"
	"strings"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
)

func commonResources(scopes []*corewire.ResourceScope) map[string]string {
	ids := map[string]string{}
	if len(scopes) == 0 {
		return ids
	}
	for k, v := range scopes[0].GetSelector().ResourceIds {
		same := true
		for _, s := range scopes[1:] {
			if s.GetSelector().ResourceIds[k] != v {
				same = false
				break
			}
		}
		if same {
			ids[k] = v
		}
	}
	return ids
}
func resultKind(operation string) string {
	switch {
	case operation == "User" || operation == "UserUpdate" || operation == "MessageReactions":
		return "user_id"
	case operation == "UserGuilds" || operation == "Guild" || operation == "GuildPreview" || operation == "GuildEdit":
		return "guild_id"
	case strings.HasPrefix(operation, "ApplicationCommand") || operation == "GuildApplicationCommandsPermissions":
		return "command_id"
	case strings.HasPrefix(operation, "GuildRole"):
		return "role_id"
	case strings.HasPrefix(operation, "GuildEmoji") || strings.HasPrefix(operation, "ApplicationEmoji"):
		return "emoji_id"
	case strings.HasPrefix(operation, "GuildScheduledEvent"):
		return "scheduled_event_id"
	case strings.HasPrefix(operation, "AutoModerationRule"):
		return "rule_id"
	case operation == "SKUs":
		return "sku_id"
	case strings.HasPrefix(operation, "Entitlement"):
		return "entitlement_id"
	case strings.HasPrefix(operation, "Subscription"):
		return "subscription_id"
	case strings.Contains(operation, "Webhook") && !strings.Contains(operation, "Message") && !strings.Contains(operation, "Execute"):
		return "webhook_id"
	case strings.Contains(operation, "Message") && !strings.Contains(operation, "ThreadStart") && !strings.Contains(operation, "Pinned"):
		return "message_id"
	case operation == "Channel" || operation == "ChannelEdit" || operation == "ChannelDelete" || operation == "GuildChannels" || operation == "GuildChannelCreateComplex" || operation == "UserChannelCreate" || strings.Contains(operation, "ThreadStart"):
		return "channel_id"
	}
	return ""
}

var childResources = map[string]string{"guild": "guild_id", "guilds": "guild_id", "source_guild": "guild_id", "serialized_source_guild": "guild_id", "channel": "channel_id", "channels": "channel_id", "threads": "channel_id", "user": "user_id", "users": "user_id", "author": "user_id", "creator": "user_id", "recipients": "user_id", "role": "role_id", "roles": "role_id", "emoji": "emoji_id", "emojis": "emoji_id", "message": "message_id", "messages": "message_id", "referenced_message": "message_id", "webhook": "webhook_id", "webhooks": "webhook_id", "member": "", "members": "", "items": "", "resolved": "", "data": "", "thread_member": "", "presences": "", "voice_states": "", "permission_overwrites": "", "guild_scheduled_event": "scheduled_event_id", "integrations": "integration_id", "stickers": "sticker_id", "entitlements": "entitlement_id"}

// resourceGraph checks reviewed Discord resource relationships without parsing
// arbitrary audit OldValue/NewValue or application JSON as authority selectors.
func resourceGraph(raw json.RawMessage, kind string, parent map[string]string, grant *corewire.CapabilityGrant, depth int) error {
	return (resourceGraphContext{grant: grant}).check(raw, kind, parent, depth, false)
}

// An interaction event or credential's invoking user describes authenticated
// context. A nested or returned message's author is data about that message, not
// a replacement caller. Other relationships and user targets still need the grant.
type resourceGraphContext struct {
	grant        *corewire.CapabilityGrant
	invokingUser string
}

func (g resourceGraphContext) check(raw json.RawMessage, kind string, parent map[string]string, depth int, messageAuthor bool) error {
	if depth > 64 {
		return unavailable("DISCORD_RESPONSE_INVALID")
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] == '[' {
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return unavailable("DISCORD_RESPONSE_INVALID")
		}
		for _, item := range items {
			if e := g.check(item, kind, parent, depth+1, messageAuthor); e != nil {
				return e
			}
		}
		return nil
	}
	if raw[0] != '{' {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return unavailable("DISCORD_RESPONSE_INVALID")
	}
	ids := make(map[string]string, len(parent)+4)
	for k, v := range parent {
		ids[k] = v
	}
	for _, key := range []string{"guild_id", "channel_id", "application_id", "user_id", "webhook_id", "command_id", "interaction_id", "message_id", "role_id", "sku_id", "scheduled_event_id"} {
		var id string
		if json.Unmarshal(fields[key], &id) == nil && id != "" {
			if !snowflake(id) {
				return unavailable("DISCORD_RESPONSE_INVALID")
			}
			ids[key] = id
		}
	}
	if kind != "" {
		var id string
		if json.Unmarshal(fields["id"], &id) == nil && id != "" {
			if !snowflake(id) {
				return unavailable("DISCORD_RESPONSE_INVALID")
			}
			if !messageAuthor {
				ids[kind] = id
			}
		}
	}
	if kind != "" && !messageAuthor && fields["id"] == nil && len(fields) > 0 {
		keyed := true
		for key := range fields {
			if !snowflake(key) {
				keyed = false
				break
			}
		}
		if keyed {
			for key, value := range fields {
				context := make(map[string]string, len(parent)+1)
				for k, v := range parent {
					context[k] = v
				}
				context[kind] = key
				if !grantAllows(g.grant, []*corewire.ResourceScope{scope(context)}) {
					return denied("RESOURCE_SCOPE_DENIED")
				}
				if e := g.check(value, kind, context, depth+1, false); e != nil {
					return e
				}
			}
			return nil
		}
	}
	if len(ids) != 0 && !grantAllows(g.grant, []*corewire.ResourceScope{scope(ids)}) {
		return denied("RESOURCE_SCOPE_DENIED")
	}
	for name, childKind := range childResources {
		if value, ok := fields[name]; ok {
			if e := g.check(value, childKind, ids, depth+1, g.invokingUser != "" && name == "author"); e != nil {
				return e
			}
		}
	}
	return nil
}
