package discordbackend

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/bwmarrin/discordgo"
	"github.com/thirdscam/chatanium/internal/discordacl"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
)

// The graph consumes authenticated Discord ingress and host-resolved targets,
// never module payloads. Its retained result contains only unique scope pairs.
type scopeEvidence struct {
	backend *Backend
	scopes  []discordacl.Scope
	seen    map[discordacl.Scope]struct{}
}

func (g *scopeEvidence) add(s discordacl.Scope) bool {
	if !discordacl.ValidID(s.GuildID) || s.ChannelID != "" && !discordacl.ValidID(s.ChannelID) {
		return false
	}
	if g.seen == nil {
		g.seen = make(map[discordacl.Scope]struct{})
	}
	if _, found := g.seen[s]; !found {
		g.seen[s] = struct{}{}
		g.scopes = append(g.scopes, s)
	}
	return true
}

func selectorEvidence(target *corewire.ResourceScope) discordacl.Scope {
	ids := target.GetSelector().GetResourceIds()
	return discordacl.Scope{GuildID: ids["guild_id"], ChannelID: ids["channel_id"]}
}

func (g *scopeEvidence) resolveChannel(s discordacl.Scope, channel string, explicitGuild, sameGuild bool) (discordacl.Scope, bool) {
	if channel == s.ChannelID || channel == "" {
		return s, true
	}
	for _, known := range g.scopes {
		if known.ChannelID == channel {
			return known, !(explicitGuild || sameGuild) || known.GuildID == s.GuildID
		}
	}
	if !explicitGuild && !sameGuild {
		if g.backend.session == nil {
			return discordacl.Scope{}, false
		}
		facts, ok := g.backend.channelFacts(channel)
		if !ok || facts.GuildID == "" || facts.ID != channel {
			return discordacl.Scope{}, false
		}
		s.GuildID = facts.GuildID
	}
	s.ChannelID = channel
	return s, true
}

func evidenceID(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", true
	}
	var id string
	ok := json.Unmarshal(raw, &id) == nil && (id == "" || discordacl.ValidID(id))
	return id, ok
}

func (g *scopeEvidence) nodeScope(fields map[string]json.RawMessage, inherited discordacl.Scope, kind string) (discordacl.Scope, bool) {
	guild, guildOK := evidenceID(fields["guild_id"])
	channel, channelOK := evidenceID(fields["channel_id"])
	if !guildOK || !channelOK {
		return discordacl.Scope{}, false
	}
	switch kind {
	case "guild_id", "channel_id", "guild_channel":
		id, ok := evidenceID(fields["id"])
		if !ok || id == "" {
			return discordacl.Scope{}, false
		}
		if kind == "guild_id" {
			if guild != "" && guild != id {
				return discordacl.Scope{}, false
			}
			guild = id
		} else {
			if channel != "" && channel != id {
				return discordacl.Scope{}, false
			}
			channel = id
		}
	case "thread_member":
		if id, ok := evidenceID(fields["id"]); !ok {
			return discordacl.Scope{}, false
		} else if id != "" {
			channel = id
		}
	case "entitlement":
		if guild == "" {
			return discordacl.Scope{}, false
		}
	}
	s := inherited
	if guild != "" && (guild != s.GuildID || kind == "guild_id" || kind == "entitlement") {
		s = discordacl.Scope{GuildID: guild}
	}
	return g.resolveChannel(s, channel, guild != "", kind == "guild_channel" || kind == "thread_member")
}

func (g *scopeEvidence) walk(raw json.RawMessage, inherited discordacl.Scope, kind string, depth int) bool {
	raw = bytes.TrimSpace(raw)
	if depth > 64 {
		return false
	}
	if len(raw) == 0 || (raw[0] != '{' && raw[0] != '[') {
		return true
	}
	if raw[0] == '[' {
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return false
		}
		for _, value := range values {
			if !g.walk(value, inherited, kind, depth+1) {
				return false
			}
		}
		return true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	// Resolved interaction objects are dictionaries keyed by snowflake.
	if (kind == "channel_id" || kind == "guild_id" || kind == "message_id") && fields["id"] == nil && len(fields) > 0 {
		keyed := true
		for id := range fields {
			keyed = keyed && discordacl.ValidID(id)
		}
		if keyed {
			for _, value := range fields {
				if !g.walk(value, inherited, kind, depth+1) {
					return false
				}
			}
			return true
		}
	}
	s, ok := g.nodeScope(fields, inherited, kind)
	if !ok || !g.add(s) {
		return false
	}
	// Guild installation owner and message-forward origin are independent of
	// the channel that contains the interaction or forwarded message.
	if owners, exists := fields["authorizing_integration_owners"]; exists {
		var ids map[string]string
		if json.Unmarshal(owners, &ids) != nil {
			return false
		}
		if guild := ids["0"]; guild != "" && guild != s.GuildID && !g.add(discordacl.Scope{GuildID: guild}) {
			return false
		}
	}
	origin := s
	if ref := fields["message_reference"]; len(ref) != 0 && string(ref) != "null" {
		var ids map[string]json.RawMessage
		if json.Unmarshal(ref, &ids) != nil {
			return false
		}
		origin, ok = g.nodeScope(ids, s, "")
		if !ok || !g.add(origin) {
			return false
		}
		if snapshots := fields["message_snapshots"]; len(snapshots) > 0 && string(snapshots) != "null" && string(snapshots) != "[]" {
			channel, valid := evidenceID(ids["channel_id"])
			if !valid || channel == "" {
				return false
			}
		}
	} else if snapshots := fields["message_snapshots"]; len(snapshots) > 0 && string(snapshots) != "null" && string(snapshots) != "[]" {
		return false
	}
	for name, value := range fields {
		var childKind string
		parent := s
		switch name {
		case "guild_id", "channel_id", "message_reference", "authorizing_integration_owners":
			continue
		case "guild", "guilds", "source_guild", "serialized_source_guild":
			childKind = "guild_id"
		case "channel", "channels", "threads", "thread", "mention_channels":
			childKind = "channel_id"
			if kind == "guild_id" && (name == "channels" || name == "threads") {
				childKind = "guild_channel"
			}
		case "thread_member", "added_members":
			childKind = "thread_member"
		case "members":
			if kind == "thread_list" {
				childKind = "thread_member"
			}
		case "entitlements":
			childKind = "entitlement"
		case "messages", "message":
			childKind = "message_id"
		case "referenced_message", "message_snapshots":
			parent = origin
		case "channel_ids", "default_channel_ids", "exempt_channels":
			var ids []string
			if json.Unmarshal(value, &ids) != nil {
				return false
			}
			for _, id := range ids {
				if id != "" && !g.add(discordacl.Scope{GuildID: s.GuildID, ChannelID: id}) {
					return false
				}
			}
			continue
		case "parent_id":
			if kind != "channel_id" && kind != "guild_channel" {
				continue
			}
			fallthrough
		case "afk_channel_id", "system_channel_id", "rules_channel_id", "public_updates_channel_id", "widget_channel_id", "webhook_channel_id", "safety_alerts_channel_id":
			id, valid := evidenceID(value)
			if !valid || id != "" && !g.add(discordacl.Scope{GuildID: s.GuildID, ChannelID: id}) {
				return false
			}
			continue
		case "source_guild_id":
			id, valid := evidenceID(value)
			if !valid || id != "" && !g.add(discordacl.Scope{GuildID: id}) {
				return false
			}
			continue
		case "audit_log_entries", "changes", "private_channels":
			// Some of these objects have action-dependent, untyped resource
			// relationships that cannot be verified from the response.
			if string(value) != "null" && string(value) != "[]" {
				return false
			}
			continue
		}
		if !g.walk(value, parent, childKind, depth+1) {
			return false
		}
	}
	return true
}

func (b *Backend) eventDiscordEvidence(name string, raw []byte, source any, target *corewire.ResourceScope) []discordacl.Scope {
	s := selectorEvidence(target)
	if s.GuildID == "" || strings.HasPrefix(name, "ENTITLEMENT_") || strings.HasPrefix(name, "SUBSCRIPTION_") || name == "GUILD_AUDIT_LOG_ENTRY_CREATE" {
		return nil
	}
	g := scopeEvidence{backend: b}
	kind := ""
	switch name {
	case "CHANNEL_CREATE", "CHANNEL_UPDATE", "CHANNEL_DELETE", "THREAD_CREATE", "THREAD_UPDATE", "THREAD_DELETE":
		kind = "channel_id"
	case "GUILD_CREATE", "GUILD_UPDATE", "GUILD_DELETE":
		kind = "guild_id"
	case "THREAD_LIST_SYNC":
		kind = "thread_list"
	case "THREAD_MEMBER_UPDATE", "THREAD_MEMBERS_UPDATE":
		kind = "thread_member"
		var fields map[string]json.RawMessage
		var ok bool
		if json.Unmarshal(raw, &fields) != nil {
			return nil
		}
		if s, ok = g.nodeScope(fields, s, kind); !ok {
			return nil
		}
	}
	if !g.add(s) || !g.walk(raw, s, kind, 0) {
		return nil
	}
	snapshot, kind := eventBeforeSnapshot(source)
	if snapshot != nil {
		encoded, err := json.Marshal(snapshot)
		if err != nil || !g.walk(encoded, s, kind, 0) {
			return nil
		}
	}
	return g.scopes
}

func eventBeforeSnapshot(source any) (any, string) {
	switch v := source.(type) {
	case *discordgo.ChannelDelete:
		return v.BeforeDelete, "channel_id"
	case *discordgo.ChannelUpdate:
		return v.BeforeUpdate, "channel_id"
	case *discordgo.GuildDelete:
		return v.BeforeDelete, "guild_id"
	case *discordgo.GuildMemberRemove:
		return v.BeforeDelete, ""
	case *discordgo.GuildMemberUpdate:
		return v.BeforeUpdate, ""
	case *discordgo.GuildRoleDelete:
		return v.BeforeDelete, ""
	case *discordgo.GuildRoleUpdate:
		return v.BeforeUpdate, ""
	case *discordgo.MessageDelete:
		return v.BeforeDelete, "message_id"
	case *discordgo.MessageUpdate:
		return v.BeforeUpdate, "message_id"
	case *discordgo.ThreadDelete:
		return v.BeforeDelete, "channel_id"
	case *discordgo.ThreadUpdate:
		return v.BeforeUpdate, "channel_id"
	case *discordgo.VoiceStateUpdate:
		return v.BeforeUpdate, ""
	default:
		return nil, ""
	}
}
