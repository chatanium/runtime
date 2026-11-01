package main

import (
	"errors"
	"fmt"
	"strconv"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
)

type GeneralExampleConfig struct {
	ApplicationID           string        `json:"application_id"`
	Guilds                  []GuildConfig `json:"guilds"`
	AllowDM                 bool          `json:"allow_dm"`
	EnableMessages          bool          `json:"enable_messages"`
	EnableForms             bool          `json:"enable_forms"`
	EnableAttachments       bool          `json:"enable_attachments"`
	OperationTimeoutSeconds int           `json:"operation_timeout_seconds"`
}
type GuildConfig struct {
	GuildID         string           `json:"guild_id"`
	TextChannelIDs  []string         `json:"text_channel_ids"`
	AuditChannelIDs []string         `json:"audit_channel_ids"`
	Moderation      ModerationConfig `json:"moderation"`
}
type ModerationConfig struct {
	Enabled                bool     `json:"enabled"`
	ApprovedMemberIDs      []string `json:"approved_member_ids"`
	ApprovedRoleIDs        []string `json:"approved_role_ids"`
	ApprovedBanUserIDs     []string `json:"approved_ban_user_ids"`
	ApprovedTimeoutUserIDs []string `json:"approved_timeout_user_ids"`
	AllowedParentIDs       []string `json:"allowed_parent_ids"`
	MaxTimeoutSeconds      int      `json:"max_timeout_seconds"`
}

func snowflake(id string) bool {
	if id == "" || id[0] == '0' {
		return false
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(id, 10, 64)
	return err == nil
}
func contains(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func validIDs(ids []string, max int) bool {
	if len(ids) > max {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !snowflake(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func (c GeneralExampleConfig) validate() error {
	if !snowflake(c.ApplicationID) || len(c.Guilds) > 32 || c.OperationTimeoutSeconds < 1 || c.OperationTimeoutSeconds > 120 {
		return errors.New("invalid application, guild count or operation deadline")
	}
	if len(c.Guilds) == 0 && !c.AllowDM {
		return errors.New("at least one guild or DM context must be enabled")
	}
	seen := map[string]bool{}
	channels := map[string]bool{}
	for _, g := range c.Guilds {
		m := g.Moderation
		if !snowflake(g.GuildID) || seen[g.GuildID] || len(g.TextChannelIDs) == 0 || !validIDs(g.TextChannelIDs, 64) || !validIDs(g.AuditChannelIDs, 64) || !validIDs(m.ApprovedMemberIDs, 64) || !validIDs(m.ApprovedRoleIDs, 64) || !validIDs(m.ApprovedBanUserIDs, 64) || !validIDs(m.ApprovedTimeoutUserIDs, 64) || !validIDs(m.AllowedParentIDs, 64) {
			return errors.New("invalid or duplicate configured resource scope")
		}
		seen[g.GuildID] = true
		for _, id := range g.TextChannelIDs {
			if channels[id] {
				return errors.New("channel assigned to multiple guilds")
			}
			channels[id] = true
		}
		for _, id := range g.AuditChannelIDs {
			if !contains(g.TextChannelIDs, id) {
				return errors.New("audit channels must be approved text channels")
			}
		}
		if m.Enabled && (m.MaxTimeoutSeconds < 1 || m.MaxTimeoutSeconds > 2419200) {
			return errors.New("enabled moderation requires finite timeout maximum at most 28 days")
		}
	}
	return nil
}
func (c GeneralExampleConfig) guild(id string) (GuildConfig, bool) {
	for _, g := range c.Guilds {
		if g.GuildID == id {
			return g, true
		}
	}
	return GuildConfig{}, false
}
func (c GeneralExampleConfig) channel(guild, channel string) bool {
	g, ok := c.guild(guild)
	return ok && contains(g.TextChannelIDs, channel)
}

// This checks the immutable actual grant, never the manifest's requested ceiling.
func allows(grants []*corewire.CapabilityGrant, name string, ids map[string]string) bool {
	for _, g := range grants {
		if g == nil || g.Name != name {
			continue
		}
		for _, s := range g.ResourceScopes {
			if s.GetAllResources() {
				return true
			}
			selector := s.GetSelector()
			if selector == nil {
				continue
			}
			if len(selector.ResourceIds) == 0 {
				if len(ids) == 0 {
					return true
				}
				continue
			}
			match := true
			for k, v := range selector.ResourceIds {
				if ids[k] != v {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}
func require(grants []*corewire.CapabilityGrant, name string, ids map[string]string) error {
	if !allows(grants, name, ids) {
		return fmt.Errorf("required scoped capability unavailable: %s", name)
	}
	return nil
}
func rest(name string) string { return "discord.rest." + name }
func appScope(app, guild string) map[string]string {
	ids := map[string]string{"application_id": app}
	if guild != "" {
		ids["guild_id"] = guild
	}
	return ids
}
func guildScope(guild string) map[string]string { return map[string]string{"guild_id": guild} }
func channelScope(guild, channel string) map[string]string {
	ids := map[string]string{"channel_id": channel}
	if guild != "" {
		ids["guild_id"] = guild
	}
	return ids
}

// compatibleGrant is only a preflight existence check for future event/credential
// resources. Unknown-yet IDs (for example the authenticated caller or interaction)
// may add constraints; every already known ID must agree. Never use this to
// authorize a mutation: its complete target is checked with allows and by host.
func compatibleGrant(grants []*corewire.CapabilityGrant, name string, known map[string]string) bool {
	for _, grant := range grants {
		if grant == nil || grant.Name != name {
			continue
		}
		for _, scope := range grant.ResourceScopes {
			if scope.GetAllResources() {
				return true
			}
			selector := scope.GetSelector()
			if selector == nil || len(selector.ResourceIds) == 0 {
				continue
			}
			compatible := true
			for key, value := range selector.ResourceIds {
				if actual, knownKey := known[key]; knownKey && actual != value {
					compatible = false
					break
				}
			}
			if compatible {
				return true
			}
		}
	}
	return false
}
