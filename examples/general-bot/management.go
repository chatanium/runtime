package main

import (
	"context"
	"fmt"
)

var managementCommands = []string{"member-info", "role-add", "role-remove", "channel-create", "channel-edit", "channel-delete", "ban", "unban", "timeout", "clear-timeout", "audit-log"}

func userScope(guild, user string) map[string]string {
	return map[string]string{"guild_id": guild, "user_id": user}
}
func roleScope(guild, role string) map[string]string {
	return map[string]string{"guild_id": guild, "role_id": role}
}
func (b *GeneralBot) scopedOperation(operation string, ids map[string]string) error {
	if !allows(b.grants, rest(operation), ids) {
		return commandRejection("the operation is not granted for the selected resource")
	}
	return nil
}

// initializeManagement is the management part of INIT. Each optional command
// keeps its own actual-grant decision; unrelated absent capabilities never gate it.
func (b *GeneralBot) initializeManagement(ctx context.Context, g GuildConfig) error {
	owned, err := b.store.OwnedChannels(ctx, g.GuildID)
	if err != nil {
		return err
	}
	available := b.managementAvailability(g, owned)
	b.management[g.GuildID] = available
	if g.Moderation.Enabled {
		for _, command := range managementCommands {
			if !available[command] {
				b.disabled = append(b.disabled, fmt.Sprintf("management:%s:%s", g.GuildID, command))
			}
		}
	}
	return nil
}

func (b *GeneralBot) managementAvailability(g GuildConfig, owned []string) map[string]bool {
	available := make(map[string]bool, len(managementCommands))
	if !g.Moderation.Enabled {
		return available
	}
	anyUser := func(operation string, users []string) bool {
		for _, user := range users {
			if allows(b.grants, rest(operation), userScope(g.GuildID, user)) {
				return true
			}
		}
		return false
	}
	anyRole := func(operation string) bool {
		for _, role := range g.Moderation.ApprovedRoleIDs {
			if allows(b.grants, rest(operation), roleScope(g.GuildID, role)) {
				return true
			}
		}
		return false
	}
	available["member-info"] = anyUser("GuildMember", g.Moderation.ApprovedMemberIDs)
	for _, item := range []struct{ command, operation string }{{"role-add", "GuildMemberRoleAdd"}, {"role-remove", "GuildMemberRoleRemove"}} {
		// These are separate leaf resources in the backend's canonical request plan.
		available[item.command] = anyUser(item.operation, g.Moderation.ApprovedMemberIDs) && anyRole(item.operation)
	}
	available["ban"] = anyUser("GuildBanCreateWithReason", g.Moderation.ApprovedBanUserIDs)
	available["unban"] = anyUser("GuildBanDelete", g.Moderation.ApprovedBanUserIDs)
	available["timeout"] = anyUser("GuildMemberEdit", g.Moderation.ApprovedTimeoutUserIDs)
	available["clear-timeout"] = available["timeout"]
	// Creation's mutation root and an unfiltered audit query are genuinely guild-wide.
	available["channel-create"] = allows(b.grants, rest("GuildChannelCreateComplex"), guildScope(g.GuildID))
	available["audit-log"] = allows(b.grants, rest("GuildAuditLog"), guildScope(g.GuildID))
	for _, item := range []struct{ command, operation string }{{"channel-edit", "ChannelEdit"}, {"channel-delete", "ChannelDelete"}} {
		available[item.command] = allows(b.grants, rest(item.operation), guildScope(g.GuildID))
		for _, channel := range owned {
			if allows(b.grants, rest(item.operation), channelScope(g.GuildID, channel)) {
				available[item.command] = true
			}
		}
	}
	return available
}
