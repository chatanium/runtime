package discordbackend

import (
	"context"
	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

// observeVoiceResource is readonly relationship validation, not a raw join or a
// voice transport capability. A connected state's channel is itself scoped and
// Discord requires the host bot to have CONNECT on that destination.
func (b *Backend) observeVoiceResource(ctx context.Context, p runtime.InstancePrincipal, plan *RESTPlan) error {
	guild, user := "", ""
	for _, t := range plan.Targets {
		if t.Kind == "guild_id" {
			guild = t.ID
		}
		if t.Kind == "user_id" {
			user = t.ID
		}
	}
	if user == "@me" {
		user = b.config.BotUserID
	}
	if !snowflake(guild) || !snowflake(user) {
		return invalid("DISCORD_RESOURCE_INVALID")
	}
	var observed struct {
		GuildID   string `json:"guild_id"`
		UserID    string `json:"user_id"`
		ChannelID string `json:"channel_id"`
	}
	if e := b.readJSON(ctx, p, "/guilds/"+guild+"/voice-states/"+user, &observed); e != nil {
		return e
	}
	if observed.UserID != user || (observed.GuildID != "" && observed.GuildID != guild) {
		return denied("RESOURCE_RELATIONSHIP_DENIED")
	}
	if observed.ChannelID == "" {
		return nil
	}
	if !snowflake(observed.ChannelID) {
		return unavailable("DISCORD_RESPONSE_INVALID")
	}
	channel := &discordgo.Channel{}
	if e := b.readJSON(ctx, p, "/channels/"+observed.ChannelID, channel); e != nil {
		return e
	}
	if channel.GuildID != guild {
		return denied("RESOURCE_RELATIONSHIP_DENIED")
	}
	g := &discordgo.Guild{}
	if e := b.readJSON(ctx, p, "/guilds/"+guild, g); e != nil {
		return e
	}
	m := &discordgo.Member{}
	if e := b.readJSON(ctx, p, "/guilds/"+guild+"/members/"+b.config.BotUserID, m); e != nil {
		return e
	}
	permissions, e := calculatePermissions(g, channel, m, b.config.BotUserID)
	if e != nil {
		return e
	}
	if permissions&discordgo.PermissionVoiceConnect == 0 {
		return denied("DISCORD_CHANNEL_CONNECT_REQUIRED")
	}
	plan.Targets = append(plan.Targets, ResourceTarget{Kind: "channel_id", ID: channel.ID, GuildID: guild})
	return nil
}

var errPermissionOverwritesUnavailable = unavailable("DISCORD_PERMISSION_OVERWRITES_UNAVAILABLE")

// calculatePermissions accepts detached snapshots; no SDK network fallback or
// incomplete-role success is permitted. It follows DiscordGo's mask semantics.
func calculatePermissions(guild *discordgo.Guild, channel *discordgo.Channel, member *discordgo.Member, user string) (int64, error) {
	if member == nil || member.User == nil || member.User.ID != user || (member.GuildID != "" && guild != nil && member.GuildID != guild.ID) {
		return 0, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
	}
	if guild != nil {
		for _, r := range guild.Roles {
			if r != nil && r.Permissions < 0 {
				return 0, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
			}
		}
	}
	if guild == nil || channel == nil || member == nil || guild.ID == "" || guild.OwnerID == "" || guild.ID != channel.GuildID {
		return 0, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
	}
	if user == guild.OwnerID {
		return discordgo.PermissionAll, nil
	}
	roles := make(map[string]int64, len(guild.Roles))
	for _, r := range guild.Roles {
		if r != nil {
			roles[r.ID] = r.Permissions
		}
	}
	permissions, exists := roles[guild.ID]
	if !exists {
		return 0, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
	}
	set := make(map[string]bool, len(member.Roles))
	for _, id := range member.Roles {
		mask, ok := roles[id]
		if !ok {
			return 0, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
		}
		permissions |= mask
		set[id] = true
	}
	if permissions&discordgo.PermissionAdministrator != 0 {
		return permissions | discordgo.PermissionAll, nil
	}
	if channel.PermissionOverwrites == nil {
		return 0, errPermissionOverwritesUnavailable
	}
	for _, o := range channel.PermissionOverwrites {
		if o == nil || o.Allow < 0 || o.Deny < 0 {
			return 0, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
		}
	}
	for _, o := range channel.PermissionOverwrites {
		if o != nil && o.Type == discordgo.PermissionOverwriteTypeRole && o.ID == guild.ID {
			permissions = permissions&^o.Deny | o.Allow
			break
		}
	}
	var deny, allow int64
	for _, o := range channel.PermissionOverwrites {
		if o != nil && o.Type == discordgo.PermissionOverwriteTypeRole && set[o.ID] {
			deny |= o.Deny
			allow |= o.Allow
		}
	}
	permissions = permissions&^deny | allow
	for _, o := range channel.PermissionOverwrites {
		if o != nil && o.Type == discordgo.PermissionOverwriteTypeMember && o.ID == user {
			permissions = permissions&^o.Deny | o.Allow
			break
		}
	}
	if permissions&discordgo.PermissionAdministrator != 0 {
		permissions |= discordgo.PermissionAllChannel
	}
	return permissions, nil
}
