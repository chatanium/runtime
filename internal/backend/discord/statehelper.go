package discordbackend

import (
	"context"
	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/proto"
)

func (h *Helper) userChannelPermissions(ctx context.Context, request proto.Message) (_ proto.Message, err error) {
	req, ok := request.(*wire.UserChannelPermissionsRequest)
	if !ok || !snowflake(req.ChannelId) || (req.UserId != "@me" && !snowflake(req.UserId)) {
		return nil, invalid("DISCORD_PERMISSION_TARGET_INVALID")
	}
	user := req.UserId
	if user == "@me" {
		user = h.backend.config.BotUserID
	}
	if e := validateRequestOptions(req.Options); e != nil {
		return nil, e
	}
	if req.Options != nil {
		if req.Options.AuditLogReason != nil {
			return nil, invalid("DISCORD_AUDIT_REASON_UNSUPPORTED")
		}
		if req.Options.Locale != nil {
			locale := *req.Options.Locale
			if int64(len(locale)) > h.backend.config.HTTP.HeaderMaxBytes {
				return nil, invalid("DISCORD_REQUEST_LIMIT")
			}
			ctx = context.WithValue(ctx, readLocaleKey{}, &locale)
		}
	}
	if _, e := h.services.Authorizer.AwaitOperation(ctx, BackendID, "UserChannelPermissions"); e != nil {
		return nil, e
	}
	admitted := false
	defer func() {
		if !admitted {
			err = h.scopeLookupError(ctx, err)
		}
	}()
	lookup, cancel := context.WithTimeout(ctx, h.backend.config.HTTP.RequestDeadline)
	defer cancel()
	channel, cached := h.backend.channelSnapshot(req.ChannelId)
	if !cached {
		target, e := h.backend.resolveTarget(lookup, h.services.Principal, ResourceTarget{Kind: "channel_id", ID: req.ChannelId})
		if e != nil {
			return nil, e
		}
		if e = h.requireReadGrant(ctx, "Channel", []*corewire.ResourceScope{target}); e != nil {
			return nil, e
		}
		channel = &discordgo.Channel{}
		if e = h.backend.readJSON(lookup, h.services.Principal, "/channels/"+req.ChannelId, channel); e != nil {
			return nil, e
		}
	}
	if channel.ID != req.ChannelId || channel.GuildID == "" {
		return nil, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
	}
	guildID := channel.GuildID
	targets := []ResourceTarget{{Kind: "channel_id", ID: req.ChannelId, GuildID: guildID}, {Kind: "user_id", ID: user, GuildID: guildID, ChannelID: req.ChannelId}}
	overwriteChannelID := req.ChannelId
	switch channel.Type {
	case discordgo.ChannelTypeGuildNewsThread, discordgo.ChannelTypeGuildPublicThread, discordgo.ChannelTypeGuildPrivateThread:
		if !snowflake(channel.ParentID) {
			return nil, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
		}
		overwriteChannelID = channel.ParentID
		targets = append(targets, ResourceTarget{Kind: "channel_id", ID: channel.ParentID, GuildID: guildID})
		if parent, ok := h.backend.channelSnapshot(channel.ParentID); ok {
			if parent.GuildID != guildID {
				return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
			}
			channel.PermissionOverwrites = parent.PermissionOverwrites
		} else {
			channel.PermissionOverwrites = nil
		}
	}
	op, e := h.authorize(ctx, "UserChannelPermissions", &RESTPlan{Targets: targets})
	if e != nil {
		return nil, e
	}
	admitted = true
	defer op.Admission.Release()
	bounded, done, e := h.gatewayContext(op.Context, op.Principal)
	if e != nil {
		return nil, e
	}
	defer done()
	guild, cached := h.backend.guildSnapshot(guildID)
	if cached && guild.ID == guildID && guild.OwnerID == user {
		return &wire.UserChannelPermissionsResponse{Value: formatPermission(discordgo.PermissionAll)}, nil
	}
	if !cached || guild.OwnerID == "" || guild.Roles == nil {
		if e = h.requireReadGrant(ctx, "Guild", []*corewire.ResourceScope{scope(map[string]string{"guild_id": guildID})}); e != nil {
			return nil, e
		}
		guild = &discordgo.Guild{}
		if e = h.backend.readJSON(bounded, op.Principal, "/guilds/"+guildID, guild); e != nil {
			return nil, e
		}
	}
	if guild.ID != guildID || guild.OwnerID == "" {
		return nil, unavailable("DISCORD_PERMISSION_STATE_INCOMPLETE")
	}
	if user == guild.OwnerID {
		return &wire.UserChannelPermissionsResponse{Value: formatPermission(discordgo.PermissionAll)}, nil
	}
	member, cached := h.backend.memberSnapshot(guildID, user)
	if !cached {
		if e = h.requireReadGrant(ctx, "GuildMember", []*corewire.ResourceScope{scope(map[string]string{"guild_id": guildID, "user_id": user})}); e != nil {
			return nil, e
		}
		member = &discordgo.Member{}
		if e = h.backend.readJSON(bounded, op.Principal, "/guilds/"+guildID+"/members/"+user, member); e != nil {
			return nil, e
		}
	}
	permissions, e := calculatePermissions(guild, channel, member, user)
	if e == errPermissionOverwritesUnavailable {
		if e = h.requireReadGrant(ctx, "Channel", []*corewire.ResourceScope{scope(map[string]string{"guild_id": guildID, "channel_id": overwriteChannelID})}); e != nil {
			return nil, e
		}
		parent := &discordgo.Channel{}
		if e = h.backend.readJSON(bounded, op.Principal, "/channels/"+overwriteChannelID, parent); e != nil {
			return nil, e
		}
		if parent.ID != overwriteChannelID || parent.GuildID != guildID {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
		channel.PermissionOverwrites = parent.PermissionOverwrites
		permissions, e = calculatePermissions(guild, channel, member, user)
	}
	if e != nil {
		return nil, e
	}
	return &wire.UserChannelPermissionsResponse{Value: formatPermission(permissions)}, nil
}
