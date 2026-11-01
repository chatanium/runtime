package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
)

func noMentions() *discordgo.MessageAllowedMentions {
	return &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}
}
func option(name, description string, kind discordgo.ApplicationCommandOptionType, required bool) *discord.ApplicationCommandOptionView {
	return &discord.ApplicationCommandOptionView{Name: name, Description: description, Type: kind, Required: required}
}
func (b *GeneralBot) commandDefinitions(guild string) []*discord.ApplicationCommandView {
	contexts := []discordgo.InteractionContextType{discordgo.InteractionContextGuild}
	if guild == "" {
		contexts = []discordgo.InteractionContextType{discordgo.InteractionContextBotDM}
	}
	integrations := []discordgo.ApplicationIntegrationType{discordgo.ApplicationIntegrationGuildInstall}
	makeCommand := func(name, description string, permissions int64, options ...*discord.ApplicationCommandOptionView) *discord.ApplicationCommandView {
		sort.SliceStable(options, func(i, j int) bool { return options[i].Required && !options[j].Required })
		return &discord.ApplicationCommandView{Name: name, Type: discordgo.ChatApplicationCommand, Description: description, DefaultMemberPermissions: &discord.Nullable[int64]{Value: permissions}, Contexts: &contexts, IntegrationTypes: &integrations, Options: options}
	}
	out := []*discord.ApplicationCommandView{makeCommand("hello", "Ordinary isolated module response", 0)}
	if b.forms {
		search := option("topic", "Choose a form topic", discordgo.ApplicationCommandOptionString, false)
		search.Autocomplete = true
		out = append(out, makeCommand("form", "Open the button/select form", 0, search))
	}
	if b.attachments {
		out = append(out, makeCommand("attachment-demo", "Upload, reuse, retain, add index zero, clear and delete owned messages", 0))
	}
	for _, cmd := range out {
		cmd.DefaultMemberPermissions = nil
	}
	if guild == "" {
		return out
	}
	channel := option("channel", "An explicitly approved audit response channel", discordgo.ApplicationCommandOptionChannel, false)
	channel.ChannelTypes = []discordgo.ChannelType{discordgo.ChannelTypeGuildText}
	out = append(out, makeCommand("settings", "Read or save the persistent audit reply channel", discordgo.PermissionManageGuild|discordgo.PermissionViewAuditLogs, channel), makeCommand("permission-check", "Explicit zero default permissions: administrators only", 0))
	if b.management[guild] == nil {
		return out
	}
	user := func() *discord.ApplicationCommandOptionView {
		return option("user", "Operator-approved test member", discordgo.ApplicationCommandOptionUser, true)
	}
	role := func() *discord.ApplicationCommandOptionView {
		return option("role", "Operator-approved test role", discordgo.ApplicationCommandOptionRole, true)
	}
	reason := func() *discord.ApplicationCommandOptionView {
		return option("reason", "Audit reason (no secrets)", discordgo.ApplicationCommandOptionString, true)
	}
	start := len(out)
	out = append(out,
		makeCommand("member-info", "Inspect a member without inventing absent user fields", discordgo.PermissionManageRoles, user()),
		makeCommand("role-add", "Assign an approved test role", discordgo.PermissionManageRoles, user(), role(), reason()),
		makeCommand("role-remove", "Remove an approved test role", discordgo.PermissionManageRoles, user(), role(), reason()),
		makeCommand("channel-create", "Create an owned test text channel or category", discordgo.PermissionManageChannels, option("name", "Test channel name", discordgo.ApplicationCommandOptionString, true), option("kind", "text or category; omitted means text", discordgo.ApplicationCommandOptionString, false), option("parent", "Approved category", discordgo.ApplicationCommandOptionChannel, false), reason()),
		makeCommand("channel-edit", "Edit only a channel created by this module", discordgo.PermissionManageChannels, option("channel", "Owned channel", discordgo.ApplicationCommandOptionChannel, true), option("name", "New name; omitted leaves unchanged", discordgo.ApplicationCommandOptionString, false), option("topic", "Set topic; omitted leaves unchanged", discordgo.ApplicationCommandOptionString, false), option("clear-topic", "Explicitly clear topic", discordgo.ApplicationCommandOptionBoolean, false), option("slowmode", "Seconds; explicit zero clears slowmode", discordgo.ApplicationCommandOptionInteger, false), option("parent", "Set an approved parent category", discordgo.ApplicationCommandOptionChannel, false), option("clear-parent", "Explicitly clear parent", discordgo.ApplicationCommandOptionBoolean, false), option("clear-overwrites", "Explicit empty permission overwrite list", discordgo.ApplicationCommandOptionBoolean, false), reason()),
		makeCommand("channel-delete", "Delete only a channel created by this module", discordgo.PermissionManageChannels, option("channel", "Owned channel", discordgo.ApplicationCommandOptionChannel, true), reason()),
		makeCommand("ban", "Ban only an explicitly approved test user", discordgo.PermissionBanMembers, user(), reason()),
		makeCommand("unban", "Unban only an explicitly approved test user", discordgo.PermissionBanMembers, user(), reason()),
		makeCommand("timeout", "Set an approved member timeout", discordgo.PermissionModerateMembers, user(), option("seconds", "Finite approved timeout duration", discordgo.ApplicationCommandOptionInteger, true), reason()),
		makeCommand("clear-timeout", "Explicitly clear an approved member timeout", discordgo.PermissionModerateMembers, user(), reason()),
		makeCommand("audit-log", "Summarize audit changes while preserving exact JSON values", discordgo.PermissionViewAuditLogs),
	)
	n := start
	for _, command := range out[start:] {
		if b.management[guild][command.Name] {
			out[n] = command
			n++
		}
	}
	return out[:n]
}

type commandOptions map[string]*discordgo.ApplicationCommandInteractionDataOption

func optionsMap(options []*discordgo.ApplicationCommandInteractionDataOption) (commandOptions, error) {
	out := commandOptions{}
	for _, o := range options {
		if o == nil || o.Name == "" || out[o.Name] != nil {
			return nil, commandRejection("invalid or duplicate command option")
		}
		out[o.Name] = o
	}
	return out, nil
}
func (o commandOptions) text(name string, required bool) (string, error) {
	v := o[name]
	if v == nil {
		if required {
			return "", commandRejection("required option is absent")
		}
		return "", nil
	}
	switch v.Type {
	case discordgo.ApplicationCommandOptionString, discordgo.ApplicationCommandOptionUser, discordgo.ApplicationCommandOptionRole, discordgo.ApplicationCommandOptionChannel:
	default:
		return "", commandRejection("option kind is not a string or ID")
	}
	s, ok := v.Value.(string)
	if !ok || (required && s == "") {
		return "", commandRejection("invalid option value")
	}
	return s, nil
}
func (o commandOptions) integer(name string) (int64, bool, error) {
	v := o[name]
	if v == nil {
		return 0, false, nil
	}
	if v.Type != discordgo.ApplicationCommandOptionInteger {
		return 0, false, commandRejection("expected integer option")
	}
	n, ok := v.Value.(float64)
	if !ok || n != float64(int64(n)) || n > 9007199254740991 || n < -9007199254740991 {
		return 0, false, commandRejection("invalid exact integer option")
	}
	return int64(n), true, nil
}
func (o commandOptions) boolean(name string) (bool, error) {
	v := o[name]
	if v == nil {
		return false, nil
	}
	if v.Type != discordgo.ApplicationCommandOptionBoolean {
		return false, commandRejection("expected boolean option")
	}
	value, ok := v.Value.(bool)
	if !ok {
		return false, commandRejection("invalid boolean option")
	}
	return value, nil
}

func (b *GeneralBot) executeCommand(ctx context.Context, h *discord.InteractionHandle, name string, o commandOptions) (string, error) {
	i := h.Value
	switch name {
	case "hello":
		return "Hello from the ordinary v2 module. No media tools, voice or internet are required.", nil
	case "permission-check":
		return "Explicit zero command permission was retained; administrator permission was checked.", nil
	case "attachment-demo":
		if !b.attachments {
			return "", commandRejection("attachment feature is disabled")
		}
		return "Owned attachment upload/reuse/edit-clear sequence completed.", b.attachmentDemo(ctx, h)
	}
	g, ok := b.config.guild(i.GuildID)
	if !ok || i.Member == nil {
		return "", commandRejection("guild management is unavailable in this context")
	}
	if name == "settings" {
		channel, err := o.text("channel", false)
		if err != nil {
			return "", err
		}
		if channel != "" {
			if !contains(g.AuditChannelIDs, channel) {
				return "", commandRejection("audit channel is not operator approved")
			}
			if err = b.store.SetGuildSettings(ctx, g.GuildID, GuildSettings{AuditReplyChannelID: channel}); err != nil {
				return "", err
			}
		}
		v, present, err := b.store.GetGuildSettings(ctx, g.GuildID)
		if err != nil {
			return "", err
		}
		if !present {
			return "No audit reply channel has been saved.", nil
		}
		return "Saved audit reply channel: " + v.AuditReplyChannelID, nil
	}
	if !g.Moderation.Enabled || !b.management[g.GuildID][name] {
		return "", commandRejection("this management command is not enabled for approved resources")
	}
	user, err := o.text("user", false)
	if err != nil {
		return "", err
	}
	role, err := o.text("role", false)
	if err != nil {
		return "", err
	}
	reason, err := o.text("reason", name != "member-info" && name != "audit-log")
	if err != nil {
		return "", err
	}
	if len(reason) > 256 || strings.ContainsAny(reason, "\r\n") {
		return "", commandRejection("audit reason must be a single line of at most 256 bytes")
	}
	audit := discord.WithAuditLogReason(reason)
	switch name {
	case "member-info":
		if !contains(g.Moderation.ApprovedMemberIDs, user) {
			return "", commandRejection("member lookup target is not explicitly approved")
		}
		if err := b.scopedOperation("GuildMember", userScope(g.GuildID, user)); err != nil {
			return "", err
		}
		member, err := b.api.GuildMember(ctx, g.GuildID, user)
		if err != nil {
			return "", err
		}
		var roles []*discordgo.Role
		if allows(b.grants, rest("GuildRoles"), guildScope(g.GuildID)) {
			roles, err = b.api.GuildRoles(ctx, g.GuildID)
			if err != nil {
				return "", err
			}
		}
		if member == nil {
			return "", commandRejection("member lookup returned no member")
		}
		display := "user details absent"
		if member.User != nil {
			display = member.User.GlobalName
			if display == "" {
				display = member.User.Username
			}
		}
		names := []string{}
		for _, id := range member.Roles {
			label := id
			for _, r := range roles {
				if r != nil && r.ID == id {
					label = r.Name
					break
				}
			}
			names = append(names, label)
		}
		return truncate(fmt.Sprintf("Member %s (%s); nick=%s; roles=%s", user, display, member.Nick, strings.Join(names, ", ")), 1800), nil
	case "role-add", "role-remove":
		if !contains(g.Moderation.ApprovedMemberIDs, user) || !contains(g.Moderation.ApprovedRoleIDs, role) {
			return "", commandRejection("member or role is not explicitly approved")
		}
		operation := "GuildMemberRoleRemove"
		if name == "role-add" {
			operation = "GuildMemberRoleAdd"
		}
		if err = b.scopedOperation(operation, userScope(g.GuildID, user)); err != nil {
			return "", err
		}
		if err = b.scopedOperation(operation, roleScope(g.GuildID, role)); err != nil {
			return "", err
		}
		if name == "role-add" {
			err = b.api.GuildMemberRoleAdd(ctx, g.GuildID, user, role, audit)
		} else {
			err = b.api.GuildMemberRoleRemove(ctx, g.GuildID, user, role, audit)
		}
		if err != nil {
			return "", err
		}
		return "Approved role operation completed.", nil
	case "ban", "unban":
		if !contains(g.Moderation.ApprovedBanUserIDs, user) {
			return "", commandRejection("ban/unban target is not explicitly approved")
		}
		operation := "GuildBanDelete"
		if name == "ban" {
			operation = "GuildBanCreateWithReason"
		}
		if err = b.scopedOperation(operation, userScope(g.GuildID, user)); err != nil {
			return "", err
		}
		if name == "ban" {
			err = b.api.GuildBanCreateWithReason(ctx, g.GuildID, user, &reason, 0)
		} else {
			err = b.api.GuildBanDelete(ctx, g.GuildID, user, audit)
		}
		if err != nil {
			return "", err
		}
		return "Approved ban operation completed.", nil
	case "timeout", "clear-timeout":
		if !contains(g.Moderation.ApprovedTimeoutUserIDs, user) {
			return "", commandRejection("timeout target is not explicitly approved")
		}
		if err = b.scopedOperation("GuildMemberEdit", userScope(g.GuildID, user)); err != nil {
			return "", err
		}
		until := &discord.Nullable[time.Time]{Null: true}
		if name == "timeout" {
			seconds, present, e := o.integer("seconds")
			if e != nil {
				return "", e
			}
			if !present || seconds < 1 || seconds > int64(g.Moderation.MaxTimeoutSeconds) {
				return "", commandRejection("timeout duration exceeds the approved finite limit")
			}
			until = &discord.Nullable[time.Time]{Value: time.Now().UTC().Add(time.Duration(seconds) * time.Second)}
		}
		_, err = b.api.GuildMemberEdit(ctx, g.GuildID, user, &discord.GuildMemberParamsView{CommunicationDisabledUntil: until}, audit)
		if err != nil {
			return "", err
		}
		return "Approved timeout operation completed.", nil
	case "channel-create", "channel-edit", "channel-delete":
		return b.channelCommand(ctx, g, name, o, audit)
	case "audit-log":
		if err = b.scopedOperation("GuildAuditLog", guildScope(g.GuildID)); err != nil {
			return "", err
		}
		log, e := b.api.GuildAuditLog(ctx, g.GuildID, "", "", 0, 10)
		if e != nil {
			return "", e
		}
		if log == nil {
			return "", commandRejection("audit lookup returned no log")
		}
		lines := []string{}
		for _, entry := range log.AuditLogEntries {
			if entry == nil {
				continue
			}
			for _, change := range entry.Changes {
				if change == nil {
					continue
				}
				old, newValue := "<absent>", "<absent>"
				if change.OldValue != nil {
					old = string(change.OldValue.Raw)
				}
				if change.NewValue != nil {
					newValue = string(change.NewValue.Raw)
				}
				key := "<absent>"
				if change.Key != nil {
					key = string(*change.Key)
				} // Only non-personal, structured permission/position fields are displayed.
				if key == "permissions" || key == "position" || key == "rate_limit_per_user" {
					if !json.Valid([]byte(old)) && old != "<absent>" {
						return "", commandRejection("invalid audit JSON")
					}
					lines = append(lines, fmt.Sprintf("%s %s: %s -> %s", entry.ID, key, old, newValue))
				}
			}
		}
		text := truncate(strings.Join(lines, "\n"), 1800)
		if text == "" {
			text = "No safe permission/position changes in the latest 10 entries."
		}
		setting, present, e := b.store.GetGuildSettings(ctx, g.GuildID)
		if e != nil {
			return "", e
		}
		if present && setting.AuditReplyChannelID != "" {
			if !contains(g.AuditChannelIDs, setting.AuditReplyChannelID) {
				return "", commandRejection("saved audit channel is not approved")
			}
			if e = b.scopedOperation("ChannelMessageSendComplex", channelScope(g.GuildID, setting.AuditReplyChannelID)); e != nil {
				return "", e
			}
			if _, e = b.api.ChannelMessageSendComplex(ctx, setting.AuditReplyChannelID, &discord.MessageSendView{Content: text, AllowedMentions: noMentions(), Flags: discordgo.MessageFlagsSuppressNotifications}); e != nil {
				return "", e
			}
		}
		return text, nil
	default:
		return "", commandRejection("unsupported command")
	}
}
func truncate(value string, max int) string {
	r := []rune(value)
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return value
}
