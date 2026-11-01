package discordbackend

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"golang.org/x/text/language"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func applyOptions(p *RESTPlan, operation string, reason *string, options *wire.RequestOptions) error {
	if err := validateRequestOptions(options); err != nil {
		return err
	}
	if reason != nil && !validHeaderMetadata(*reason) {
		return invalidRequest("invalid audit reason")
	}
	if options != nil {
		if reason != nil && options.AuditLogReason != nil && *reason != *options.AuditLogReason {
			return invalidRequest("conflicting audit reasons")
		}
		p.Request.AuditReason = options.AuditLogReason
		p.Request.Locale = options.Locale
	}
	if reason != nil {
		p.Request.AuditReason = reason
	}
	if p.Request.AuditReason != nil && !supportsAuditReason(operation) {
		return invalidRequest("audit reason not supported for operation")
	}
	return nil
}
func addTarget(p *RESTPlan, kind, id, guild, channel, application string) {
	if kind == "channel_id" {
		channel = id
	}
	if id == "" {
		return
	}
	target := ResourceTarget{Kind: kind, ID: id, GuildID: guild, ChannelID: channel, ApplicationID: application}
	if kind == "attachment_id" {
		for _, parent := range p.Targets {
			if parent.Kind == "message_id" {
				target.MessageID = parent.ID
				break
			}
		}
	}
	for _, previous := range p.Targets {
		if previous == target {
			return
		}
	}
	p.Targets = append(p.Targets, target)
}
func queryString(p *RESTPlan, key, value string) {
	if value != "" {
		p.Request.Query.Set(key, value)
	}
}
func queryBool(p *RESTPlan, key string, value bool) {
	if value {
		p.Request.Query.Set(key, "true")
	}
}
func queryLimit(p *RESTPlan, limit, max int64) error {
	// Nonpositive means unspecified in these source signatures. Do not substitute
	// a client default or retrieve extra pages on the caller's behalf.
	if limit > max {
		return numericRange("Limit")
	}
	if limit > 0 {
		p.Request.Query.Set("limit", strconv.FormatInt(limit, 10))
	}
	return nil
}
func queryTime(p *RESTPlan, key string, value *timestamppb.Timestamp) error {
	if value == nil {
		return nil
	}
	if value.CheckValid() != nil {
		return invalidRequest("invalid timestamp")
	}
	p.Request.Query.Set(key, value.AsTime().Format("2006-01-02T15:04:05Z07:00"))
	return nil
}

// plannerExtras contains source exceptions that are not expressible as a simple
// fixed route/body argument. It never performs IO or resolves an authority ref.
func plannerExtras(p *RESTPlan, operation string, req proto.Message, payload any) error {
	var err error
	switch r := req.(type) {
	case *wire.ApplicationRequest:
		if r.AppId != "@me" {
			return invalidRequest("only current bot application is supported")
		}
	case *wire.ApplicationCommandsRequest:
		p.Request.Query.Set("with_localizations", "true")
	case *wire.ChannelMessagesRequest:
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
		queryString(p, "before", r.BeforeId)
		queryString(p, "after", r.AfterId)
		queryString(p, "around", r.AroundId)
		cursors := 0
		for _, id := range []string{r.BeforeId, r.AfterId, r.AroundId} {
			if id != "" {
				cursors++
			}
		}
		if cursors > 1 {
			return invalidRequest("conflicting cursors")
		}
	case *wire.ChannelMessagesPinnedRequest:
		if err = queryLimit(p, r.Limit, 50); err != nil {
			return err
		}
		if err = queryTime(p, "before", r.Before); err != nil {
			return err
		}
	case *wire.GuildRequest:
		queryBool(p, "with_counts", r.WithCounts)
	case *wire.GuildBansRequest:
		if r.Limit < 0 {
			return invalidRequest("negative limit")
		}
		if err = queryLimit(p, r.Limit, 1000); err != nil {
			return err
		}
		queryString(p, "before", r.BeforeId)
		queryString(p, "after", r.AfterId)
	case *wire.GuildMembersRequest:
		if err = queryLimit(p, r.Limit, 1000); err != nil {
			return err
		}
		queryString(p, "after", r.After)
	case *wire.GuildMembersSearchRequest:
		p.Request.Query.Set("query", r.Query)
		if r.Limit > 1 {
			if err = queryLimit(p, r.Limit, 1000); err != nil {
				return err
			}
		}
	case *wire.GuildAuditLogRequest:
		queryString(p, "user_id", r.UserId)
		queryString(p, "before", r.BeforeId)
		if r.ActionType < 0 {
			return invalidRequest("negative action type")
		}
		if r.ActionType > 0 {
			p.Request.Query.Set("action_type", strconv.FormatInt(r.ActionType, 10))
		}
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
	case *wire.GuildBanCreateWithReasonRequest:
		if r.Days < 0 || r.Days > 7 {
			return numericRange("Days")
		}
		if r.Days > 0 {
			p.Request.Query.Set("delete_message_days", strconv.FormatInt(r.Days, 10))
		}
	case *wire.GuildPruneRequest:
		if r.Days == 0 {
			return invalidRequest("prune days must be positive")
		}
		payload = map[string]any{"days": r.Days}
	case *wire.GuildPruneCountRequest:
		if r.Days == 0 {
			return invalidRequest("prune days must be positive")
		}
		p.Request.Query.Set("days", strconv.FormatUint(uint64(r.Days), 10))
	case *wire.MessageReactionsRequest:
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
		queryString(p, "before", r.BeforeId)
		queryString(p, "after", r.AfterId)
	case *wire.UserGuildsRequest:
		p.FullList = true
		if err = queryLimit(p, r.Limit, 200); err != nil {
			return err
		}
		queryString(p, "before", r.BeforeId)
		queryString(p, "after", r.AfterId)
		queryBool(p, "with_counts", r.WithCounts)
	case *wire.GuildScheduledEventRequest:
		queryBool(p, "with_user_count", r.UserCount)
	case *wire.GuildScheduledEventsRequest:
		queryBool(p, "with_user_count", r.UserCount)
	case *wire.GuildScheduledEventUsersRequest:
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
		queryBool(p, "with_member", r.WithMember)
		queryString(p, "before", r.BeforeId)
		queryString(p, "after", r.AfterId)
	case *wire.ThreadMemberRequest:
		queryBool(p, "with_member", r.WithMember)
	case *wire.ThreadMembersRequest:
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
		queryBool(p, "with_member", r.WithMember)
		queryString(p, "after", r.AfterId)
	case *wire.ThreadsArchivedRequest:
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
		if err = queryTime(p, "before", r.Before); err != nil {
			return err
		}
	case *wire.ThreadsPrivateArchivedRequest:
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
		if err = queryTime(p, "before", r.Before); err != nil {
			return err
		}
	case *wire.ThreadsPrivateJoinedArchivedRequest:
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
		if err = queryTime(p, "before", r.Before); err != nil {
			return err
		}
	case *wire.InviteComplexRequest:
		queryString(p, "guild_scheduled_event_id", r.GuildScheduledEventId)
		queryBool(p, "with_counts", r.WithCounts)
		queryBool(p, "with_expiration", r.WithExpiration)
	case *wire.SubscriptionRequest:
		queryString(p, "user_id", r.UserId)
	case *wire.SubscriptionsRequest:
		queryString(p, "user_id", r.UserId)
		if err = queryLimit(p, r.Limit, 100); err != nil {
			return err
		}
		if err = queryTime(p, "before", r.Before); err != nil {
			return err
		}
		if err = queryTime(p, "after", r.After); err != nil {
			return err
		}
	case *wire.EntitlementsRequest:
		if r.FilterOptions != nil {
			f := r.FilterOptions
			queryString(p, "user_id", f.GetUserId())
			queryString(p, "guild_id", f.GetGuildId())
			queryBool(p, "exclude_ended", f.GetExcludeEnded())
			if f.SkuIds != nil {
				queryString(p, "sku_ids", strings.Join(f.SkuIds.Values, ","))
			}
			if err = queryLimit(p, f.GetLimit(), 100); err != nil {
				return err
			}
			if err = queryTime(p, "before", f.Before); err != nil {
				return err
			}
			if err = queryTime(p, "after", f.After); err != nil {
				return err
			}
			addTarget(p, "user_id", f.GetUserId(), f.GetGuildId(), "", r.AppId)
			addTarget(p, "guild_id", f.GetGuildId(), f.GetGuildId(), "", r.AppId)
			if f.SkuIds != nil {
				for _, id := range f.SkuIds.Values {
					addTarget(p, "sku_id", id, f.GetGuildId(), "", r.AppId)
				}
			}
		}
	case *wire.UserChannelCreateRequest:
		payload = map[string]any{"recipient_id": r.RecipientId}
	case *wire.UserUpdateRequest:
		payload = map[string]any{}
		for k, v := range map[string]string{"username": r.Username, "avatar": r.Avatar, "banner": r.Banner} {
			if v != "" {
				payload.(map[string]any)[k] = v
			}
		}
	case *wire.WebhookCreateRequest:
		payload = map[string]any{"name": r.Name}
		if r.Avatar != "" {
			payload.(map[string]any)["avatar"] = r.Avatar
		}
	case *wire.WebhookEditRequest:
		payload = map[string]any{}
		for k, v := range map[string]string{"name": r.Name, "avatar": r.Avatar, "channel_id": r.ChannelId} {
			if v != "" {
				payload.(map[string]any)[k] = v
			}
		}
	case *wire.WebhookEditWithTokenRequest:
		payload = map[string]any{}
		for k, v := range map[string]string{"name": r.Name, "avatar": r.Avatar} {
			if v != "" {
				payload.(map[string]any)[k] = v
			}
		}
		if err = credentialPath(p, r.Credential, false, false); err != nil {
			return err
		}
	case *wire.WebhookWithTokenRequest:
		if err = credentialPath(p, r.Credential, false, false); err != nil {
			return err
		}
	case *wire.WebhookDeleteWithTokenRequest:
		if err = credentialPath(p, r.Credential, false, false); err != nil {
			return err
		}
	case *wire.WebhookMessageRequest:
		if err = credentialPath(p, r.Credential, true, false); err != nil {
			return err
		}
	case *wire.WebhookMessageDeleteRequest:
		if err = credentialPath(p, r.Credential, true, false); err != nil {
			return err
		}
	case *wire.GuildMemberNicknameRequest:
		payload = map[string]any{"nick": r.Nickname}
		if r.UserId == "@me" {
			p.Request.Path += "/nick"
		}
	case *wire.ChannelNewsFollowRequest:
		payload = map[string]any{"webhook_channel_id": r.TargetId}
		addTarget(p, "channel_id", r.TargetId, "", "", "")
	case *wire.ChannelPermissionSetRequest:
		if r.TargetType < 0 || r.TargetType > 1 {
			return invalidRequest("invalid permission overwrite type")
		}
		if !decimalPermission(r.Allow) {
			return numericRange("Allow")
		}
		if !decimalPermission(r.Deny) {
			return numericRange("Deny")
		}
		payload = map[string]any{"id": r.TargetId, "type": r.TargetType, "allow": r.Allow, "deny": r.Deny}
		kind := "role_id"
		if r.TargetType == 1 {
			kind = "user_id"
		}
		addTarget(p, kind, r.TargetId, "", r.ChannelId, "")
	case *wire.ChannelInviteCreateRequest:
		if r.I.GetMaxAge() < 0 || r.I.GetMaxAge() > 604800 {
			return numericRange("I.MaxAge")
		}
		if r.I.GetMaxUses() < 0 || r.I.GetMaxUses() > 100 {
			return numericRange("I.MaxUses")
		}
		payload = map[string]any{"max_age": r.I.GetMaxAge(), "max_uses": r.I.GetMaxUses(), "temporary": r.I.GetTemporary(), "unique": r.I.GetUnique()}
	case *wire.ChannelMessagesBulkDeleteRequest:
		ids := r.Messages.GetValues()
		if len(ids) > 100 {
			return invalidRequest("too many messages")
		}
		for _, id := range ids {
			if id == "" {
				return invalidRequest("empty message ID")
			}
			addTarget(p, "message_id", id, "", r.ChannelId, "")
		}
		switch len(ids) {
		case 0:
			p.NoDispatch = true
			payload = nil
		case 1:
			p.Request.Method = "DELETE"
			p.Request.Path = "/api/v10/channels/" + url.PathEscape(r.ChannelId) + "/messages/" + url.PathEscape(ids[0])
			p.Request.Bucket = "DELETE /api/v10/channels/" + r.ChannelId + "/messages/{message_id}"
			payload = nil
		default:
			payload = map[string]any{"messages": ids}
		}
	case *wire.ChannelMessageSendComplexRequest:
		normalizeMessageEmbeds(payload.(map[string]any))
		p.Files = r.Data.Files.GetValues()
		if err = applyAttachments(payload.(map[string]any), p.Files, nil, false); err != nil {
			return err
		}
		if len(r.Data.StickerIds.GetValues()) > 3 {
			return invalidRequest("too many stickers")
		}
	case *wire.ChannelMessageEditComplexRequest:
		normalizeMessageEmbeds(payload.(map[string]any))
		addTarget(p, "channel_id", r.M.ChannelId, "", r.M.ChannelId, "")
		addTarget(p, "message_id", r.M.Id, "", r.M.ChannelId, "")
		p.Files = r.M.Files.GetValues()
		if err = applyAttachments(payload.(map[string]any), p.Files, r.M.Attachments, true); err != nil {
			return err
		}
	case *wire.WebhookThreadExecuteRequest:
		queryBool(p, "wait", r.Wait)
		queryString(p, "thread_id", r.ThreadId)
		p.Files = r.Data.Files.GetValues()
		if err = applyAttachments(payload.(map[string]any), p.Files, nil, false); err != nil {
			return err
		}
		if err = credentialPath(p, r.Credential, true, false); err != nil {
			return err
		}
		p.Credentials[len(p.Credentials)-1].ThreadDestination = r.ThreadId
	case *wire.WebhookMessageEditRequest:
		p.Files = r.Data.Files.GetValues()
		if err = applyAttachments(payload.(map[string]any), p.Files, r.Data.Attachments, true); err != nil {
			return err
		}
		if err = credentialPath(p, r.Credential, true, false); err != nil {
			return err
		}
	case *wire.InteractionRespondRequest:
		if r.Interaction == nil {
			return invalidRequest("interaction handle required")
		}
		for k, v := range map[string]string{"interaction_id": r.Interaction.GetId(), "application_id": r.Interaction.GetAppId(), "guild_id": r.Interaction.GetGuildId(), "channel_id": r.Interaction.GetChannelId()} {
			addTarget(p, k, v, r.Interaction.GetGuildId(), r.Interaction.GetChannelId(), r.Interaction.GetAppId())
		}
		if r.Interaction.Message != nil {
			addTarget(p, "message_id", r.Interaction.Message.GetId(), r.Interaction.GetGuildId(), r.Interaction.GetChannelId(), r.Interaction.GetAppId())
		}
		if err = credentialPath(p, r.Interaction.CredentialRef, true, true); err != nil {
			return err
		}
		if r.Resp.Data != nil {
			p.Files = r.Resp.Data.Files.GetValues()
			data := payload.(map[string]any)["data"].(map[string]any)
			if r.Resp.GetType() != 7 && r.Resp.Data.Attachments != nil {
				for _, entry := range r.Resp.Data.Attachments.Values {
					if _, existing := entry.Source.(*wire.AttachmentEditEntry_ExistingAttachmentId); existing {
						return invalidRequest("new response cannot retain existing attachment")
					}
				}
			}
			if err = applyAttachments(data, p.Files, r.Resp.Data.Attachments, r.Resp.GetType() == 7 || r.Resp.Data.Attachments != nil); err != nil {
				return err
			}
		}
	case *wire.ForumThreadStartComplexRequest:
		p.Files = r.MessageData.Files.GetValues()
		if err = applyAttachments(payload.(map[string]any)["message"].(map[string]any), p.Files, nil, false); err != nil {
			return err
		}
	case *wire.GuildMemberAddRequest:
		ref := r.Data.CredentialRef
		if ref == nil {
			return invalidRequest("join credential required")
		}
		if ref.Purpose != "discord.user.guilds.join" {
			return credentialMismatch()
		}
		body := payload.(map[string]any)
		p.Credentials = append(p.Credentials, CredentialUse{Ref: ref, Purpose: "discord.user.guilds.join", Resource: ref.ResourceScope, Apply: func(secret string) error {
			body["access_token"] = secret
			encoded, err := json.Marshal(body)
			if err != nil {
				return invalidRequest("invalid body")
			}
			p.Request.JSON = encoded
			return nil
		}})
		if ref.ResourceScope != nil {
			addTarget(p, "application_id", ref.ResourceScope.ResourceIds["application_id"], r.GuildId, "", ref.ResourceScope.ResourceIds["application_id"])
		}
	case *wire.StageInstanceCreateRequest:
		addTarget(p, "channel_id", r.Data.GetChannelId(), "", r.Data.GetChannelId(), "")
	case *wire.PollAnswerVotersRequest:
		if r.AnswerId < 1 {
			return invalidRequest("invalid poll answer")
		}
	case *wire.GuildRoleReorderRequest:
		for _, role := range r.Roles.Values {
			addTarget(p, "role_id", role.GetId(), r.GuildId, "", "")
		}
	case *wire.GuildChannelsReorderRequest:
		for _, channel := range r.Channels.Values {
			addTarget(p, "channel_id", channel.GetId(), r.GuildId, channel.GetId(), "")
		}
	}
	switch operation {
	case "Gateway", "GatewayBot", "VoiceRegions", "UserUpdate", "UserGuilds":
		p.ResourceFree = true
	}
	if payload != nil {
		if err = validateBody(operation, payload); err != nil {
			return err
		}
		guild, channel, application := "", "", ""
		for _, target := range p.Targets {
			switch target.Kind {
			case "guild_id":
				guild = target.ID
			case "channel_id":
				channel = target.ID
			case "application_id":
				application = target.ID
			}
		}
		rootKind := ""
		if operation == "AutoModerationRuleCreate" || operation == "AutoModerationRuleEdit" {
			rootKind = "rule_id"
		}
		addNestedTargets(p, payload, rootKind, guild, channel, application)
		collectRoutes(p, payload, 0)
		p.Request.JSON, err = json.Marshal(payload)
		if err != nil {
			return invalidRequest("invalid JSON body")
		}
	}
	return commandPlan(p, operation, req)
}

func credentialPath(p *RESTPlan, ref *corewire.CredentialRef, allowInteraction, initial bool) error {
	if ref == nil {
		return invalidRequest("credential required")
	}
	if (ref.Purpose != "discord.webhook" && !(allowInteraction && ref.Purpose == "discord.interaction")) || (initial && ref.Purpose != "discord.interaction") {
		return credentialMismatch()
	}
	template := p.Request.Path
	p.Credentials = append(p.Credentials, CredentialUse{Ref: ref, Purpose: ref.Purpose, Resource: ref.ResourceScope, InitialCallback: initial, Apply: func(secret string) error {
		if secret == "" {
			return invalidRequest("empty credential")
		}
		p.Request.Path = strings.ReplaceAll(template, "{secret}", url.PathEscape(secret))
		return nil
	}})
	return nil
}

func commandPlan(p *RESTPlan, operation string, req proto.Message) error {
	var commands []*wire.ApplicationCommand
	var mutation *CommandMutation
	switch r := req.(type) {
	case *wire.ApplicationCommandCreateRequest:
		mutation = &CommandMutation{ApplicationID: r.AppId, GuildID: r.GuildId}
		commands = []*wire.ApplicationCommand{r.Cmd}
	case *wire.ApplicationCommandEditRequest:
		mutation = &CommandMutation{ApplicationID: r.AppId, GuildID: r.GuildId, CommandID: r.CmdId}
		commands = []*wire.ApplicationCommand{r.Cmd}
	case *wire.ApplicationCommandDeleteRequest:
		mutation = &CommandMutation{ApplicationID: r.AppId, GuildID: r.GuildId, CommandID: r.CmdId, Delete: true}
	case *wire.ApplicationCommandBulkOverwriteRequest:
		mutation = &CommandMutation{ApplicationID: r.AppId, GuildID: r.GuildId, Bulk: true}
		commands = r.Commands.GetValues()
	}
	if mutation == nil {
		return nil
	}
	for _, c := range commands {
		if c == nil {
			return invalidRequest("command required")
		}
		typ := c.GetType()
		if typ == 0 && operation != "ApplicationCommandEdit" {
			typ = 1
		}
		mutation.Commands = append(mutation.Commands, CommandKey{Type: int32(typ), Name: c.GetName()})
	}
	p.Command = mutation
	return nil
}

// addNestedTargets walks only the static codec's reviewed Discord JSON keys.
// It reports resources, never authorizes their caller-claimed relationships.
func addNestedTargets(p *RESTPlan, value any, kind, guild, channel, application string) {
	switch v := value.(type) {
	case map[string]any:
		stringAt := func(k string) string { s, _ := v[k].(string); return s }
		if id := stringAt("guild_id"); id != "" {
			guild = id
		}
		if id := stringAt("channel_id"); id != "" {
			channel = id
		}
		if id := stringAt("application_id"); id != "" {
			application = id
		}
		if kind == "overwrite_id" {
			switch v["type"] {
			case int64(0):
				kind = "role_id"
			case int64(1):
				kind = "user_id"
			}
		}
		if kind == "select_default" {
			switch stringAt("type") {
			case "user":
				kind = "user_id"
			case "role":
				kind = "role_id"
			case "channel":
				kind = "channel_id"
			default:
				kind = ""
			}
		}
		if id := stringAt("id"); id != "" && kind != "" {
			addTarget(p, kind, id, guild, channel, application)
		}
		for key, item := range v {
			targetKind := ""
			switch key {
			case "guild_id":
				targetKind = "guild_id"
			case "channel_id", "parent_id", "afk_channel_id", "system_channel_id", "rules_channel_id", "public_updates_channel_id", "widget_channel_id", "webhook_channel_id":
				targetKind = "channel_id"
			case "user_id", "owner_id", "recipient_id":
				targetKind = "user_id"
			case "role_id":
				targetKind = "role_id"
			case "application_id":
				targetKind = "application_id"
			case "message_id":
				targetKind = "message_id"
			case "emoji_id":
				targetKind = "emoji_id"
			case "sku_id":
				targetKind = "sku_id"
			}
			if key == "owner_id" {
				if v["owner_type"] == int64(1) {
					targetKind = "guild_id"
				}
			}
			if id, ok := item.(string); ok && targetKind != "" {
				addTarget(p, targetKind, id, guild, channel, application)
			}
			childKind := ""
			switch key {
			case "roles", "role_ids", "exempt_roles":
				childKind = "role_id"
			case "channels", "exempt_channels", "channel_ids", "default_channel_ids":
				childKind = "channel_id"
			case "users", "user_ids":
				childKind = "user_id"
			case "messages":
				childKind = "message_id"
			case "stickers", "sticker_ids":
				childKind = "sticker_id"
			case "emoji":
				childKind = "emoji_id"
			case "default_values":
				childKind = "select_default"
			}
			if key == "applied_tags" || key == "available_tags" {
				childKind = "tag_id"
			}
			if key == "attachments" {
				childKind = "attachment_id"
			}
			if key == "permission_overwrites" {
				childKind = "overwrite_id"
			}
			addNestedTargets(p, item, childKind, guild, channel, application)
		}
	case []any:
		for _, item := range v {
			if id, ok := item.(string); ok && kind != "" {
				addTarget(p, kind, id, guild, channel, application)
			} else {
				addNestedTargets(p, item, kind, guild, channel, application)
			}
		}
	case []string:
		for _, id := range v {
			if kind != "" {
				addTarget(p, kind, id, guild, channel, application)
			}
		}
	}
}
func collectRoutes(p *RESTPlan, value any, parent int32) {
	switch v := value.(type) {
	case map[string]any:
		typ := int32(0)
		switch n := v["type"].(type) {
		case int64:
			typ = int32(n)
		case uint32:
			typ = int32(n)
		case uint64:
			typ = int32(n)
		case int:
			typ = int32(n)
		}
		if id, ok := v["custom_id"].(string); ok && id != "" {
			kind := int32(1)
			callback := typ == 2 || typ == 3 || typ == 5 || typ == 6 || typ == 7 || typ == 8
			if _, modal := v["title"]; modal {
				kind = 2
				callback = true
			}
			if typ == 2 {
				style := int64(0)
				switch n := v["style"].(type) {
				case uint64:
					style = int64(n)
				case int64:
					style = n
				case uint32:
					style = int64(n)
				case int:
					style = int64(n)
				}
				if style == 5 || style == 6 {
					callback = false
				}
			}
			if callback {
				p.Routes = append(p.Routes, RouteKey{Kind: kind, CustomID: id})
			}
		}
		for _, child := range v {
			collectRoutes(p, child, typ)
		}
	case []any:
		for _, child := range v {
			collectRoutes(p, child, parent)
		}
	}
}

func validateBody(operation string, payload any) error {
	// Bounds historically enforced by the SDK must not disappear when avoiding
	// its uncancellable REST transport. Discord retains final semantic validation.
	if body, ok := payload.(map[string]any); ok {
		if level, ok := body["verification_level"].(int64); ok && (level < 0 || level > 4) {
			return invalidRequest("verification level out of range")
		}
		if operation == "GuildRoleEdit" || operation == "GuildRoleCreate" {
			if permissions, ok := body["permissions"].(string); ok && !decimalPermission(permissions) {
				return invalidRequest("invalid permissions")
			}
		}
	}
	return nil
}

type restProjectionKey struct{}
type restProjectionMetadata struct {
	GuildID string
	NoWait  bool
}

func withRESTProjectionContext(ctx context.Context, p *RESTPlan) context.Context {
	metadata := restProjectionMetadata{NoWait: !p.RequireResponse}
	for _, target := range p.Targets {
		if target.Kind == "guild_id" {
			metadata.GuildID = target.ID
			break
		}
	}
	return context.WithValue(ctx, restProjectionKey{}, metadata)
}
func projectionMetadata(ctx context.Context) restProjectionMetadata {
	metadata, _ := ctx.Value(restProjectionKey{}).(restProjectionMetadata)
	return metadata
}

func normalizeMessageEmbeds(body map[string]any) {
	if embeds, ok := body["embeds"].([]any); ok {
		for _, item := range embeds {
			if embed, ok := item.(map[string]any); ok {
				if kind, present := embed["type"]; !present || kind == "" {
					embed["type"] = "rich"
				}
			}
		}
	}
}

// Endpoint support is explicit: accepting a reason on an unrelated read/send
// would silently discard caller intent. Source: Discord's resource docs,
// https://docs.discord.com/developers/resources/{guild,channel,message,emoji,
// webhook,invite,auto-moderation,guild-scheduled-event,stage-instance}.md
func supportsAuditReason(operation string) bool {
	switch operation {
	case "GuildEdit", "GuildChannelCreateComplex", "GuildMemberEdit", "GuildMemberNickname",
		"GuildMemberRoleAdd", "GuildMemberRoleRemove", "GuildMemberDeleteWithReason",
		"GuildBanCreateWithReason", "GuildBanDelete", "GuildRoleCreate", "GuildRoleReorder",
		"GuildRoleEdit", "GuildRoleDelete", "GuildPrune", "GuildIntegrationDelete", "GuildEmbedEdit",
		"GuildOnboardingEdit", "GuildEmojiCreate", "GuildEmojiEdit", "GuildEmojiDelete",
		"ChannelEdit", "ChannelDelete", "ChannelPermissionSet", "ChannelPermissionDelete",
		"ChannelInviteCreate", "ChannelNewsFollow", "ChannelMessageDelete", "ChannelMessagesBulkDelete",
		"ChannelMessagePin", "ChannelMessageUnpin", "ThreadStartComplex", "MessageThreadStartComplex",
		"ForumThreadStartComplex", "WebhookCreate", "WebhookEdit", "WebhookEditWithToken",
		"WebhookDelete", "WebhookDeleteWithToken", "InviteDelete", "StageInstanceCreate",
		"StageInstanceEdit", "StageInstanceDelete", "AutoModerationRuleCreate", "AutoModerationRuleEdit",
		"AutoModerationRuleDelete", "GuildScheduledEventCreate", "GuildScheduledEventEdit":
		return true
	default:
		return false
	}
}

func publicGatewayURL(value string) bool {
	target, err := url.Parse(value)
	return err == nil && target.Scheme == "wss" && target.Host == "gateway.discord.gg" && target.User == nil && target.RawQuery == "" && target.Fragment == "" && (target.Path == "" || target.Path == "/")
}

// validateRequestOptions is shared with the state helper's authorized readonly
// fetch path. It validates syntax without normalizing the caller's locale or
// restricting it to today's registry; transport applies the operator byte bound.
func validateRequestOptions(options *wire.RequestOptions) error {
	if options == nil {
		return nil
	}
	if len(options.ProtoReflect().GetUnknown()) != 0 {
		return invalidRequest("unsupported options")
	}
	if options.AuditLogReason != nil && !validHeaderMetadata(*options.AuditLogReason) {
		return invalidRequest("invalid audit reason")
	}
	if options.Locale != nil {
		locale := *options.Locale
		if locale == "" || !validHeaderMetadata(locale) {
			return invalidRequest("invalid locale")
		}
		// Parse also accepts Unicode locale identifier conveniences such as "_".
		// Only the BCP47 header alphabet is admitted here.
		for _, c := range locale {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return invalidRequest("invalid locale")
			}
		}
		if _, err := language.Parse(locale); err != nil {
			if _, unknownValue := err.(language.ValueError); !unknownValue {
				return invalidRequest("invalid locale")
			}
		}
	}
	return nil
}
func validHeaderMetadata(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if c == 0x7f || (c < 0x20 && c != '\t') {
			return false
		}
	}
	return true
}

// Required mutation roots are independent of relationship ancestors. A payload
// reference must never make the actual mutated guild/channel disappear during
// leaf-scope reduction. Copy the operation's declared target and its parents.
func requireMutationRoot(p *RESTPlan, kind, id string) error {
	if id == "" {
		return invalidRequest("mutation target is required")
	}
	for _, target := range p.Targets {
		if target.Kind != kind || target.ID != id {
			continue
		}
		// Thread-member methods address user membership in the selected thread.
		// Guild-member roots instead stay guild+user: a move destination is only
		// a relationship and must not qualify that member's protected root.
		if target.Kind == "user_id" && target.GuildID == "" && target.ChannelID == "" && len(p.Credentials) == 0 {
			for _, parent := range p.Targets {
				if parent.Kind == "channel_id" {
					target.ChannelID = parent.ID
					target.GuildID = parent.GuildID
					break
				}
			}
		}
		for _, previous := range p.RequiredRoots {
			if previous == target {
				return nil
			}
		}
		p.RequiredRoots = append(p.RequiredRoots, target)
		return nil
	}
	return invalidRequest("mutation target is missing")
}
