package discordbackend

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/bwmarrin/discordgo"
	"github.com/thirdscam/chatanium/internal/backend/discord/discordhttp"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/proto"
)

var selectorKeys = map[string]bool{"guild_id": true, "channel_id": true, "user_id": true, "application_id": true, "role_id": true, "webhook_id": true, "command_id": true, "message_id": true, "interaction_id": true, "emoji_id": true, "scheduled_event_id": true, "rule_id": true, "sku_id": true, "entitlement_id": true, "subscription_id": true, "integration_id": true, "sticker_id": true}

func validateSelector(s *corewire.ResourceSelector) error {
	if s == nil {
		return invalid("DISCORD_SELECTOR_INVALID")
	}
	for k, v := range s.ResourceIds {
		if !selectorKeys[k] || !snowflake(v) {
			return invalid("DISCORD_SELECTOR_INVALID")
		}
	}
	return nil
}
func scope(ids map[string]string) *corewire.ResourceScope {
	return &corewire.ResourceScope{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{ResourceIds: ids}}}
}
func selectorContains(ceiling, target *corewire.ResourceScope) bool {
	if ceiling.GetAllResources() {
		return true
	}
	a, z := ceiling.GetSelector(), target.GetSelector()
	if a == nil || z == nil {
		return false
	}
	if len(a.ResourceIds) == 0 {
		return len(z.ResourceIds) == 0
	}
	for k, v := range a.ResourceIds {
		if z.ResourceIds[k] != v {
			return false
		}
	}
	return true
}
func grantAllows(g *corewire.CapabilityGrant, targets []*corewire.ResourceScope) bool {
	if g == nil {
		return false
	}
	for _, target := range targets {
		ok := false
		for _, c := range g.ResourceScopes {
			if selectorContains(c, target) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func (b *Backend) readJSON(ctx context.Context, owner runtime.InstancePrincipal, path string, out any) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	cache, _ := ctx.Value(relationshipCacheKey{}).(*relationshipCache)
	if cache != nil {
		if raw, ok := cache.entries[path]; ok {
			if json.Unmarshal(raw, out) != nil {
				return unavailable("DISCORD_RELATIONSHIP_UNAVAILABLE")
			}
			return nil
		}
	}
	life, done, e := b.beginWork(owner)
	if e != nil {
		return e
	}
	defer done()
	bounded, cancel := context.WithTimeout(ctx, b.config.HTTP.RequestDeadline)
	defer cancel()
	stop := context.AfterFunc(life, cancel)
	defer stop()
	route := path
	var query url.Values
	if pos := strings.IndexByte(path, '?'); pos >= 0 {
		route = path[:pos]
		query, e = url.ParseQuery(path[pos+1:])
		if e != nil {
			return invalid("DISCORD_RESOURCE_INVALID")
		}
	}
	response, e := b.transport.Do(bounded, discordhttp.Request{Owner: string(owner.InstanceID), Method: "GET", Path: "/api/v10" + route, Query: query, Bucket: route, Authorization: "Bot " + strings.TrimPrefix(b.config.BotToken, "Bot "), Locale: readLocale(ctx), MaxBodyBytes: b.config.RequestMaxBytes})
	if e != nil {
		return httpTransportError(e, response.Dispatched)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return discordHTTPError(response.StatusCode, response.Body)
	}
	if json.Unmarshal(response.Body, out) != nil {
		return unavailable("DISCORD_RELATIONSHIP_UNAVAILABLE")
	}
	if cache != nil && int64(len(response.Body)) <= cache.max-cache.bytes {
		cache.entries[path] = response.Body
		cache.bytes += int64(len(response.Body))
	}
	return nil
}

// Relationship lookups are host-only and readonly, after AwaitOperation but
// before the one complete Authorize. Claimed parent IDs are always verified.
func (b *Backend) resolveTarget(ctx context.Context, p runtime.InstancePrincipal, t ResourceTarget) (*corewire.ResourceScope, error) {
	if t.ApplicationID == "@me" {
		t.ApplicationID = b.config.ApplicationID
	}
	if t.Kind == "tag_id" {
		return b.resolveTag(ctx, p, t)
	}
	if t.Kind == "invite_id" || t.Kind == "template_code" {
		if t.ID == "" || len(t.ID) > 2048 || !utf8.ValidString(t.ID) {
			return nil, invalid("DISCORD_RESOURCE_INVALID")
		}
		var actual struct {
			Guild *struct {
				ID string `json:"id"`
			} `json:"guild"`
			Channel *struct {
				ID      string `json:"id"`
				GuildID string `json:"guild_id"`
			} `json:"channel"`
			SourceGuildID string `json:"source_guild_id"`
		}
		path := "/invites/" + url.PathEscape(t.ID)
		if t.Kind == "template_code" {
			path = "/guilds/templates/" + url.PathEscape(t.ID)
		}
		if e := b.readJSON(ctx, p, path, &actual); e != nil {
			return nil, e
		}
		ids := map[string]string{}
		if actual.Guild != nil {
			ids["guild_id"] = actual.Guild.ID
		}
		if actual.SourceGuildID != "" {
			ids["guild_id"] = actual.SourceGuildID
		}
		if actual.Channel != nil {
			ids["channel_id"] = actual.Channel.ID
			if actual.Channel.GuildID != "" {
				ids["guild_id"] = actual.Channel.GuildID
			}
		}
		if len(ids) == 0 {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		if e := validateSelector(&corewire.ResourceSelector{ResourceIds: ids}); e != nil {
			return nil, e
		}
		return scope(ids), nil
	}
	if t.Kind == "emoji_id" && !snowflake(t.ID) {
		if n := strings.LastIndexByte(t.ID, ':'); n >= 0 && snowflake(t.ID[n+1:]) {
			t.ID = t.ID[n+1:]
		} else if t.ChannelID != "" && t.ID != "" && utf8.ValidString(t.ID) {
			return nil, nil
		} else {
			return nil, invalid("DISCORD_RESOURCE_INVALID")
		}
	}
	if t.ID == "@me" {
		switch t.Kind {
		case "user_id":
			t.ID = b.config.BotUserID
		case "application_id":
			t.ID = b.config.ApplicationID
		default:
			return nil, invalid("DISCORD_RESOURCE_INVALID")
		}
	}
	if t.Kind == "guild_scheduled_event_id" || t.Kind == "event_id" {
		t.Kind = "scheduled_event_id"
	}
	if t.Kind == "target_id" || t.Kind == "overwrite_id" {
		if !snowflake(t.ID) || !snowflake(t.ChannelID) {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		channel, cached := b.channelSnapshot(t.ChannelID)
		if !cached || channel.PermissionOverwrites == nil {
			channel = &discordgo.Channel{}
			if e := b.readJSON(ctx, p, "/channels/"+t.ChannelID, channel); e != nil {
				return nil, e
			}
		}
		if t.GuildID != "" && t.GuildID != channel.GuildID {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
		t.GuildID = channel.GuildID
		kind := ""
		for _, o := range channel.PermissionOverwrites {
			if o != nil && o.ID == t.ID {
				if o.Type == discordgo.PermissionOverwriteTypeRole {
					kind = "role_id"
				} else if o.Type == discordgo.PermissionOverwriteTypeMember {
					kind = "user_id"
				}
				break
			}
		}
		if kind == "" {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		t.Kind = kind
	}
	if !selectorKeys[t.Kind] || !snowflake(t.ID) {
		return nil, invalid("DISCORD_RESOURCE_INVALID")
	}
	if t.Kind == "emoji_id" || t.Kind == "sticker_id" {
		return b.resolveAsset(ctx, p, t)
	}
	if t.Kind == "sku_id" {
		return b.resolveSKU(ctx, p, t.ID)
	}
	ids := map[string]string{t.Kind: t.ID}
	guild, channel, app := t.GuildID, t.ChannelID, t.ApplicationID
	if guild == "" && channel != "" && t.Kind != "channel_id" {
		parent, e := b.resolveTarget(ctx, p, ResourceTarget{Kind: "channel_id", ID: channel})
		if e != nil {
			return nil, e
		}
		guild = parent.GetSelector().ResourceIds["guild_id"]
	}
	switch t.Kind {
	case "channel_id":
		var actual struct {
			ID      string `json:"id"`
			GuildID string `json:"guild_id"`
		}
		if c, ok := b.channelFacts(t.ID); ok {
			actual.ID = c.ID
			actual.GuildID = c.GuildID
		} else if e := b.readJSON(ctx, p, "/channels/"+t.ID, &actual); e != nil {
			return nil, e
		}
		if actual.ID != t.ID || (guild != "" && guild != actual.GuildID) {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
		guild = actual.GuildID
	case "webhook_id":
		var actual struct {
			ID            string `json:"id"`
			GuildID       string `json:"guild_id"`
			ChannelID     string `json:"channel_id"`
			ApplicationID string `json:"application_id"`
		}
		if e := b.readJSON(ctx, p, "/webhooks/"+t.ID, &actual); e != nil {
			return nil, e
		}
		if actual.ID != t.ID || (guild != "" && guild != actual.GuildID) || (channel != "" && channel != actual.ChannelID) || (app != "" && actual.ApplicationID != "" && app != actual.ApplicationID) {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
		guild, channel = actual.GuildID, actual.ChannelID
		if actual.ApplicationID != "" {
			app = actual.ApplicationID
		}
	case "role_id":
		if !snowflake(guild) {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		var actual struct {
			ID string `json:"id"`
		}
		if e := b.readJSON(ctx, p, "/guilds/"+guild+"/roles/"+t.ID, &actual); e != nil {
			return nil, e
		}
		if actual.ID != t.ID {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
	case "command_id":
		if app == "" {
			app = b.config.ApplicationID
		}
		if app != b.config.ApplicationID {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
		path := "/applications/" + app
		if guild != "" {
			path += "/guilds/" + guild
		}
		var actual struct {
			ID            string `json:"id"`
			ApplicationID string `json:"application_id"`
			GuildID       string `json:"guild_id"`
		}
		if e := b.readJSON(ctx, p, path+"/commands/"+t.ID, &actual); e != nil {
			return nil, e
		}
		if actual.ID != t.ID || actual.ApplicationID != app || actual.GuildID != guild {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
	case "message_id":
		if channel == "" {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		var actual struct {
			ID        string `json:"id"`
			ChannelID string `json:"channel_id"`
		}
		if e := b.readJSON(ctx, p, "/channels/"+channel+"/messages/"+t.ID, &actual); e != nil {
			return nil, e
		}
		if actual.ID != t.ID || actual.ChannelID != channel {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
	case "scheduled_event_id", "rule_id":
		if !snowflake(guild) {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		segment := "scheduled-events"
		if t.Kind == "rule_id" {
			segment = "auto-moderation/rules"
		}
		var actual struct {
			ID      string `json:"id"`
			GuildID string `json:"guild_id"`
		}
		if e := b.readJSON(ctx, p, "/guilds/"+guild+"/"+segment+"/"+t.ID, &actual); e != nil {
			return nil, e
		}
		if actual.ID != t.ID || (actual.GuildID != "" && actual.GuildID != guild) {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
	case "integration_id":
		if !snowflake(guild) {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		var integrations []struct {
			ID string `json:"id"`
		}
		if e := b.readJSON(ctx, p, "/guilds/"+guild+"/integrations", &integrations); e != nil {
			return nil, e
		}
		found := false
		for _, i := range integrations {
			found = found || i.ID == t.ID
		}
		if !found {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
	case "application_id":
		if t.ID != b.config.ApplicationID {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
	}
	for k, v := range map[string]string{"guild_id": guild, "channel_id": channel, "application_id": app} {
		if v != "" {
			if !snowflake(v) {
				return nil, invalid("DISCORD_RESOURCE_INVALID")
			}
			ids[k] = v
		}
	}
	return scope(ids), nil
}
func (h *Helper) authorize(ctx context.Context, operation string, plan *RESTPlan) (_ *OperationContext, err error) {
	p, e := h.services.Authorizer.AwaitOperation(ctx, BackendID, operation)
	if e != nil {
		return nil, e
	}
	if p != h.services.Principal {
		return nil, denied("UNAUTHENTICATED_INSTANCE")
	}
	defer func() { err = h.scopeLookupError(ctx, err) }()
	lookup, cancel := context.WithTimeout(ctx, h.backend.config.HTTP.RequestDeadline)
	defer cancel()
	cache := &relationshipCache{entries: make(map[string][]byte), max: h.backend.config.HTTP.ResponseMaxBytes}
	lookup = context.WithValue(lookup, relationshipCacheKey{}, cache)
	if operation == "UserVoiceState" {
		if e := h.backend.observeVoiceResource(lookup, p, plan); e != nil {
			return nil, e
		}
	}
	for _, use := range plan.Credentials {
		if use.ThreadDestination != "" && operation != "WebhookThreadExecute" {
			return nil, denied("CREDENTIAL_CHANNEL_MISMATCH")
		}
	}
	targets, e := h.credentialTargets(lookup, plan, p)
	if e != nil {
		return nil, e
	}
	invokingUser := ""
	if len(plan.Credentials) == 1 && plan.Credentials[0].Purpose == "discord.interaction" && len(targets) == 1 {
		invokingUser = targets[0].GetSelector().ResourceIds["user_id"]
	}
	guild, channel, app := "", "", ""
	for _, t := range plan.Targets {
		switch t.Kind {
		case "guild_id":
			guild = t.ID
		case "channel_id":
			if channel == "" {
				channel = t.ID
			}
		case "application_id":
			app = t.ID
		}
	}
	commerce, e := h.backend.subscriptionResources(lookup, p, operation, plan)
	if e != nil {
		return nil, e
	}
	targets = append(targets, commerce...)
	replacementTargets, replacementRoot, e := h.memberRoleReplacementTargets(lookup, p, plan.RoleReplacement)
	if e != nil {
		return nil, e
	}
	targets = append(targets, replacementTargets...)
	for _, t := range plan.Targets {
		if (operation == "Subscription" || operation == "Subscriptions") && (t.Kind == "subscription_id" || t.Kind == "sku_id") {
			continue
		}
		if t.Kind == "target_id" || t.Kind == "overwrite_id" {
			typed := false
			for _, other := range plan.Targets {
				if other.ID == t.ID && (other.Kind == "role_id" || other.Kind == "user_id") {
					typed = true
					break
				}
			}
			if typed {
				continue
			}
		}
		if len(plan.Credentials) > 0 && (t.Kind == "webhook_id" || t.Kind == "message_id" || t.Kind == "interaction_id") {
			s, e := h.credentialTarget(plan, p, t)
			if e != nil {
				return nil, e
			}
			if s != nil {
				targets = append(targets, s)
			}
			continue
		}
		if t.GuildID == "" && t.Kind != "channel_id" {
			t.GuildID = guild
		}
		if t.ChannelID == "" && (t.Kind == "message_id" || t.Kind == "role_id" || t.Kind == "target_id" || t.Kind == "overwrite_id" || t.Kind == "tag_id" || t.Kind == "attachment_id") {
			t.ChannelID = channel
		}
		if t.ApplicationID == "" {
			t.ApplicationID = app
		}
		if t.Kind == "sku_id" {
			t.GuildID = ""
			t.ChannelID = ""
		}
		if t.Kind == "emoji_id" || t.Kind == "sticker_id" {
			if t.ChannelID == "" {
				t.ChannelID = channel
			}
			if t.ChannelID != "" || t.Kind == "sticker_id" {
				t.GuildID = ""
			}
			if !strings.HasPrefix(operation, "ApplicationEmoji") {
				t.ApplicationID = ""
			}
		}
		if t.Kind == "channel_id" && t.GuildID == "" && (strings.HasPrefix(operation, "Guild") || strings.HasPrefix(operation, "AutoModeration") || operation == "UserVoiceState") {
			t.GuildID = guild
		}
		if operation == "WebhookEdit" && t.Kind == "webhook_id" {
			t.ChannelID = ""
		}
		if t.Kind == "channel_id" {
			if e := h.validateCredentialChannel(lookup, p, plan, t.ID); e != nil {
				return nil, e
			}
		}
		if t.Kind == "attachment_id" {
			s, e := h.attachmentScope(lookup, p, plan, t)
			if e != nil {
				return nil, e
			}
			targets = append(targets, s)
			continue
		}
		s, e := h.backend.resolveTarget(lookup, p, t)
		if e != nil {
			return nil, e
		}
		if s != nil {
			if t.GuildID != "" && s.GetSelector().ResourceIds["guild_id"] != t.GuildID {
				return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
			}
			targets = append(targets, s)
			if t.Kind == "invite_id" || t.Kind == "template_code" {
				if g := s.GetSelector().ResourceIds["guild_id"]; g != "" {
					guild = g
				}
			}
		}
	}
	rootCount := len(plan.RequiredRoots)
	if replacementRoot != nil {
		rootCount++
	}
	required := make([]*corewire.ResourceScope, 0, rootCount)
	if replacementRoot != nil {
		required = append(required, replacementRoot)
	}
	for _, t := range plan.RequiredRoots {
		var s *corewire.ResourceScope
		if len(plan.Credentials) > 0 && (t.Kind == "webhook_id" || t.Kind == "message_id" || t.Kind == "interaction_id") {
			s, e = h.credentialTarget(plan, p, t)
		} else {
			s, e = h.backend.resolveTarget(lookup, p, t)
		}
		if e != nil {
			return nil, e
		}
		if s == nil {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		required = append(required, s)
	}
	targets = requiredScopes(targets, required)
	if len(targets) == 0 {
		if !plan.ResourceFree {
			return nil, denied("RESOURCE_SCOPE_DENIED")
		}
		targets = append(targets, scope(map[string]string{}))
	}
	// Crossposting fans out to undisclosed follower channels, and audit-log
	// entries contain arbitrary, action-dependent resource relationships.
	unscopable := plan.FullList || operation == "GuildAuditLog" || operation == "ChannelMessageCrosspost"
	// Starting a thread creates a new channel whose exact ID is not yet known.
	guildWide := operation == "ForumThreadStartComplex" || operation == "MessageThreadStartComplex" || operation == "ThreadStartComplex"
	if _, e = h.services.Authorizer.Authorize(ctx, runtime.AccessRequest{Backend: BackendID, Operation: operation, Scopes: targets, DiscordUnscopable: unscopable, DiscordGuildWide: guildWide}); e != nil {
		return nil, e
	}
	admission, e := runtime.AdmissionFromContext(ctx)
	if e != nil {
		return nil, e
	}
	grant, e := admission.CapabilityGrant()
	if e != nil {
		return nil, e
	}
	if plan.FullList {
		all := false
		for _, s := range grant.ResourceScopes {
			all = all || s.GetAllResources()
		}
		if !all {
			return nil, denied("RESOURCE_SCOPE_DENIED")
		}
	}
	return &OperationContext{Context: context.WithValue(admission.Context(), relationshipCacheKey{}, cache), Principal: p, Admission: admission, Scopes: targets, credentialDestinations: plan.credentialDestinations, invokingUser: invokingUser}, nil
}

// Before final scope admission a lookup's error could reveal the existence or
// state of an unrelated resource. Keep lookup diagnostics inside the host.
func (h *Helper) scopeLookupError(ctx context.Context, err error) error {
	if err != nil && ctx.Err() == nil && h.services.Authorizer.ManagedDiscordACL() {
		return denied("RESOURCE_SCOPE_DENIED")
	}
	return err
}

func (h *Helper) requireReadGrant(ctx context.Context, op string, targets []*corewire.ResourceScope) error {
	if _, e := h.services.Authorizer.AwaitOperation(ctx, BackendID, op); e != nil {
		return e
	}
	h.backend.mu.Lock()
	defer h.backend.mu.Unlock()
	i := h.backend.instances[h.services.Principal.InstanceID]
	if i == nil || i.grant == nil {
		return unavailable("DISCORD_INSTANCE_NOT_PREPARED")
	}
	for _, g := range i.grant.Capabilities {
		if g.Name == "discord.rest."+op && grantAllows(g, targets) {
			return nil
		}
	}
	return denied("REQUIRED_CAPABILITY_DENIED")
}
func copySelector(s *corewire.ResourceSelector) *corewire.ResourceSelector {
	if s == nil {
		return nil
	}
	return proto.Clone(s).(*corewire.ResourceSelector)
}

// Ancestor identifiers describe the same resolved resource, not an additional
// guild-wide operation. Preserve every distinct leaf while avoiding an implicit
// requirement to grant an entire guild merely to access one verified member.
func leafScopes(targets []*corewire.ResourceScope) []*corewire.ResourceScope {
	for n, target := range targets {
		if target == nil {
			continue
		}
		for m, other := range targets {
			if n == m || other == nil {
				continue
			}
			a, z := target.GetSelector().ResourceIds, other.GetSelector().ResourceIds
			if len(a) > len(z) || (len(a) == len(z) && m > n) {
				continue
			}
			matches := true
			for k, v := range a {
				if z[k] != v {
					matches = false
					break
				}
			}
			if matches {
				targets[n] = nil
				break
			}
		}
	}
	out := targets[:0]
	for _, target := range targets {
		if target != nil {
			out = append(out, target)
		}
	}
	return out
}

// Only relationship ancestors may be pruned. A real mutation root is required
// even if an allowed descendant happens to occur in its payload.
func requiredScopes(targets, roots []*corewire.ResourceScope) []*corewire.ResourceScope {
	targets = leafScopes(targets)
	for _, root := range roots {
		duplicate := false
		for _, target := range targets {
			if proto.Equal(root, target) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			targets = append(targets, root)
		}
	}
	return targets
}
func (h *Helper) memberRoleReplacementTargets(ctx context.Context, p runtime.InstancePrincipal, replacement *MemberRoleReplacement) ([]*corewire.ResourceScope, *corewire.ResourceScope, error) {
	if replacement == nil {
		return nil, nil, nil
	}
	userID := replacement.UserID
	if userID == "@me" {
		userID = h.backend.config.BotUserID
	}
	if !snowflake(replacement.GuildID) || !snowflake(userID) {
		return nil, nil, invalid("DISCORD_RESOURCE_INVALID")
	}
	var member struct {
		User *struct {
			ID string `json:"id"`
		} `json:"user"`
		GuildID string   `json:"guild_id"`
		Roles   []string `json:"roles"`
	}
	if e := h.backend.readJSON(ctx, p, "/guilds/"+replacement.GuildID+"/members/"+userID, &member); e != nil {
		return nil, nil, e
	}
	if member.User == nil || member.User.ID != userID || (member.GuildID != "" && member.GuildID != replacement.GuildID) || member.Roles == nil {
		return nil, nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
	}
	roles := make(map[string]bool, len(member.Roles)+len(replacement.RoleIDs))
	for _, id := range member.Roles {
		roles[id] = true
	}
	for _, id := range replacement.RoleIDs {
		roles[id] = true
	}
	targets := make([]*corewire.ResourceScope, 0, len(roles))
	for id := range roles {
		resolved, e := h.backend.resolveTarget(ctx, p, ResourceTarget{Kind: "role_id", ID: id, GuildID: replacement.GuildID})
		if e != nil {
			return nil, nil, e
		}
		targets = append(targets, resolved)
	}
	// GET + PATCH has no server-side version fence. Enumerating existing roles
	// alone cannot authorize concurrent assignment changes; require the guild
	// itself. Role-scoped callers must use the granular add/remove endpoints.
	return targets, scope(map[string]string{"guild_id": replacement.GuildID}), nil
}
