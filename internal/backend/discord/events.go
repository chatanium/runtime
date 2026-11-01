package discordbackend

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// gatewayIngressFailed receives a fixed SDK sentinel, never a raw frame/error.
// It is called on the SDK callback lane and must not reenter lifecycle APIs.
func (b *Backend) gatewayIngressFailed(_ error) {
	b.mu.Lock()
	dispatcher, closed := b.dispatcher, b.closed
	b.mu.Unlock()
	if closed {
		return
	}
	if dispatcher != nil {
		if e := dispatcher.FailBackend(b.life, BackendID, "DISCORD_GATEWAY_INGRESS_FAILED"); e != nil {
			b.config.OnError(e)
		}
	}
	b.config.OnError(unavailable("DISCORD_GATEWAY_INGRESS_FAILED"))
}

// observe runs on the one ordered SDK receive lane. It never invokes a module
// or performs a network request; Dispatcher owns bounded per-instance queues.
func (b *Backend) observe(session *discordgo.Session, event *discordgo.Event, sdkError error) {
	b.mu.Lock()
	voice, dispatcher, closed := b.voice, b.dispatcher, b.closed
	b.mu.Unlock()
	if closed {
		return
	}
	if event == nil {
		if sdkError != nil {
			b.gatewayIngressFailed(sdkError)
		}
		return
	}
	if sdkError != nil {
		if _, known := discordv2.LookupEvent(event.Type); known && dispatcher != nil {
			if e := dispatcher.FailEvent(b.life, BackendID, event.Type, "DISCORD_EVENT_DECODE_FAILED"); e != nil {
				b.config.OnError(e)
			}
		}
		b.config.OnError(invalid("DISCORD_EVENT_DECODE_FAILED"))
		return
	}
	if event.Type == "READY" {
		ready, ok := event.Struct.(*discordgo.Ready)
		if !ok || !b.verifyReadyIdentity(ready) {
			if dispatcher != nil {
				if e := dispatcher.FailBackend(b.life, BackendID, "DISCORD_GATEWAY_IDENTITY_MISMATCH"); e != nil {
					b.config.OnError(e)
				}
			}
			b.config.OnError(unavailable("DISCORD_GATEWAY_IDENTITY_MISMATCH"))
			return
		}
	}
	switch v := event.Struct.(type) {
	case *discordgo.VoiceServerUpdate:
		if v != nil {
			if e := session.VoiceGatewayDispatch(event); e != nil {
				b.config.OnError(unavailable("DISCORD_VOICE_DISPATCH_FAILED"))
			}
			if voice != nil {
				voice.OnVoiceServer(b.life, VoiceServer{v.GuildID, v.Endpoint, v.Token})
			}
		}
		return
	case *discordgo.VoiceStateUpdate:
		if v != nil && v.VoiceState != nil && v.UserID == b.config.BotUserID {
			if e := session.VoiceGatewayDispatch(event); e != nil {
				b.config.OnError(unavailable("DISCORD_VOICE_DISPATCH_FAILED"))
			}
			if voice != nil {
				voice.OnBotVoiceState(b.life, BotVoiceState{v.GuildID, v.ChannelID, v.UserID, v.SessionID})
			}
		}
	}
	descriptor, registered := discordv2.LookupEvent(event.Type)
	if !registered {
		return
	}
	if dispatcher == nil {
		b.config.OnError(unavailable("DISCORD_DISPATCHER_NOT_ATTACHED"))
		return
	}
	ingress, cancel := context.WithTimeout(b.life, b.config.HTTP.RequestDeadline)
	defer cancel()
	raw := []byte(event.RawData)
	var recipient runtime.ModuleID
	var exact runtime.InstancePrincipal
	var leaseRoute *RouteKey
	if event.Type == "INTERACTION_CREATE" {
		interaction, ok := event.Struct.(*discordgo.InteractionCreate)
		if !ok || interaction == nil || interaction.Interaction == nil {
			if e := dispatcher.FailEvent(b.life, BackendID, event.Type, "DISCORD_EVENT_DECODE_FAILED"); e != nil {
				b.config.OnError(e)
			}
			b.config.OnError(invalid("DISCORD_INTERACTION_INVALID"))
			return
		}
		var e error
		recipient, leaseRoute, e = b.interactionOwner(ingress, interaction.Interaction)
		if e != nil {
			b.config.OnError(e)
			return
		}
	}
	if leaseRoute != nil {
		release, e := b.ownership.leaseRoutes(ingress, recipient, []RouteKey{*leaseRoute})
		if e != nil {
			b.config.OnError(e)
			return
		}
		defer release()
	}
	if event.Type == "GUILD_MEMBERS_CHUNK" {
		var e error
		raw, exact, e = b.correlateChunk(raw)
		if e != nil {
			if failure := dispatcher.FailEvent(b.life, BackendID, event.Type, "DISCORD_CHUNK_INVALID"); failure != nil {
				b.config.OnError(failure)
			}
			b.config.OnError(e)
			return
		}
		if raw == nil {
			return
		}
	}
	target, e := b.eventScope(event.Type, raw)
	if e != nil {
		if failure := dispatcher.FailEvent(b.life, BackendID, event.Type, "DISCORD_EVENT_SCOPE_INVALID"); failure != nil {
			b.config.OnError(failure)
		}
		b.config.OnError(e)
		return
	}
	received := time.Now()
	admitted := runtime.BackendEvent{BackendID: BackendID, BackendMajor: BackendMajor, EventType: event.Type, Operation: descriptor.Capability, Scope: target, ReceivedAt: received}
	admitted.Recipient = func(p runtime.InstancePrincipal) bool {
		b.mu.Lock()
		i := b.instances[p.InstanceID]
		if i == nil || i.grant == nil || i.services.Principal != p || !i.active || i.ctx.Err() != nil || (recipient != "" && p.ModuleID != recipient) || (exact.InstanceID != "" && p != exact) {
			b.mu.Unlock()
			return false
		}
		var grant *corewire.CapabilityGrant
		for _, g := range i.grant.Capabilities {
			if g.Name == descriptor.Capability {
				grant = g
				break
			}
		}
		b.mu.Unlock()
		if grant == nil {
			return false
		}
		// The connection-wide READY guild collection needs explicitly global access.
		if event.Type == "READY" {
			all := false
			for _, s := range grant.ResourceScopes {
				all = all || s.GetAllResources()
			}
			if !all {
				return false
			}
		}
		if e := eventResourceGraph(event.Type, raw, target, grant); e != nil && status.Code(e) == codes.PermissionDenied {
			return false
		}
		return true
	}
	admitted.Project = func(ctx context.Context, p runtime.InstancePrincipal) (*anypb.Any, error) {
		if sdkError != nil {
			return nil, invalid("DISCORD_EVENT_DECODE_FAILED")
		}
		b.mu.Lock()
		binding := b.instances[p.InstanceID]
		b.mu.Unlock()
		if binding == nil {
			return nil, unavailable("DISCORD_INSTANCE_NOT_RUNNING")
		}
		var source struct {
			Type    int32 `json:"type"`
			Limit   int64 `json:"attachment_size_limit"`
			Message *struct {
				ID          string `json:"id"`
				Attachments []struct {
					ID string `json:"id"`
				} `json:"attachments"`
			} `json:"message"`
		}
		json.Unmarshal(raw, &source)
		messageID := ""
		var attachments map[string]bool
		if source.Message != nil {
			messageID = source.Message.ID
			attachments = make(map[string]bool, len(source.Message.Attachments))
			for _, a := range source.Message.Attachments {
				attachments[a.ID] = true
			}
		}
		encoder := instanceEncoder{backend: b, services: binding.services, fileLimit: source.Limit, sourceMessageID: messageID, attachmentIDs: attachments, interactionType: source.Type}
		value, e := projectGatewayEvent(ctx, event.Type, raw, event.Struct, encoder, b.projectionPolicy)
		if e != nil {
			return nil, e
		}
		return anypb.New(value)
	}
	if e = dispatcher.Admit(ingress, admitted); e != nil {
		if failure := dispatcher.FailEvent(b.life, BackendID, event.Type, "DISCORD_EVENT_ADMISSION_FAILED"); failure != nil {
			b.config.OnError(failure)
		}
		b.config.OnError(e)
	}
}
func (b *Backend) interactionOwner(ctx context.Context, i *discordgo.Interaction) (runtime.ModuleID, *RouteKey, error) {
	if i.AppID != b.config.ApplicationID {
		return "", nil, denied("INTERACTION_APPLICATION_INVALID")
	}
	// Never call ApplicationCommandData before discriminating the actual variant.
	switch i.Type {
	case discordgo.InteractionApplicationCommand, discordgo.InteractionApplicationCommandAutocomplete:
		data, ok := i.Data.(discordgo.ApplicationCommandInteractionData)
		if !ok || data.ID == "" {
			return "", nil, invalid("INTERACTION_COMMAND_INVALID")
		}
		owner, e := b.ownership.commandOwner(ctx, i.AppID, data.ID)
		return owner, nil, e
	case discordgo.InteractionMessageComponent:
		data, ok := i.Data.(discordgo.MessageComponentInteractionData)
		if !ok {
			return "", nil, invalid("INTERACTION_ROUTE_INVALID")
		}
		key := RouteKey{i.AppID, 1, data.CustomID}
		owner, e := b.ownership.routeOwner(ctx, key)
		return owner, &key, e
	case discordgo.InteractionModalSubmit:
		data, ok := i.Data.(discordgo.ModalSubmitInteractionData)
		if !ok {
			return "", nil, invalid("INTERACTION_ROUTE_INVALID")
		}
		key := RouteKey{i.AppID, 2, data.CustomID}
		owner, e := b.ownership.routeOwner(ctx, key)
		return owner, &key, e
	}
	return "", nil, invalid("INTERACTION_TYPE_INVALID")
}

func eventResourceGraph(name string, raw []byte, target *corewire.ResourceScope, grant *corewire.CapabilityGrant) error {
	parent := target.GetSelector().ResourceIds
	graph := resourceGraphContext{grant: grant}
	if name == "INTERACTION_CREATE" {
		// The event scope authenticates the top-level actor; a component's
		// originating message author is not the user invoking this interaction.
		graph.invokingUser = parent["user_id"]
	}
	return graph.check(raw, "", parent, 0, false)
}

func (b *Backend) eventScope(name string, raw []byte) (*corewire.ResourceScope, error) {
	if eventResourceFree(name) {
		return scope(map[string]string{}), nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, invalid("DISCORD_EVENT_INVALID")
	}
	ids := map[string]string{}
	get := func(key string) string { var value string; json.Unmarshal(fields[key], &value); return value }
	for _, key := range []string{"guild_id", "channel_id", "application_id", "user_id", "message_id", "rule_id", "webhook_id", "sku_id"} {
		if v := get(key); v != "" {
			ids[key] = v
		}
	}
	id := get("id")
	switch {
	case name == "GUILD_CREATE" || name == "GUILD_UPDATE" || name == "GUILD_DELETE":
		ids["guild_id"] = id
	case strings.HasPrefix(name, "CHANNEL_") || name == "THREAD_CREATE" || name == "THREAD_UPDATE" || name == "THREAD_DELETE":
		if id != "" {
			ids["channel_id"] = id
		}
	case name == "MESSAGE_CREATE" || name == "MESSAGE_UPDATE" || name == "MESSAGE_DELETE":
		ids["message_id"] = id
	case name == "INTERACTION_CREATE":
		ids["interaction_id"] = id
	case strings.HasPrefix(name, "GUILD_SCHEDULED_EVENT_"):
		if id != "" {
			ids["scheduled_event_id"] = id
		}
	case strings.HasPrefix(name, "ENTITLEMENT_"):
		ids["entitlement_id"] = id
	case strings.HasPrefix(name, "SUBSCRIPTION_"):
		ids["subscription_id"] = id
	case strings.HasPrefix(name, "AUTO_MODERATION_RULE_"):
		ids["rule_id"] = id
	}
	if data := fields["role"]; data != nil {
		var role struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &role) == nil && role.ID != "" {
			ids["role_id"] = role.ID
		}
	}
	if v := get("role_id"); v != "" {
		ids["role_id"] = v
	}
	if name == "APPLICATION_COMMAND_PERMISSIONS_UPDATE" {
		ids["command_id"] = id
	}
	if scheduled := get("guild_scheduled_event_id"); scheduled != "" {
		ids["scheduled_event_id"] = scheduled
	}
	if strings.HasPrefix(name, "SUBSCRIPTION_") {
		var skus []string
		if json.Unmarshal(fields["sku_ids"], &skus) == nil && len(skus) == 1 {
			ids["sku_id"] = skus[0]
		}
		ids["application_id"] = b.config.ApplicationID
	}
	// Message authors must reach the runtime's initial selector check, before
	// recursive resource validation. Partial updates never borrow an actor.
	var user struct {
		ID string `json:"id"`
	}
	if name == "MESSAGE_CREATE" || name == "MESSAGE_UPDATE" {
		json.Unmarshal(fields["author"], &user)
	} else {
		// DM interactions carry User; guild interactions carry Member.User.
		if data := fields["member"]; data != nil {
			var member struct {
				User *struct {
					ID string `json:"id"`
				} `json:"user"`
			}
			if json.Unmarshal(data, &member) == nil && member.User != nil {
				user.ID = member.User.ID
			}
		}
		if user.ID == "" {
			json.Unmarshal(fields["user"], &user)
		}
	}
	if user.ID != "" {
		ids["user_id"] = user.ID
	}
	if channel := ids["channel_id"]; channel != "" && ids["guild_id"] == "" {
		if c, ok := b.channelFacts(channel); ok && c.GuildID != "" {
			ids["guild_id"] = c.GuildID
		}
	}
	for key, value := range ids {
		if value == "" {
			delete(ids, key)
		}
	}
	if len(ids) == 0 {
		return nil, denied("DISCORD_EVENT_SCOPE_UNKNOWN")
	}
	if e := validateSelector(&corewire.ResourceSelector{ResourceIds: ids}); e != nil {
		return nil, e
	}
	return scope(ids), nil
}
