package discordbackend

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type nonceRecord struct {
	owner         runtime.InstancePrincipal
	guild, caller string
	seen          map[int]bool
	count         int
	timer         *time.Timer
}

func (b *Backend) newNonce(p runtime.InstancePrincipal, guild, caller string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, r := range b.nonces {
		if r.owner == p {
			n++
		}
	}
	if len(b.nonces) >= b.config.NoncesPerHost || n >= b.config.NoncesPerInstance {
		return "", localError(codes.ResourceExhausted, "DISCORD_NONCE_QUOTA_EXCEEDED")
	}
	id, e := randomOpaque()
	if e != nil {
		return "", e
	}
	id = id[:32]
	r := &nonceRecord{owner: p, guild: guild, caller: caller, seen: make(map[int]bool)}
	b.nonces[id] = r
	r.timer = time.AfterFunc(b.config.NonceTTL, func() {
		b.mu.Lock()
		if b.nonces[id] == r {
			delete(b.nonces, id)
		}
		b.mu.Unlock()
	})
	return id, nil
}
func (h *Helper) gatewayContext(ctx context.Context, p runtime.InstancePrincipal) (context.Context, func(), error) {
	life, done, e := h.backend.beginWork(p)
	if e != nil {
		return nil, nil, e
	}
	bounded, cancel := context.WithTimeout(ctx, h.backend.config.HTTP.RequestDeadline)
	stop := context.AfterFunc(life, cancel)
	return bounded, func() { stop(); cancel(); done() }, nil
}
func (h *Helper) executeGateway(ctx context.Context, operation string, request proto.Message) (proto.Message, error) {
	if operation == "UserChannelPermissions" {
		return h.userChannelPermissions(ctx, request)
	}
	switch r := request.(type) {
	case *wire.UpdateStatusComplexRequest:
		if e := gatewayOptions(r.Options); e != nil {
			return nil, e
		}
	case *wire.RequestGuildMembersRequest:
		if e := gatewayOptions(r.Options); e != nil {
			return nil, e
		}
	case *wire.RequestGuildMembersListRequest:
		if e := gatewayOptions(r.Options); e != nil {
			return nil, e
		}
	}
	if operation == "UpdateStatusComplex" {
		req, ok := request.(*wire.UpdateStatusComplexRequest)
		if !ok || req.Usd == nil {
			return nil, invalid("DISCORD_STATUS_INVALID")
		}
		value, e := discordv2.ProtoToUpdateStatusData(req.Usd)
		if e != nil {
			return nil, invalid("DISCORD_STATUS_INVALID")
		}
		if value == nil {
			return nil, invalid("DISCORD_STATUS_INVALID")
		}
		if value.Activities == nil {
			value.Activities = []*discordgo.Activity{}
		}
		op, e := h.authorize(ctx, operation, &RESTPlan{ResourceFree: true})
		if e != nil {
			return nil, e
		}
		defer op.Admission.Release()
		if op.Principal.ModuleID != h.backend.config.PresenceOwner {
			return nil, denied("DISCORD_PRESENCE_OWNER_CONFLICT")
		}
		bounded, done, e := h.gatewayContext(op.Context, op.Principal)
		if e != nil {
			return nil, e
		}
		defer done()
		if e = h.backend.session.UpdateStatusComplexContext(bounded, *value); e != nil {
			return nil, externalError(e, "DISCORD_GATEWAY_WRITE_FAILED", true)
		}
		return &emptypb.Empty{}, nil
	}
	var guild, query, nonce string
	var limit int64
	var presences bool
	var users []string
	switch req := request.(type) {
	case *wire.RequestGuildMembersRequest:
		guild, query, limit, nonce, presences = req.GuildId, req.Query, req.Limit, req.Nonce, req.Presences
	case *wire.RequestGuildMembersListRequest:
		guild, limit, nonce, presences = req.GuildId, req.Limit, req.Nonce, req.Presences
		if req.UserIds != nil {
			users = req.UserIds.Values
		}
		if len(users) == 0 || len(users) > 100 {
			return nil, invalid("DISCORD_MEMBER_REQUEST_INVALID")
		}
	default:
		return nil, invalid("DISCORD_GATEWAY_OPERATION_INVALID")
	}
	if !snowflake(guild) || limit < 0 || limit > 1000 || len(nonce) > 32 {
		return nil, invalid("DISCORD_MEMBER_REQUEST_INVALID")
	}
	targets := []ResourceTarget{{Kind: "guild_id", ID: guild}}
	for _, id := range users {
		if !snowflake(id) {
			return nil, invalid("DISCORD_MEMBER_REQUEST_INVALID")
		}
		targets = append(targets, ResourceTarget{Kind: "user_id", ID: id, GuildID: guild})
	}
	if h.backend.config.Intents&discordgo.IntentGuildMembers == 0 || (presences && h.backend.config.Intents&discordgo.IntentGuildPresences == 0) {
		return nil, unavailable("BACKEND_RECONFIGURATION_REQUIRED")
	}
	op, e := h.authorize(ctx, operation, &RESTPlan{Targets: targets})
	if e != nil {
		return nil, e
	}
	defer op.Admission.Release()
	bounded, done, e := h.gatewayContext(op.Context, op.Principal)
	if e != nil {
		return nil, e
	}
	defer done()
	private, e := h.backend.newNonce(op.Principal, guild, nonce)
	if e != nil {
		return nil, e
	}
	if operation == "RequestGuildMembers" {
		e = h.backend.session.RequestGuildMembersContext(bounded, guild, query, int(limit), private, presences)
	} else {
		e = h.backend.session.RequestGuildMembersListContext(bounded, guild, users, int(limit), private, presences)
	}
	if e != nil {
		return nil, externalError(e, "DISCORD_GATEWAY_WRITE_FAILED", true)
	}
	return &emptypb.Empty{}, nil
}
func (b *Backend) correlateChunk(raw []byte) ([]byte, runtime.InstancePrincipal, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, runtime.InstancePrincipal{}, invalid("DISCORD_EVENT_INVALID")
	}
	var nonce, guild string
	var index, count int
	json.Unmarshal(fields["nonce"], &nonce)
	json.Unmarshal(fields["guild_id"], &guild)
	json.Unmarshal(fields["chunk_index"], &index)
	json.Unmarshal(fields["chunk_count"], &count)
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.nonces[nonce]
	if r == nil || r.guild != guild {
		return nil, runtime.InstancePrincipal{}, nil
	}
	if count <= 0 || count > b.config.NonceChunksMax || index < 0 || index >= count || (r.count != 0 && r.count != count) {
		return nil, runtime.InstancePrincipal{}, invalid("DISCORD_CHUNK_INVALID")
	}
	r.count = count
	r.seen[index] = true
	owner := r.owner
	fields["nonce"], _ = json.Marshal(r.caller)
	if len(r.seen) == count {
		r.timer.Stop()
		delete(b.nonces, nonce)
	}
	encoded, e := json.Marshal(fields)
	return encoded, owner, e
}

var intentBits = map[string]discordgo.Intent{"GUILDS": discordgo.IntentGuilds, "GUILD_MEMBERS": discordgo.IntentGuildMembers, "GUILD_MODERATION": discordgo.IntentGuildModeration, "GUILD_BANS": discordgo.IntentGuildModeration, "GUILD_EMOJIS_AND_STICKERS": discordgo.IntentGuildEmojis, "GUILD_EXPRESSIONS": discordgo.IntentGuildEmojis, "GUILD_INTEGRATIONS": discordgo.IntentGuildIntegrations, "GUILD_WEBHOOKS": discordgo.IntentGuildWebhooks, "GUILD_INVITES": discordgo.IntentGuildInvites, "GUILD_VOICE_STATES": discordgo.IntentGuildVoiceStates, "GUILD_PRESENCES": discordgo.IntentGuildPresences, "GUILD_MESSAGES": discordgo.IntentGuildMessages, "GUILD_MESSAGE_REACTIONS": discordgo.IntentGuildMessageReactions, "GUILD_MESSAGE_TYPING": discordgo.IntentGuildMessageTyping, "DIRECT_MESSAGES": discordgo.IntentDirectMessages, "DIRECT_MESSAGE_REACTIONS": discordgo.IntentDirectMessageReactions, "DIRECT_MESSAGE_TYPING": discordgo.IntentDirectMessageTyping, "MESSAGE_CONTENT": discordgo.IntentMessageContent, "GUILD_SCHEDULED_EVENTS": discordgo.IntentGuildScheduledEvents, "AUTO_MODERATION_CONFIGURATION": discordgo.IntentAutoModerationConfiguration, "AUTO_MODERATION_EXECUTION": discordgo.IntentAutoModerationExecution, "GUILD_MESSAGE_POLLS": discordgo.IntentGuildMessagePolls, "DIRECT_MESSAGE_POLLS": discordgo.IntentDirectMessagePolls}

func intentsAvailable(active discordgo.Intent, e discordv2.EventDescriptor) bool {
	if len(e.IntentAlternatives) == 0 {
		return true
	}
	for _, set := range e.IntentAlternatives {
		ok := true
		for _, name := range set {
			bit, exists := intentBits[name]
			if !exists || active&bit == 0 {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
func formatPermission(n int64) string { return strconv.FormatInt(n, 10) }
func gatewayOptions(options *wire.RequestOptions) error {
	if options != nil && (options.AuditLogReason != nil || options.Locale != nil || len(options.ProtoReflect().GetUnknown()) != 0) {
		return invalid("DISCORD_GATEWAY_OPTIONS_UNSUPPORTED")
	}
	return nil
}
