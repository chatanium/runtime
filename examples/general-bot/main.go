package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-plugin"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed manifest.json
var manifestJSON []byte

type commandBinding struct {
	GuildID, Name string
	Permissions   *discord.Nullable[int64]
}
type GeneralBot struct {
	mu                           sync.Mutex
	core                         core.CoreClient
	api                          *discord.Client
	files                        *core.FileClient
	config                       GeneralExampleConfig
	grants                       []*corewire.CapabilityGrant
	store                        *SettingsStore
	ready, running, stopped      bool
	life                         context.Context
	cancel                       context.CancelFunc
	active                       int
	changed                      chan struct{}
	commands                     map[string]commandBinding
	replies                      map[string]messageReply
	claims                       []*wire.InteractionRouteClaim
	forms, messages, attachments bool
	management                   map[string]map[string]bool
	disabled                     []string
}

func (b *GeneralBot) bind(_ context.Context, conn grpc.ClientConnInterface) error {
	var err error
	if b.core, err = core.NewCoreClient(conn, core.JSONLimits{MaxBytes: 128 << 10, MaxDepth: 16}); err != nil {
		return err
	}
	if b.api, err = discord.NewClient(conn); err != nil {
		return err
	}
	b.files, err = core.NewFileClient(conn)
	return err
}
func (b *GeneralBot) GetManifest(ctx context.Context) (*corewire.ModuleManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := new(corewire.ModuleManifest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(manifestJSON, out); err != nil {
		return nil, err
	}
	return out, nil
}
func (b *GeneralBot) GetStatus(ctx context.Context) (*corewire.Status, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	r := corewire.Readiness_READINESS_NOT_READY
	detail := "not ready"
	if b.ready {
		r = corewire.Readiness_READINESS_READY
		detail = fmt.Sprintf("disabled optional features: %v", b.disabled)
	}
	return &corewire.Status{Readiness: r, Detail: &detail}, nil
}
func (b *GeneralBot) OnStage(ctx context.Context, req *corewire.StageRequest) error {
	if req == nil {
		return errors.New("missing lifecycle stage")
	}
	switch req.Stage {
	case corewire.Stage_STAGE_INIT:
		return b.initialize(ctx, req.InitContext)
	case corewire.Stage_STAGE_START:
		b.mu.Lock()
		defer b.mu.Unlock()
		if !b.ready || b.running || b.stopped {
			return errors.New("invalid START")
		}
		b.running = true
		return nil
	case corewire.Stage_STAGE_DRAIN:
		b.mu.Lock()
		b.running = false
		b.ready = false
		if b.cancel != nil {
			b.cancel()
		}
		claims := b.claims
		b.mu.Unlock()
		err := b.join(ctx)
		if len(claims) > 0 {
			err = errors.Join(err, b.api.UnregisterInteractionRoutes(ctx, claims))
		}
		return err
	case corewire.Stage_STAGE_STOP:
		b.mu.Lock()
		b.running = false
		b.ready = false
		b.stopped = true
		if b.cancel != nil {
			b.cancel()
		}
		b.mu.Unlock()
		if err := b.join(ctx); err != nil {
			return err
		}
		if b.store != nil {
			return b.store.Close()
		}
		return nil
	default:
		return errors.New("unsupported lifecycle stage")
	}
}
func (b *GeneralBot) join(ctx context.Context) error {
	for {
		b.mu.Lock()
		if b.active == 0 {
			b.mu.Unlock()
			return nil
		}
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}
func (b *GeneralBot) initialize(ctx context.Context, init *corewire.InitContext) (result error) {
	b.mu.Lock()
	if b.life != nil || b.stopped || b.core == nil || b.api == nil || init == nil || init.Grants == nil {
		b.mu.Unlock()
		return errors.New("invalid INIT or missing helpers/grants")
	}
	b.life, b.cancel = context.WithCancel(context.Background())
	b.changed = make(chan struct{})
	b.mu.Unlock()
	defer func() {
		if result != nil {
			b.cancel()
			if b.store != nil {
				result = errors.Join(result, b.store.Close())
			}
		}
	}()
	if err := require(init.Grants.CoreCapabilities, "core.config.read", map[string]string{}); err != nil {
		return err
	}
	raw, err := b.core.GetConfig(ctx)
	if err != nil {
		return err
	}
	if raw == nil {
		return errors.New("missing ordinary module config")
	}
	if err = decodeJSON(raw.Json, &b.config); err != nil {
		return errors.New("invalid ordinary module config JSON")
	}
	if err = b.config.validate(); err != nil {
		return err
	}
	for _, g := range init.Grants.Backends {
		if g != nil && g.BackendId == "discord" && g.ProtocolMajor == 2 {
			for _, c := range g.Capabilities {
				if c != nil {
					b.grants = append(b.grants, proto.Clone(c).(*corewire.CapabilityGrant))
				}
			}
		}
	}
	if len(b.grants) == 0 {
		return errors.New("Discord v2 backend unavailable")
	}
	scopes := []string{}
	for _, g := range b.config.Guilds {
		scopes = append(scopes, g.GuildID)
	}
	if b.config.AllowDM {
		scopes = append(scopes, "")
	}
	if err = b.validateInteractionCapabilities(); err != nil {
		return err
	}
	b.store, err = openGrantedSettings(ctx, init)
	if err != nil {
		return err
	}
	b.commands = map[string]commandBinding{}
	b.management = map[string]map[string]bool{}
	b.forms = b.config.EnableForms && allows(b.grants, "discord.routes.manage", appScope(b.config.ApplicationID, ""))
	if b.config.EnableForms && !b.forms {
		b.disabled = append(b.disabled, "forms")
	}
	b.messages = b.config.EnableMessages
	b.attachments = b.config.EnableAttachments && allows(init.Grants.CoreCapabilities, "core.upload", map[string]string{})
	for _, g := range b.config.Guilds {
		for _, channel := range g.TextChannelIDs {
			for _, op := range []string{"ChannelMessageSendComplex", "ChannelMessageEditComplex", "ChannelMessageDelete"} {
				if !allows(b.grants, rest(op), channelScope(g.GuildID, channel)) {
					b.messages = false
					b.attachments = false
				}
			}
			for _, event := range []string{"MESSAGE_CREATE", "MESSAGE_UPDATE", "MESSAGE_DELETE"} {
				if !compatibleGrant(b.grants, "discord.event."+event, channelScope(g.GuildID, channel)) {
					b.messages = false
				}
			}
		}
		if err = b.initializeManagement(ctx, g); err != nil {
			return err
		}
		setting, ok, e := b.store.GetGuildSettings(ctx, g.GuildID)
		if e != nil {
			return e
		}
		if ok && setting.AuditReplyChannelID != "" && !contains(g.AuditChannelIDs, setting.AuditReplyChannelID) {
			return errors.New("stored audit response channel is no longer approved")
		}
	}
	if b.config.AllowDM {
		for _, op := range []string{"ChannelMessageSendComplex", "ChannelMessageEditComplex", "ChannelMessageDelete"} {
			if !allows(b.grants, rest(op), map[string]string{}) {
				b.messages = false
				b.attachments = false
			}
		}
		for _, event := range []string{"MESSAGE_CREATE", "MESSAGE_UPDATE", "MESSAGE_DELETE"} {
			if !compatibleGrant(b.grants, "discord.event."+event, map[string]string{"guild_id": ""}) {
				b.messages = false
			}
		}
	}
	for _, op := range []string{"WebhookThreadExecute", "WebhookMessageEdit", "WebhookMessageDelete"} {
		for _, known := range b.interactionPreflightScopes() {
			if !compatibleGrant(b.grants, rest(op), known) {
				b.attachments = false
			}
		}
	}
	if b.config.EnableMessages && !b.messages {
		b.disabled = append(b.disabled, "messages")
	}
	if b.config.EnableAttachments && !b.attachments {
		b.disabled = append(b.disabled, "attachments")
	}
	if b.forms {
		b.claims = routeClaims(b.config.ApplicationID)
		if err = b.api.RegisterInteractionRoutes(ctx, b.claims); err != nil {
			return err
		}
	}
	for _, guild := range scopes {
		for _, cmd := range b.commandDefinitions(guild) {
			created, e := b.api.ApplicationCommandCreate(ctx, b.config.ApplicationID, guild, cmd)
			if e != nil {
				return e
			}
			if created == nil || !snowflake(created.ID) {
				return errors.New("command registration returned no command ID")
			}
			b.commands[created.ID] = commandBinding{GuildID: guild, Name: cmd.Name, Permissions: cmd.DefaultMemberPermissions}
		}
	}
	b.mu.Lock()
	b.ready = true
	b.mu.Unlock()
	return nil
}
func (b *GeneralBot) OnEvent(ctx context.Context, event *corewire.EventEnvelope) error {
	b.mu.Lock()
	if !b.running || b.stopped {
		b.mu.Unlock()
		return errors.New("event outside RUNNING")
	}
	b.active++
	life := b.life
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.active--; close(b.changed); b.changed = make(chan struct{}); b.mu.Unlock() }()
	bounded, cancel := context.WithTimeout(ctx, time.Duration(b.config.OperationTimeoutSeconds)*time.Second)
	defer cancel()
	stop := context.AfterFunc(life, cancel)
	defer stop()
	payload, err := discord.DecodeEvent(event)
	if err != nil {
		return err
	}
	switch e := payload.(type) {
	case *wire.InteractionCreateEvent:
		return b.handleInteraction(bounded, e.Interaction.GetValue())
	case *wire.MessageCreateEvent:
		return b.handleMessage(bounded, "create", e.Message.GetValue(), false)
	case *wire.MessageUpdateEvent:
		return b.handleMessage(bounded, "update", e.Message.GetValue(), e.BeforeUpdate != nil)
	case *wire.MessageDeleteEvent:
		return b.handleMessage(bounded, "delete", e.Message.GetValue(), e.BeforeDelete != nil)
	default:
		return errors.New("unexpected ordinary bot event")
	}
}
func main() {
	bot := new(GeneralBot)
	p, err := core.NewModulePlugin(context.Background(), bot, bot.bind, core.TransportLimits{MaxReceiveBytes: 4 << 20, MaxSendBytes: 4 << 20})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ordinary module bootstrap failed")
		os.Exit(1)
	}
	defer p.Close()
	plugin.Serve(p.ServeConfig())
}

var _ core.ModuleHooks = (*GeneralBot)(nil)
