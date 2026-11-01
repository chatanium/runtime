package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/bwmarrin/discordgo"
	"github.com/hashicorp/go-plugin"
	provider "github.com/thirdscam/chatanium/modules/music-bot/provider"
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

type musicBot struct {
	mu         sync.Mutex
	readiness  corewire.Readiness
	running    bool
	draining   bool
	config     Config
	core       core.CoreClient
	discord    *discord.Client
	voice      *discord.VoiceClient
	provider   provider.Provider
	preparer   *Preparer
	scratch    string
	lifetime   context.Context
	cancel     context.CancelFunc
	playlists  map[string]*Playlist
	workers    sync.WaitGroup
	done       chan struct{}
	commandIDs map[string]map[string]string
}

func (m *musicBot) bind(_ context.Context, conn grpc.ClientConnInterface) (err error) {
	m.core, err = core.NewCoreClient(conn, core.JSONLimits{MaxBytes: 1 << 20, MaxDepth: 32})
	if err != nil {
		return err
	}
	m.discord, err = discord.NewClient(conn)
	if err != nil {
		return err
	}
	m.voice, err = discord.NewVoiceClient(conn)
	return err
}
func (m *musicBot) GetManifest(context.Context) (*corewire.ModuleManifest, error) {
	manifest := new(corewire.ModuleManifest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(manifestJSON, manifest); err != nil {
		return nil, err
	}
	return proto.Clone(manifest).(*corewire.ModuleManifest), nil
}
func (m *musicBot) GetStatus(context.Context) (*corewire.Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &corewire.Status{Readiness: m.readiness}, nil
}
func (m *musicBot) OnStage(ctx context.Context, req *corewire.StageRequest) (err error) {
	switch req.Stage {
	case corewire.Stage_STAGE_INIT:
		defer func() {
			if err != nil {
				m.mu.Lock()
				m.readiness = corewire.Readiness_READINESS_FAILED
				m.mu.Unlock()
				if m.scratch != "" {
					err = errors.Join(err, os.RemoveAll(m.scratch))
				}
			}
		}()
		if m.core == nil || m.discord == nil || m.voice == nil {
			return errors.New("authenticated helper clients unavailable")
		}
		value, err := m.core.GetConfig(ctx)
		if err != nil {
			return err
		}
		config, err := decodeConfig(value.Json)
		if err != nil {
			return err
		}
		if err = validateGrants(config, req.InitContext); err != nil {
			return err
		}
		m.config = config
		m.scratch, err = openScratch(req.InitContext.ScratchDirectory)
		if err != nil {
			return err
		}
		cache, err := os.MkdirTemp(m.scratch, "deno-*")
		if err != nil {
			return err
		}
		l := config.Limits
		m.provider = &provider.Youtube{Limits: provider.Limits{MaxResults: l.MaxResults, MaxQueryBytes: l.MaxQueryBytes, MaxOutputBytes: l.MaxProcessOutputBytes, ToolTimeoutMS: l.ToolTimeoutMS, ResolveTimeoutMS: l.ResolveTimeoutMS}, CacheDirectory: cache}
		if err = m.provider.Initialize(ctx); err != nil {
			return err
		}
		m.preparer = newPreparer(m.scratch, l)
		m.commandIDs = make(map[string]map[string]string, len(config.Guilds))
		for _, guild := range config.Guilds {
			ids := map[string]string{}
			for _, command := range musicCommands() {
				created, e := m.discord.ApplicationCommandCreate(ctx, config.ApplicationID, guild.GuildID, command)
				if e != nil {
					return e
				}
				if created == nil || created.ID == "" {
					return errors.New("command registration omitted identity")
				}
				ids[created.ID] = command.Name
			}
			m.commandIDs[guild.GuildID] = ids
		}
		m.mu.Lock()
		m.readiness = corewire.Readiness_READINESS_READY
		m.mu.Unlock()
		return nil
	case corewire.Stage_STAGE_START:
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.readiness != corewire.Readiness_READINESS_READY || m.running || m.draining {
			return errors.New("invalid music START state")
		}
		// Never retain the lifecycle/event context or its delivery reference.
		m.lifetime, m.cancel = context.WithCancel(context.Background())
		m.done = make(chan struct{})
		m.playlists = make(map[string]*Playlist, len(m.config.Guilds))
		tasks := make(chan prepareTask)
		runPreparationWorkers(m.lifetime, m.config.Limits.Workers, tasks, &m.workers)
		for _, guild := range m.config.Guilds {
			p := newPlaylist(m.lifetime, guild.GuildID, m.config.Limits, *m.config.Priority, m.voice, m.provider, m.preparer, tasks, m.notify)
			m.playlists[guild.GuildID] = p
			go p.run()
		}
		m.running = true
		go func() {
			<-m.lifetime.Done()
			for _, p := range m.playlists {
				<-p.done
			}
			m.workers.Wait()
			close(m.done)
		}()
		return nil
	case corewire.Stage_STAGE_DRAIN, corewire.Stage_STAGE_STOP:
		m.mu.Lock()
		m.draining = true
		m.running = false
		cancel, done := m.cancel, m.done
		m.mu.Unlock()
		for _, p := range m.playlists {
			p.beginClose(ctx)
		}
		if cancel != nil {
			cancel()
		}
		if done != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
		}
		var cleanup error
		if m.preparer != nil {
			m.preparer.client.CloseIdleConnections()
		}
		for _, p := range m.playlists {
			cleanup = errors.Join(cleanup, p.failure)
		}
		if m.scratch != "" {
			cleanup = errors.Join(cleanup, os.RemoveAll(m.scratch))
		}
		m.mu.Lock()
		m.readiness = corewire.Readiness_READINESS_NOT_READY
		m.mu.Unlock()
		return cleanup
	default:
		return errors.New("unsupported lifecycle stage")
	}
}
func musicCommands() []*discord.ApplicationCommandView {
	stringOption := func(name, description string) *discord.ApplicationCommandOptionView {
		return &discord.ApplicationCommandOptionView{Type: discordgo.ApplicationCommandOptionString, Name: name, Description: description, Required: true}
	}
	commands := []*discord.ApplicationCommandView{
		{Name: "play", Description: "Accept an ordered bounded music request", Options: []*discord.ApplicationCommandOptionView{
			{Type: discordgo.ApplicationCommandOptionString, Name: "provider", Description: "Music provider", Required: true, Choices: []*discordgo.ApplicationCommandOptionChoice{{Name: "youtube", Value: "youtube"}}}, stringOption("query", "YouTube URL or search query")}},
		{Name: "remove", Description: "Remove a waiting entry (never current)", Options: []*discord.ApplicationCommandOptionView{stringOption("entry", "Entry ID from /list")}},
		{Name: "list", Description: "Show independent current and waiting playlist state"},
		{Name: "pause", Description: "Pause the owned current playback job"},
		{Name: "resume", Description: "Resume the same owned current playback job"},
		{Name: "skip", Description: "Cancel current and wait for terminal and reader release"},
		{Name: "loop", Description: "Loop only normally completed entries", Options: []*discord.ApplicationCommandOptionView{{Type: discordgo.ApplicationCommandOptionBoolean, Name: "enabled", Description: "Enable loop", Required: true}}},
	}
	permissions := int64(discordgo.PermissionUseApplicationCommands)
	contexts := []discordgo.InteractionContextType{discordgo.InteractionContextGuild}
	integrations := []discordgo.ApplicationIntegrationType{discordgo.ApplicationIntegrationGuildInstall}
	for _, c := range commands {
		c.Type = discordgo.ChatApplicationCommand
		c.DefaultMemberPermissions = &discord.Nullable[int64]{Value: permissions}
		c.Contexts = &contexts
		c.IntegrationTypes = &integrations
	}
	return commands
}
func (m *musicBot) OnEvent(ctx context.Context, envelope *corewire.EventEnvelope) error {
	decoded, err := discord.DecodeEvent(envelope)
	if err != nil {
		return err
	}
	event, ok := decoded.(*wire.InteractionCreateEvent)
	if !ok {
		return errors.New("unexpected event for music module")
	}
	partial := event.GetInteraction().GetValue()
	if partial == nil {
		return errors.New("interaction payload missing")
	}
	if partial.GetType().GetValue() != uint32(discordgo.InteractionApplicationCommand) {
		return nil
	}
	command := partial.GetData().GetValue().GetApplicationCommand()
	if command == nil {
		return errors.New("application command data missing")
	}
	interaction := &discord.InteractionHandle{
		Value: &discordgo.Interaction{
			ID: partial.GetId().GetValue(), AppID: partial.GetAppId().GetValue(),
			GuildID: partial.GetGuildId().GetValue(), ChannelID: partial.GetChannelId().GetValue(),
			Type: discordgo.InteractionApplicationCommand,
			Data: discordgo.ApplicationCommandInteractionData{
				ID: command.GetId().GetValue(), Name: command.GetName().GetValue(),
				CommandType: discordgo.ApplicationCommandType(command.GetCommandType().GetValue()),
			},
		},
		Credential: partial.GetCredentialRef().GetValue(),
	}
	if interaction.Value.ID == "" || interaction.Credential == nil {
		return errors.New("interaction identity or owner credential absent")
	}
	if interaction.Value.AppID != m.config.ApplicationID {
		return errors.New("interaction application differs from configured owner")
	}
	ctx, cancel := context.WithTimeout(ctx, millis(m.config.Limits.CommandTimeoutMS))
	defer cancel()
	m.mu.Lock()
	running := m.running
	playlist := m.playlists[interaction.Value.GuildID]
	m.mu.Unlock()
	if !running {
		return m.respond(ctx, interaction, "Music module is draining; no new work accepted.")
	}
	name, owned := m.commandIDs[interaction.Value.GuildID][command.GetId().GetValue()]
	if !owned || name != command.GetName().GetValue() {
		return errors.New("interaction command ownership mismatch")
	}
	var guild *GuildConfig
	for i := range m.config.Guilds {
		if m.config.Guilds[i].GuildID == interaction.Value.GuildID {
			guild = &m.config.Guilds[i]
			break
		}
	}
	if guild == nil || !contains(guild.TextChannelIDs, interaction.Value.ChannelID) || playlist == nil {
		return m.respond(ctx, interaction, "This guild or text channel is not approved.")
	}
	member := partial.GetMember().GetValue()
	userID := ""
	if member != nil {
		userID = member.GetUser().GetValue().GetId().GetValue()
	}
	if userID == "" {
		return m.respond(ctx, interaction, "A guild member identity is required.")
	}
	options := map[string]*discordgo.ApplicationCommandInteractionDataOption{}
	for _, field := range command.GetOptions().GetValue().GetValues() {
		option := field.GetValue()
		if option == nil {
			return errors.New("null command option")
		}
		optionName, optionType := option.GetName().GetValue(), option.GetType().GetValue()
		if _, exists := options[optionName]; exists {
			return errors.New("duplicate command option")
		}
		value, e := discord.ProtoToApplicationCommandInteractionDataOption(&wire.ApplicationCommandInteractionDataOption{Name: &optionName, Type: &optionType, Value: option.GetValue().GetValue()})
		if e != nil {
			return e
		}
		options[optionName] = value
	}
	// Explicit defer precedes any potentially slow voice control or queue work.
	flags := uint64(discordgo.MessageFlagsEphemeral)
	if err = m.discord.InteractionRespond(ctx, interaction, &discord.InteractionResponseView{Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, Data: &discord.InteractionResponseDataView{Flags: &flags}}); err != nil {
		return err
	}
	result, operationErr := m.execute(ctx, playlist, guild, interaction.Value.ChannelID, userID, name, options)
	if operationErr != nil {
		result = "Music command failed: " + safeCommandError(operationErr)
	}
	_, reportErr := m.discord.InteractionResponseEdit(ctx, interaction, &discord.WebhookEditPatch{Content: &result, AllowedMentions: &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}})
	if reportErr != nil {
		return errors.Join(operationErr, fmt.Errorf("interaction reporting failed: %w", reportErr))
	}
	return nil
}
func safeCommandError(err error) string {
	// Never echo extractor output, source URL, raw RPC payload or credentials.
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "operation rejected; inspect /list task state or host safe diagnostics"
}
func (m *musicBot) execute(ctx context.Context, p *Playlist, guild *GuildConfig, textChannel, userID, name string, options map[string]*discordgo.ApplicationCommandInteractionDataOption) (string, error) {
	switch name {
	case "play":
		source, query := options["provider"], options["query"]
		if source == nil || source.Type != discordgo.ApplicationCommandOptionString || source.StringValue() != "youtube" || query == nil || query.Type != discordgo.ApplicationCommandOptionString {
			return "", errors.New("provider and query required")
		}
		state, err := m.discord.UserVoiceState(ctx, guild.GuildID, userID)
		if err != nil {
			return "", err
		}
		if state == nil || !contains(guild.VoiceChannelIDs, state.ChannelID) {
			return "", errors.New("member is not in an approved voice channel")
		}
		ticket, err := p.Enqueue(ctx, query.StringValue(), textChannel, state.ChannelID)
		if err != nil {
			return "", err
		}
		return "Accepted ordered request " + ticket + ". /list shows resolved entry IDs and preparation errors.", nil
	case "list":
		s, err := p.Snapshot(ctx)
		return formatPlaylist(s), err
	case "remove":
		entry := options["entry"]
		if entry == nil || entry.Type != discordgo.ApplicationCommandOptionString {
			return "", errors.New("waiting entry ID required")
		}
		return "Waiting entry removed.", p.Remove(ctx, entry.StringValue())
	case "pause":
		s, err := p.Pause(ctx)
		return "Playback state: " + s.State.String(), err
	case "resume":
		s, err := p.Resume(ctx)
		return "Playback state: " + s.State.String(), err
	case "skip":
		return "Current playback reached terminal and released its artifact reader.", p.Skip(ctx)
	case "loop":
		enabled := options["enabled"]
		if enabled == nil || enabled.Type != discordgo.ApplicationCommandOptionBoolean {
			return "", errors.New("explicit loop setting required")
		}
		return fmt.Sprintf("Loop: %t", enabled.BoolValue()), p.SetLoop(ctx, enabled.BoolValue())
	default:
		return "", errors.New("unsupported owned command")
	}
}
func (m *musicBot) respond(ctx context.Context, interaction *discord.InteractionHandle, content string) error {
	flags := uint64(discordgo.MessageFlagsEphemeral)
	return m.discord.InteractionRespond(ctx, interaction, &discord.InteractionResponseView{Type: discordgo.InteractionResponseChannelMessageWithSource, Data: &discord.InteractionResponseDataView{Content: &content, Flags: &flags, AllowedMentions: &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}}})
}
func (m *musicBot) notify(ctx context.Context, channel, content string) error {
	_, err := m.discord.ChannelMessageSendComplex(ctx, channel, &discord.MessageSendView{Content: content, AllowedMentions: &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}})
	return err
}
func formatPlaylist(s PlaylistSnapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Loop: %t\n", s.Loop)
	if s.Current == nil {
		b.WriteString("Current: none\n")
	} else {
		fmt.Fprintf(&b, "Current [%s]: %s (%s)\n", s.Current.ID, shortText(s.Current.Title, 120), s.Current.State)
	}
	b.WriteString("Waiting:\n")
	for _, entry := range s.Waiting {
		line := fmt.Sprintf("[%s] %s (%s)\n", entry.ID, shortText(entry.Title, 100), entry.State)
		if b.Len()+len(line) > 1500 {
			b.WriteString("More entries omitted from this response.\n")
			break
		}
		b.WriteString(line)
	}
	if s.LastError != "" {
		b.WriteString("Last task error: " + shortText(s.LastError, 250))
	}
	return b.String()
}
func shortText(value string, limit int) string {
	for index := range value {
		if limit == 0 {
			return value[:index] + "…"
		}
		limit--
	}
	return value
}
func main() {
	bot := &musicBot{readiness: corewire.Readiness_READINESS_NOT_READY}
	module, err := core.NewModulePlugin(context.Background(), bot, bot.bind, core.TransportLimits{MaxReceiveBytes: 4 << 20, MaxSendBytes: 4 << 20})
	if err != nil {
		fmt.Fprintln(os.Stderr, "music module bootstrap failed")
		os.Exit(1)
	}
	defer module.Close()
	plugin.Serve(module.ServeConfig())
}
