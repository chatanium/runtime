package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func scopedTestGrant(operation string, selectors ...map[string]string) *corewire.CapabilityGrant {
	grant := &corewire.CapabilityGrant{Name: operation}
	for _, ids := range selectors {
		grant.ResourceScopes = append(grant.ResourceScopes, &corewire.ResourceScope{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{ResourceIds: ids}}})
	}
	return grant
}
func TestINITPreflightPreservesFutureCallerConstraints(t *testing.T) {
	const app, guild, channel, user = "100", "200", "300", "400"
	b := &GeneralBot{config: GeneralExampleConfig{ApplicationID: app, Guilds: []GuildConfig{{GuildID: guild, TextChannelIDs: []string{channel}}}}}
	b.grants = append(b.grants, scopedTestGrant(rest("ApplicationCommandCreate"), appScope(app, guild)))
	for _, operation := range []string{rest("InteractionRespond"), rest("WebhookMessageEdit"), rest("WebhookThreadExecute"), rest("WebhookMessageDelete"), "discord.event.INTERACTION_CREATE"} {
		b.grants = append(b.grants, scopedTestGrant(operation, map[string]string{"application_id": app, "guild_id": guild, "channel_id": channel, "user_id": user}))
	}
	if err := b.validateInteractionCapabilities(); err != nil {
		t.Fatalf("dev-user-constrained INIT preflight failed: %v", err)
	}
	known := b.interactionPreflightScopes()[0]
	for _, operation := range []string{"WebhookThreadExecute", "WebhookMessageEdit", "WebhookMessageDelete"} {
		if !compatibleGrant(b.grants, rest(operation), known) {
			t.Fatalf("attachment preflight demanded a guild-wide %s grant", operation)
		}
	}
	concrete := map[string]string{"application_id": app, "guild_id": guild, "channel_id": channel, "user_id": "401"}
	if allows(b.grants, rest("InteractionRespond"), concrete) {
		t.Fatal("preflight compatibility authorized another authenticated caller")
	}
	b.config.Guilds[0].TextChannelIDs = []string{"301"}
	if err := b.validateInteractionCapabilities(); err == nil {
		t.Fatal("known different source channel passed INIT preflight")
	}
	if compatibleGrant(b.grants, "discord.event.INTERACTION_CREATE", map[string]string{"application_id": app, "guild_id": ""}) {
		t.Fatal("a known DM context borrowed a guild grant")
	}
}

// Stateful, offline-only helper boundary: assertions observe resource state and
// durable ownership, not call counts or a production transport fallback.
type ownedChannelFixture struct {
	wire.UnimplementedHelperServer
	mu       sync.Mutex
	channels map[string]*discordgo.Channel
}

func (f *ownedChannelFixture) ChannelEdit(_ context.Context, req *wire.ChannelEditRequest) (*wire.ChannelEditResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	channel := f.channels[req.ChannelId]
	if channel == nil {
		return nil, commandRejection("fixture channel missing")
	}
	if req.Data.Name != nil {
		channel.Name = *req.Data.Name
	}
	value, err := discord.ChannelToProto(channel)
	return &wire.ChannelEditResponse{Value: value}, err
}
func (f *ownedChannelFixture) ChannelDelete(_ context.Context, req *wire.ChannelDeleteRequest) (*wire.ChannelDeleteResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	channel := f.channels[req.ChannelId]
	if channel == nil {
		return nil, commandRejection("fixture channel missing")
	}
	delete(f.channels, req.ChannelId)
	value, err := discord.ChannelToProto(channel)
	return &wire.ChannelDeleteResponse{Value: value}, err
}
func TestLeastPrivilegeINITCommandsAndOwnedCRUD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener := bufconn.Listen(64 << 10)
	fixture := &ownedChannelFixture{channels: map[string]*discordgo.Channel{
		"300": {ID: "300", GuildID: "100", Name: "flex-test-owned"},
		"301": {ID: "301", GuildID: "100", Name: "flex-test-owned-ungranted"},
		"302": {ID: "302", GuildID: "100", Name: "unrelated-channel"},
	}}
	server := grpc.NewServer()
	wire.RegisterHelperServer(server, fixture)
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); listener.Close(); <-stopped })
	conn, err := grpc.NewClient("passthrough:///ordinary-management-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	api, err := discord.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenSettings(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, id := range []string{"300", "301"} {
		if err = store.RecordChannel(ctx, "100", id, false); err != nil {
			t.Fatal(err)
		}
	}
	g := GuildConfig{GuildID: "100", TextChannelIDs: []string{"200"}, Moderation: ModerationConfig{Enabled: true, ApprovedMemberIDs: []string{"400"}, MaxTimeoutSeconds: 60}}
	b := &GeneralBot{api: api, store: store, config: GeneralExampleConfig{ApplicationID: "500", Guilds: []GuildConfig{g}}, management: map[string]map[string]bool{}}
	b.grants = []*corewire.CapabilityGrant{
		scopedTestGrant(rest("GuildMember"), userScope("100", "400")),
		scopedTestGrant(rest("GuildChannelCreateComplex"), guildScope("100")),
		scopedTestGrant(rest("ChannelEdit"), channelScope("100", "300"), channelScope("100", "302")),
		scopedTestGrant(rest("ChannelDelete"), channelScope("100", "300"), channelScope("100", "302")),
	}
	if err = b.initializeManagement(ctx, g); err != nil {
		t.Fatal(err)
	}
	commands := map[string]bool{}
	for _, c := range b.commandDefinitions("100") {
		commands[c.Name] = true
	}
	for _, name := range []string{"settings", "member-info", "channel-create", "channel-edit", "channel-delete"} {
		if !commands[name] {
			t.Fatalf("unrelated ban/role/timeout permissions gated %s", name)
		}
	}
	for _, name := range []string{"ban", "unban", "role-add", "role-remove", "timeout", "clear-timeout", "audit-log"} {
		if commands[name] {
			t.Fatalf("unapproved management action advertised: %s", name)
		}
	}
	handle := &discord.InteractionHandle{Value: &discordgo.Interaction{GuildID: "100", Member: &discordgo.Member{User: &discordgo.User{ID: "400"}}}}
	text := func(name, value string) *discordgo.ApplicationCommandInteractionDataOption {
		return &discordgo.ApplicationCommandInteractionDataOption{Name: name, Type: discordgo.ApplicationCommandOptionString, Value: value}
	}
	edit := func(id string) (string, error) {
		return b.executeCommand(ctx, handle, "channel-edit", commandOptions{"channel": text("channel", id), "name": text("name", "flex-test-renamed"), "reason": text("reason", "bounded regression")})
	}
	if _, err = edit("301"); err == nil {
		t.Fatal("owned but ungranted channel was edited")
	}
	if _, err = edit("302"); err == nil {
		t.Fatal("granted but unowned channel was edited")
	}
	if _, err = edit("300"); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	renamed := fixture.channels["300"].Name
	ungranted := fixture.channels["301"].Name
	unrelated := fixture.channels["302"].Name
	fixture.mu.Unlock()
	if renamed != "flex-test-renamed" || ungranted != "flex-test-owned-ungranted" || unrelated != "unrelated-channel" {
		t.Fatalf("resource boundary violated: %q %q %q", renamed, ungranted, unrelated)
	}
	if _, err = b.executeCommand(ctx, handle, "channel-delete", commandOptions{"channel": text("channel", "300"), "reason": text("reason", "bounded regression cleanup")}); err != nil {
		t.Fatal(err)
	}
	owned, err := store.OwnsChannel(ctx, "100", "300")
	if err != nil || owned {
		t.Fatalf("deleted channel retained local ownership: %v", err)
	}
	fixture.mu.Lock()
	_, remains := fixture.channels["300"]
	_, ungrantedRemains := fixture.channels["301"]
	_, unrelatedRemains := fixture.channels["302"]
	fixture.mu.Unlock()
	if remains || !ungrantedRemains || !unrelatedRemains {
		t.Fatal("cleanup removed an unrelated resource or missed the owned one")
	}
}
