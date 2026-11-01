package main

import (
	"context"
	"fmt"
	"net"
	"strings"
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
	"google.golang.org/protobuf/types/known/emptypb"
)

// Model the user-visible interaction response, not request forwarding or counts.
// Settings changes below use the real durable store and real command handler.
type permissionReplyFixture struct {
	wire.UnimplementedHelperServer
	mu      sync.Mutex
	content string
}

func (f *permissionReplyFixture) InteractionRespond(_ context.Context, req *wire.InteractionRespondRequest) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.Resp.GetData().GetContent() != nil {
		f.content = req.Resp.GetData().GetContent().GetValue()
	}
	return &emptypb.Empty{}, nil
}

func (f *permissionReplyFixture) WebhookMessageEdit(_ context.Context, req *wire.WebhookMessageEditRequest) (*wire.WebhookMessageEditResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.content = req.Data.GetContent().GetValue()
	return &wire.WebhookMessageEditResponse{Value: &wire.Message{Id: new("800")}}, nil
}

func TestCommandHandlerPreservesConfiguredPermissionAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener := bufconn.Listen(64 << 10)
	fixture := &permissionReplyFixture{}
	server := grpc.NewServer()
	wire.RegisterHelperServer(server, fixture)
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); listener.Close(); <-stopped })
	conn, err := grpc.NewClient("passthrough:///command-permission-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	api, err := discord.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name              string
		command           string
		memberPermissions int64
		allowed           bool
	}{
		{"zero rejects ordinary member", "permission-check", discordgo.PermissionUseApplicationCommands, false},
		{"zero admits administrator", "permission-check", discordgo.PermissionAdministrator, true},
		{"settings rejects missing mask", "settings", 0, false},
		{"settings rejects ManageGuild alone", "settings", discordgo.PermissionManageGuild, false},
		{"settings rejects ViewAuditLogs alone", "settings", discordgo.PermissionViewAuditLogs, false},
		{"settings admits combined mask", "settings", discordgo.PermissionManageGuild | discordgo.PermissionViewAuditLogs, true},
		{"settings admits administrator", "settings", discordgo.PermissionAdministrator, true},
		{"ordinary command needs no permission", "hello", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := OpenSettings(ctx, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			bot := &GeneralBot{api: api, store: store, config: GeneralExampleConfig{ApplicationID: "500", Guilds: []GuildConfig{{GuildID: "100", TextChannelIDs: []string{"200"}, AuditChannelIDs: []string{"600"}}}}, commands: map[string]commandBinding{}}
			// Use the real configured requirement as registration does. The
			// independent member permission cases must not gain authority if
			// that requirement is accidentally cleared or reduced to one bit.
			for _, command := range bot.commandDefinitions("100") {
				if command.Name == test.command {
					bot.commands["700"] = commandBinding{GuildID: "100", Name: command.Name, Permissions: command.DefaultMemberPermissions}
				}
			}
			options := ""
			if test.command == "settings" {
				options = `,"options":[{"type":3,"name":"channel","value":"600"}]`
			}
			raw := fmt.Sprintf(`{"id":"900","application_id":"500","type":2,"guild_id":"100","channel_id":"200","member":{"user":{"id":"400"},"permissions":"%d"},"data":{"id":"700","name":%q,"type":1%s}}`, test.memberPermissions, test.command, options)
			event, err := discord.ProjectInteractionCreateEvent(ctx, []byte(raw), nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			interaction := event.GetInteraction().GetValue()
			interaction.CredentialRef = &wire.DomainNullableCredentialRef{Kind: &wire.DomainNullableCredentialRef_Value{Value: &corewire.CredentialRef{OpaqueId: "fixture-interaction", BackendId: "discord", Purpose: "discord.interaction"}}}
			fixture.mu.Lock()
			fixture.content = ""
			fixture.mu.Unlock()
			if err := bot.handleInteraction(ctx, interaction); err != nil {
				t.Fatal(err)
			}
			fixture.mu.Lock()
			content := fixture.content
			fixture.mu.Unlock()
			if content == "" || strings.HasPrefix(content, "Request rejected:") == test.allowed {
				t.Fatalf("wrong user-visible authorization result: %q, allowed=%v", content, test.allowed)
			}
			if test.command == "settings" {
				settings, present, err := store.GetGuildSettings(ctx, "100")
				if err != nil {
					t.Fatal(err)
				}
				if present != test.allowed || (present && settings.AuditReplyChannelID != "600") {
					t.Fatalf("permission boundary allowed the wrong durable mutation: %#v, present=%v", settings, present)
				}
			}
		})
	}
}
