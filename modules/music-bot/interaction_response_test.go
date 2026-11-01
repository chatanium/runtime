package main

import (
	"context"
	"errors"
	"testing"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type musicInteractionConnection struct {
	t          *testing.T
	credential *corewire.CredentialRef
	running    bool
	calls      []string
}

func (c *musicInteractionConnection) Invoke(_ context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	c.calls = append(c.calls, method)
	switch method {
	case wire.Helper_InteractionRespond_FullMethodName:
		request := args.(*wire.InteractionRespondRequest)
		interaction := request.GetInteraction()
		if interaction.GetId() != "900" || interaction.GetAppId() != "500" || interaction.GetGuildId() != "100" || interaction.GetChannelId() != "200" || interaction.GetType() != uint32(discordgo.InteractionApplicationCommand) {
			c.t.Fatal("initial callback lost delivered interaction identity")
		}
		if !proto.Equal(interaction.GetCredentialRef(), c.credential) {
			c.t.Fatal("initial callback replaced the delivered credential")
		}
		command := interaction.GetData().GetApplicationCommand()
		if command == nil || command.GetId() != "700" || command.GetName() != "play" || command.GetCommandType() != uint32(discordgo.ChatApplicationCommand) {
			c.t.Fatal("initial callback lost its typed application command data")
		}
		wantType := uint32(discordgo.InteractionResponseChannelMessageWithSource)
		if c.running {
			wantType = uint32(discordgo.InteractionResponseDeferredChannelMessageWithSource)
		}
		if request.GetResp().GetType() != wantType || len(c.calls) != 1 {
			c.t.Fatal("initial response did not precede command work")
		}
		return nil
	case wire.Helper_UserVoiceState_FullMethodName:
		request := args.(*wire.UserVoiceStateRequest)
		if !c.running || len(c.calls) != 2 || request.GetGuildId() != "100" || request.GetUserId() != "400" {
			c.t.Fatal("voice lookup did not follow defer with the delivered actor")
		}
		// A command-operation failure must be reported through the original
		// response after the initial defer, not abort the event callback.
		return errors.New("voice lookup fixture rejected")
	case wire.Helper_WebhookMessageEdit_FullMethodName:
		if !c.running || len(c.calls) != 3 {
			c.t.Fatal("original response edit occurred out of order")
		}
		reply.(*wire.WebhookMessageEditResponse).Value = &wire.Message{}
		return nil
	default:
		c.t.Fatalf("unexpected helper operation %s", method)
		return errors.New("unexpected helper operation")
	}
}

func (c *musicInteractionConnection) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	c.t.Fatal("command response unexpectedly opened a stream")
	return nil, errors.New("unexpected stream")
}

func TestMusicCommandReachesInitialResponseWithTypedData(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		running     bool
		missingData bool
	}{
		{name: "defer_before_voice_lookup", running: true},
		{name: "draining_rejection"},
		{name: "missing_command_data", missingData: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			running := scenario.running
			ctx := context.Background()
			event, err := discord.ProjectInteractionCreateEvent(ctx, []byte(`{"id":"900","application_id":"500","type":2,"guild_id":"100","channel_id":"200","member":{"user":{"id":"400"}},"data":{"id":"700","name":"play","type":1,"options":[{"type":3,"name":"provider","value":"youtube"},{"type":3,"name":"query","value":"fixture query"}]}}`), nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			credential := &corewire.CredentialRef{OpaqueId: "music-interaction-fixture", BackendId: "discord", Purpose: "discord.interaction"}
			event.GetInteraction().GetValue().CredentialRef = &wire.DomainNullableCredentialRef{Kind: &wire.DomainNullableCredentialRef_Value{Value: credential}}
			if scenario.missingData {
				event.GetInteraction().GetValue().Data = nil
			}
			payload, err := anypb.New(event)
			if err != nil {
				t.Fatal(err)
			}
			connection := &musicInteractionConnection{t: t, credential: credential, running: running}
			api, err := discord.NewClient(connection)
			if err != nil {
				t.Fatal(err)
			}
			bot := &musicBot{
				discord:    api,
				running:    running,
				config:     Config{ApplicationID: "500", Guilds: []GuildConfig{{GuildID: "100", TextChannelIDs: []string{"200"}, VoiceChannelIDs: []string{"300"}}}, Limits: MediaLimits{CommandTimeoutMS: 1000}},
				commandIDs: map[string]map[string]string{"100": {"700": "play"}},
				playlists:  map[string]*Playlist{"100": {}},
			}
			err = bot.OnEvent(ctx, &corewire.EventEnvelope{BackendId: "discord", BackendMajor: 2, EventType: "INTERACTION_CREATE", Payload: payload})
			if scenario.missingData {
				if err == nil || err.Error() != "application command data missing" || len(connection.calls) != 0 {
					t.Fatalf("missing command data was not rejected before helper calls: err=%v calls=%d", err, len(connection.calls))
				}
				return
			}
			if err != nil {
				t.Fatalf("initial response/reporting failed before normal command completion: %v", err)
			}
			wantCalls := 1
			if running {
				wantCalls = 3
			}
			if len(connection.calls) != wantCalls {
				t.Fatalf("helper calls=%d, want %d", len(connection.calls), wantCalls)
			}
		})
	}
}
