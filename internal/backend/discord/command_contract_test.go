package discordbackend

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/protobuf/proto"
)

func TestCommandPermissionHTTPBodiesPreserveAbsentNullZeroAndMask(t *testing.T) {
	for _, state := range []struct {
		name       string
		permission *discordv2.Nullable[int64]
		json       string
	}{
		{"absent", nil, ""},
		{"clear", &discordv2.Nullable[int64]{Null: true}, "null"},
		{"administrator only", &discordv2.Nullable[int64]{Value: 0}, `"0"`},
		{"mask", &discordv2.Nullable[int64]{Value: 40}, `"40"`},
	} {
		t.Run(state.name, func(t *testing.T) {
			contexts := []discordgo.InteractionContextType{discordgo.InteractionContextGuild}
			integrations := []discordgo.ApplicationIntegrationType{discordgo.ApplicationIntegrationGuildInstall}
			command, err := discordv2.ApplicationCommandToProto(&discordv2.ApplicationCommandView{Name: "permission-check", Description: "permission boundary", Type: discordgo.ChatApplicationCommand, DefaultMemberPermissions: state.permission, DefaultPermission: new(false), DMPermission: new(false), NSFW: new(false), Contexts: &contexts, IntegrationTypes: &integrations})
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []struct {
				name    string
				request proto.Message
				method  string
			}{
				{"ApplicationCommandCreate", &wire.ApplicationCommandCreateRequest{AppId: "200", GuildId: "300", Cmd: command}, "POST"},
				{"ApplicationCommandEdit", &wire.ApplicationCommandEditRequest{AppId: "200", GuildId: "300", CmdId: "400", Cmd: command}, "PATCH"},
				{"ApplicationCommandBulkOverwrite", &wire.ApplicationCommandBulkOverwriteRequest{AppId: "200", GuildId: "300", Commands: &wire.ApplicationCommandBulkOverwriteCommandsArgList{Values: []*wire.ApplicationCommand{command}}}, "PUT"},
			} {
				t.Run(operation.name, func(t *testing.T) {
					plan, err := buildRESTPlan(operation.name, operation.request)
					if err != nil {
						t.Fatal(err)
					}
					if plan.Request.Method != operation.method || plan.Command == nil || plan.Command.ApplicationID != "200" || plan.Command.GuildID != "300" || len(plan.Command.Commands) != 1 || plan.Command.Commands[0].Name != "permission-check" {
						t.Fatal("permission encoding changed command mutation identity")
					}
					body := plan.Request.JSON
					if operation.name == "ApplicationCommandBulkOverwrite" {
						var commands []json.RawMessage
						if err := json.Unmarshal(body, &commands); err != nil || len(commands) != 1 {
							t.Fatalf("bulk command body: %s, %v", body, err)
						}
						body = commands[0]
					}
					var fields map[string]json.RawMessage
					if err := json.Unmarshal(body, &fields); err != nil {
						t.Fatal(err)
					}
					permission, present := fields["default_member_permissions"]
					if present != (state.permission != nil) || string(permission) != state.json {
						t.Fatalf("permission state changed at HTTP boundary: %s, want %s", permission, state.json)
					}
					for key, expected := range map[string]string{"default_permission": "false", "dm_permission": "false", "nsfw": "false", "contexts": "[0]", "integration_types": "[0]"} {
						if string(fields[key]) != expected {
							t.Fatalf("command default %s: %s, want %s", key, fields[key], expected)
						}
					}
				})
			}
		})
	}
}

func TestCommandRESTResponsesExposeNullablePermissionToConsumer(t *testing.T) {
	for _, operation := range []string{"ApplicationCommandCreate", "ApplicationCommandEdit", "ApplicationCommand", "ApplicationCommands", "ApplicationCommandBulkOverwrite"} {
		t.Run(operation, func(t *testing.T) {
			for _, state := range []struct {
				name  string
				field string
				want  *discordv2.Nullable[int64]
			}{
				{"absent", "", nil},
				{"null", `,"default_member_permissions":null`, &discordv2.Nullable[int64]{Null: true}},
				{"zero", `,"default_member_permissions":"0"`, &discordv2.Nullable[int64]{Value: 0}},
				{"mask", `,"default_member_permissions":"40"`, &discordv2.Nullable[int64]{Value: 40}},
			} {
				t.Run(state.name, func(t *testing.T) {
					body := `{"id":"1565492046699958272","application_id":"200","guild_id":"300","name":"hello","type":1` + state.field + `}`
					if operation == "ApplicationCommands" || operation == "ApplicationCommandBulkOverwrite" {
						body = "[" + body + "]"
					}
					response, err := projectRESTResponse(context.Background(), operation, []byte(body), nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					var command *wire.ApplicationCommand
					switch value := response.(type) {
					case *wire.ApplicationCommandCreateResponse:
						command = value.Value
					case *wire.ApplicationCommandEditResponse:
						command = value.Value
					case *wire.ApplicationCommandResponse:
						command = value.Value
					case *wire.ApplicationCommandsResponse:
						if len(value.Value.GetValues()) != 1 {
							t.Fatal("command list lost its entry")
						}
						command = value.Value.Values[0]
					case *wire.ApplicationCommandBulkOverwriteResponse:
						if len(value.Value.GetValues()) != 1 {
							t.Fatal("bulk result lost its entry")
						}
						command = value.Value.Values[0]
					default:
						t.Fatalf("unexpected command response %T", response)
					}
					got, err := discordv2.ProtoToApplicationCommand(command)
					if err != nil || got == nil {
						t.Fatalf("remote command could not be consumed: %#v, %v", got, err)
					}
					if got.ID != "1565492046699958272" || got.Name != "hello" {
						t.Fatal("remote command identity lost")
					}
					if state.want == nil {
						if got.DefaultMemberPermissions != nil {
							t.Fatal("omitted response permission became present")
						}
					} else if got.DefaultMemberPermissions == nil || *got.DefaultMemberPermissions != *state.want {
						t.Fatalf("remote permission changed: %#v, want %#v", got.DefaultMemberPermissions, state.want)
					}
				})
			}
		})
	}
}

func TestCommandOptionHTTPBoundsRetainPresence(t *testing.T) {
	type optionJSON struct {
		Type         uint32          `json:"type"`
		Autocomplete bool            `json:"autocomplete"`
		MaxValue     json.RawMessage `json:"max_value"`
		MaxLength    json.RawMessage `json:"max_length"`
		Options      []optionJSON    `json:"options"`
	}
	for _, test := range []struct {
		name      string
		option    *discordv2.ApplicationCommandOptionView
		maxValue  string
		maxLength string
	}{
		{"string autocomplete", &discordv2.ApplicationCommandOptionView{Type: discordgo.ApplicationCommandOptionString, Name: "topic", Description: "Choose a topic", Autocomplete: true}, "", ""},
		{"numeric zero upper bound", &discordv2.ApplicationCommandOptionView{Type: discordgo.ApplicationCommandOptionInteger, Name: "offset", Description: "Nonpositive offset", MaxValue: new(float64(0))}, "0", ""},
		{"string length limit", &discordv2.ApplicationCommandOptionView{Type: discordgo.ApplicationCommandOptionString, Name: "text", Description: "Bounded text", MaxLength: new(200)}, "", "200"},
	} {
		for _, recursive := range []bool{false, true} {
			name := test.name
			if recursive {
				name += " recursively nested"
			}
			t.Run(name, func(t *testing.T) {
				options := []*discordv2.ApplicationCommandOptionView{test.option}
				if recursive {
					options = []*discordv2.ApplicationCommandOptionView{{Type: discordgo.ApplicationCommandOptionSubCommandGroup, Name: "group", Description: "Grouped commands", Options: []*discordv2.ApplicationCommandOptionView{{Type: discordgo.ApplicationCommandOptionSubCommand, Name: "run", Description: "Nested command", Options: options}}}}
				}
				command, err := discordv2.ApplicationCommandToProto(&discordv2.ApplicationCommandView{Name: "form", Description: "Command option presence", Type: discordgo.ChatApplicationCommand, Options: options})
				if err != nil {
					t.Fatal(err)
				}
				for _, operation := range []struct {
					name    string
					request proto.Message
				}{
					{"ApplicationCommandCreate", &wire.ApplicationCommandCreateRequest{AppId: "200", GuildId: "300", Cmd: command}},
					{"ApplicationCommandEdit", &wire.ApplicationCommandEditRequest{AppId: "200", GuildId: "300", CmdId: "400", Cmd: command}},
					{"ApplicationCommandBulkOverwrite", &wire.ApplicationCommandBulkOverwriteRequest{AppId: "200", GuildId: "300", Commands: &wire.ApplicationCommandBulkOverwriteCommandsArgList{Values: []*wire.ApplicationCommand{command}}}},
				} {
					t.Run(operation.name, func(t *testing.T) {
						plan, err := buildRESTPlan(operation.name, operation.request)
						if err != nil {
							t.Fatal(err)
						}
						body := plan.Request.JSON
						if operation.name == "ApplicationCommandBulkOverwrite" {
							var commands []json.RawMessage
							if err := json.Unmarshal(body, &commands); err != nil || len(commands) != 1 {
								t.Fatalf("bulk command body: %s, %v", body, err)
							}
							body = commands[0]
						}
						var payload struct {
							Options []optionJSON `json:"options"`
						}
						if err := json.Unmarshal(body, &payload); err != nil {
							t.Fatal(err)
						}
						encoded := payload.Options
						if recursive {
							for range 2 {
								if len(encoded) != 1 {
									t.Fatal("recursive option structure lost")
								}
								if len(encoded[0].MaxValue) != 0 || len(encoded[0].MaxLength) != 0 {
									t.Fatal("subcommand acquired an absent bound")
								}
								encoded = encoded[0].Options
							}
						}
						if len(encoded) != 1 {
							t.Fatal("command option lost")
						}
						got := encoded[0]
						if string(got.MaxValue) != test.maxValue || string(got.MaxLength) != test.maxLength {
							t.Fatalf("HTTP bounds changed: max_value=%s, max_length=%s; want %q, %q", got.MaxValue, got.MaxLength, test.maxValue, test.maxLength)
						}
						if test.option.Autocomplete && !got.Autocomplete {
							t.Fatal("autocomplete option disabled")
						}
					})
				}
			})
		}
	}
}
