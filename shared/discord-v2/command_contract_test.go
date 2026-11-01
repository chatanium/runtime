package discordv2_test

import (
	"context"
	"testing"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
)

func TestCommandClientConsumesRemoteNullPermission(t *testing.T) {
	// This independent Discord response reproduces the first-create failure:
	// the command exists remotely, but the SDK used to reject its null permission.
	remote, err := discordv2.ProjectApplicationCommandJSON(context.Background(), []byte(`{"id":"1565492046699958272","application_id":"200","guild_id":"300","version":"400","type":1,"name":"hello","description":"Ordinary isolated module response","default_member_permissions":null,"default_permission":false,"dm_permission":false,"nsfw":false,"contexts":[0],"integration_types":[0],"options":[{"type":3,"name":"query","description":"Search","required":true}]}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := sdkClient(t, func(_ context.Context, _ string, _ any, response any) error {
		switch out := response.(type) {
		case *wire.ApplicationCommandCreateResponse:
			out.Value = remote
		case *wire.ApplicationCommandResponse:
			out.Value = remote
		case *wire.ApplicationCommandEditResponse:
			out.Value = remote
		case *wire.ApplicationCommandsResponse:
			out.Value = &wire.ApplicationCommandsResultList{Values: []*wire.ApplicationCommand{remote}}
		case *wire.ApplicationCommandBulkOverwriteResponse:
			out.Value = &wire.ApplicationCommandBulkOverwriteResultList{Values: []*wire.ApplicationCommand{remote}}
		default:
			t.Fatalf("unexpected result type %T", response)
		}
		return nil
	})
	input := &discordv2.ApplicationCommandView{Name: "hello", Description: "Ordinary isolated module response"}
	for _, test := range []struct {
		name string
		call func() ([]*discordv2.ApplicationCommandView, error)
	}{
		{"create", func() ([]*discordv2.ApplicationCommandView, error) {
			v, err := client.ApplicationCommandCreate(context.Background(), "200", "300", input)
			return []*discordv2.ApplicationCommandView{v}, err
		}},
		{"get", func() ([]*discordv2.ApplicationCommandView, error) {
			v, err := client.ApplicationCommand(context.Background(), "200", "300", "1565492046699958272")
			return []*discordv2.ApplicationCommandView{v}, err
		}},
		{"edit", func() ([]*discordv2.ApplicationCommandView, error) {
			v, err := client.ApplicationCommandEdit(context.Background(), "200", "300", "1565492046699958272", input)
			return []*discordv2.ApplicationCommandView{v}, err
		}},
		{"list", func() ([]*discordv2.ApplicationCommandView, error) {
			return client.ApplicationCommands(context.Background(), "200", "300")
		}},
		{"bulk", func() ([]*discordv2.ApplicationCommandView, error) {
			return client.ApplicationCommandBulkOverwrite(context.Background(), "200", "300", []*discordv2.ApplicationCommandView{input})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			values, err := test.call()
			if err != nil || len(values) != 1 || values[0] == nil {
				t.Fatalf("remote command could not be consumed: %#v, %v", values, err)
			}
			got := values[0]
			if got.ID != "1565492046699958272" || got.ApplicationID != "200" || got.GuildID != "300" || got.Version != "400" || got.Name != "hello" {
				t.Fatalf("remote command identity lost: %#v", got)
			}
			if got.DefaultMemberPermissions == nil || !got.DefaultMemberPermissions.Null {
				t.Fatalf("remote null became absent or administrator-only zero: %#v", got.DefaultMemberPermissions)
			}
			if got.DefaultPermission == nil || *got.DefaultPermission || got.DMPermission == nil || *got.DMPermission || got.NSFW == nil || *got.NSFW {
				t.Fatal("explicit false command defaults lost")
			}
			if got.Contexts == nil || len(*got.Contexts) != 1 || (*got.Contexts)[0] != discordgo.InteractionContextGuild || got.IntegrationTypes == nil || len(*got.IntegrationTypes) != 1 || (*got.IntegrationTypes)[0] != discordgo.ApplicationIntegrationGuildInstall {
				t.Fatal("command installation/context defaults changed")
			}
			if len(got.Options) != 1 || got.Options[0].Type != discordgo.ApplicationCommandOptionString || !got.Options[0].Required || got.Options[0].Name != "query" {
				t.Fatal("nested SDK option values were not retained")
			}
		})
	}
	if input.DefaultMemberPermissions != nil {
		t.Fatal("response changed the caller's absent permission")
	}
}

func TestCommandPermissionViewPreservesAllStates(t *testing.T) {
	for _, test := range []struct {
		name    string
		field   string
		want    *discordv2.Nullable[int64]
		decimal string
	}{
		{"absent", "", nil, ""},
		{"null", `,"default_member_permissions":null`, &discordv2.Nullable[int64]{Null: true}, ""},
		{"zero", `,"default_member_permissions":"0"`, &discordv2.Nullable[int64]{Value: 0}, "0"},
		{"nonzero", `,"default_member_permissions":"40"`, &discordv2.Nullable[int64]{Value: 40}, "40"},
		{"maximum", `,"default_member_permissions":"9223372036854775807"`, &discordv2.Nullable[int64]{Value: 9223372036854775807}, "9223372036854775807"},
	} {
		t.Run(test.name, func(t *testing.T) {
			projected, err := discordv2.ProjectApplicationCommandJSON(context.Background(), []byte(`{"id":"123","name":"permission-check"`+test.field+`}`), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := discordv2.ProtoToApplicationCommand(projected)
			if err != nil || got == nil {
				t.Fatalf("command decode: %#v, %v", got, err)
			}
			if test.want == nil {
				if got.DefaultMemberPermissions != nil {
					t.Fatal("absent became present")
				}
			} else if got.DefaultMemberPermissions == nil || *got.DefaultMemberPermissions != *test.want {
				t.Fatalf("permission state lost: %#v, want %#v", got.DefaultMemberPermissions, test.want)
			}
			encoded, err := discordv2.ApplicationCommandToProto(&discordv2.ApplicationCommandView{DefaultMemberPermissions: test.want})
			if err != nil {
				t.Fatal(err)
			}
			if test.want == nil {
				if encoded.DefaultMemberPermissions != nil {
					t.Fatal("absent permission encoded")
				}
			} else if test.want.Null {
				if _, ok := encoded.DefaultMemberPermissions.GetKind().(*corewire.NullableString_NullValue); !ok {
					t.Fatal("clear did not encode explicit null")
				}
			} else if value, ok := encoded.DefaultMemberPermissions.GetKind().(*corewire.NullableString_Value); !ok || value.Value != test.decimal {
				t.Fatalf("permission not encoded as an exact decimal string: %v", encoded.DefaultMemberPermissions)
			}
		})
	}
}

func TestCommandPermissionViewRejectsMalformedPresenceAndRange(t *testing.T) {
	for _, permission := range []*corewire.NullableString{
		{},
		{Kind: (*corewire.NullableString_Value)(nil)},
		{Kind: (*corewire.NullableString_NullValue)(nil)},
		{Kind: &corewire.NullableString_Value{Value: "-1"}},
		{Kind: &corewire.NullableString_Value{Value: "9223372036854775808"}},
		{Kind: &corewire.NullableString_Value{Value: "1.5"}},
	} {
		got, err := discordv2.ProtoToApplicationCommand(&wire.ApplicationCommand{DefaultMemberPermissions: permission})
		if got != nil {
			t.Fatal("invalid permission produced a partial command")
		}
		requireConversionError(t, err, "ProtoToStruct", "ApplicationCommand", "DefaultMemberPermissions")
	}
	got, err := discordv2.ApplicationCommandToProto(&discordv2.ApplicationCommandView{DefaultMemberPermissions: &discordv2.Nullable[int64]{Value: -1}})
	if got != nil {
		t.Fatal("negative permission produced a partial command")
	}
	requireConversionError(t, err, "StructToProto", "ApplicationCommand", "DefaultMemberPermissions")
}

func TestCommandOptionResponseBoundsPreserveAbsenceAndExplicitZero(t *testing.T) {
	for _, test := range []struct {
		name          string
		raw           string
		wantMaxValue  *float64
		wantMaxLength *int
	}{
		{"string autocomplete", `{"type":3,"name":"topic","description":"Choose a topic","autocomplete":true}`, nil, nil},
		{"numeric zero upper bound", `{"type":4,"name":"offset","description":"Nonpositive offset","max_value":0}`, new(float64(0)), nil},
		{"string length limit", `{"type":3,"name":"text","description":"Bounded text","max_length":200}`, nil, new(200)},
	} {
		t.Run(test.name, func(t *testing.T) {
			projected, err := discordv2.ProjectApplicationCommandJSON(context.Background(), []byte(`{"id":"123","name":"form","options":[{"type":1,"name":"run","description":"Nested command","options":[`+test.raw+`]}]}`), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			command, err := discordv2.ProtoToApplicationCommand(projected)
			if err != nil {
				t.Fatal(err)
			}
			if command == nil || len(command.Options) != 1 || len(command.Options[0].Options) != 1 {
				t.Fatal("recursive response option structure lost")
			}
			option := command.Options[0].Options[0]
			if (option.MaxValue == nil) != (test.wantMaxValue == nil) || (option.MaxValue != nil && *option.MaxValue != *test.wantMaxValue) {
				t.Fatalf("numeric bound presence changed: %#v, want %#v", option.MaxValue, test.wantMaxValue)
			}
			if (option.MaxLength == nil) != (test.wantMaxLength == nil) || (option.MaxLength != nil && *option.MaxLength != *test.wantMaxLength) {
				t.Fatalf("string bound presence changed: %#v, want %#v", option.MaxLength, test.wantMaxLength)
			}
		})
	}
}
