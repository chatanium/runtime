package discordv2_test

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"testing"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
)

func TestCommandPermissionsPreserveAbsentAndExplicitZero(t *testing.T) {
	absent, err := discordv2.ApplicationCommandToProto(&discordv2.ApplicationCommandView{Name: "absent"})
	if err != nil || absent.DefaultMemberPermissions != nil {
		t.Fatalf("absent permission: %v, %v", absent, err)
	}
	zero, err := discordv2.ApplicationCommandToProto(&discordv2.ApplicationCommandView{Name: "zero", DefaultMemberPermissions: &discordv2.Nullable[int64]{Value: 0}})
	if err != nil || zero.DefaultMemberPermissions == nil || zero.DefaultMemberPermissions.GetValue() != "0" {
		t.Fatalf("zero permission: %v, %v", zero, err)
	}
	decoded, err := discordv2.ProtoToApplicationCommand(&wire.ApplicationCommand{DefaultMemberPermissions: &corewire.NullableString{Kind: &corewire.NullableString_Value{Value: "0"}}})
	if err != nil || decoded.DefaultMemberPermissions == nil || decoded.DefaultMemberPermissions.Null || decoded.DefaultMemberPermissions.Value != 0 {
		t.Fatalf("decoded explicit zero: %#v, %v", decoded, err)
	}
	for _, invalid := range []string{"-1", "9223372036854775808", "1.5", "not-a-permission"} {
		t.Run(invalid, func(t *testing.T) {
			got, err := discordv2.ProtoToRole(&wire.Role{Permissions: new(invalid)})
			if got != nil {
				t.Fatal("invalid permission returned output")
			}
			requireConversionError(t, err, "ProtoToStruct", "Role", "Permissions")
		})
	}
	max, err := discordv2.RoleToProto(&discordgo.Role{Permissions: math.MaxInt64})
	if err != nil || max.GetPermissions() != "9223372036854775807" {
		t.Fatalf("permission precision: %v, %v", max, err)
	}
	negative, err := discordv2.RoleToProto(&discordgo.Role{Permissions: -1})
	if negative != nil {
		t.Fatal("negative permission accepted")
	}
	requireConversionError(t, err, "StructToProto", "Role", "Permissions")
}

func TestEnumsMasksAndStringValuesUseDiscordValues(t *testing.T) {
	message, err := discordv2.MessageToProto(&discordgo.Message{Flags: discordgo.MessageFlags(64 | 4096 | 1<<40), Type: discordgo.MessageType(701)})
	if err != nil || message.GetFlags() != 1099511631936 || message.GetType() != 701 {
		t.Fatalf("mask or unknown message type changed: %v, %v", message, err)
	}
	decoded, err := discordv2.ProtoToMessage(&wire.Message{Flags: new(uint64(64 | 4096)), Type: new(int64(702))})
	if err != nil || decoded.Flags != discordgo.MessageFlags(4160) || decoded.Type != discordgo.MessageType(702) {
		t.Fatalf("mask or type decoded incorrectly: %#v, %v", decoded, err)
	}
	overflow, err := discordv2.ProtoToMessage(&wire.Message{Flags: new(uint64(1) << 63)})
	if overflow != nil {
		t.Fatal("mask narrowing overflow accepted")
	}
	if detail := requireConversionError(t, err, "ProtoToStruct", "Message", "Flags"); detail.Code != "OutOfRange" {
		t.Fatalf("mask overflow code: %s", detail.Code)
	}
	command, err := discordv2.ProtoToApplicationCommand(&wire.ApplicationCommand{Type: new(uint32(255))})
	if err != nil || command.Type != discordgo.ApplicationCommandType(255) {
		t.Fatalf("representable unknown enum: %#v, %v", command, err)
	}
	command, err = discordv2.ProtoToApplicationCommand(&wire.ApplicationCommand{Type: new(uint32(256))})
	if command != nil {
		t.Fatal("uint8 enum overflow accepted")
	}
	if detail := requireConversionError(t, err, "ProtoToStruct", "ApplicationCommand", "Type"); detail.Code != "OutOfRange" {
		t.Fatalf("enum overflow code: %s", detail.Code)
	}
	channel, err := discordv2.ChannelToProto(&discordgo.Channel{Type: discordgo.ChannelTypeGuildText})
	if err != nil || channel.GetType() != 0 {
		t.Fatalf("channel type incorrectly offset: %v, %v", channel, err)
	}
	for _, embedType := range []discordgo.EmbedType{"", discordgo.EmbedTypeRich} {
		got, err := discordv2.MessageEmbedToProto(&discordgo.MessageEmbed{Type: embedType})
		if err != nil || got.GetType() != string(embedType) {
			t.Fatalf("embed type %q: %v, %v", embedType, got, err)
		}
	}
	mentions, err := discordv2.MessageAllowedMentionsToProto(&discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{discordgo.AllowedMentionTypeRoles, discordgo.AllowedMentionTypeUsers, discordgo.AllowedMentionTypeEveryone}})
	if err != nil {
		t.Fatal(err)
	}
	values := mentions.GetParse().GetValues()
	if len(values) != 3 || values[0] != "roles" || values[1] != "users" || values[2] != "everyone" {
		t.Fatalf("mention string values: %v", values)
	}
}

func TestIntegerOptionsSupportSDKIntValueAtExactBoundaries(t *testing.T) {
	for _, value := range []int64{0, -9007199254740991, 9007199254740991} {
		src := &wire.ApplicationCommandInteractionDataOption{Type: new(uint32(4)), Value: &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_IntegerValue{IntegerValue: value}}}
		got, err := discordv2.ProtoToApplicationCommandInteractionDataOption(src)
		if err != nil {
			t.Fatalf("integer %d: %v", value, err)
		}
		if _, ok := got.Value.(float64); !ok {
			t.Fatalf("integer accessor dynamic type: %T", got.Value)
		}
		if got.IntValue() != value {
			t.Fatalf("integer accessor got %d, want %d", got.IntValue(), value)
		}
		encoded, err := discordv2.ApplicationCommandInteractionDataOptionToProto(&discordgo.ApplicationCommandInteractionDataOption{Type: discordgo.ApplicationCommandOptionInteger, Value: float64(value)})
		if err != nil || encoded.GetValue().GetIntegerValue() != value {
			t.Fatalf("integer encoding %d: %v, %v", value, encoded, err)
		}
	}
}

func TestOptionNumericAndDiscriminatorFailures(t *testing.T) {
	for name, value := range map[string]any{"fraction": 1.5, "positive-overflow": float64(9007199254740992), "negative-overflow": float64(-9007199254740992), "nan": math.NaN(), "infinity": math.Inf(1), "wrong-type": "1"} {
		t.Run(name, func(t *testing.T) {
			got, err := discordv2.ApplicationCommandInteractionDataOptionToProto(&discordgo.ApplicationCommandInteractionDataOption{Type: discordgo.ApplicationCommandOptionInteger, Value: value})
			if got != nil {
				t.Fatal("invalid integer returned output")
			}
			requireConversionError(t, err, "StructToProto", "ApplicationCommandInteractionDataOption", "Value")
		})
	}
	for _, value := range []float64{-9007199254740992, 9007199254740992, 0.5} {
		got, err := discordv2.ProtoToApplicationCommandInteractionDataOption(&wire.ApplicationCommandInteractionDataOption{Type: new(uint32(10)), Value: &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_NumberValue{NumberValue: value}}})
		if err != nil || got.FloatValue() != value {
			t.Fatalf("number boundary %v: %#v, %v", value, got, err)
		}
	}
	for _, value := range []float64{9007199254740994, math.NaN(), math.Inf(-1)} {
		got, err := discordv2.ProtoToApplicationCommandInteractionDataOption(&wire.ApplicationCommandInteractionDataOption{Type: new(uint32(10)), Value: &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_NumberValue{NumberValue: value}}})
		if got != nil {
			t.Fatal("invalid number returned output")
		}
		requireConversionError(t, err, "ProtoToStruct", "ApplicationCommandInteractionDataOption", "Value")
	}
	wrong, err := discordv2.ProtoToApplicationCommandInteractionDataOption(&wire.ApplicationCommandInteractionDataOption{Type: new(uint32(4)), Value: &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_StringValue{StringValue: "17"}}})
	if wrong != nil {
		t.Fatal("string discriminator accepted as integer")
	}
	requireConversionError(t, err, "ProtoToStruct", "ApplicationCommandInteractionDataOption", "Value")
	tooLarge, err := discordv2.ProtoToApplicationCommandInteractionDataOption(&wire.ApplicationCommandInteractionDataOption{Type: new(uint32(4)), Value: &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_IntegerValue{IntegerValue: 9007199254740992}}})
	if tooLarge != nil {
		t.Fatal("wire integer outside Discord range accepted")
	}
	requireConversionError(t, err, "ProtoToStruct", "ApplicationCommandInteractionDataOption", "Value")
}

func TestChoiceRequiresMatchingParentAndPreservesLocalizations(t *testing.T) {
	choice := &discordgo.ApplicationCommandOptionChoice{Name: "one", NameLocalizations: map[discordgo.Locale]string{discordgo.French: "un"}, Value: "one"}
	got, err := discordv2.ApplicationCommandOptionChoiceToProto(choice, discordgo.ApplicationCommandOptionString)
	if err != nil || got.GetValue().GetStringValue() != "one" || got.GetNameLocalizations().GetValues()["fr"] != "un" {
		t.Fatalf("localized string choice: %v, %v", got, err)
	}
	invalid, err := discordv2.ApplicationCommandOptionChoiceToProto(choice, discordgo.ApplicationCommandOptionInteger)
	if invalid != nil {
		t.Fatal("string choice accepted under integer parent")
	}
	requireConversionError(t, err, "StructToProto", "ApplicationCommandOptionChoice", "Value")
	decoded, err := discordv2.ProtoToApplicationCommandOptionChoice(&wire.ApplicationCommandOptionChoice{Value: &wire.ApplicationCommandChoiceValue{Value: &wire.ApplicationCommandChoiceValue_IntegerValue{IntegerValue: 42}}}, discordgo.ApplicationCommandOptionBoolean)
	if decoded != nil {
		t.Fatal("boolean parent accepted choice")
	}
	requireConversionError(t, err, "ProtoToStruct", "ApplicationCommandOptionChoice", "")
	parent, err := discordv2.ApplicationCommandOptionToProto(&discordv2.ApplicationCommandOptionView{Type: discordgo.ApplicationCommandOptionInteger, Choices: []*discordgo.ApplicationCommandOptionChoice{choice}})
	if parent != nil {
		t.Fatal("parent failed to enforce choice type")
	}
	requireConversionError(t, err, "StructToProto", "ApplicationCommandOption", "Choices[0]")
}

func TestNestedOptionsAndIDKindsKeepTheirDiscriminators(t *testing.T) {
	for _, tc := range []struct {
		kind  discordgo.ApplicationCommandOptionType
		value *wire.ApplicationCommandOptionValue
	}{
		{discordgo.ApplicationCommandOptionRole, &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_RoleId{RoleId: "role-id"}}},
		{discordgo.ApplicationCommandOptionMentionable, &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_MentionableId{MentionableId: "mentionable-id"}}},
		{discordgo.ApplicationCommandOptionAttachment, &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_AttachmentId{AttachmentId: "attachment-id"}}},
	} {
		expected := map[discordgo.ApplicationCommandOptionType]string{discordgo.ApplicationCommandOptionRole: "role-id", discordgo.ApplicationCommandOptionMentionable: "mentionable-id", discordgo.ApplicationCommandOptionAttachment: "attachment-id"}[tc.kind]
		decoded, err := discordv2.ProtoToApplicationCommandInteractionDataOption(&wire.ApplicationCommandInteractionDataOption{Type: new(uint32(tc.kind)), Value: tc.value})
		if err != nil || decoded.Type != tc.kind || decoded.Value != expected {
			t.Fatalf("ID kind %d: %#v, %v", tc.kind, decoded, err)
		}
	}
	nested, err := discordv2.ApplicationCommandInteractionDataOptionToProto(&discordgo.ApplicationCommandInteractionDataOption{
		Name: "group", Type: discordgo.ApplicationCommandOptionSubCommandGroup,
		Options: []*discordgo.ApplicationCommandInteractionDataOption{{Name: "sub", Type: discordgo.ApplicationCommandOptionSubCommand, Options: []*discordgo.ApplicationCommandInteractionDataOption{{Name: "query", Type: discordgo.ApplicationCommandOptionString, Value: "needle", Focused: true}}}},
	})
	if err != nil || nested.Value != nil || nested.GetType() != 2 {
		t.Fatalf("group option: %v, %v", nested, err)
	}
	sub := nested.GetOptions().GetValues()[0]
	query := sub.GetOptions().GetValues()[0]
	if sub.Value != nil || sub.GetType() != 1 || query.GetName() != "query" || query.GetValue().GetStringValue() != "needle" || !query.GetFocused() {
		t.Fatalf("nested option loss: %v", nested)
	}
}

func TestChoiceRangeAndWireDiscriminatorAreChecked(t *testing.T) {
	for _, value := range []int64{-9007199254740991, 9007199254740991} {
		got, err := discordv2.ProtoToApplicationCommandOptionChoice(&wire.ApplicationCommandOptionChoice{Value: &wire.ApplicationCommandChoiceValue{Value: &wire.ApplicationCommandChoiceValue_IntegerValue{IntegerValue: value}}}, discordgo.ApplicationCommandOptionInteger)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(got.Value)
		if err != nil || string(raw) != strconv.FormatInt(value, 10) {
			t.Fatalf("integer choice %d: %s, %v", value, raw, err)
		}
	}
	mismatch, err := discordv2.ProtoToApplicationCommandOptionChoice(&wire.ApplicationCommandOptionChoice{Value: &wire.ApplicationCommandChoiceValue{Value: &wire.ApplicationCommandChoiceValue_NumberValue{NumberValue: 1}}}, discordgo.ApplicationCommandOptionInteger)
	if mismatch != nil {
		t.Fatal("number discriminator accepted as integer choice")
	}
	requireConversionError(t, err, "ProtoToStruct", "ApplicationCommandOptionChoice", "Value")
	overflow, err := discordv2.ApplicationCommandOptionChoiceToProto(&discordgo.ApplicationCommandOptionChoice{Value: float64(9007199254740992)}, discordgo.ApplicationCommandOptionInteger)
	if overflow != nil {
		t.Fatal("integer choice overflow accepted")
	}
	requireConversionError(t, err, "StructToProto", "ApplicationCommandOptionChoice", "Value")
}

func TestOutboundNumericDefaultsMatchSourceJSON(t *testing.T) {
	cases := []struct {
		name    string
		source  any
		fields  map[string]string
		convert func(any) (any, error)
	}{
		{"Poll", &discordgo.Poll{}, map[string]string{"Duration": "duration", "LayoutType": "layout_type"}, func(v any) (any, error) { return discordv2.PollToProto(v.(*discordgo.Poll)) }},
		{"SelectMenu", &discordgo.SelectMenu{}, map[string]string{"MaxValues": "max_values"}, func(v any) (any, error) { return discordv2.SelectMenuToProto(v.(*discordgo.SelectMenu)) }},
		{"FileUpload", &discordgo.FileUpload{}, map[string]string{"MaxValues": "max_values"}, func(v any) (any, error) { return discordv2.FileUploadToProto(v.(*discordgo.FileUpload)) }},
		{"TextInput", &discordgo.TextInput{}, map[string]string{"MaxLength": "max_length"}, func(v any) (any, error) { return discordv2.TextInputToProto(v.(*discordgo.TextInput)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := reflect.ValueOf(tc.source).Elem()
			for _, value := range []int64{0, 1, -1} {
				for field := range tc.fields {
					source.FieldByName(field).SetInt(value)
				}
				raw, err := json.Marshal(tc.source)
				if err != nil {
					t.Fatal(err)
				}
				var sourceJSON map[string]json.RawMessage
				if err = json.Unmarshal(raw, &sourceJSON); err != nil {
					t.Fatal(err)
				}
				converted, err := tc.convert(tc.source)
				if err != nil {
					t.Fatal(err)
				}
				output := reflect.ValueOf(converted).Elem()
				for field, jsonName := range tc.fields {
					wireField := output.FieldByName(field)
					_, sourcePresent := sourceJSON[jsonName]
					if (!wireField.IsNil()) != sourcePresent || !wireField.IsNil() && wireField.Elem().Int() != value {
						t.Fatalf("%s source omission/nonzero value changed", field)
					}
				}
			}
		})
	}
}
