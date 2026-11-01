package discordv2_test

import (
	"context"
	"testing"

	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
)

func TestPermissionsUpdateIngressPreservesFalseAndNullElements(t *testing.T) {
	raw := []byte(`{"id":"123456789012345678","application_id":"223456789012345678","guild_id":"323456789012345678","permissions":[{"id":"423456789012345678","permission":false},null]}`)
	got, err := discordv2.ProjectApplicationCommandPermissionsUpdateEvent(context.Background(), raw, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := got.GetGuildApplicationCommandPermissions().GetValue()
	if payload.GetId().GetValue() != "123456789012345678" || payload.GetApplicationId().GetValue() != "223456789012345678" || payload.GetGuildId().GetValue() != "323456789012345678" {
		t.Fatalf("permission event identity: %v", got)
	}
	entries := payload.GetPermissions().GetValue().GetValues()
	if len(entries) != 2 {
		t.Fatalf("permission entries, including null, changed: %v", entries)
	}
	first := entries[0].GetValue()
	if first.GetId().GetValue() != "423456789012345678" || first.Type != nil {
		t.Fatalf("partial permission entry: %v", first)
	}
	permission, ok := first.GetPermission().GetKind().(*wire.DomainNullableBool_Value)
	if !ok || permission.Value {
		t.Fatalf("explicit false permission lost presence: %v", first.GetPermission())
	}
	if _, ok := entries[1].GetKind().(*wire.DomainNullablePartialApplicationCommandPermissions_NullValue); !ok {
		t.Fatalf("null permission element replaced or dropped: %v", entries[1])
	}
}

func TestPermissionsUpdateIngressKeepsNestedAbsentAndNullDistinct(t *testing.T) {
	got, err := discordv2.ProjectApplicationCommandPermissionsUpdateEvent(context.Background(), []byte(`{"id":"123456789012345678","permissions":[{"id":"423456789012345678"},{"id":"523456789012345678","permission":null}]}`), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := got.GetGuildApplicationCommandPermissions().GetValue().GetPermissions().GetValue().GetValues()
	if len(entries) != 2 || entries[0].GetValue().GetId().GetValue() != "423456789012345678" || entries[1].GetValue().GetId().GetValue() != "523456789012345678" {
		t.Fatalf("partial permission entries: %v", entries)
	}
	if entries[0].GetValue().Permission != nil {
		t.Fatal("absent nested permission fabricated a value")
	}
	if _, ok := entries[1].GetValue().GetPermission().GetKind().(*wire.DomainNullableBool_NullValue); !ok {
		t.Fatalf("explicit null nested permission lost: %v", entries[1])
	}
	omitted, err := discordv2.ProjectApplicationCommandPermissionsUpdateEvent(context.Background(), []byte(`{"id":"123456789012345678"}`), nil, nil, nil)
	if err != nil || omitted.GetGuildApplicationCommandPermissions().GetValue().Permissions != nil {
		t.Fatalf("omitted permission collection: %v, %v", omitted, err)
	}
	null, err := discordv2.ProjectApplicationCommandPermissionsUpdateEvent(context.Background(), []byte(`{"id":"123456789012345678","permissions":null}`), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := null.GetGuildApplicationCommandPermissions().GetValue().GetPermissions().GetKind().(*wire.DomainNullableDomainDomainNullablePartialApplicationCommandPermissionsList_NullValue); !ok {
		t.Fatalf("explicit null permission collection lost: %v", null)
	}
}

func TestInteractionIngressUsesParentDiscriminatorAfterData(t *testing.T) {
	// Both the interaction kind and the option kind follow the payload whose
	// interpretation they control. No SDK-decoded value can supply presence.
	raw := []byte(`{"id":"123456789012345678","data":{"name":"lookup","options":[{"value":0,"focused":false,"name":"amount","type":4}],"type":1},"type":4}`)
	got, err := discordv2.ProjectInteractionCreateEvent(context.Background(), raw, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	interaction := got.GetInteraction().GetValue()
	if interaction.GetId().GetValue() != "123456789012345678" || interaction.GetType().GetValue() != 4 {
		t.Fatalf("autocomplete parent kind: %v", got)
	}
	command, ok := interaction.GetData().GetValue().GetData().(*wire.PartialInteractionData_ApplicationCommand)
	if !ok || command.ApplicationCommand.GetName().GetValue() != "lookup" || command.ApplicationCommand.GetCommandType().GetValue() != 1 {
		t.Fatalf("parent-discriminated command data: %v", interaction.GetData())
	}
	options := command.ApplicationCommand.GetOptions().GetValue().GetValues()
	if len(options) != 1 {
		t.Fatalf("autocomplete options: %v", options)
	}
	option := options[0].GetValue()
	if option.GetType().GetValue() != 4 || option.GetName().GetValue() != "amount" {
		t.Fatalf("option parent kind: %v", option)
	}
	integer, ok := option.GetValue().GetValue().GetValue().(*wire.ApplicationCommandOptionValue_IntegerValue)
	if !ok || integer.IntegerValue != 0 {
		t.Fatalf("zero INTEGER discriminator or presence lost: %v", option.GetValue())
	}
	focused, ok := option.GetFocused().GetKind().(*wire.DomainNullableBool_Value)
	if !ok || focused.Value {
		t.Fatalf("explicit false focus lost: %v", option.GetFocused())
	}
}

func TestPresenceIngressDoesNotFabricateNestedActivityOrUserValues(t *testing.T) {
	got, err := discordv2.ProjectPresenceUpdateEvent(context.Background(), []byte(`{"guild_id":"123456789012345678","user":{"id":"223456789012345678"},"activities":[{"name":"partial"}]}`), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	presence := got.GetPresence().GetValue()
	activities := presence.GetActivities().GetValue().GetValues()
	if len(activities) != 1 || activities[0].GetValue().GetName().GetValue() != "partial" {
		t.Fatalf("partial activity identity: %v", presence)
	}
	activity := activities[0].GetValue()
	if activity.Timestamps != nil || activity.Emoji != nil || activity.Party != nil || activity.Assets != nil || activity.Secrets != nil {
		t.Fatalf("absent nested activity fields were fabricated: %v", activity)
	}
	user := presence.GetUser().GetValue()
	if user.GetId().GetValue() != "223456789012345678" || user.PrimaryGuild != nil || presence.ClientStatus != nil {
		t.Fatalf("absent user or presence value fields were fabricated: %v", presence)
	}
}
