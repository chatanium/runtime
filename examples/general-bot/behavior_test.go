package main

import (
	"errors"
	"testing"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestChannelPatchDistinguishesUnsetZeroAndClear(t *testing.T) {
	g := GuildConfig{Moderation: ModerationConfig{AllowedParentIDs: []string{"300"}}}
	stringOption := func(name, value string) *discordgo.ApplicationCommandInteractionDataOption {
		return &discordgo.ApplicationCommandInteractionDataOption{Name: name, Type: discordgo.ApplicationCommandOptionString, Value: value}
	}
	boolOption := func(name string, value bool) *discordgo.ApplicationCommandInteractionDataOption {
		return &discordgo.ApplicationCommandInteractionDataOption{Name: name, Type: discordgo.ApplicationCommandOptionBoolean, Value: value}
	}
	patch, err := channelPatch(g, commandOptions{"name": stringOption("name", "flex-test-renamed")})
	if err != nil {
		t.Fatal(err)
	}
	if patch.Topic != nil || patch.ParentID != nil || patch.RateLimitPerUser != nil || patch.PermissionOverwrites != nil {
		t.Fatal("an omitted field became a clear or zero")
	}
	patch, err = channelPatch(g, commandOptions{"slowmode": {Name: "slowmode", Type: discordgo.ApplicationCommandOptionInteger, Value: float64(0)}, "clear-topic": boolOption("clear-topic", true), "clear-parent": boolOption("clear-parent", true), "clear-overwrites": boolOption("clear-overwrites", true)})
	if err != nil {
		t.Fatal(err)
	}
	if patch.RateLimitPerUser == nil || *patch.RateLimitPerUser != 0 || patch.Topic == nil || patch.Topic.Null || patch.Topic.Value != "" || patch.ParentID == nil || !patch.ParentID.Null || patch.PermissionOverwrites == nil || len(patch.PermissionOverwrites) != 0 {
		t.Fatalf("clear/zero presence lost: %#v", patch)
	}
	if _, err = channelPatch(g, commandOptions{"parent": stringOption("parent", "400")}); err == nil {
		t.Fatal("unapproved parent accepted")
	}
	if _, err = channelPatch(g, commandOptions{"parent": stringOption("parent", "300"), "clear-parent": boolOption("clear-parent", true)}); err == nil {
		t.Fatal("contradictory parent set/clear accepted")
	}
}
func TestActorAndModalDoNotInventMissingIdentity(t *testing.T) {
	if _, err := actor(&discordgo.Interaction{GuildID: "100", User: &discordgo.User{ID: "200"}}); err == nil {
		t.Fatal("guild interaction borrowed the DM user")
	}
	if _, err := actor(&discordgo.Interaction{Member: &discordgo.Member{User: &discordgo.User{ID: "200"}}}); err == nil {
		t.Fatal("DM interaction borrowed the guild member")
	}
	if user, err := actor(&discordgo.Interaction{User: &discordgo.User{ID: "200"}}); err != nil || user != "200" {
		t.Fatalf("valid DM actor: %s %v", user, err)
	}
	input := discordgo.TextInput{CustomID: formInput, Value: "feedback"}
	if _, err := feedbackValue([]discordgo.MessageComponent{discordgo.ActionsRow{Components: []discordgo.MessageComponent{input, input}}}); err == nil {
		t.Fatal("duplicate modal field accepted")
	}
	if _, err := feedbackValue(nil); err == nil {
		t.Fatal("missing modal input invented")
	}
}
func TestAttachmentEditIncludesRetainedIDAndExplicitNewZero(t *testing.T) {
	entries, err := retainedAndNew(&discordgo.Message{Attachments: []*discordgo.MessageAttachment{{ID: "200"}}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := discord.AttachmentEditEntryToProto(&entries[1])
	if err != nil {
		t.Fatal(err)
	}
	if wire.Source == nil {
		t.Fatal("new index zero became absent")
	}
	back, err := discord.ProtoToAttachmentEditEntry(wire)
	if err != nil {
		t.Fatal(err)
	}
	index, ok := back.Source.(discord.NewFileIndex)
	if !ok || index != 0 {
		t.Fatalf("new index zero variant lost: %#v", back.Source)
	}
	if id, ok := entries[0].Source.(discord.ExistingAttachmentID); !ok || id != "200" {
		t.Fatal("retained ID lost")
	}
	if _, err = retainedAndNew(&discordgo.Message{}); err == nil {
		t.Fatal("missing remote attachment ID invented")
	}
	// An embedded upload can legitimately have an empty attachment list. Its
	// image URL is not authority to invent an attachment ID for a later edit.
	if _, err = retainedAndNew(&discordgo.Message{
		Attachments: []*discordgo.MessageAttachment{},
		Embeds:      []*discordgo.MessageEmbed{{Image: &discordgo.MessageEmbedImage{URL: "https://cdn.discordapp.com/attachments/100/200/sample.png"}}},
	}); err == nil {
		t.Fatal("embedded image URL became a synthetic attachment ID")
	}
}
func TestScopedGrantDoesNotBecomeWildcard(t *testing.T) {
	grants := []*corewire.CapabilityGrant{{Name: "test", ResourceScopes: []*corewire.ResourceScope{{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{ResourceIds: map[string]string{"guild_id": "100", "channel_id": "200"}}}}}}}
	if !allows(grants, "test", map[string]string{"guild_id": "100", "channel_id": "200"}) {
		t.Fatal("exact conjunction rejected")
	}
	for _, ids := range []map[string]string{{"guild_id": "100"}, {"guild_id": "101", "channel_id": "200"}, {"guild_id": "100", "channel_id": "201"}} {
		if allows(grants, "test", ids) {
			t.Fatalf("scope widened: %v", ids)
		}
	}
}
func TestExpectedErrorReportingCannotHideInternalCause(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "safe denial")
	if !expectedCommandFailure(denied) {
		t.Fatal("ordinary permission rejection became fatal")
	}
	if expectedCommandFailure(errors.Join(errors.New("storage corruption"), denied)) {
		t.Fatal("reportable remote error hid an internal failure")
	}
	if expectedCommandFailure(&changedResourceError{channelID: "200", cause: denied}) {
		t.Fatal("durability failure was treated as an ordinary command rejection")
	}
}
