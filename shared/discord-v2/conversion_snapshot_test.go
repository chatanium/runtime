package discordv2_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
)

func requireConversionError(t *testing.T, err error, direction, message, path string) *discordv2.ConversionError {
	t.Helper()
	var detail *discordv2.ConversionError
	if !errors.As(err, &detail) {
		t.Fatalf("want ConversionError, got %T: %v", err, err)
	}
	if detail.Direction != direction || detail.Message != message || detail.Code == "" || detail.Reason == "" || !strings.Contains(detail.Path, path) {
		t.Fatalf("incomplete conversion diagnostic: %#v", detail)
	}
	return detail
}

func TestSnapshotFieldsHaveIndependentValues(t *testing.T) {
	thumbnail, err := discordv2.MessageEmbedThumbnailToProto(&discordgo.MessageEmbedThumbnail{Width: 641, Height: 359})
	if err != nil || thumbnail.GetWidth() != 641 || thumbnail.GetHeight() != 359 {
		t.Fatalf("thumbnail: %v, %v", thumbnail, err)
	}
	decoded, err := discordv2.ProtoToMessageEmbedThumbnail(&wire.MessageEmbedThumbnail{Width: new(int64(1920)), Height: new(int64(1080))})
	if err != nil || decoded.Width != 1920 || decoded.Height != 1080 {
		t.Fatalf("decoded thumbnail: %v, %v", decoded, err)
	}
	emoji, err := discordv2.EmojiToProto(&discordgo.Emoji{Available: true, Animated: false})
	if err != nil || !emoji.GetAvailable() || emoji.GetAnimated() {
		t.Fatalf("emoji: %v, %v", emoji, err)
	}
	decodedEmoji, err := discordv2.ProtoToEmoji(&wire.Emoji{Available: new(false), Animated: new(true)})
	if err != nil || decodedEmoji.Available || !decodedEmoji.Animated {
		t.Fatalf("decoded emoji: %v, %v", decodedEmoji, err)
	}
}

func TestResolvedKeysAndPartialMembersAreNotReconstructed(t *testing.T) {
	src := &discordgo.ApplicationCommandInteractionDataResolved{
		Users:       map[string]*discordgo.User{"lookup-user": {ID: "embedded-user", Username: "original"}},
		Members:     map[string]*discordgo.Member{"lookup-member": {Nick: "partial", Roles: []string{"role-a"}}},
		Channels:    map[string]*discordgo.Channel{"lookup-channel": {ID: "embedded-channel", Name: "partial channel"}},
		Attachments: map[string]*discordgo.MessageAttachment{"lookup-file": {ID: "embedded-file", Filename: "voice.ogg", DurationSecs: 1.25, Waveform: "AQID", Flags: 4}},
	}
	got, err := discordv2.ApplicationCommandInteractionDataResolvedToProto(src)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetUsers().GetValues()["lookup-user"].GetId() != "embedded-user" || got.GetMembers().GetValues()["lookup-member"].GetUser() != nil || got.GetChannels().GetValues()["lookup-channel"].GetId() != "embedded-channel" {
		t.Fatalf("resolved identity changed: %v", got)
	}
	file := got.GetAttachments().GetValues()["lookup-file"]
	if file.GetDurationSecs() != 1.25 || file.GetWaveform() != "AQID" || file.GetFlags() != 4 {
		t.Fatalf("attachment fields: %v", file)
	}
	src.Users["lookup-user"].Username = "mutated"
	src.Members["lookup-member"].Roles[0] = "changed"
	if got.GetUsers().GetValues()["lookup-user"].GetUsername() != "original" || got.GetMembers().GetValues()["lookup-member"].GetRoles().GetValues()[0] != "role-a" {
		t.Fatal("wire snapshot aliases source")
	}
	decoded, err := discordv2.ProtoToApplicationCommandInteractionDataResolved(&wire.ApplicationCommandInteractionDataResolved{
		Members: &wire.DomainStringToMemberMap{Values: map[string]*wire.Member{"original-key": {Nick: new("wire partial")}}},
	})
	if err != nil || len(decoded.Members) != 1 || decoded.Members["original-key"] == nil || decoded.Members["original-key"].User != nil || decoded.Members["original-key"].Nick != "wire partial" {
		t.Fatalf("decoded partial member: %#v, %v", decoded, err)
	}
}

func TestNilAndPartialSnapshots(t *testing.T) {
	if got, err := discordv2.MessageToProto(nil); got != nil || err != nil {
		t.Fatalf("nil source: %v, %v", got, err)
	}
	if got, err := discordv2.ProtoToMessage(nil); got != nil || err != nil {
		t.Fatalf("nil wire: %v, %v", got, err)
	}
	// Full SDK Activity stores these nested objects as values. Explicit empty
	// containers represent their zero values; ingress PartialActivity owns absence.
	activity, err := discordv2.ProtoToActivity(&wire.Activity{
		Name:       new("partial"),
		Timestamps: &wire.TimeStamps{},
		Emoji:      &wire.Emoji{},
		Party:      &wire.Party{},
		Assets:     &wire.Assets{},
		Secrets:    &wire.Secrets{},
	})
	if err != nil || activity.Name != "partial" || activity.Party.ID != "" || activity.Party.Size != nil || activity.Assets != (discordgo.Assets{}) || activity.Secrets != (discordgo.Secrets{}) {
		t.Fatalf("partial activity: %#v, %v", activity, err)
	}
	message, err := discordv2.ProtoToMessage(&wire.Message{Id: new("1")})
	if err != nil || message.EditedTimestamp != nil || message.Author != nil || message.Member != nil || message.ReferencedMessage != nil || message.Thread != nil {
		t.Fatalf("fabricated snapshot: %#v, %v", message, err)
	}
}

func TestCyclesFailButSharedAcyclicPointersAreValid(t *testing.T) {
	cycle := &discordgo.Message{ID: "1"}
	cycle.ReferencedMessage = cycle
	got, err := discordv2.MessageToProto(cycle)
	if got != nil {
		t.Fatal("cycle returned partial output")
	}
	requireConversionError(t, err, "StructToProto", "Message", "ReferencedMessage")
	wireCycle := &wire.Message{Id: new("2")}
	wireCycle.ReferencedMessage = wireCycle
	decoded, err := discordv2.ProtoToMessage(wireCycle)
	if decoded != nil {
		t.Fatal("wire cycle returned partial output")
	}
	requireConversionError(t, err, "ProtoToStruct", "Message", "ReferencedMessage")
	user := &discordgo.User{ID: "3", Username: "shared"}
	dag, err := discordv2.MessageToProto(&discordgo.Message{Author: user, Mentions: []*discordgo.User{user, user}})
	if err != nil || dag.GetAuthor().GetUsername() != "shared" || len(dag.GetMentions().GetValues()) != 2 || dag.GetMentions().GetValues()[1].GetId() != "3" {
		t.Fatalf("valid shared source: %v, %v", dag, err)
	}
	wireUser := &wire.User{Id: new("4"), Username: new("wire shared"), PrimaryGuild: &wire.UserPrimaryGuild{}}
	wireDAG := &wire.Message{Author: wireUser, Mentions: &wire.DomainUserList{Values: []*wire.User{wireUser, wireUser}}}
	decodedDAG, err := discordv2.ProtoToMessage(wireDAG)
	if err != nil || decodedDAG.Author.Username != "wire shared" || len(decodedDAG.Mentions) != 2 || decodedDAG.Mentions[1].ID != "4" {
		t.Fatalf("valid shared wire: %#v, %v", decodedDAG, err)
	}
}

func TestNilCollectionElementsAreNotSilentlyDropped(t *testing.T) {
	got, err := discordv2.MessageToProto(&discordgo.Message{Mentions: []*discordgo.User{{ID: "first"}, nil, {ID: "third"}}})
	if got != nil {
		t.Fatal("nil member returned a shortened snapshot")
	}
	requireConversionError(t, err, "StructToProto", "Message", "Mentions[1]")
	decoded, err := discordv2.ProtoToMessage(&wire.Message{Mentions: &wire.DomainUserList{Values: []*wire.User{{Id: new("first"), PrimaryGuild: &wire.UserPrimaryGuild{}}, nil}}})
	if decoded != nil {
		t.Fatal("nil wire element returned a shortened snapshot")
	}
	requireConversionError(t, err, "ProtoToStruct", "Message", "Mentions[1]")
}

func TestMessageRelationshipsSurviveAsIndependentWireFields(t *testing.T) {
	got, err := discordv2.MessageToProto(&discordgo.Message{
		ID:                  "message",
		Interaction:         &discordgo.MessageInteraction{ID: "legacy-interaction", Name: "legacy"},
		InteractionMetadata: &discordgo.MessageInteractionMetadata{ID: "interaction-metadata"},
		MessageReference:    &discordgo.MessageReference{MessageID: "reference", ChannelID: "reference-channel"},
		ReferencedMessage:   &discordgo.Message{ID: "referenced", Content: "quoted"},
		MessageSnapshots:    []discordgo.MessageSnapshot{{Message: &discordgo.Message{ID: "forwarded", Content: "snapshot"}}},
		Reactions:           []*discordgo.MessageReactions{{Count: 3, Me: true, Emoji: &discordgo.Emoji{Name: "reaction"}}},
		Thread:              &discordgo.Channel{ID: "thread", Name: "discussion"},
		StickerItems:        []*discordgo.StickerItem{{ID: "sticker", Name: "wave"}},
		Poll:                &discordgo.Poll{Question: discordgo.PollMedia{Text: "Question?"}, AllowMultiselect: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetInteraction().GetId() != "legacy-interaction" || got.GetInteractionMetadata().GetId() != "interaction-metadata" || got.GetMessageReference().GetMessageId() != "reference" || got.GetReferencedMessage().GetContent() != "quoted" || got.GetMessageSnapshots().GetValues()[0].GetMessage().GetContent() != "snapshot" || got.GetReactions().GetValues()[0].GetCount() != 3 || !got.GetReactions().GetValues()[0].GetMe() || got.GetThread().GetName() != "discussion" || got.GetStickerItems().GetValues()[0].GetName() != "wave" || got.GetPoll().GetQuestion().GetText() != "Question?" || !got.GetPoll().GetAllowMultiselect() {
		t.Fatalf("message relationship loss: %v", got)
	}
	decoded, err := discordv2.ProtoToMessage(&wire.Message{
		MessageReference:  &wire.MessageReference{MessageId: new("wire-reference")},
		ReferencedMessage: &wire.Message{Content: new("wire quote")},
		Thread:            &wire.Channel{Name: new("wire thread"), DefaultReactionEmoji: &wire.ForumDefaultReaction{}},
		Poll:              &wire.Poll{Question: &wire.PollMedia{Text: new("Wire question")}},
	})
	if err != nil || decoded.MessageReference.MessageID != "wire-reference" || decoded.ReferencedMessage.Content != "wire quote" || decoded.Thread.Name != "wire thread" || decoded.Poll.Question.Text != "Wire question" {
		t.Fatalf("decoded relationships: %#v, %v", decoded, err)
	}
}

func TestProviderSnapshotValueObjectPresence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		author  string
		present bool
		want    discordgo.UserPrimaryGuild
	}{
		{name: "absent", author: `{"id":"42"}`},
		{name: "null", author: `{"id":"42","primary_guild":null}`},
		{name: "empty", author: `{"id":"42","primary_guild":{}}`, present: true},
		{name: "value", author: `{"id":"42","primary_guild":{"identity_guild_id":"84","identity_enabled":true,"tag":"TAG","badge":"badge"}}`, present: true, want: discordgo.UserPrimaryGuild{IdentityGuildID: "84", IdentityEnabled: true, Tag: "TAG", Badge: "badge"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The typed provider snapshot remains authoritative for presence.
			// Only the SDK's nonpointer value field collapses absence to zero.
			snapshot, err := discordv2.ProjectMessageJSON(context.Background(), []byte(`{"id":"21","author":`+tc.author+`,"member":null}`), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Author == nil || (snapshot.Author.PrimaryGuild != nil) != tc.present || snapshot.Member != nil {
				t.Fatal("provider snapshot presence changed")
			}
			decoded, err := discordv2.ProtoToMessage(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Author == nil || decoded.Author.ID != "42" || decoded.Author.PrimaryGuild != tc.want || decoded.Member != nil || decoded.EditedTimestamp != nil {
				t.Fatal("SDK value adaptation changed fields or pointer presence")
			}
			if (snapshot.Author.PrimaryGuild != nil) != tc.present {
				t.Fatal("SDK conversion mutated authoritative snapshot")
			}
		})
	}
}

func TestAbsentSnapshotValueObjectsAcrossFamilies(t *testing.T) {
	activity, err := discordv2.ProjectActivityJSON(context.Background(), []byte(`{"name":"partial","timestamps":null,"assets":null}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if activity.Timestamps != nil || activity.Emoji != nil || activity.Party != nil || activity.Assets != nil || activity.Secrets != nil {
		t.Fatal("projection fabricated missing activity objects")
	}
	decoded, err := discordv2.ProtoToActivity(activity)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "partial" || decoded.Timestamps != (discordgo.TimeStamps{}) || decoded.Emoji.ID != "" || decoded.Party.ID != "" || decoded.Party.Size != nil || decoded.Assets != (discordgo.Assets{}) || decoded.Secrets != (discordgo.Secrets{}) {
		t.Fatal("missing activity value objects did not remain SDK zero values")
	}
	channel, err := discordv2.ProjectChannelJSON(context.Background(), []byte(`{"id":"42","default_reaction_emoji":null}`), nil, nil)
	if err != nil || channel.DefaultReactionEmoji != nil {
		t.Fatal("channel projection changed null value object")
	}
	decodedChannel, err := discordv2.ProtoToChannel(channel)
	if err != nil || decodedChannel.ID != "42" || decodedChannel.DefaultReactionEmoji != (discordgo.ForumDefaultReaction{}) {
		t.Fatal("channel value object adaptation failed")
	}
}

func TestSnapshotValueObjectAdaptationKeepsInvalidInputsStrict(t *testing.T) {
	for _, raw := range []string{
		`{"author":{"primary_guild":[]}}`,
		`{"author":{"primary_guild":false}}`,
		`{"author":{"primary_guild":{"identity_enabled":"true"}}}`,
	} {
		snapshot, err := discordv2.ProjectMessageJSON(context.Background(), []byte(raw), nil, nil)
		if snapshot != nil {
			t.Fatal("invalid provider object returned partial output")
		}
		requireConversionError(t, err, "StructToProto", "Message", "Author.PrimaryGuild")
	}
	decoded, err := discordv2.ProtoToMessage(&wire.Message{
		Author:   &wire.User{Id: new("42")},
		Mentions: &wire.DomainUserList{Values: []*wire.User{nil}},
	})
	if decoded != nil {
		t.Fatal("null collection element returned partial output")
	}
	requireConversionError(t, err, "ProtoToStruct", "Message", "Mentions[0]")
	patch, err := discordv2.ProtoToChannelEdit(&wire.ChannelEdit{
		DefaultReactionEmoji: &wire.DomainNullableForumDefaultReaction{
			Kind: &wire.DomainNullableForumDefaultReaction_Value{},
		},
	})
	if patch != nil {
		t.Fatal("selected nullable value without an object returned partial output")
	}
	requireConversionError(t, err, "ProtoToStruct", "ChannelEdit", "DefaultReactionEmoji")
}
