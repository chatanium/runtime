package discordbackend

import (
	"bytes"
	"context"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/proto"
)

func TestVoiceStateRESTProjectionPreservesFieldsWithoutSessionSecrets(t *testing.T) {
	value, err := projectRESTResponse(context.Background(), "UserVoiceState", []byte(`{"guild_id":"111","channel_id":"222","user_id":"333","session_id":"runtime-session-secret","mute":true,"deaf":false,"member":{"user":{"id":"333","username":"listener","token":"runtime-user-secret"}}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := value.(*wire.UserVoiceStateResponse).Value
	if state == nil || state.GetGuildId() != "111" || state.GetChannelId() != "222" || state.GetUserId() != "333" {
		t.Fatal("voice observation identifiers were changed or dropped")
	}
	if state.Mute == nil || !*state.Mute || state.Deaf == nil || *state.Deaf {
		t.Fatal("explicit mute/deaf presence was lost")
	}
	if state.GetMember().GetUser().GetId() != "333" || state.GetMember().GetUser().GetUsername() != "listener" {
		t.Fatal("safe nested member data was dropped while stripping credentials")
	}
	encoded, err := proto.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"runtime-session-secret", "runtime-user-secret"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("runtime credential escaped voice observation projection")
		}
	}
}

func TestMessageRESTProjectionPreservesExplicitEmptyAndZero(t *testing.T) {
	value, err := projectRESTResponse(context.Background(), "ChannelMessageSendComplex", []byte(`{"id":"8008","channel_id":"9009","content":"","tts":false,"flags":0,"embeds":[],"components":[]}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := value.(*wire.ChannelMessageSendComplexResponse).Value
	if message == nil || message.GetId() != "8008" || message.GetChannelId() != "9009" {
		t.Fatal("message result addressed a different resource")
	}
	if message.Content == nil || *message.Content != "" || message.Tts == nil || *message.Tts || message.Flags == nil || *message.Flags != 0 {
		t.Fatal("explicit empty, false or zero response field became absent")
	}
	if message.Embeds == nil || len(message.Embeds.Values) != 0 {
		t.Fatal("present empty embeds were dropped")
	}
	if message.Components == nil || len(message.Components.Values) != 0 {
		t.Fatal("present empty components were dropped")
	}
	absent, err := projectRESTResponse(context.Background(), "ChannelMessageSendComplex", []byte(`{"id":"8118","channel_id":"9229","content":"ordinary"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	absentMessage := absent.(*wire.ChannelMessageSendComplexResponse).Value
	if absentMessage.Embeds != nil || absentMessage.Components != nil {
		t.Fatal("absent response collections became explicit empty collections")
	}
	populated, err := projectRESTResponse(context.Background(), "ChannelMessageSendComplex", []byte(`{"id":"8338","channel_id":"9449","flags":32768,"components":[{"type":10,"content":"shown"}]}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	populatedMessage := populated.(*wire.ChannelMessageSendComplexResponse).Value
	if populatedMessage.Components == nil || len(populatedMessage.Components.Values) != 1 {
		t.Fatal("populated response components were dropped or replaced with an empty default")
	}
	display := populatedMessage.Components.Values[0].GetTextDisplay()
	if display == nil || display.Content == nil || *display.Content != "shown" {
		t.Fatal("response component discriminator or safe content was lost")
	}
}

func TestPinnedMessageRESTProjectionPreservesPaginationAndTimestamp(t *testing.T) {
	value, err := projectRESTResponse(context.Background(), "ChannelMessagesPinned", []byte(`{"items":[{"pinned_at":"2026-10-30T12:34:56.123Z","message":{"id":"6060","channel_id":"7070"}}],"has_more":true}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pins := value.(*wire.ChannelMessagesPinnedResponse).Value
	if pins == nil || pins.Items == nil || len(pins.Items.Values) != 1 || pins.HasMore == nil || !*pins.HasMore {
		t.Fatal("pin page was flattened or pagination was dropped")
	}
	pin := pins.Items.Values[0]
	if pin == nil || pin.Message == nil || pin.Message.GetId() != "6060" || pin.Message.GetChannelId() != "7070" {
		t.Fatal("pinned message identity was not retained")
	}
	want := time.Date(2026, 10, 30, 12, 34, 56, 123000000, time.UTC)
	if pin.PinnedAt == nil || !pin.PinnedAt.AsTime().Equal(want) {
		t.Fatal("pin timestamp precision was lost")
	}
}

func TestGatewayBotRESTProjectionPreservesCompleteSnapshot(t *testing.T) {
	value, err := projectRESTResponse(context.Background(), "GatewayBot", []byte(`{"url":"wss://gateway.discord.gg","shards":3,"session_start_limit":{"total":20,"remaining":7,"reset_after":123456,"max_concurrency":2}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway := value.(*wire.GatewayBotResponse)
	if gateway.GetUrl() != "wss://gateway.discord.gg/" || gateway.GetShards() != 3 {
		t.Fatal("public gateway URL or shard recommendation changed")
	}
	limit := gateway.SessionStartLimit
	if limit == nil || limit.GetTotal() != 20 || limit.GetRemaining() != 7 || limit.GetResetAfter() != 123456 || limit.GetMaxConcurrency() != 2 {
		t.Fatal("gateway start-limit snapshot was reduced or its milliseconds changed")
	}
	if value, err = projectRESTResponse(context.Background(), "GatewayBot", []byte(`{"url":"wss://gateway.discord.gg","shards":3}`), nil, nil); err == nil || value != nil {
		t.Fatal("incomplete gateway snapshot became a successful result")
	}
}

func TestMalformedRESTResponseDoesNotPublishPartialDTO(t *testing.T) {
	for _, operation := range []string{"Guild", "ChannelMessageSendComplex", "ChannelMessagesPinned", "GuildRoleMemberCounts", "GatewayBot", "WebhookMessage"} {
		value, err := projectRESTResponse(context.Background(), operation, []byte(":"), nil, nil)
		if err == nil || value != nil {
			t.Fatalf("%s accepted malformed upstream data or returned a partial result", operation)
		}
	}
}
