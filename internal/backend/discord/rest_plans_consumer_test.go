package discordbackend

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestChannelMessagesCursorAndQueryContract(t *testing.T) {
	cases := []struct {
		name, before, after, around string
		query                       url.Values
	}{
		{"before", "24680", "", "", url.Values{"before": {"24680"}, "limit": {"25"}}},
		{"after", "", "35791", "", url.Values{"after": {"35791"}, "limit": {"25"}}},
		{"around", "", "", "46802", url.Values{"around": {"46802"}, "limit": {"25"}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan, err := buildRESTPlan("ChannelMessages", &wire.ChannelMessagesRequest{ChannelId: "13579", Limit: 25, BeforeId: test.before, AfterId: test.after, AroundId: test.around})
			if err != nil {
				t.Fatal(err)
			}
			if plan.Request.Method != "GET" || plan.Request.Path != "/api/v10/channels/13579/messages" {
				t.Fatal("message listing addressed the wrong channel endpoint")
			}
			if !reflect.DeepEqual(plan.Request.Query, test.query) {
				t.Fatalf("cursor/query changed: %v", plan.Request.Query)
			}
			if len(plan.Targets) != 1 || plan.Targets[0].Kind != "channel_id" || plan.Targets[0].ID != "13579" {
				t.Fatal("pagination cursor was treated as an independent resource")
			}
		})
	}
	for _, request := range []*wire.ChannelMessagesRequest{
		{ChannelId: "13579", BeforeId: "24680", AfterId: "35791"},
		{ChannelId: "13579", BeforeId: "24680", AroundId: "46802"},
		{ChannelId: "13579", AfterId: "35791", AroundId: "46802"},
	} {
		if _, err := buildRESTPlan("ChannelMessages", request); status.Code(err) != codes.InvalidArgument {
			t.Fatal("mutually exclusive cursors were not rejected")
		}
	}
	plan, err := buildRESTPlan("ChannelMessages", &wire.ChannelMessagesRequest{ChannelId: "13579"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Request.Query) != 0 {
		t.Fatal("unspecified pagination acquired hidden query defaults")
	}
}

func TestUserGuildsWithCountsQueryContract(t *testing.T) {
	for _, withCounts := range []bool{false, true} {
		plan, err := buildRESTPlan("UserGuilds", &wire.UserGuildsRequest{Limit: 17, BeforeId: "550055", WithCounts: withCounts})
		if err != nil {
			t.Fatal(err)
		}
		if plan.Request.Method != "GET" || plan.Request.Path != "/api/v10/users/@me/guilds" {
			t.Fatal("bot guild listing addressed a different principal")
		}
		want := url.Values{"limit": {"17"}, "before": {"550055"}}
		if withCounts {
			want.Set("with_counts", "true")
		}
		if !reflect.DeepEqual(plan.Request.Query, want) {
			t.Fatalf("guild count/pagination options changed: %v", plan.Request.Query)
		}
	}
}

func TestInviteWithCountsQueryContract(t *testing.T) {
	for _, withCounts := range []bool{false, true} {
		plan, err := buildRESTPlan("InviteComplex", &wire.InviteComplexRequest{InviteId: "invite-code-A", GuildScheduledEventId: "990099", WithCounts: withCounts, WithExpiration: true})
		if err != nil {
			t.Fatal(err)
		}
		if plan.Request.Method != "GET" || plan.Request.Path != "/api/v10/invites/invite-code-A" {
			t.Fatal("invite code was replaced by the scheduled event ID")
		}
		want := url.Values{"guild_scheduled_event_id": {"990099"}, "with_expiration": {"true"}}
		if withCounts {
			want.Set("with_counts", "true")
		}
		if !reflect.DeepEqual(plan.Request.Query, want) {
			t.Fatalf("invite options changed: %v", plan.Request.Query)
		}
		invite, event := false, false
		for _, target := range plan.Targets {
			if target.Kind == "invite_id" && target.ID == "invite-code-A" {
				invite = true
			}
			if target.Kind == "scheduled_event_id" && target.ID == "990099" {
				event = true
			}
		}
		if !invite || !event {
			t.Fatal("invite/event relationship targets were conflated or dropped")
		}
	}
}

func TestMessageAttachmentClearIsNotAbsence(t *testing.T) {
	for _, test := range []struct {
		name        string
		attachments *wire.AttachmentEditList
		present     bool
	}{{"retain", nil, false}, {"clear", &wire.AttachmentEditList{}, true}} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := buildRESTPlan("ChannelMessageEditComplex", &wire.ChannelMessageEditComplexRequest{M: &wire.MessageEdit{Id: "880088", ChannelId: "770077", Content: &corewire.NullableString{Kind: &corewire.NullableString_Value{Value: "unchanged"}}, Attachments: test.attachments}})
			if err != nil {
				t.Fatal(err)
			}
			if plan.Request.Method != "PATCH" || plan.Request.Path != "/api/v10/channels/770077/messages/880088" {
				t.Fatal("message patch swapped the selected channel/message")
			}
			var body map[string]json.RawMessage
			if err = json.Unmarshal(plan.Request.JSON, &body); err != nil {
				t.Fatal(err)
			}
			raw, present := body["attachments"]
			if present != test.present {
				t.Fatal("absent and explicitly empty attachment sets were conflated")
			}
			if present {
				var entries []json.RawMessage
				if json.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) != 0 {
					t.Fatal("explicit clear must be an empty array, not null or an omitted field")
				}
			}
		})
	}
}
