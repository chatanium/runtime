package discordbackend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/proto"
)

func TestPollAnswerIsEndpointParameterNotAuthoritySelector(t *testing.T) {
	plan, err := buildRESTPlan("PollAnswerVoters", &wire.PollAnswerVotersRequest{ChannelId: "123", MessageId: "456", AnswerId: 7})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Request.Path != "/api/v10/channels/123/polls/456/answers/7" {
		t.Fatal("numeric poll answer route changed")
	}
	channel, message := false, false
	for _, target := range plan.Targets {
		switch target.Kind {
		case "channel_id":
			channel = target.ID == "123"
		case "message_id":
			message = target.ID == "456" && target.ChannelID == "123"
		default:
			t.Fatalf("non-resource poll parameter became authority selector: %s", target.Kind)
		}
	}
	if !channel || !message {
		t.Fatal("containing channel/message authority is missing")
	}
	// Consume the actual resolver/reducer under trusted relationship snapshots:
	// a grant for this message must not need a second channel-wide grant, and
	// an unrelated message grant must not authorize the read.
	cache := &relationshipCache{max: 4096, entries: map[string][]byte{
		"/channels/123":              []byte(`{"id":"123","guild_id":"909"}`),
		"/channels/123/messages/456": []byte(`{"id":"456","channel_id":"123"}`),
	}}
	ctx := context.WithValue(context.Background(), relationshipCacheKey{}, cache)
	backend := &Backend{session: &discordgo.Session{}}
	var resolved []*corewire.ResourceScope
	for _, target := range plan.Targets {
		actual, resolveErr := backend.resolveTarget(ctx, runtime.InstancePrincipal{}, target)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		if actual != nil {
			resolved = append(resolved, actual)
		}
	}
	scopes := requiredScopes(resolved, nil)
	messageGrant := &corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{scope(map[string]string{"guild_id": "909", "channel_id": "123", "message_id": "456"})}}
	if len(scopes) != 1 || !grantAllows(messageGrant, scopes) {
		t.Fatal("message-scoped poll read acquired an independent channel-wide requirement")
	}
	messageGrant.ResourceScopes[0] = scope(map[string]string{"guild_id": "909", "channel_id": "123", "message_id": "987"})
	if grantAllows(messageGrant, scopes) {
		t.Fatal("unrelated message scope authorized poll answer lookup")
	}
	for _, answer := range []int64{0, -1} {
		if _, err := buildRESTPlan("PollAnswerVoters", &wire.PollAnswerVotersRequest{ChannelId: "123", MessageId: "456", AnswerId: answer}); err == nil {
			t.Fatal("nonpositive poll answer accepted")
		}
	}
}

func TestMutatedGuildRootsAreIndependentOfPayloadChannels(t *testing.T) {
	cases := []struct {
		operation string
		request   proto.Message
	}{
		{"GuildEdit", &wire.GuildEditRequest{GuildId: "123", G: &wire.GuildParams{Name: apiFixturePointer("changed"), SystemChannelId: &corewire.NullableString{Kind: &corewire.NullableString_Value{Value: "456"}}}}},
		{"GuildEmbedEdit", &wire.GuildEmbedEditRequest{GuildId: "123", Data: &wire.GuildEmbed{Enabled: apiFixturePointer(true), ChannelId: apiFixturePointer("456")}}},
	}
	for _, test := range cases {
		t.Run(test.operation, func(t *testing.T) {
			plan, err := buildRESTPlan(test.operation, test.request)
			if err != nil {
				t.Fatal(err)
			}
			protected := false
			for _, root := range plan.RequiredRoots {
				if root.Kind == "guild_id" && root.ID == "123" && root.GuildID == "123" && root.ChannelID == "" {
					protected = true
				}
			}
			if !protected {
				t.Fatal("guild mutation root was not preserved separately from relationship leaves")
			}
			related := false
			for _, target := range plan.Targets {
				if target.Kind == "channel_id" && target.ID == "456" {
					related = true
				}
			}
			if !related {
				t.Fatal("nested channel relationship was dropped")
			}
		})
	}
}

func TestMemberRoleReplacementPresenceAndGranularMemberRoot(t *testing.T) {
	for _, test := range []struct {
		name    string
		roles   *wire.DomainStringList
		replace bool
	}{{"absent", nil, false}, {"clear", &wire.DomainStringList{}, true}, {"replace", &wire.DomainStringList{Values: []string{"789"}}, true}} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := buildRESTPlan("GuildMemberEdit", &wire.GuildMemberEditRequest{GuildId: "123", UserId: "456", Data: &wire.GuildMemberParams{Roles: test.roles, ChannelId: &corewire.NullableString{Kind: &corewire.NullableString_Value{Value: "999"}}}})
			if err != nil {
				t.Fatal(err)
			}
			if (plan.RoleReplacement != nil) != test.replace {
				t.Fatal("absent roles and explicit empty replacement were conflated")
			}
			if test.replace {
				replacement := plan.RoleReplacement
				if replacement.GuildID != "123" || replacement.UserID != "456" || len(replacement.RoleIDs) != len(test.roles.Values) {
					t.Fatal("replacement lookup identifiers changed")
				}
			}
			member := false
			for _, root := range plan.RequiredRoots {
				if root.Kind == "guild_id" {
					t.Fatal("granular member operation incorrectly promotes every request to guild-wide mutation")
				}
				if root.Kind == "user_id" && root.ID == "456" && root.GuildID == "123" && root.ChannelID == "" {
					member = true
				}
			}
			if !member {
				t.Fatal("member mutation root was qualified by a move destination")
			}
		})
	}
}

func TestThreadDestinationDoesNotRewriteCredentialParent(t *testing.T) {
	credential := apiFixtureCredential("discord.webhook")
	plan, err := buildRESTPlan("WebhookThreadExecute", &wire.WebhookThreadExecuteRequest{WebhookId: "456", Credential: credential, ThreadId: "789", Data: &wire.WebhookParams{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Credentials) != 1 || plan.Credentials[0].ThreadDestination != "789" {
		t.Fatal("explicit thread proof target missing")
	}
	if plan.Credentials[0].Resource.ResourceIds["channel_id"] != "123" || credential.ResourceScope.ResourceIds["channel_id"] != "123" {
		t.Fatal("credential immutable parent was rewritten to thread")
	}
	if plan.Request.Query.Get("thread_id") != "789" {
		t.Fatal("thread destination lost from fixed query")
	}
	if len(plan.RequiredRoots) != 1 || plan.RequiredRoots[0].Kind != "channel_id" || plan.RequiredRoots[0].ID != "789" {
		t.Fatal("selected thread mutation root missing")
	}
}

func TestRESTProjectionRejectsCanceledOperationBeforeParsing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value, err := projectRESTResponse(ctx, "WebhookWithToken", []byte(`{"id":"123","token":"must-not-project"}`), nil, nil)
	if value != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled projection parsed or published a result")
	}
	if strings.Contains(err.Error(), "must-not-project") {
		t.Fatal("private payload escaped canceled projection")
	}
}
