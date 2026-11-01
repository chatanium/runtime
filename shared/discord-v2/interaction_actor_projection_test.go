package discordv2_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type interactionActorEncoder struct{ calls int }

func (e *interactionActorEncoder) EncodeCredential(_ context.Context, binding core.CredentialBinding, _ string) (*corewire.CredentialRef, error) {
	e.calls++
	return &corewire.CredentialRef{OpaqueId: "actor-projection-fixture", BackendId: binding.BackendID, Purpose: binding.Purpose, ResourceScope: proto.Clone(binding.ResourceScope).(*corewire.ResourceSelector), ExpiresAt: timestamppb.New(binding.ExpiresAt)}, nil
}

func TestInteractionProjectionBindsInvokingUserAcrossRepresentations(t *testing.T) {
	for _, test := range []struct {
		name, guild, member, user string
		valid                     bool
	}{
		{"guild member", "10", "40", "", true},
		{"DM user", "", "", "40", true},
		{"matching duplicate", "10", "40", "40", true},
		{"conflicting guild user", "10", "40", "41", false},
		{"conflicting DM member", "", "41", "40", false},
		{"missing guild member", "10", "", "", false},
		{"guild cannot borrow DM user", "10", "", "40", false},
		{"DM cannot borrow guild member", "", "40", "", false},
		{"missing DM user", "", "", "", false},
		{"invalid actor", "10", "not-an-id", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &discordgo.Interaction{ID: "50", AppID: "20", GuildID: test.guild, ChannelID: "30", Type: discordgo.InteractionApplicationCommand, Token: "private-fixture-secret", Data: discordgo.ApplicationCommandInteractionData{ID: "60", Name: "hello", CommandType: discordgo.ChatApplicationCommand}}
			if test.member != "" {
				source.Member = &discordgo.Member{User: &discordgo.User{ID: test.member}}
			}
			if test.user != "" {
				source.User = &discordgo.User{ID: test.user}
			}
			raw, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			for _, representation := range []string{"struct", "JSON snapshot", "gateway partial"} {
				t.Run(representation, func(t *testing.T) {
					encoder := new(interactionActorEncoder)
					policyCalls := 0
					policy := func(_ context.Context, target discord.CredentialTarget) (core.CredentialBinding, error) {
						policyCalls++
						if target.ResourceScope.ResourceIds["user_id"] != "40" {
							t.Fatal("policy received no exact authenticated actor")
						}
						return core.CredentialBinding{BackendID: "discord", Purpose: target.Purpose, ResourceScope: target.ResourceScope, ExpiresAt: time.Now().Add(time.Minute)}, nil
					}
					var ref *corewire.CredentialRef
					var err error
					switch representation {
					case "struct":
						var value *wire.Interaction
						value, err = discord.ProjectInteraction(context.Background(), source, encoder, policy)
						ref = value.GetCredentialRef()
					case "JSON snapshot":
						var value *wire.Interaction
						value, err = discord.ProjectInteractionJSON(context.Background(), raw, encoder, policy)
						ref = value.GetCredentialRef()
					case "gateway partial":
						var value *wire.InteractionCreateEvent
						value, err = discord.ProjectInteractionCreateEvent(context.Background(), raw, nil, encoder, policy)
						ref = value.GetInteraction().GetValue().GetCredentialRef().GetValue()
					}
					if !test.valid {
						if err == nil || ref != nil || encoder.calls != 0 || policyCalls != 0 {
							t.Fatal("ambiguous or missing actor reached credential issuance")
						}
						if strings.Contains(err.Error(), source.Token) {
							t.Fatal("projection error leaked credential")
						}
						return
					}
					if err != nil || ref == nil || encoder.calls != 1 || policyCalls != 1 {
						t.Fatalf("valid actor projection failed: %v", err)
					}
					ids := ref.ResourceScope.ResourceIds
					if ids["user_id"] != "40" || ids["application_id"] != "20" || ids["guild_id"] != test.guild || ids["channel_id"] != "30" || ids["interaction_id"] != "50" {
						t.Fatal("credential lost exact source scope")
					}
				})
			}
		})
	}
}

func TestInteractionProjectionRejectsPolicyActorSubstitution(t *testing.T) {
	for _, substituted := range []string{"", "41"} {
		encoder := new(interactionActorEncoder)
		policy := func(_ context.Context, target discord.CredentialTarget) (core.CredentialBinding, error) {
			target.ResourceScope.ResourceIds["user_id"] = substituted
			return core.CredentialBinding{BackendID: "discord", Purpose: target.Purpose, ResourceScope: target.ResourceScope, ExpiresAt: time.Now().Add(time.Minute)}, nil
		}
		value, err := discord.ProjectInteractionJSON(context.Background(), []byte(`{"id":"50","application_id":"20","guild_id":"10","channel_id":"30","type":2,"data":{"id":"60","name":"hello","type":1},"member":{"user":{"id":"40"}},"token":"private-fixture-secret"}`), encoder, policy)
		if err == nil || value != nil || encoder.calls != 0 {
			t.Fatal("policy substituted or removed authenticated actor")
		}
	}
}

func TestTokenEmptyInteractionDTOsRemainPartialSafe(t *testing.T) {
	if value, err := discord.InteractionToProto(nil); err != nil || value != nil {
		t.Fatal("nil interaction DTO changed")
	}
	source := &discordgo.Interaction{Type: discordgo.InteractionApplicationCommand, Data: discordgo.ApplicationCommandInteractionData{Name: "hello", CommandType: discordgo.ChatApplicationCommand}}
	value, err := discord.ProjectInteraction(context.Background(), source, nil, nil)
	if err != nil || value == nil || value.CredentialRef != nil || value.Member != nil || value.User != nil {
		t.Fatal("token-empty partial interaction acquired actor or credential requirements")
	}
	ref := conversionCredentialFixture()
	ref.ResourceScope.ResourceIds["user_id"] = "40"
	handle, err := discord.InteractionHandleToProto(&discord.InteractionHandle{Value: source, Credential: ref})
	if err != nil || handle.GetCredentialRef().GetResourceScope().GetResourceIds()["user_id"] != "40" {
		t.Fatal("identity-minimal handle lost its existing bound actor")
	}
	event, err := discord.ProjectInteractionCreateEvent(context.Background(), []byte(`{"type":2,"data":{"name":"hello","type":1}}`), nil, nil, nil)
	if err != nil || event.GetInteraction().GetValue().GetCredentialRef() != nil {
		t.Fatal("token-empty partial gateway DTO acquired actor requirements")
	}
}
