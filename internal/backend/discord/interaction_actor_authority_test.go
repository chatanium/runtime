package discordbackend

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This fixture replaces only registry issuance: projection policy, immutable
// credential lookup, REST planning, scope reduction, grant matching and callback
// validation below are production code. No helper or Discord response is mocked.
type interactionAuthorityEncoder struct {
	backend   *Backend
	principal runtime.InstancePrincipal
}

func (e interactionAuthorityEncoder) EncodeCredential(_ context.Context, binding core.CredentialBinding, secret string) (*corewire.CredentialRef, error) {
	ref := &corewire.CredentialRef{OpaqueId: "interaction-authority-fixture", BackendId: binding.BackendID, Purpose: binding.Purpose, ResourceScope: copySelector(binding.ResourceScope), ExpiresAt: timestamppb.New(binding.ExpiresAt)}
	e.backend.vault[ref.OpaqueId] = &vaultRecord{owner: e.principal, secret: secret, purpose: binding.Purpose, resource: copySelector(binding.ResourceScope), expires: binding.ExpiresAt, ref: proto.Clone(ref).(*corewire.CredentialRef), interactionType: 2}
	return ref, nil
}

func TestInteractionProjectionAuthorizesOnlyBoundInvokingUser(t *testing.T) {
	for _, guild := range []string{"10", ""} {
		t.Run("guild="+guild, func(t *testing.T) {
			ctx := context.Background()
			principal := runtime.InstancePrincipal{ModuleID: "module", InstanceID: "instance"}
			b := &Backend{config: Config{ApplicationID: "20", CredentialTTL: time.Minute, InteractionTTL: time.Minute}, vault: make(map[string]*vaultRecord)}
			h := &Helper{backend: b, services: runtime.InstanceServices{Principal: principal}}
			id := strconv.FormatUint(uint64(time.Now().UnixMilli()-1420070400000)<<22, 10)
			actor := `"user":{"id":"40"}`
			guildField := ""
			if guild != "" {
				actor = `"member":{"user":{"id":"40"}}`
				guildField = `"guild_id":"10",`
			}
			raw := []byte(fmt.Sprintf(`{"id":%q,"application_id":"20",%s"channel_id":"30","type":2,"data":{"id":"60","name":"hello","type":1},%s,"token":"private-fixture-secret"}`, id, guildField, actor))
			event, err := discord.ProjectInteractionCreateEvent(ctx, raw, nil, interactionAuthorityEncoder{backend: b, principal: principal}, b.projectionPolicy)
			if err != nil {
				t.Fatal(err)
			}
			partial := event.Interaction.GetValue()
			ref := partial.CredentialRef.GetValue()
			if ref.GetResourceScope().GetResourceIds()["user_id"] != "40" {
				t.Fatal("gateway projection lost actor before authorization")
			}
			command := partial.Data.GetValue().GetApplicationCommand()
			// Match the real consumer boundary: partial ingress supplies identity
			// to an SDK handle; the canonical producer emits its full snapshot
			// schema (including User's value-typed PrimaryGuild object).
			source := &discordgo.Interaction{
				ID: id, AppID: "20", GuildID: guild, ChannelID: "30", Type: discordgo.InteractionApplicationCommand,
				Data: discordgo.ApplicationCommandInteractionData{ID: command.Id.GetValue(), Name: command.Name.GetValue(), CommandType: discordgo.ApplicationCommandType(command.CommandType.GetValue())},
			}
			if guild != "" {
				source.Member = &discordgo.Member{User: &discordgo.User{ID: "40"}}
			} else {
				source.User = &discordgo.User{ID: "40"}
			}
			interaction, err := discord.InteractionHandleToProto(&discord.InteractionHandle{Value: source, Credential: ref})
			if err != nil {
				t.Fatal(err)
			}
			initial := &wire.InteractionRespondRequest{Interaction: interaction, Resp: &wire.InteractionResponse{
				Type: new(uint32(4)),
				Data: &wire.InteractionResponseData{Content: &corewire.NullableString{Kind: &corewire.NullableString_Value{Value: "Hello from the ordinary v2 module."}}},
			}}
			requests := []struct {
				operation string
				request   proto.Message
			}{
				{"InteractionRespond", initial},
				{"WebhookMessageEdit", &wire.WebhookMessageEditRequest{WebhookId: "20", MessageId: "@original", Credential: ref, Data: &wire.WebhookEdit{}}},
				{"WebhookThreadExecute", &wire.WebhookThreadExecuteRequest{WebhookId: "20", Credential: ref, Data: &wire.WebhookParams{}}},
				{"WebhookMessageDelete", &wire.WebhookMessageDeleteRequest{WebhookId: "20", MessageId: "@original", Credential: ref}},
			}
			for _, request := range requests {
				t.Run(request.operation, func(t *testing.T) {
					plan, err := buildRESTPlan(request.operation, request.request)
					if err != nil {
						t.Fatal(err)
					}
					targets, err := h.credentialTargets(ctx, plan, principal)
					if err != nil {
						t.Fatal(err)
					}
					for _, target := range plan.Targets {
						if target.Kind == "interaction_id" || target.Kind == "webhook_id" || target.Kind == "message_id" {
							resolved, err := h.credentialTarget(plan, principal, target)
							if err != nil {
								t.Fatal(err)
							}
							targets = append(targets, resolved)
						}
					}
					targets = requiredScopes(targets, nil)
					for _, allowedUser := range []string{"40", "41"} {
						ids := map[string]string{"application_id": "20", "channel_id": "30", "user_id": allowedUser}
						if guild != "" {
							ids["guild_id"] = guild
						}
						grant := &corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{scope(ids)}}
						if grantAllows(grant, targets) != (allowedUser == "40") {
							t.Fatal("actual callback/followup targets lost invoking-user restriction")
						}
						// Exercise the runtime's exported selector comparison as well as
						// the backend gate, not a fixture's approximation of matching.
						if runtime.ResourceScopesSubset(targets, grant.ResourceScopes) != (allowedUser == "40") {
							t.Fatal("runtime selector authorization disagrees with invoking-user scope")
						}
					}
					op := &OperationContext{Principal: principal, Scopes: targets}
					if err := op.validateCredentialScopes(plan.Credentials[0]); err != nil {
						t.Fatal(err)
					}
					if request.operation == "InteractionRespond" {
						if err := h.validateInitialCallback(ctx, request.operation, request.request, op, plan); err != nil {
							t.Fatal(err)
						}
						minimal := proto.Clone(initial).(*wire.InteractionRespondRequest)
						minimal.Interaction.Member, minimal.Interaction.User = nil, nil
						minimalPlan, err := buildRESTPlan(request.operation, minimal)
						if err != nil {
							t.Fatal(err)
						}
						if err := h.validateInitialCallback(ctx, request.operation, minimal, op, minimalPlan); err != nil {
							t.Fatal("stored actor rejected identity-minimal callback DTO")
						}
						for _, field := range []string{"member", "user"} {
							bad := proto.Clone(minimal).(*wire.InteractionRespondRequest)
							if field == "member" {
								bad.Interaction.Member = &wire.Member{User: &wire.User{Id: new("41")}}
							} else {
								bad.Interaction.User = &wire.User{Id: new("41")}
							}
							if h.validateInitialCallback(ctx, request.operation, bad, op, plan) == nil {
								t.Fatal("caller substituted authenticated invoking user")
							}
						}
					}
				})
			}
			for _, user := range []string{"41", ""} {
				forged := proto.Clone(ref).(*corewire.CredentialRef)
				forged.ResourceScope.ResourceIds["user_id"] = user
				if _, err := h.credentialRecord(CredentialUse{Ref: forged, Resource: forged.ResourceScope, Purpose: forged.Purpose}, principal); err == nil {
					t.Fatal("caller reference metadata rewrote stored actor")
				}
			}
			stored := b.vault[ref.OpaqueId]
			delete(stored.resource.ResourceIds, "user_id")
			delete(stored.ref.ResourceScope.ResourceIds, "user_id")
			missing := proto.Clone(stored.ref).(*corewire.CredentialRef)
			if _, err := h.credentialRecord(CredentialUse{Ref: missing, Resource: missing.ResourceScope, Purpose: missing.Purpose}, principal); err == nil {
				t.Fatal("stored interaction credential without actor was accepted")
			}
		})
	}
}
