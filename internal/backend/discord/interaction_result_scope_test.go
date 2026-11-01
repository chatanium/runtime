package discordbackend

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInteractionResultScopePreservesInvokerInsteadOfMessageAuthor(t *testing.T) {
	ctx := context.Background()
	principal := runtime.InstancePrincipal{ModuleID: "module", InstanceID: "instance"}
	b := &Backend{config: Config{ApplicationID: "20", CredentialTTL: time.Minute, InteractionTTL: time.Minute}, vault: make(map[string]*vaultRecord)}
	h := &Helper{backend: b, services: runtime.InstanceServices{Principal: principal}}
	id := strconv.FormatUint(uint64(time.Now().UnixMilli()-1420070400000)<<22, 10)
	raw := []byte(fmt.Sprintf(`{"id":%q,"application_id":"20","guild_id":"10","channel_id":"30","type":2,"data":{"id":"60","name":"attachment-demo","type":1},"member":{"user":{"id":"40"}},"token":"private-fixture-secret"}`, id))
	event, err := discord.ProjectInteractionCreateEvent(ctx, raw, nil, interactionAuthorityEncoder{backend: b, principal: principal}, b.projectionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	ref := event.Interaction.GetValue().CredentialRef.GetValue()
	grant := &corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{scope(map[string]string{"application_id": "20", "guild_id": "10", "channel_id": "30", "user_id": "40"})}}
	for _, operation := range []string{"WebhookMessage", "WebhookMessageEdit", "WebhookThreadExecute"} {
		t.Run(operation, func(t *testing.T) {
			plan := &RESTPlan{}
			switch operation {
			case "WebhookMessage":
				plan, err = buildRESTPlan(operation, &wire.WebhookMessageRequest{WebhookId: "20", MessageId: "@original", Credential: ref})
			case "WebhookMessageEdit":
				plan, err = buildRESTPlan(operation, &wire.WebhookMessageEditRequest{WebhookId: "20", MessageId: "@original", Credential: ref, Data: &wire.WebhookEdit{}})
			case "WebhookThreadExecute":
				plan, err = buildRESTPlan(operation, &wire.WebhookThreadExecuteRequest{WebhookId: "20", Credential: ref, Wait: true, Data: &wire.WebhookParams{}})
			}
			if err != nil {
				t.Fatal(err)
			}
			targets, err := h.credentialTargets(ctx, plan, principal)
			if err != nil {
				t.Fatal(err)
			}
			parent := commonResources(targets)
			if parent["user_id"] != "40" {
				t.Fatal("credential target lost authenticated invoker")
			}
			graph := resourceGraphContext{grant: grant, invokingUser: parent["user_id"]}
			body := []byte(`{"id":"70","guild_id":"10","channel_id":"30","application_id":"20","author":{"id":"90","bot":true},"content":"uploaded"}`)
			if err := graph.check(body, resultKind(operation), parent, 0, false); err != nil {
				t.Fatalf("bot author replaced authenticated invoker: %v", err)
			}
			if parent["user_id"] != "40" || ref.ResourceScope.ResourceIds["user_id"] != "40" {
				t.Fatal("postflight mutated immutable invocation context")
			}
			if err := resourceGraph(body, resultKind(operation), parent, grant, 0); status.Code(err) != codes.PermissionDenied {
				t.Fatal("test no longer exercises author/invoker distinction")
			}
			for _, denied := range []string{
				`{"id":"70","guild_id":"11","channel_id":"30","author":{"id":"90"}}`,
				`{"id":"70","guild_id":"10","channel_id":"31","author":{"id":"90"}}`,
				`{"id":"70","guild_id":"10","channel_id":"30","application_id":"21","author":{"id":"90"}}`,
				`{"id":"70","guild_id":"10","channel_id":"30","user_id":"41","author":{"id":"90"}}`,
				`{"id":"70","guild_id":"10","channel_id":"30","user":{"id":"41"},"author":{"id":"90"}}`,
				`{"id":"70","guild_id":"10","channel_id":"30","author":{"id":"90","guild_id":"11"}}`,
			} {
				if err := graph.check([]byte(denied), resultKind(operation), parent, 0, false); status.Code(err) != codes.PermissionDenied {
					t.Fatal("immutable invoker weakened returned relationship validation")
				}
			}
			invalidAuthor := []byte(`{"id":"70","guild_id":"10","channel_id":"30","author":{"id":"not-a-snowflake"}}`)
			if err := graph.check(invalidAuthor, resultKind(operation), parent, 0, false); err == nil {
				t.Fatal("informational author bypassed ID validation")
			}
		})
	}
}
