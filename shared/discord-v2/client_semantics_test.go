package discordv2_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This boundary rejects requests rather than echoing them back as success. Tests
// exercise alias-created presence, cancellation and consumer error semantics;
// canonical method forwarding is intentionally not tested here.
type sdkBoundary func(context.Context, string, any, any) error

func (f sdkBoundary) Invoke(ctx context.Context, method string, request, response any, _ ...grpc.CallOption) error {
	return f(ctx, method, request, response)
}
func (f sdkBoundary) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected streaming call")
}
func sdkClient(t *testing.T, boundary sdkBoundary) *discordv2.Client {
	t.Helper()
	client, err := discordv2.NewClient(boundary)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestClientMemberAliasesPreserveFalseAndExplicitNull(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	tests := []struct {
		name    string
		call    func(*discordv2.Client) error
		inspect func(*testing.T, *wire.GuildMemberParams)
	}{
		{"mute false", func(c *discordv2.Client) error { return c.GuildMemberMute(context.Background(), "1", "2", false) }, func(t *testing.T, p *wire.GuildMemberParams) {
			if p.Mute == nil || *p.Mute || p.Deaf != nil || p.ChannelId != nil || p.CommunicationDisabledUntil != nil {
				t.Fatalf("false became absent or unrelated fields were set: %v", p)
			}
		}},
		{"deaf false", func(c *discordv2.Client) error { return c.GuildMemberDeafen(context.Background(), "1", "2", false) }, func(t *testing.T, p *wire.GuildMemberParams) {
			if p.Deaf == nil || *p.Deaf || p.Mute != nil || p.ChannelId != nil || p.CommunicationDisabledUntil != nil {
				t.Fatalf("false became absent or unrelated fields were set: %v", p)
			}
		}},
		{"disconnect", func(c *discordv2.Client) error { return c.GuildMemberMove(context.Background(), "1", "2", nil) }, func(t *testing.T, p *wire.GuildMemberParams) {
			if p.ChannelId == nil {
				t.Fatal("disconnect was omitted")
			}
			if _, ok := p.ChannelId.Kind.(*corewire.NullableString_NullValue); !ok {
				t.Fatalf("disconnect is not explicit null: %v", p)
			}
			if p.Mute != nil || p.Deaf != nil || p.CommunicationDisabledUntil != nil {
				t.Fatalf("unrelated mutation: %v", p)
			}
		}},
		{"clear timeout", func(c *discordv2.Client) error { return c.GuildMemberTimeout(context.Background(), "1", "2", nil) }, func(t *testing.T, p *wire.GuildMemberParams) {
			if p.CommunicationDisabledUntil == nil {
				t.Fatal("timeout clear was omitted")
			}
			if _, ok := p.CommunicationDisabledUntil.Kind.(*corewire.NullableTimestamp_NullValue); !ok {
				t.Fatalf("timeout clear is not explicit null: %v", p)
			}
			if p.Mute != nil || p.Deaf != nil || p.ChannelId != nil {
				t.Fatalf("unrelated mutation: %v", p)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := sdkClient(t, func(_ context.Context, _ string, request, _ any) error {
				calls++
				test.inspect(t, request.(*wire.GuildMemberEditRequest).Data)
				return denied
			})
			if err := test.call(client); err != denied || calls != 1 {
				t.Fatalf("alias hid mutation error: %v; calls=%d", err, calls)
			}
		})
	}
}

func TestClientReasonlessAliasesDoNotCreateExplicitEmptyReason(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	client := sdkClient(t, func(_ context.Context, _ string, request, _ any) error {
		switch req := request.(type) {
		case *wire.GuildBanCreateWithReasonRequest:
			if req.Reason != nil || req.GetOptions().GetAuditLogReason() != "audit" {
				t.Fatalf("reasonless ban conflicts with audit option: %v", req)
			}
		case *wire.GuildMemberDeleteWithReasonRequest:
			if req.Reason != nil || req.GetOptions().GetAuditLogReason() != "audit" {
				t.Fatalf("reasonless removal conflicts with audit option: %v", req)
			}
		default:
			t.Fatalf("unexpected mutation type %T", request)
		}
		return denied
	})
	if err := client.GuildBanCreate(context.Background(), "1", "2", 0, discordv2.WithAuditLogReason("audit")); err != denied {
		t.Fatal(err)
	}
	if err := client.GuildMemberDelete(context.Background(), "1", "2", discordv2.WithAuditLogReason("audit")); err != denied {
		t.Fatal(err)
	}
	explicitEmpty := ""
	if err := client.GuildBanCreateWithReason(context.Background(), "1", "2", &explicitEmpty, 0, discordv2.WithAuditLogReason("audit")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("explicit empty conflict accepted: %v", err)
	}
}

func TestClientEmbedClearAliasAndNilReplyBoundary(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	calls := 0
	client := sdkClient(t, func(_ context.Context, _ string, request, _ any) error {
		calls++
		patch := request.(*wire.ChannelMessageEditComplexRequest).M
		if patch.Embeds == nil || len(patch.Embeds.Values) != 0 || patch.Content != nil || patch.Attachments != nil {
			t.Fatalf("clear lost presence or changed another field: %v", patch)
		}
		return denied
	})
	if _, err := client.ChannelMessageEditEmbeds(context.Background(), "1", "2", nil); err != denied {
		t.Fatal(err)
	}
	if _, err := client.ChannelMessageSendReply(context.Background(), "1", "text", nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil reference accepted: %v", err)
	}
	if calls != 1 {
		t.Fatalf("invalid reply reached backend: calls=%d", calls)
	}
}

func TestClientGatewayBatchesStopAfterFirstErrorOrCancellation(t *testing.T) {
	for _, list := range []bool{false, true} {
		for _, cancelAfterFirst := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			var seen []string
			denied := status.Error(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
			client := sdkClient(t, func(_ context.Context, _ string, request, _ any) error {
				guild := ""
				switch req := request.(type) {
				case *wire.RequestGuildMembersRequest:
					guild = req.GuildId
				case *wire.RequestGuildMembersListRequest:
					guild = req.GuildId
				default:
					t.Fatalf("unexpected operation %T", request)
				}
				seen = append(seen, guild)
				if cancelAfterFirst {
					cancel()
					return nil
				}
				return denied
			})
			var err error
			if list {
				err = client.RequestGuildMembersBatchList(ctx, []string{"1", "2", "3"}, []string{"4"}, 0, "nonce", false)
			} else {
				err = client.RequestGuildMembersBatch(ctx, []string{"1", "2", "3"}, "", 0, "nonce", false)
			}
			if cancelAfterFirst {
				if status.Code(err) != codes.Canceled {
					t.Fatalf("batch did not stop on cancellation: %v", err)
				}
			} else if err != denied {
				t.Fatalf("batch suppressed first error: %v", err)
			}
			if !reflect.DeepEqual(seen, []string{"1"}) {
				t.Fatalf("batch continued or retried: %v", seen)
			}
			cancel()
		}
	}
	client := sdkClient(t, func(context.Context, string, any, any) error { t.Fatal("empty batch made a call"); return nil })
	if err := client.RequestGuildMembersBatch(context.Background(), nil, "", 0, "", false); err != nil {
		t.Fatal(err)
	}
}

func TestClientPresenceAliasesClearActivitiesAndKeepSourceDefaults(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	client := sdkClient(t, func(_ context.Context, _ string, request, _ any) error {
		patch := request.(*wire.UpdateStatusComplexRequest).Usd
		if patch.Activities == nil || len(patch.Activities.Values) != 0 || patch.GetStatus() != "online" || patch.Afk == nil || *patch.Afk || patch.IdleSince != nil {
			t.Fatalf("empty game did not clear with source defaults: %v", patch)
		}
		return denied
	})
	if err := client.UpdateGameStatus(context.Background(), 0, ""); err != denied {
		t.Fatal(err)
	}
}

func TestClientInteractionAliasesRejectRawTokenAndWiderPurpose(t *testing.T) {
	client := sdkClient(t, func(context.Context, string, any, any) error { t.Fatal("unsafe handle reached backend"); return nil })
	for _, handle := range []*discordv2.InteractionHandle{
		{Value: &discordgo.Interaction{AppID: "1", Token: "raw-secret"}, Credential: &corewire.CredentialRef{BackendId: "discord", Purpose: "discord.interaction"}},
		{Value: &discordgo.Interaction{AppID: "1"}, Credential: &corewire.CredentialRef{BackendId: "discord", Purpose: "discord.webhook"}},
	} {
		if _, err := client.InteractionResponse(context.Background(), handle); err == nil {
			t.Fatal("unsafe handle accepted")
		}
	}
}

func TestClientWebhookNoBodyIsOnlyAllowedForWaitFalse(t *testing.T) {
	client := sdkClient(t, func(context.Context, string, any, any) error { return nil })
	credential := &corewire.CredentialRef{BackendId: "discord", Purpose: "discord.webhook"}
	if result, err := client.WebhookExecute(context.Background(), "1", credential, false, &discordv2.WebhookParamsView{}); result != nil || err != nil {
		t.Fatalf("wait=false rejected successful no-body result: %v, %v", result, err)
	}
	if result, err := client.WebhookExecute(context.Background(), "1", credential, true, &discordv2.WebhookParamsView{}); result != nil || status.Code(err) != codes.Internal {
		t.Fatalf("wait=true missing result treated as success: %v, %v", result, err)
	}
	if result, err := client.ChannelMessageSend(context.Background(), "1", "text"); result != nil || status.Code(err) != codes.Internal {
		t.Fatalf("required message body treated as success: %v, %v", result, err)
	}
}
