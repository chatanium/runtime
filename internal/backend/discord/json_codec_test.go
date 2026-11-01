package discordbackend

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSixCanonicalFilePlans(t *testing.T) {
	file := &wire.FileAttachment{UploadedFileRef: &corewire.UploadedFileRef{OpaqueId: "upload-secret-reference", FileName: "stored-name", ContentType: "text/plain", SizeBytes: 3}, Filename: "payload.txt", Description: apiFixturePointer("")}
	files := &wire.FileAttachmentList{Values: []*wire.FileAttachment{file}}
	entries := &wire.AttachmentEditList{Values: []*wire.AttachmentEditEntry{{Source: &wire.AttachmentEditEntry_NewFileIndex{NewFileIndex: 0}}}}
	cases := []struct {
		name    string
		request proto.Message
	}{
		{"ChannelMessageSendComplex", &wire.ChannelMessageSendComplexRequest{ChannelId: "123", Data: &wire.MessageSend{Files: files}}},
		{"ChannelMessageEditComplex", &wire.ChannelMessageEditComplexRequest{M: &wire.MessageEdit{Id: "456", ChannelId: "123", Files: files, Attachments: entries}}},
		{"WebhookThreadExecute", &wire.WebhookThreadExecuteRequest{WebhookId: "123", Credential: apiFixtureCredential("discord.webhook"), Data: &wire.WebhookParams{Files: files}}},
		{"WebhookMessageEdit", &wire.WebhookMessageEditRequest{WebhookId: "123", MessageId: "456", Credential: apiFixtureCredential("discord.webhook"), Data: &wire.WebhookEdit{Files: files, Attachments: entries}}},
		{"InteractionRespond", &wire.InteractionRespondRequest{Interaction: &wire.Interaction{Id: apiFixturePointer("123"), AppId: apiFixturePointer("123"), CredentialRef: apiFixtureCredential("discord.interaction")}, Resp: &wire.InteractionResponse{Type: apiFixturePointer(uint32(4)), Data: &wire.InteractionResponseData{Files: files, Attachments: entries}}}},
		{"ForumThreadStartComplex", &wire.ForumThreadStartComplexRequest{ChannelId: "123", ThreadData: &wire.ThreadStart{}, MessageData: &wire.MessageSend{Files: files}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan, err := buildRESTPlan(test.name, test.request)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Files) != 1 || plan.Files[0] != file {
				t.Fatal("file references did not reach the lease boundary")
			}
			body := string(plan.Request.JSON)
			for _, forbidden := range []string{"upload-secret-reference", "uploaded_file_ref", "credential_ref", "stored-name"} {
				if strings.Contains(body, forbidden) {
					t.Fatal("host reference leaked into HTTP JSON")
				}
			}
			if !strings.Contains(body, `"filename":"payload.txt"`) || !strings.Contains(body, `"id":0`) {
				t.Fatal("multipart index zero metadata missing")
			}
		})
	}
}

func TestAuditReasonPresenceConflict(t *testing.T) {
	empty, reason := "", "reason"
	for _, test := range []struct {
		explicit, option *string
		reject           bool
	}{{nil, nil, false}, {nil, &reason, false}, {&empty, &empty, false}, {&empty, &reason, true}, {&reason, &empty, true}} {
		_, err := buildRESTPlan("GuildBanCreateWithReason", &wire.GuildBanCreateWithReasonRequest{GuildId: "123", UserId: "456", Reason: test.explicit, Options: &wire.RequestOptions{AuditLogReason: test.option}})
		if (err != nil) != test.reject {
			t.Fatalf("unexpected conflict decision: %v", err)
		}
	}
}

func TestPatchJSONPresenceAndPermissions(t *testing.T) {
	plan, err := buildRESTPlan("ChannelEdit", &wire.ChannelEditRequest{ChannelId: "123", Data: &wire.ChannelEdit{Nsfw: apiFixturePointer(false), Position: apiFixturePointer(int64(0)), Topic: &corewire.NullableString{Kind: &corewire.NullableString_Value{Value: ""}}, ParentId: &corewire.NullableString{Kind: &corewire.NullableString_NullValue{}}}})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(plan.Request.JSON, &body) != nil {
		t.Fatal("invalid JSON")
	}
	for key, expected := range map[string]string{"nsfw": "false", "position": "0", "topic": `""`, "parent_id": "null"} {
		if string(body[key]) != expected {
			t.Fatalf("presence lost for %s", key)
		}
	}
	for _, permission := range []string{"0", "9223372036854775807"} {
		plan, err = buildRESTPlan("ChannelPermissionSet", &wire.ChannelPermissionSetRequest{ChannelId: "123", TargetId: "456", Allow: permission, Deny: "0"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(plan.Request.JSON), `"allow":"`+permission+`"`) {
			t.Fatal("permission was not a decimal string")
		}
	}
	for _, permission := range []string{"-1", "9223372036854775808", "1.0", ""} {
		if _, err := buildRESTPlan("ChannelPermissionSet", &wire.ChannelPermissionSetRequest{ChannelId: "123", TargetId: "456", Allow: permission, Deny: "0"}); err == nil {
			t.Fatal("invalid permission accepted")
		}
	}
}

func TestBulkDeleteAndPinnedDefaults(t *testing.T) {
	for _, test := range []struct {
		ids    []string
		method string
		noop   bool
	}{{nil, "POST", true}, {[]string{"456"}, "DELETE", false}, {[]string{"456", "789"}, "POST", false}} {
		plan, err := buildRESTPlan("ChannelMessagesBulkDelete", &wire.ChannelMessagesBulkDeleteRequest{ChannelId: "123", Messages: &wire.ChannelMessagesBulkDeleteMessagesArgList{Values: test.ids}})
		if err != nil {
			t.Fatal(err)
		}
		if plan.NoDispatch != test.noop || plan.Request.Method != test.method {
			t.Fatal("bulk delete source semantics changed")
		}
	}
	before := timestamppb.New(time.Date(2026, 10, 30, 1, 2, 3, 0, time.UTC))
	for _, limit := range []int64{-1, 0, 1, 50} {
		plan, err := buildRESTPlan("ChannelMessagesPinned", &wire.ChannelMessagesPinnedRequest{ChannelId: "123", Limit: limit, Before: before})
		if err != nil {
			t.Fatal(err)
		}
		if (plan.Request.Query.Get("limit") == "") != (limit <= 0) {
			t.Fatal("pin default limit changed")
		}
		if plan.Request.Query.Get("before") != "2026-10-30T01:02:03Z" {
			t.Fatal("pin cursor not RFC3339")
		}
	}
	if _, err := buildRESTPlan("ChannelMessagesPinned", &wire.ChannelMessagesPinnedRequest{ChannelId: "123", Limit: 51}); err == nil {
		t.Fatal("invalid pin limit accepted")
	}
}

func TestExactCountProjectionAndWebhookNoWait(t *testing.T) {
	response, err := projectRESTResponse(context.Background(), "GuildRoleMemberCounts", []byte(`{"123":18446744073709551615}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.(*wire.GuildRoleMemberCountsResponse).Value.Values["123"] != ^uint64(0) {
		t.Fatal("uint64 count lost precision")
	}
	plan, err := buildRESTPlan("WebhookThreadExecute", &wire.WebhookThreadExecuteRequest{WebhookId: "123", Credential: apiFixtureCredential("discord.webhook"), Data: &wire.WebhookParams{}})
	if err != nil {
		t.Fatal(err)
	}
	response, err = projectRESTResponse(withRESTProjectionContext(context.Background(), plan), "WebhookThreadExecute", []byte(`{"id":"456"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.(*wire.WebhookThreadExecuteResponse).Value != nil {
		t.Fatal("wait=false unexpectedly returned a message")
	}
}

func TestSafeDiscordHTTPFailures(t *testing.T) {
	for _, test := range []struct {
		status int
		code   codes.Code
	}{{400, codes.InvalidArgument}, {401, codes.FailedPrecondition}, {403, codes.PermissionDenied}, {404, codes.NotFound}, {429, codes.ResourceExhausted}, {500, codes.Unavailable}} {
		err := discordHTTPError(test.status, []byte(`{"code":50013,"message":"https://discord.com/api/webhooks/secret-token","retry_after":1.25,"errors":{"secret-token":{"_errors":[{"message":"secret-token"}]}}}`))
		if status.Code(err) != test.code {
			t.Fatalf("upstream status %d translated incorrectly", test.status)
		}
		if strings.Contains(err.Error(), "secret-token") {
			t.Fatal("upstream secret leaked")
		}
		found := false
		for _, detail := range status.Convert(err).Details() {
			if core, ok := detail.(*corewire.ErrorDetail); ok {
				if core.Origin != corewire.ErrorOrigin_ERROR_ORIGIN_BACKEND || core.RemoteOutcome != corewire.RemoteOutcome_REMOTE_OUTCOME_RESPONSE_RECEIVED {
					t.Fatal("remote outcome lost")
				}
				discord := &wire.DiscordErrorDetail{}
				if core.BackendDetail.UnmarshalTo(discord) != nil {
					t.Fatal("missing Discord detail")
				}
				if int(discord.HttpStatus) != test.status || discord.GetApiCode() != 50013 || discord.RetryAfter.AsDuration() != 1250*time.Millisecond {
					t.Fatal("safe remote metadata lost")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing structured core error")
		}
	}
}

func TestUnsupportedAuditAndNestedResources(t *testing.T) {
	if _, err := buildRESTPlan("Gateway", &wire.GatewayRequest{Options: &wire.RequestOptions{AuditLogReason: apiFixturePointer("")}}); err == nil {
		t.Fatal("unsupported explicit audit reason silently ignored")
	}
	body := &wire.AutoModerationRule{ExemptRoles: &wire.DomainStringList{Values: []string{"456"}}, ExemptChannels: &wire.DomainStringList{Values: []string{"789"}}}
	plan, err := buildRESTPlan("AutoModerationRuleCreate", &wire.AutoModerationRuleCreateRequest{GuildId: "123", Rule: body})
	if err != nil {
		t.Fatal(err)
	}
	foundRole, foundChannel := false, false
	for _, target := range plan.Targets {
		if target.Kind == "role_id" && target.ID == "456" && target.GuildID == "123" {
			foundRole = true
		}
		if target.Kind == "channel_id" && target.ID == "789" && target.GuildID == "123" {
			foundChannel = true
		}
	}
	if !foundRole || !foundChannel {
		t.Fatal("nested rule target was not advertised for authority")
	}
}

func TestRequestMetadataSyntax(t *testing.T) {
	for _, locale := range []string{"en-US", "es-419", "zz-Zzzz-ZZ", "x-private", "i-klingon"} {
		if err := validateRequestOptions(&wire.RequestOptions{Locale: apiFixturePointer(locale)}); err != nil {
			t.Fatalf("well-formed locale rejected: %v", err)
		}
	}
	for _, locale := range []string{"", "en_US", "en US", "en--US", "é-US", "en-US\r\nX-Token: secret"} {
		if err := validateRequestOptions(&wire.RequestOptions{Locale: apiFixturePointer(locale)}); err == nil {
			t.Fatal("invalid locale accepted")
		}
	}
	for _, reason := range []string{"bad\rvalue", "bad\nvalue", "bad\x00value", string([]byte{0xff})} {
		if err := validateRequestOptions(&wire.RequestOptions{AuditLogReason: apiFixturePointer(reason)}); err == nil {
			t.Fatal("invalid header metadata accepted")
		}
		if _, err := buildRESTPlan("GuildBanCreateWithReason", &wire.GuildBanCreateWithReasonRequest{GuildId: "123", UserId: "456", Reason: apiFixturePointer(reason)}); err == nil {
			t.Fatal("canonical reason bypassed metadata validation")
		}
	}
	options := &wire.RequestOptions{}
	options.ProtoReflect().SetUnknown([]byte{0x1a, 0})
	if err := validateRequestOptions(options); err == nil {
		t.Fatal("unknown request option accepted")
	}
}

func TestInteractionButtonSKUJSONPresence(t *testing.T) {
	for _, sku := range []string{"", "123456789012345678"} {
		t.Run(sku, func(t *testing.T) {
			button := discordgo.Button{Label: "Ordinary", Style: discordgo.PrimaryButton, CustomID: "ordinary"}
			if sku != "" {
				button = discordgo.Button{Style: discordgo.PremiumButton, SKUID: sku}
			}
			response, err := discordv2.InteractionResponseToProto(&discordv2.InteractionResponseView{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordv2.InteractionResponseDataView{
					Components: []discordgo.MessageComponent{discordgo.ActionsRow{Components: []discordgo.MessageComponent{button}}},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := buildRESTPlan("InteractionRespond", &wire.InteractionRespondRequest{
				Interaction: &wire.Interaction{Id: apiFixturePointer("123"), AppId: apiFixturePointer("123"), CredentialRef: apiFixtureCredential("discord.interaction")},
				Resp:        response,
			})
			if err != nil {
				t.Fatal(err)
			}
			var body struct {
				Data struct {
					Components []struct {
						Components []struct {
							SKU *string `json:"sku_id"`
						} `json:"components"`
					} `json:"components"`
				} `json:"data"`
			}
			if err = json.Unmarshal(plan.Request.JSON, &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Data.Components) != 1 || len(body.Data.Components[0].Components) != 1 {
				t.Fatal("component union shape changed")
			}
			got := body.Data.Components[0].Components[0].SKU
			if (got != nil) != (sku != "") || got != nil && *got != sku {
				t.Fatal("HTTP SKU omission or nonempty identifier changed")
			}
		})
	}
	// Direct typed input remains authoritative. Do not hide an explicitly empty
	// identifier in the HTTP encoder as a workaround for SDK source omission.
	value, err := discordJSON(&wire.Button{Skuid: apiFixturePointer("")})
	if err != nil {
		t.Fatal(err)
	}
	object, ok := value.(map[string]any)
	if !ok || object["sku_id"] != "" {
		t.Fatal("explicit typed empty SKU was silently omitted")
	}
}

func TestWebhookOptionalStringsMatchSourceJSON(t *testing.T) {
	for _, source := range []*discordgo.WebhookParams{
		{},
		{Content: "message", Username: "speaker", AvatarURL: "https://example.com/avatar.png", ThreadName: "topic"},
	} {
		data, err := discordv2.WebhookParamsToProto(&discordv2.WebhookParamsView{
			Content: source.Content, Username: source.Username, AvatarURL: source.AvatarURL, ThreadName: source.ThreadName,
		})
		if err != nil {
			t.Fatal(err)
		}
		plan, err := buildRESTPlan("WebhookThreadExecute", &wire.WebhookThreadExecuteRequest{
			WebhookId: "123", Credential: apiFixtureCredential("discord.webhook"), Wait: true, Data: data,
		})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		var sdkJSON, outgoing map[string]json.RawMessage
		if json.Unmarshal(raw, &sdkJSON) != nil || json.Unmarshal(plan.Request.JSON, &outgoing) != nil {
			t.Fatal("invalid request JSON")
		}
		for _, field := range []string{"content", "username", "avatar_url", "thread_name"} {
			if string(outgoing[field]) != string(sdkJSON[field]) {
				t.Fatalf("%s source omission/value changed at HTTP boundary", field)
			}
		}
	}
	value, err := discordJSON(&wire.WebhookParams{
		Content: apiFixturePointer(""), Username: apiFixturePointer(""),
		AvatarUrl: apiFixturePointer(""), ThreadName: apiFixturePointer(""),
	})
	if err != nil {
		t.Fatal(err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatal("typed webhook did not encode as an object")
	}
	for _, field := range []string{"content", "username", "avatar_url", "thread_name"} {
		if got, present := object[field]; !present || got != "" {
			t.Fatalf("%s explicit wire empty was silently removed", field)
		}
	}
}

func TestOutboundDefaultFieldsPreserveExplicitWireZero(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  any
		fields []string
	}{
		{"Poll", &wire.Poll{Duration: apiFixturePointer(int64(0)), LayoutType: apiFixturePointer(int64(0))}, []string{"duration", "layout_type"}},
		{"SelectMenu", &wire.SelectMenu{MaxValues: apiFixturePointer(int64(0))}, []string{"max_values"}},
		{"FileUpload", &wire.FileUpload{MaxValues: apiFixturePointer(int64(0))}, []string{"max_values"}},
		{"TextInput", &wire.TextInput{MaxLength: apiFixturePointer(int64(0))}, []string{"max_length"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := discordJSON(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			object, ok := value.(map[string]any)
			if !ok {
				t.Fatal("typed input did not encode as an object")
			}
			for _, field := range tc.fields {
				if got, present := object[field]; !present || got != int64(0) {
					t.Fatalf("%s explicit wire zero was silently removed", field)
				}
			}
		})
	}
}
