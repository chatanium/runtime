package discordv2_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuditExactJSONPresenceAndCopyOwnership(t *testing.T) {
	for name, raw := range map[string]string{
		"large-integer": ` {"id":9007199254740993,"negative":-9223372036854775808,"decimal":1.2300e+4} `,
		"null":          `null`, "false": `false`, "zero": `0`, "empty-string": `""`, "empty-array": `[]`, "empty-object": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			sourceBytes := json.RawMessage(raw)
			got, err := discordv2.AuditLogChangeToProto(&discordv2.AuditLogChangeValue{OldValue: nil, NewValue: &discordv2.JSONValue{Raw: sourceBytes}})
			if err != nil || got.OldValue != nil || got.NewValue == nil || string(got.NewValue.Json) != raw {
				t.Fatalf("exact source JSON: %v, %v", got, err)
			}
			sourceBytes[0] = 'X'
			if string(got.NewValue.Json) != raw {
				t.Fatal("wire JSON aliases source bytes")
			}
			wireBytes := []byte(raw)
			decoded, err := discordv2.ProtoToAuditLogChange(&wire.AuditLogChange{OldValue: &corewire.JSONValue{Json: wireBytes}})
			if err != nil || decoded.NewValue != nil || decoded.OldValue == nil || !bytes.Equal(decoded.OldValue.Raw, []byte(raw)) {
				t.Fatalf("exact wire JSON: %#v, %v", decoded, err)
			}
			wireBytes[0] = 'X'
			if string(decoded.OldValue.Raw) != raw {
				t.Fatal("SDK JSON view aliases wire bytes")
			}
		})
	}
	key := discordgo.AuditLogChangeKey("name")
	entry, err := discordv2.AuditLogEntryToProto(&discordv2.AuditLogEntryView{ID: "audit-entry", TargetID: "target", UserID: "actor", Reason: "renamed", Changes: []*discordv2.AuditLogChangeValue{{Key: &key, NewValue: &discordv2.JSONValue{Raw: json.RawMessage(`"new-name"`)}}}})
	if err != nil || entry.GetId() != "audit-entry" || entry.GetTargetId() != "target" || entry.GetUserId() != "actor" || entry.GetReason() != "renamed" || entry.GetChanges().GetValues()[0].GetKey() != "name" || string(entry.GetChanges().GetValues()[0].GetNewValue().Json) != `"new-name"` {
		t.Fatalf("outer audit entry: %v, %v", entry, err)
	}
}

func TestMalformedAuditJSONFailsWholeResultWithoutEcho(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty": {}, "trailing-value": []byte(`{} []`), "invalid-utf8": {'"', 0xff, '"'}, "malformed": []byte(`{"private-token":"DO-NOT-ECHO",`),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := discordv2.GuildAuditLogToProto(&discordv2.GuildAuditLogView{AuditLogEntries: []*discordv2.AuditLogEntryView{{ID: "entry", Changes: []*discordv2.AuditLogChangeValue{{NewValue: &discordv2.JSONValue{Raw: raw}}}}}})
			if got != nil {
				t.Fatal("malformed nested JSON returned partial audit log")
			}
			detail := requireConversionError(t, err, "StructToProto", "GuildAuditLog", "AuditLogEntries[0]")
			if detail.Code != "InvalidJSON" || !strings.Contains(detail.Path, "Changes[0]") || strings.Contains(err.Error(), "DO-NOT-ECHO") {
				t.Fatalf("unsafe JSON diagnostic: %#v", detail)
			}
		})
	}
	got, err := discordv2.ProtoToAuditLogChange(&wire.AuditLogChange{NewValue: &corewire.JSONValue{Json: []byte(`false true`)}})
	if got != nil {
		t.Fatal("invalid wire JSON returned output")
	}
	requireConversionError(t, err, "ProtoToStruct", "AuditLogChange", "NewValue")
}

func conversionCredentialFixture() *corewire.CredentialRef {
	return &corewire.CredentialRef{OpaqueId: "opaque-not-a-token", BackendId: "discord", Purpose: "discord.interaction", ResourceScope: &corewire.ResourceSelector{ResourceIds: map[string]string{"interaction_id": "123"}}, ExpiresAt: timestamppb.New(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))}
}

func TestHandlesKeepCredentialsSeparateAndCopied(t *testing.T) {
	credential := conversionCredentialFixture()
	interaction, err := discordv2.ProtoToInteractionHandle(&wire.Interaction{Id: new("123"), Type: new(uint32(2)), CredentialRef: credential, Data: &wire.InteractionData{Data: &wire.InteractionData_ApplicationCommand{ApplicationCommand: &wire.ApplicationCommandInteractionData{Name: new("safe")}}}})
	if err != nil || interaction.Value.Token != "" || interaction.Value.ID != "123" || interaction.Credential.GetOpaqueId() != "opaque-not-a-token" {
		t.Fatalf("interaction handle: %#v, %v", interaction, err)
	}
	credential.ResourceScope.ResourceIds["interaction_id"] = "mutated"
	if interaction.Credential.ResourceScope.ResourceIds["interaction_id"] != "123" {
		t.Fatal("handle reference scope aliases wire")
	}
	webhookRef := conversionCredentialFixture()
	webhookRef.Purpose = "discord.webhook"
	webhookRef.ResourceScope.ResourceIds = map[string]string{"webhook_id": "456"}
	webhook, err := discordv2.ProtoToWebhookHandle(&wire.Webhook{Id: new("456"), Name: new("safe-webhook"), CredentialRef: webhookRef})
	if err != nil || webhook.Value.Token != "" || webhook.Value.Name != "safe-webhook" || webhook.Credential.GetOpaqueId() != "opaque-not-a-token" {
		t.Fatalf("webhook handle: %#v, %v", webhook, err)
	}
	webhookRef.ResourceScope.ResourceIds["webhook_id"] = "789"
	encoded, err := discordv2.WebhookHandleToProto(&discordv2.WebhookHandle{Value: &discordgo.Webhook{ID: "789", Name: "forward"}, Credential: webhookRef})
	if err != nil || encoded.GetId() != "789" || encoded.GetName() != "forward" || encoded.GetCredentialRef().GetOpaqueId() != "opaque-not-a-token" {
		t.Fatalf("forward handle: %v, %v", encoded, err)
	}
	// These are data-copy assertions only: a converter cannot authorize a ref.
}

func TestRawCredentialsFailWithoutLeakingValuesOrSecretMapKeys(t *testing.T) {
	const secret = "NEVER-EXPORT-RAW-CREDENTIAL"
	got, err := discordv2.MessageToProto(&discordgo.Message{Mentions: []*discordgo.User{{ID: "1", Token: secret}}})
	if got != nil {
		t.Fatal("nested raw user token accepted")
	}
	detail := requireConversionError(t, err, "StructToProto", "Message", "Mentions[0]")
	if detail.Code != "CredentialBoundaryRequired" || strings.Contains(err.Error(), secret) || strings.Contains(detail.Reason, secret) {
		t.Fatalf("unsafe credential diagnostic: %#v", detail)
	}
	resolved, err := discordv2.ApplicationCommandInteractionDataResolvedToProto(&discordgo.ApplicationCommandInteractionDataResolved{Users: map[string]*discordgo.User{secret: {Token: secret}}})
	if resolved != nil {
		t.Fatal("raw resolved credential accepted")
	}
	requireConversionError(t, err, "StructToProto", "ApplicationCommandInteractionDataResolved", "Users")
	if strings.Contains(err.Error(), secret) {
		t.Fatal("credential leaked through map key path")
	}
	interaction, err := discordv2.InteractionHandleToProto(&discordv2.InteractionHandle{Value: &discordgo.Interaction{ID: "123", Token: secret}})
	if interaction != nil {
		t.Fatal("raw interaction token accepted")
	}
	requireConversionError(t, err, "StructToProto", "Interaction", "Token")
	if strings.Contains(err.Error(), secret) {
		t.Fatal("interaction token leaked")
	}
	webhook, err := discordv2.WebhookHandleToProto(&discordv2.WebhookHandle{Value: &discordgo.Webhook{ID: "456", Token: secret}})
	if webhook != nil {
		t.Fatal("raw webhook token accepted")
	}
	requireConversionError(t, err, "StructToProto", "Webhook", "Token")
	voice, err := discordv2.VoiceStateToProto(&discordgo.VoiceState{SessionID: secret})
	if voice != nil {
		t.Fatal("voice session credential accepted")
	}
	requireConversionError(t, err, "StructToProto", "VoiceState", "SessionID")
	button, err := discordv2.MessageComponentToProto(discordgo.Button{Style: discordgo.LinkButton, URL: "https://discord.com/api/webhooks/123/" + secret})
	if button != nil {
		t.Fatal("token-bearing webhook URL accepted")
	}
	requireConversionError(t, err, "StructToProto", "MessageComponent", "URL")
	if strings.Contains(err.Error(), secret) {
		t.Fatal("webhook URL credential leaked")
	}
}

func TestAuditChangeKeyPresenceIsIndependentOfJSONNull(t *testing.T) {
	absent, err := discordv2.AuditLogChangeToProto(&discordv2.AuditLogChangeValue{NewValue: &discordv2.JSONValue{Raw: json.RawMessage("null")}})
	if err != nil || absent.Key != nil || absent.NewValue == nil || string(absent.NewValue.Json) != "null" {
		t.Fatalf("absent key with explicit null: %v, %v", absent, err)
	}
	emptyKey := discordgo.AuditLogChangeKey("")
	present, err := discordv2.AuditLogChangeToProto(&discordv2.AuditLogChangeValue{Key: &emptyKey})
	if err != nil || present.Key == nil || *present.Key != "" || present.OldValue != nil || present.NewValue != nil {
		t.Fatalf("present empty key: %v, %v", present, err)
	}
	decoded, err := discordv2.ProtoToAuditLogChange(&wire.AuditLogChange{Key: new(""), NewValue: &corewire.JSONValue{Json: []byte("null")}})
	if err != nil || decoded.Key == nil || *decoded.Key != "" || decoded.OldValue != nil || decoded.NewValue == nil || string(decoded.NewValue.Raw) != "null" {
		t.Fatalf("decoded key/null presence: %#v, %v", decoded, err)
	}
}
