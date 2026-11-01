package discordv2_test

import (
	"testing"
	"time"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func conversionFileFixture() discordv2.FileAttachment {
	return discordv2.FileAttachment{Ref: &corewire.UploadedFileRef{OpaqueId: "upload-reference", FileName: "original.txt", ContentType: "text/plain", SizeBytes: 17, ExpiresAt: timestamppb.New(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))}, Filename: "renamed.txt", Description: new("evidence")}
}

func TestAttachmentEditIndexZeroIsASelectedValue(t *testing.T) {
	got, err := discordv2.AttachmentEditEntryToProto(&discordv2.AttachmentEditEntry{Source: discordv2.NewFileIndex(0)})
	if err != nil {
		t.Fatal(err)
	}
	selected, ok := got.Source.(*wire.AttachmentEditEntry_NewFileIndex)
	if !ok || selected.NewFileIndex != 0 {
		t.Fatalf("index zero lost oneof presence: %v", got)
	}
	decoded, err := discordv2.ProtoToAttachmentEditEntry(&wire.AttachmentEditEntry{Source: &wire.AttachmentEditEntry_NewFileIndex{NewFileIndex: 0}})
	if err != nil {
		t.Fatal(err)
	}
	index, ok := decoded.Source.(discordv2.NewFileIndex)
	if !ok || index != 0 {
		t.Fatalf("zero source concrete variant: %#v", decoded.Source)
	}
	var typedNil *discordv2.NewFileIndex
	for _, source := range []discordv2.AttachmentEditSource{nil, typedNil, new(discordv2.NewFileIndex(0))} {
		got, err := discordv2.AttachmentEditEntryToProto(&discordv2.AttachmentEditEntry{Source: source})
		if got != nil {
			t.Fatal("invalid source returned output")
		}
		requireConversionError(t, err, "StructToProto", "AttachmentEditEntry", "Source")
	}
	var nilSource *wire.AttachmentEditEntry_NewFileIndex
	for _, entry := range []*wire.AttachmentEditEntry{{}, {Source: nilSource}} {
		got, err := discordv2.ProtoToAttachmentEditEntry(entry)
		if got != nil {
			t.Fatal("empty source returned output")
		}
		requireConversionError(t, err, "ProtoToStruct", "AttachmentEditEntry", "Source")
	}
}

func TestMessageEditPreservesCompletePostEditSetAndMetadata(t *testing.T) {
	files := []discordv2.FileAttachment{conversionFileFixture()}
	entries := []discordv2.AttachmentEditEntry{{Source: discordv2.ExistingAttachmentID("123456789012345678")}, {Source: discordv2.NewFileIndex(0), Filename: new("renamed.txt"), Description: new("evidence")}}
	got, err := discordv2.MessageEditToProto(&discordv2.MessageEditPatch{ID: "message", ChannelID: "channel", Content: new(""), Flags: new(uint64(0)), Files: files, Attachments: &entries})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetId() != "message" || got.GetChannelId() != "channel" || got.Content == nil || got.Content.GetValue() != "" || got.Flags == nil || got.GetFlags() != 0 {
		t.Fatalf("patch scalar presence: %v", got)
	}
	attachments := got.GetAttachments().GetValues()
	if len(attachments) != 2 || attachments[0].GetExistingAttachmentId() != "123456789012345678" {
		t.Fatalf("complete ordered attachment set: %v", attachments)
	}
	if selected, ok := attachments[1].Source.(*wire.AttachmentEditEntry_NewFileIndex); !ok || selected.NewFileIndex != 0 {
		t.Fatalf("new file index: %v", attachments[1])
	}
	file := got.GetFiles().GetValues()[0]
	if file.GetUploadedFileRef().GetOpaqueId() != "upload-reference" || file.GetUploadedFileRef().GetContentType() != "text/plain" || file.GetUploadedFileRef().GetSizeBytes() != 17 || file.GetFilename() != "renamed.txt" || file.Description == nil || file.GetDescription() != "evidence" {
		t.Fatalf("file reference and metadata: %v", file)
	}
	files[0].Ref.OpaqueId = "mutated"
	*entries[1].Description = "changed"
	if file.GetUploadedFileRef().GetOpaqueId() != "upload-reference" || attachments[1].GetDescription() != "evidence" {
		t.Fatal("patch aliases source metadata")
	}
	decoded, err := discordv2.ProtoToMessageEdit(&wire.MessageEdit{Files: &wire.FileAttachmentList{Values: []*wire.FileAttachment{{UploadedFileRef: conversionFileFixture().Ref, Filename: "wire.txt"}}}, Attachments: &wire.AttachmentEditList{Values: []*wire.AttachmentEditEntry{{Source: &wire.AttachmentEditEntry_NewFileIndex{NewFileIndex: 0}}}}})
	if err != nil || decoded.Attachments == nil || len(*decoded.Attachments) != 1 || (*decoded.Attachments)[0].Source != discordv2.NewFileIndex(0) || decoded.Files[0].Filename != "wire.txt" {
		t.Fatalf("decoded complete set: %#v, %v", decoded, err)
	}
}

func TestEditAttachmentAbsentAndEmptyAreDifferent(t *testing.T) {
	omitted, err := discordv2.MessageEditToProto(&discordv2.MessageEditPatch{})
	if err != nil || omitted.Attachments != nil {
		t.Fatalf("omitted attachments: %v, %v", omitted, err)
	}
	empty := []discordv2.AttachmentEditEntry{}
	cleared, err := discordv2.MessageEditToProto(&discordv2.MessageEditPatch{Attachments: &empty})
	if err != nil || cleared.Attachments == nil || len(cleared.Attachments.Values) != 0 {
		t.Fatalf("clear attachments: %v, %v", cleared, err)
	}
	decoded, err := discordv2.ProtoToMessageEdit(&wire.MessageEdit{Attachments: &wire.AttachmentEditList{}})
	if err != nil || decoded.Attachments == nil || len(*decoded.Attachments) != 0 {
		t.Fatalf("decoded clear: %#v, %v", decoded, err)
	}
}

func TestEveryEditConversionRejectsIncompleteAttachmentSets(t *testing.T) {
	cases := []struct {
		name    string
		files   []discordv2.FileAttachment
		entries *[]discordv2.AttachmentEditEntry
	}{
		{"omitted-with-new-file", []discordv2.FileAttachment{conversionFileFixture()}, nil},
		{"missing-index", []discordv2.FileAttachment{conversionFileFixture()}, new([]discordv2.AttachmentEditEntry{{Source: discordv2.ExistingAttachmentID("123456789012345678")}})},
		{"duplicate-index", []discordv2.FileAttachment{conversionFileFixture()}, new([]discordv2.AttachmentEditEntry{{Source: discordv2.NewFileIndex(0)}, {Source: discordv2.NewFileIndex(0)}})},
		{"out-of-range", []discordv2.FileAttachment{conversionFileFixture()}, new([]discordv2.AttachmentEditEntry{{Source: discordv2.NewFileIndex(1)}})},
		{"duplicate-existing", nil, new([]discordv2.AttachmentEditEntry{{Source: discordv2.ExistingAttachmentID("123456789012345678")}, {Source: discordv2.ExistingAttachmentID("123456789012345678")}})},
		{"empty-oneof", nil, new([]discordv2.AttachmentEditEntry{{}})},
		{"filename-conflict", []discordv2.FileAttachment{conversionFileFixture()}, new([]discordv2.AttachmentEditEntry{{Source: discordv2.NewFileIndex(0), Filename: new("different.txt")}})},
		{"description-conflict", []discordv2.FileAttachment{conversionFileFixture()}, new([]discordv2.AttachmentEditEntry{{Source: discordv2.NewFileIndex(0), Description: new("different")}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message, err := discordv2.MessageEditToProto(&discordv2.MessageEditPatch{Files: tc.files, Attachments: tc.entries})
			if message != nil {
				t.Fatal("invalid message attachment set returned output")
			}
			requireConversionError(t, err, "StructToProto", "MessageEdit", "Attachments")
			webhook, err := discordv2.WebhookEditToProto(&discordv2.WebhookEditPatch{Files: tc.files, Attachments: tc.entries})
			if webhook != nil {
				t.Fatal("invalid webhook attachment set returned output")
			}
			requireConversionError(t, err, "StructToProto", "WebhookEdit", "Attachments")
			response, err := discordv2.InteractionResponseDataToProto(&discordv2.InteractionResponseDataView{Files: tc.files, Attachments: tc.entries})
			if response != nil {
				t.Fatal("invalid response-update attachment set returned output")
			}
			requireConversionError(t, err, "StructToProto", "InteractionResponseData", "Attachments")
		})
	}
}

func TestWireEditConversionsRejectMissingAndDuplicateIndices(t *testing.T) {
	for name, attachments := range map[string]*wire.AttachmentEditList{
		"omitted":   nil,
		"missing":   {},
		"duplicate": {Values: []*wire.AttachmentEditEntry{{Source: &wire.AttachmentEditEntry_NewFileIndex{NewFileIndex: 0}}, {Source: &wire.AttachmentEditEntry_NewFileIndex{NewFileIndex: 0}}}},
	} {
		t.Run(name, func(t *testing.T) {
			files := &wire.FileAttachmentList{Values: []*wire.FileAttachment{{UploadedFileRef: conversionFileFixture().Ref, Filename: "file.txt"}}}
			message, err := discordv2.ProtoToMessageEdit(&wire.MessageEdit{Files: files, Attachments: attachments})
			if message != nil {
				t.Fatal("invalid wire message edit returned output")
			}
			requireConversionError(t, err, "ProtoToStruct", "MessageEdit", "Attachments")
			webhook, err := discordv2.ProtoToWebhookEdit(&wire.WebhookEdit{Files: files, Attachments: attachments})
			if webhook != nil {
				t.Fatal("invalid wire webhook edit returned output")
			}
			requireConversionError(t, err, "ProtoToStruct", "WebhookEdit", "Attachments")
			response, err := discordv2.ProtoToInteractionResponseData(&wire.InteractionResponseData{Files: files, Attachments: attachments})
			if response != nil {
				t.Fatal("invalid wire response update returned output")
			}
			requireConversionError(t, err, "ProtoToStruct", "InteractionResponseData", "Attachments")
		})
	}
}

func TestWebhookEditRetainsZeroFlagsAndEmptyCollections(t *testing.T) {
	got, err := discordv2.WebhookEditToProto(&discordv2.WebhookEditPatch{Flags: new(uint64(0)), Attachments: new([]discordv2.AttachmentEditEntry{})})
	if err != nil || got.Flags == nil || got.GetFlags() != 0 || got.Attachments == nil {
		t.Fatalf("webhook patch presence: %v, %v", got, err)
	}
	decoded, err := discordv2.ProtoToWebhookEdit(&wire.WebhookEdit{Flags: new(uint64(0)), Attachments: &wire.AttachmentEditList{}})
	if err != nil || decoded.Flags == nil || *decoded.Flags != 0 || decoded.Attachments == nil || len(*decoded.Attachments) != 0 {
		t.Fatalf("decoded webhook patch presence: %#v, %v", decoded, err)
	}
}

func TestWebhookAndResponseUpdatesPreserveExplicitCompleteSets(t *testing.T) {
	entries := []discordv2.AttachmentEditEntry{{Source: discordv2.NewFileIndex(0)}, {Source: discordv2.ExistingAttachmentID("123456789012345678")}}
	files := []discordv2.FileAttachment{conversionFileFixture()}
	webhook, err := discordv2.WebhookEditToProto(&discordv2.WebhookEditPatch{Files: files, Attachments: &entries})
	if err != nil || len(webhook.GetAttachments().GetValues()) != 2 || webhook.GetAttachments().GetValues()[1].GetExistingAttachmentId() != "123456789012345678" || webhook.GetFiles().GetValues()[0].GetFilename() != "renamed.txt" {
		t.Fatalf("webhook complete set: %v, %v", webhook, err)
	}
	response, err := discordv2.InteractionResponseDataToProto(&discordv2.InteractionResponseDataView{Files: files, Attachments: &entries})
	if err != nil || len(response.GetAttachments().GetValues()) != 2 || response.GetAttachments().GetValues()[1].GetExistingAttachmentId() != "123456789012345678" || response.GetFiles().GetValues()[0].GetUploadedFileRef().GetOpaqueId() != "upload-reference" {
		t.Fatalf("response update complete set: %v, %v", response, err)
	}
	for _, selected := range []*wire.AttachmentEditEntry{webhook.GetAttachments().GetValues()[0], response.GetAttachments().GetValues()[0]} {
		if source, ok := selected.Source.(*wire.AttachmentEditEntry_NewFileIndex); !ok || source.NewFileIndex != 0 {
			t.Fatalf("selected index zero: %v", selected)
		}
	}
	decodedWebhook, err := discordv2.ProtoToWebhookEdit(&wire.WebhookEdit{Attachments: &wire.AttachmentEditList{Values: []*wire.AttachmentEditEntry{{Source: &wire.AttachmentEditEntry_ExistingAttachmentId{ExistingAttachmentId: "987654321098765432"}}}}})
	if err != nil || decodedWebhook.Attachments == nil || (*decodedWebhook.Attachments)[0].Source != discordv2.ExistingAttachmentID("987654321098765432") {
		t.Fatalf("wire webhook complete set: %#v, %v", decodedWebhook, err)
	}
	decodedResponse, err := discordv2.ProtoToInteractionResponseData(&wire.InteractionResponseData{Files: &wire.FileAttachmentList{Values: []*wire.FileAttachment{{UploadedFileRef: conversionFileFixture().Ref, Filename: "response.txt"}}}, Attachments: &wire.AttachmentEditList{Values: []*wire.AttachmentEditEntry{{Source: &wire.AttachmentEditEntry_NewFileIndex{NewFileIndex: 0}}}}})
	if err != nil || decodedResponse.Attachments == nil || (*decodedResponse.Attachments)[0].Source != discordv2.NewFileIndex(0) || decodedResponse.Files[0].Filename != "response.txt" {
		t.Fatalf("wire response complete set: %#v, %v", decodedResponse, err)
	}
}

func TestMissingUploadedFileReferenceIsNotMetadataOnlySuccess(t *testing.T) {
	entries := []discordv2.AttachmentEditEntry{{Source: discordv2.NewFileIndex(0)}}
	got, err := discordv2.MessageEditToProto(&discordv2.MessageEditPatch{Files: []discordv2.FileAttachment{{Filename: "lost.txt"}}, Attachments: &entries})
	if got != nil {
		t.Fatal("metadata-only file accepted without uploaded reference")
	}
	detail := requireConversionError(t, err, "StructToProto", "MessageEdit", "Files[0]")
	if detail.Code != "UploadedFileRefRequired" {
		t.Fatalf("missing uploaded ref code: %s", detail.Code)
	}
	decoded, err := discordv2.ProtoToMessageEdit(&wire.MessageEdit{Files: &wire.FileAttachmentList{Values: []*wire.FileAttachment{{Filename: "lost.txt"}}}, Attachments: &wire.AttachmentEditList{Values: []*wire.AttachmentEditEntry{{Source: &wire.AttachmentEditEntry_NewFileIndex{NewFileIndex: 0}}}}})
	if decoded != nil {
		t.Fatal("wire metadata-only file accepted")
	}
	requireConversionError(t, err, "ProtoToStruct", "MessageEdit", "Files[0]")
}
