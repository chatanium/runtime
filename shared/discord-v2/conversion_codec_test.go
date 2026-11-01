package discordv2_test

import (
	"context"
	"testing"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
)

func TestActivityJSONUsesUnixMillisecondsAndExactApplicationID(t *testing.T) {
	for _, applicationID := range []string{`9007199254740993`, `"9007199254740993"`} {
		raw := []byte(`{"name":"activity","created_at":1700000000123,"application_id":` + applicationID + `}`)
		got, err := discordv2.ProjectActivityJSON(context.Background(), raw, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.GetName() != "activity" || got.CreatedAt == nil || got.CreatedAt.Seconds != 1700000000 || got.CreatedAt.Nanos != 123000000 || got.ApplicationId == nil || got.GetApplicationId() != "9007199254740993" {
			t.Fatalf("activity numeric JSON codec: %v", got)
		}
	}
	negative, err := discordv2.ProjectActivityJSON(context.Background(), []byte(`{"created_at":-1}`), nil, nil)
	if err != nil || negative.CreatedAt == nil || negative.CreatedAt.Seconds != -1 || negative.CreatedAt.Nanos != 999000000 {
		t.Fatalf("negative Unix milliseconds: %v, %v", negative, err)
	}
	got, err := discordv2.ProjectActivityJSON(context.Background(), []byte(`{"created_at":"2023-11-14T22:13:20.123Z"}`), nil, nil)
	if got != nil {
		t.Fatal("ordinary time.Time JSON accepted for numeric Activity.created_at")
	}
	requireConversionError(t, err, "StructToProto", "Activity", "CreatedAt")
}

func TestPartialActivityJSONKeepsAbsentNullAndNumericZeroDistinct(t *testing.T) {
	raw := []byte(`{"activities":[{"name":"absent"},{"created_at":null,"application_id":null,"timestamps":{"start":0,"end":null}},{"created_at":0,"application_id":0}]}`)
	got, err := discordv2.ProjectPresenceUpdateEvent(context.Background(), raw, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	activities := got.GetPresence().GetValue().GetActivities().GetValue().GetValues()
	if len(activities) != 3 {
		t.Fatalf("activity JSON cases changed: %v", activities)
	}
	absent := activities[0].GetValue()
	if absent.CreatedAt != nil || absent.ApplicationId != nil || absent.Timestamps != nil {
		t.Fatalf("absent custom-codec fields fabricated: %v", absent)
	}
	null := activities[1].GetValue()
	if _, ok := null.GetCreatedAt().GetKind().(*corewire.NullableTimestamp_NullValue); !ok {
		t.Fatalf("null creation timestamp lost: %v", null)
	}
	if _, ok := null.GetApplicationId().GetKind().(*corewire.NullableString_NullValue); !ok {
		t.Fatalf("null application ID lost: %v", null)
	}
	timestamps := null.GetTimestamps().GetValue()
	start, ok := timestamps.GetStartTimestamp().GetKind().(*wire.DomainNullableSint64_Value)
	if !ok || start.Value != 0 {
		t.Fatalf("explicit zero start timestamp lost: %v", timestamps)
	}
	if _, ok := timestamps.GetEndTimestamp().GetKind().(*wire.DomainNullableSint64_NullValue); !ok {
		t.Fatalf("null end timestamp lost: %v", timestamps)
	}
	zero := activities[2].GetValue()
	created, ok := zero.GetCreatedAt().GetKind().(*corewire.NullableTimestamp_Value)
	if !ok || created.Value == nil || created.Value.Seconds != 0 || created.Value.Nanos != 0 {
		t.Fatalf("numeric zero creation timestamp lost: %v", zero)
	}
	applicationID, ok := zero.GetApplicationId().GetKind().(*corewire.NullableString_Value)
	if !ok || applicationID.Value != "0" {
		t.Fatalf("numeric zero application ID lost: %v", zero)
	}
}

func TestTimeStampsJSONKeepsExactSignedMillisecondValues(t *testing.T) {
	got, err := discordv2.ProjectTimeStampsJSON(context.Background(), []byte(`{"start":9007199254740993,"end":9223372036854775807}`), nil, nil)
	if err != nil || got.StartTimestamp == nil || got.EndTimestamp == nil || got.GetStartTimestamp() != 9007199254740993 || got.GetEndTimestamp() != 9223372036854775807 {
		t.Fatalf("timestamp precision or unit changed: %v, %v", got, err)
	}
	integral, err := discordv2.ProjectTimeStampsJSON(context.Background(), []byte(`{"start":9.007199254740993e15,"end":42.0}`), nil, nil)
	if err != nil || integral.GetStartTimestamp() != 9007199254740993 || integral.GetEndTimestamp() != 42 {
		t.Fatalf("exact integral exponent or decimal was rounded: %v, %v", integral, err)
	}
	for name, value := range map[string]string{
		"fraction":      `1.5`,
		"overflow":      `9223372036854775808`,
		"quoted":        `"123"`,
		"huge-exponent": `1e1000000000`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := discordv2.ProjectTimeStampsJSON(context.Background(), []byte(`{"start":`+value+`}`), nil, nil)
			if got != nil {
				t.Fatal("unrepresentable numeric timestamp returned output")
			}
			requireConversionError(t, err, "StructToProto", "TimeStamps", "StartTimestamp")
		})
	}
}

func TestRetryAfterJSONConvertsSecondsToExactNanoseconds(t *testing.T) {
	for _, tc := range []struct {
		seconds     string
		nanoseconds int64
	}{
		{"1.23456789", 1234567890},
		{"0.000000001", 1},
		{"9223372036.854775807", 9223372036854775807},
	} {
		got, err := discordv2.ProjectTooManyRequestsJSON(context.Background(), []byte(`{"bucket":"bucket","message":"retry","retry_after":`+tc.seconds+`}`), nil, nil)
		if err != nil || got.RetryAfter == nil || got.GetRetryAfter() != tc.nanoseconds || got.GetBucket() != "bucket" || got.GetMessage() != "retry" {
			t.Fatalf("retry_after %s seconds: %v, %v", tc.seconds, got, err)
		}
	}
	for name, value := range map[string]string{
		"sub-nanosecond":      `0.0000000001`,
		"nanosecond-overflow": `9223372036.854775808`,
		"quoted":              `"1.25"`,
		"huge-exponent":       `1e1000000000`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := discordv2.ProjectTooManyRequestsJSON(context.Background(), []byte(`{"retry_after":`+value+`}`), nil, nil)
			if got != nil {
				t.Fatal("unrepresentable retry_after returned output")
			}
			requireConversionError(t, err, "StructToProto", "TooManyRequests", "RetryAfter")
		})
	}
}

func TestActivityCreatedAtJSONChecksTimestampBoundaries(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		seconds int64
		nanos   int32
	}{
		{`{"created_at":0}`, 0, 0},
		{`{"created_at":253402300799999}`, 253402300799, 999000000},
		{`{"created_at":-62135596800000}`, -62135596800, 0},
	} {
		got, err := discordv2.ProjectActivityJSON(context.Background(), []byte(tc.raw), nil, nil)
		if err != nil || got.CreatedAt == nil || got.CreatedAt.Seconds != tc.seconds || got.CreatedAt.Nanos != tc.nanos {
			t.Fatalf("created_at boundary %s: %v, %v", tc.raw, got, err)
		}
	}
	for _, raw := range []string{`{"created_at":253402300800000}`, `{"created_at":-62135596800001}`} {
		got, err := discordv2.ProjectActivityJSON(context.Background(), []byte(raw), nil, nil)
		if got != nil {
			t.Fatal("created_at outside protobuf timestamp range returned output")
		}
		requireConversionError(t, err, "StructToProto", "Activity", "CreatedAt")
	}
}

func TestRawMessageAndModalComponentsPreserveCollectionPresence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		field   string
		present bool
		null    bool
	}{
		{"absent", "", false, false},
		{"empty", `,"components":[]`, true, false},
		{"null", `,"components":null`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			messageRaw := []byte(`{"content":"snapshot"` + tc.field + `}`)
			modalRaw := []byte(`{"custom_id":"modal"` + tc.field + `}`)
			if !tc.null {
				message, err := discordv2.ProjectMessageJSON(context.Background(), messageRaw, nil, nil)
				if err != nil || message.GetContent() != "snapshot" || (message.Components != nil) != tc.present || len(message.GetComponents().GetValues()) != 0 {
					t.Fatalf("snapshot message component presence: %v, %v", message, err)
				}
				modal, err := discordv2.ProjectModalSubmitInteractionDataJSON(context.Background(), modalRaw, nil, nil)
				if err != nil || modal.GetCustomId() != "modal" || (modal.Components != nil) != tc.present || len(modal.GetComponents().GetValues()) != 0 {
					t.Fatalf("snapshot modal component presence: %v, %v", modal, err)
				}
			}
			messageEvent, err := discordv2.ProjectMessageUpdateEvent(context.Background(), messageRaw, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			messageComponents := messageEvent.GetMessage().GetValue().GetComponents()
			if (messageComponents != nil) != tc.present {
				t.Fatalf("partial message component presence: %v", messageComponents)
			}
			modalEvent, err := discordv2.ProjectInteractionCreateEvent(context.Background(), []byte(`{"type":5,"data":`+string(modalRaw)+`}`), nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			modal := modalEvent.GetInteraction().GetValue().GetData().GetValue().GetModalSubmit()
			if modal.GetCustomId().GetValue() != "modal" {
				t.Fatalf("partial modal identity: %v", modal)
			}
			modalComponents := modal.GetComponents()
			if (modalComponents != nil) != tc.present {
				t.Fatalf("partial modal component presence: %v", modalComponents)
			}
			for _, components := range []*wire.DomainNullableDomainDomainNullablePartialMessageComponentList{messageComponents, modalComponents} {
				if tc.null {
					if _, ok := components.GetKind().(*wire.DomainNullableDomainDomainNullablePartialMessageComponentList_NullValue); !ok {
						t.Fatalf("explicit null components lost: %v", components)
					}
				} else if tc.present {
					selected, ok := components.GetKind().(*wire.DomainNullableDomainDomainNullablePartialMessageComponentList_Value)
					if !ok || selected.Value == nil || len(selected.Value.Values) != 0 {
						t.Fatalf("explicit empty component list lost: %v", components)
					}
				}
			}
		})
	}
}

func TestRawMessageComponentsDecodeNestedLayoutsAndMedia(t *testing.T) {
	raw := []byte(`{"components":[{"accent_color":0,"components":[
		{"components":[{"content":"Context","type":10}],"accessory":{"media":{"url":"https://example.com/thumb.png"},"description":"thumb","type":11},"type":9},
		{"items":[{"media":{"url":"https://example.com/gallery.png"},"description":"gallery","spoiler":true}],"type":12},
		{"file":{"url":"attachment://report.txt"},"spoiler":true,"type":13},
		{"divider":false,"spacing":2,"type":14},
		{"components":[{"custom_id":"approve","label":"Approve","style":3,"type":2}],"type":1},
		{"components":[{"custom_id":"menu","options":[{"label":"One","value":"one"}],"values":["one"],"type":3}],"type":1}
	],"type":17}]}`)
	snapshot, err := discordv2.ProjectMessageJSON(context.Background(), raw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	components := snapshot.GetComponents().GetValues()
	if len(components) != 1 || components[0].GetContainer().AccentColor == nil || components[0].GetContainer().GetAccentColor() != 0 {
		t.Fatalf("raw container variant or zero color lost: %v", snapshot)
	}
	children := components[0].GetContainer().GetComponents().GetValues()
	if len(children) != 6 {
		t.Fatalf("nested message layout changed: %v", children)
	}
	if children[0].GetSection().GetComponents().GetValues()[0].GetTextDisplay().GetContent() != "Context" || children[0].GetSection().GetAccessory().GetThumbnail().GetMedia().GetUrl() != "https://example.com/thumb.png" {
		t.Fatalf("raw section/text/thumbnail fields: %v", children[0])
	}
	if children[1].GetMediaGallery().GetItems().GetValues()[0].GetDescription() != "gallery" || !children[1].GetMediaGallery().GetItems().GetValues()[0].GetSpoiler() || children[2].GetFile().GetFile().GetUrl() != "attachment://report.txt" || !children[2].GetFile().GetSpoiler() {
		t.Fatalf("raw gallery/file fields: %v", children)
	}
	if children[3].GetSeparator().Divider == nil || children[3].GetSeparator().GetDivider() || children[3].GetSeparator().GetSpacing() != 2 || children[4].GetActionsRow().GetComponents().GetValues()[0].GetButton().GetCustomId() != "approve" {
		t.Fatalf("raw separator/row/button fields: %v", children)
	}
	menu := children[5].GetActionsRow().GetComponents().GetValues()[0].GetSelectMenu()
	if menu.GetMenuType() != 3 || menu.GetOptions().GetValues()[0].GetValue() != "one" || menu.GetValues().GetValues()[0] != "one" {
		t.Fatalf("raw select menu fields: %v", menu)
	}
	event, err := discordv2.ProjectMessageUpdateEvent(context.Background(), raw, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	partialChildren := event.GetMessage().GetValue().GetComponents().GetValue().GetValues()[0].GetValue().GetContainer().GetComponents().GetValue().GetValues()
	if partialChildren[0].GetValue().GetSection().GetComponents().GetValue().GetValues()[0].GetValue().GetTextDisplay().GetContent().GetValue() != "Context" || partialChildren[0].GetValue().GetSection().GetAccessory().GetValue().GetThumbnail().GetMedia().GetValue().GetUrl().GetValue() != "https://example.com/thumb.png" {
		t.Fatalf("partial nested section fields: %v", event)
	}
	divider, ok := partialChildren[3].GetValue().GetSeparator().GetDivider().GetKind().(*wire.DomainNullableBool_Value)
	if !ok || divider.Value || partialChildren[4].GetValue().GetActionsRow().GetComponents().GetValue().GetValues()[0].GetValue().GetButton().GetCustomId().GetValue() != "approve" {
		t.Fatalf("partial false divider/row/button fields: %v", event)
	}
	partialMenu := partialChildren[5].GetValue().GetActionsRow().GetComponents().GetValue().GetValues()[0].GetValue().GetSelectMenu()
	if partialMenu.GetMenuType().GetValue() != 3 || partialMenu.GetValues().GetValue().GetValues()[0].GetValue() != "one" {
		t.Fatalf("partial select menu fields: %v", partialMenu)
	}
}

func TestRawModalComponentsDecodeLabelsUploadsAndTextInputs(t *testing.T) {
	raw := []byte(`{"custom_id":"modal","components":[
		{"component":{"custom_id":"documents","required":false,"min_values":0,"values":["upload-id"],"type":19},"label":"Files","type":18},
		{"component":{"custom_id":"notes","style":1,"required":true,"value":"details","type":4},"label":"Notes","type":18}
	]}`)
	snapshot, err := discordv2.ProjectModalSubmitInteractionDataJSON(context.Background(), raw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	components := snapshot.GetComponents().GetValues()
	if len(components) != 2 || components[0].GetLabel().GetLabel() != "Files" || components[1].GetLabel().GetLabel() != "Notes" {
		t.Fatalf("raw modal label order: %v", snapshot)
	}
	upload := components[0].GetLabel().GetComponent().GetFileUpload()
	text := components[1].GetLabel().GetComponent().GetTextInput()
	if upload.GetCustomId() != "documents" || upload.Required == nil || upload.GetRequired() || upload.MinValues == nil || upload.GetMinValues() != 0 || upload.GetValues().GetValues()[0] != "upload-id" || text.GetCustomId() != "notes" || text.GetValue() != "details" || !text.GetRequired() || text.Label != nil {
		t.Fatalf("raw modal upload/text fields: %v", snapshot)
	}
	event, err := discordv2.ProjectInteractionCreateEvent(context.Background(), []byte(`{"data":`+string(raw)+`,"type":5}`), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	partialComponents := event.GetInteraction().GetValue().GetData().GetValue().GetModalSubmit().GetComponents().GetValue().GetValues()
	partialUpload := partialComponents[0].GetValue().GetLabel().GetComponent().GetValue().GetFileUpload()
	required, ok := partialUpload.GetRequired().GetKind().(*wire.DomainNullableBool_Value)
	if !ok || required.Value || partialUpload.GetMinValues().GetValue() != 0 || partialUpload.GetValues().GetValue().GetValues()[0].GetValue() != "upload-id" {
		t.Fatalf("partial upload values/presence: %v", partialUpload)
	}
	partialText := partialComponents[1].GetValue().GetLabel().GetComponent().GetValue().GetTextInput()
	if partialText.GetCustomId().GetValue() != "notes" || partialText.GetValue().GetValue() != "details" || partialText.GetRequired().GetValue() != true || partialText.Label != nil {
		t.Fatalf("partial text input fields/presence: %v", partialText)
	}
}
