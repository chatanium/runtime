package discordv2_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
)

type unsupportedConversionComponent struct{}

func (unsupportedConversionComponent) Type() discordgo.ComponentType { return 255 }
func (unsupportedConversionComponent) MarshalJSON() ([]byte, error) {
	return []byte(`{"type":255}`), nil
}

func TestComponentInvalidVariantsAndTypedNilFailAtomically(t *testing.T) {
	var typedNil *discordgo.Button
	for name, component := range map[string]discordgo.MessageComponent{"typed-nil": typedNil, "unknown": unsupportedConversionComponent{}} {
		t.Run(name, func(t *testing.T) {
			got, err := discordv2.MessageToProto(&discordgo.Message{Components: []discordgo.MessageComponent{discordgo.Button{CustomID: "first", Style: discordgo.PrimaryButton}, component}})
			if got != nil {
				t.Fatal("invalid nested component returned partial message")
			}
			requireConversionError(t, err, "StructToProto", "Message", "Components[1]")
		})
	}
	var typedNilOneof *wire.MessageComponent_Button
	for name, component := range map[string]*wire.MessageComponent{
		"empty-oneof":     {},
		"typed-nil-oneof": {Component: typedNilOneof},
		"nil-payload":     {Component: &wire.MessageComponent_Button{}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := discordv2.ProtoToMessageComponent(component)
			if got != nil {
				t.Fatal("invalid wire component returned output")
			}
			requireConversionError(t, err, "ProtoToStruct", "MessageComponent", "")
		})
	}
}

func TestButtonSKUOmissionMatchesSDKJSON(t *testing.T) {
	for _, sku := range []string{"", "123456789012345678"} {
		t.Run(sku, func(t *testing.T) {
			source := discordgo.Button{Label: "Button", Style: discordgo.PrimaryButton, CustomID: "ordinary"}
			if sku != "" {
				source.Style = discordgo.PremiumButton
				source.CustomID = ""
				source.SKUID = sku
			}
			raw, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			var sdkJSON map[string]json.RawMessage
			if err = json.Unmarshal(raw, &sdkJSON); err != nil {
				t.Fatal(err)
			}
			component, err := discordv2.MessageComponentToProto(source)
			if err != nil {
				t.Fatal(err)
			}
			button := component.GetButton()
			_, sourcePresent := sdkJSON["sku_id"]
			if button == nil || (button.Skuid != nil) != sourcePresent || button.GetSkuid() != sku {
				t.Fatal("SDK SKU omission or nonempty identifier was changed")
			}
		})
	}
}

func TestModalLabelFileUploadAndResolvedAttachments(t *testing.T) {
	src := &discordgo.ModalSubmitInteractionData{
		CustomID:   "evidence",
		Components: []discordgo.MessageComponent{discordgo.Label{ID: 7, Label: "Evidence", Description: "Upload documents", Component: discordgo.FileUpload{ID: 8, CustomID: "documents", MinValues: new(0), MaxValues: 3, Required: new(false), Values: []string{"lookup-file"}}}},
		Resolved: discordgo.ComponentInteractionDataResolved{
			Attachments: map[string]*discordgo.MessageAttachment{"lookup-file": {ID: "embedded-file", Filename: "evidence.txt", Size: 17, URL: "https://cdn.discordapp.com/attachments/1/2/evidence.txt?ex=abc&is=def&hm=123"}},
			Members:     map[string]*discordgo.Member{"partial": {Nick: "moderator"}},
		},
	}
	got, err := discordv2.ModalSubmitInteractionDataToProto(src)
	if err != nil {
		t.Fatal(err)
	}
	label := got.GetComponents().GetValues()[0].GetLabel()
	if label.GetId() != 7 || label.GetLabel() != "Evidence" || label.GetDescription() != "Upload documents" {
		t.Fatalf("label fields: %v", label)
	}
	upload := label.GetComponent().GetFileUpload()
	if upload.GetId() != 8 || upload.GetCustomId() != "documents" || upload.MinValues == nil || upload.GetMinValues() != 0 || upload.GetMaxValues() != 3 || upload.Required == nil || upload.GetRequired() || !reflect.DeepEqual(upload.GetValues().GetValues(), []string{"lookup-file"}) {
		t.Fatalf("upload fields: %v", upload)
	}
	attachment := got.GetResolved().GetAttachments().GetValues()["lookup-file"]
	if attachment.GetId() != "embedded-file" || attachment.GetFilename() != "evidence.txt" || attachment.GetSize() != 17 || attachment.GetUrl() != src.Resolved.Attachments["lookup-file"].URL {
		t.Fatalf("modal attachment: %v", attachment)
	}
	if got.GetResolved().GetMembers().GetValues()["partial"].GetUser() != nil {
		t.Fatal("modal fabricated partial member user")
	}
	src.Components[0] = discordgo.TextDisplay{Content: "mutated"}
	if got.GetComponents().GetValues()[0].GetLabel().GetLabel() != "Evidence" {
		t.Fatal("modal snapshot aliases source")
	}
	decoded, err := discordv2.ProtoToModalSubmitInteractionData(&wire.ModalSubmitInteractionData{
		CustomId: new("wire-modal"),
		Components: &wire.ComponentList{
			Values: []*wire.MessageComponent{
				{
					Component: &wire.MessageComponent_Label{
						Label: &wire.Label{
							Label: new("Files"),
							Component: &wire.MessageComponent{
								Component: &wire.MessageComponent_FileUpload{
									FileUpload: &wire.FileUpload{
										CustomId: new("wire-file"),
										Required: new(true),
										Values: &wire.DomainStringList{
											Values: []string{"wire-key"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Resolved: &wire.ComponentInteractionDataResolved{Attachments: &wire.DomainStringToMessageAttachmentMap{Values: map[string]*wire.MessageAttachment{"wire-key": {Id: new("different-id"), Filename: new("wire.txt")}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(decoded.Components[0])
	if err != nil {
		t.Fatal(err)
	}
	var object struct {
		Type      int    `json:"type"`
		Label     string `json:"label"`
		Component struct {
			Type     int      `json:"type"`
			CustomID string   `json:"custom_id"`
			Required *bool    `json:"required"`
			Values   []string `json:"values"`
		} `json:"component"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	if object.Type != 18 || object.Label != "Files" || object.Component.Type != 19 || object.Component.CustomID != "wire-file" || object.Component.Required == nil || !*object.Component.Required || !reflect.DeepEqual(object.Component.Values, []string{"wire-key"}) || decoded.Resolved.Attachments["wire-key"].ID != "different-id" || decoded.Resolved.Attachments["wire-key"].Filename != "wire.txt" {
		t.Fatalf("decoded modal: %s, %#v", raw, decoded.Resolved)
	}
}

func TestRequiredPointerSemanticsOnModalControls(t *testing.T) {
	for _, required := range []*bool{nil, new(false), new(true)} {
		text, err := discordv2.TextInputToProto(&discordgo.TextInput{CustomID: "text", Style: discordgo.TextInputShort, Required: required})
		if err != nil || !reflect.DeepEqual(text.Required, required) {
			t.Fatalf("text required %v: %v, %v", required, text, err)
		}
		selectMenu, err := discordv2.SelectMenuToProto(&discordgo.SelectMenu{CustomID: "select", Required: required, Values: []string{"one", "two"}})
		if err != nil || !reflect.DeepEqual(selectMenu.Required, required) || !reflect.DeepEqual(selectMenu.GetValues().GetValues(), []string{"one", "two"}) {
			t.Fatalf("select required: %v, %v", selectMenu, err)
		}
		upload, err := discordv2.FileUploadToProto(&discordgo.FileUpload{CustomID: "upload", Required: required})
		if err != nil || !reflect.DeepEqual(upload.Required, required) {
			t.Fatalf("upload required: %v, %v", upload, err)
		}
		decoded, err := discordv2.ProtoToTextInput(&wire.TextInput{CustomId: new("text"), Style: new(uint64(1)), Required: required})
		if err != nil || !reflect.DeepEqual(decoded.Required, required) {
			t.Fatalf("decoded required: %#v, %v", decoded, err)
		}
		raw, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		_, present := object["required"]
		if present != (required != nil) || (required != nil && string(object["required"]) != map[bool]string{false: "false", true: "true"}[*required]) {
			t.Fatalf("required JSON: %s", raw)
		}
		if _, present := object["label"]; present {
			t.Fatalf("empty TextInput label no longer omitted: %s", raw)
		}
		decodedSelect, err := discordv2.ProtoToSelectMenu(&wire.SelectMenu{Required: required, Values: &wire.DomainStringList{Values: []string{"selected"}}})
		if err != nil || !reflect.DeepEqual(decodedSelect.Required, required) || !reflect.DeepEqual(decodedSelect.Values, []string{"selected"}) {
			t.Fatalf("decoded select: %#v, %v", decodedSelect, err)
		}
		decodedUpload, err := discordv2.ProtoToFileUpload(&wire.FileUpload{Required: required, MinValues: new(int64(0)), MaxValues: new(int64(2))})
		if err != nil || !reflect.DeepEqual(decodedUpload.Required, required) || decodedUpload.MinValues == nil || *decodedUpload.MinValues != 0 || decodedUpload.MaxValues != 2 {
			t.Fatalf("decoded upload: %#v, %v", decodedUpload, err)
		}
	}
}

func TestFileUploadMustBeInsideLabelInModal(t *testing.T) {
	for _, components := range [][]discordgo.MessageComponent{
		{discordgo.FileUpload{CustomID: "unwrapped"}},
		{discordgo.ActionsRow{Components: []discordgo.MessageComponent{discordgo.FileUpload{CustomID: "row-upload"}}}},
	} {
		got, err := discordv2.ModalSubmitInteractionDataToProto(&discordgo.ModalSubmitInteractionData{Components: components})
		if got != nil {
			t.Fatal("invalid upload placement returned output")
		}
		requireConversionError(t, err, "StructToProto", "ModalSubmitInteractionData", "Components")
	}
	decoded, err := discordv2.ProtoToModalSubmitInteractionData(&wire.ModalSubmitInteractionData{
		Components: &wire.ComponentList{
			Values: []*wire.MessageComponent{
				{
					Component: &wire.MessageComponent_FileUpload{
						FileUpload: &wire.FileUpload{CustomId: new("unwrapped")},
					},
				},
			},
		},
		Resolved: &wire.ComponentInteractionDataResolved{},
	})
	if decoded != nil {
		t.Fatal("invalid wire upload placement returned output")
	}
	requireConversionError(t, err, "ProtoToStruct", "ModalSubmitInteractionData", "Components")
}

func TestInteractionFamilyAndAutocompleteAccessors(t *testing.T) {
	for _, kind := range []uint32{2, 4} {
		got, err := discordv2.ProtoToInteractionHandle(&wire.Interaction{Type: new(kind), Data: &wire.InteractionData{Data: &wire.InteractionData_ApplicationCommand{ApplicationCommand: &wire.ApplicationCommandInteractionData{Name: new("search"), Options: &wire.DomainApplicationCommandInteractionDataOptionList{Values: []*wire.ApplicationCommandInteractionDataOption{{Name: new("query"), Type: new(uint32(3)), Focused: new(true), Value: &wire.ApplicationCommandOptionValue{Value: &wire.ApplicationCommandOptionValue_StringValue{StringValue: "find"}}}}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		data := got.Value.ApplicationCommandData()
		if got.Value.Type != discordgo.InteractionType(kind) || data.Name != "search" || data.GetOption("query").StringValue() != "find" || !data.GetOption("query").Focused {
			t.Fatalf("command/autocomplete data: %#v", data)
		}
	}
	component, err := discordv2.ProtoToInteractionHandle(&wire.Interaction{Type: new(uint32(3)), Data: &wire.InteractionData{Data: &wire.InteractionData_MessageComponent{MessageComponent: &wire.MessageComponentInteractionData{CustomId: new("pick"), ComponentType: new(uint64(3)), Values: &wire.DomainStringList{Values: []string{"selected"}}, Resolved: &wire.ComponentInteractionDataResolved{}}}}})
	if err != nil || component.Value.MessageComponentData().CustomID != "pick" || component.Value.MessageComponentData().Values[0] != "selected" {
		t.Fatalf("component accessor: %#v, %v", component, err)
	}
	modal, err := discordv2.ProtoToInteractionHandle(&wire.Interaction{Type: new(uint32(5)), Data: &wire.InteractionData{Data: &wire.InteractionData_ModalSubmit{ModalSubmit: &wire.ModalSubmitInteractionData{CustomId: new("submitted"), Resolved: &wire.ComponentInteractionDataResolved{}}}}})
	if err != nil || modal.Value.ModalSubmitData().CustomID != "submitted" {
		t.Fatalf("modal accessor: %#v, %v", modal, err)
	}
	wrong, err := discordv2.ProtoToInteractionHandle(&wire.Interaction{Type: new(uint32(3)), Data: &wire.InteractionData{Data: &wire.InteractionData_ApplicationCommand{ApplicationCommand: &wire.ApplicationCommandInteractionData{Name: new("wrong-family")}}}})
	if wrong != nil {
		t.Fatal("interaction discriminator mismatch accepted")
	}
	requireConversionError(t, err, "ProtoToStruct", "Interaction", "Data")
}

func TestRichLayoutComponentsRetainNestedMediaAndPresence(t *testing.T) {
	got, err := discordv2.MessageComponentToProto(discordgo.Container{
		ID: 20, AccentColor: new(0), Spoiler: true,
		Components: []discordgo.MessageComponent{
			discordgo.Section{ID: 21, Components: []discordgo.MessageComponent{discordgo.TextDisplay{Content: "Context"}}, Accessory: discordgo.Thumbnail{Media: discordgo.UnfurledMediaItem{URL: "https://example.com/thumb.png"}, Description: new("thumbnail"), Spoiler: true}},
			discordgo.MediaGallery{Items: []discordgo.MediaGalleryItem{{Media: discordgo.UnfurledMediaItem{URL: "https://example.com/first.png"}, Description: new("first"), Spoiler: true}, {Media: discordgo.UnfurledMediaItem{URL: "https://example.com/second.png"}, Description: new("")}}},
			discordgo.FileComponent{ID: 22, File: discordgo.UnfurledMediaItem{URL: "attachment://report.txt"}, Spoiler: true},
			discordgo.Separator{ID: 23, Divider: new(false), Spacing: new(discordgo.SeparatorSpacingSizeLarge)},
			discordgo.ActionsRow{ID: 24, Components: []discordgo.MessageComponent{discordgo.Button{CustomID: "approve", Label: "Approve", Style: discordgo.SuccessButton, Emoji: &discordgo.ComponentEmoji{Name: "check", ID: "emoji-id", Animated: true}}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	container := got.GetContainer()
	if container.GetId() != 20 || container.AccentColor == nil || container.GetAccentColor() != 0 || !container.GetSpoiler() {
		t.Fatalf("container: %v", container)
	}
	children := container.GetComponents().GetValues()
	section := children[0].GetSection()
	if section.GetId() != 21 || section.GetComponents().GetValues()[0].GetTextDisplay().GetContent() != "Context" || section.GetAccessory().GetThumbnail().GetMedia().GetUrl() != "https://example.com/thumb.png" || section.GetAccessory().GetThumbnail().GetDescription() != "thumbnail" || !section.GetAccessory().GetThumbnail().GetSpoiler() {
		t.Fatalf("section: %v", section)
	}
	items := children[1].GetMediaGallery().GetItems().GetValues()
	if items[0].GetMedia().GetUrl() != "https://example.com/first.png" || !items[0].GetSpoiler() || items[1].GetMedia().GetUrl() != "https://example.com/second.png" || items[1].Description == nil || items[1].GetDescription() != "" {
		t.Fatalf("gallery: %v", items)
	}
	if children[2].GetFile().GetFile().GetUrl() != "attachment://report.txt" || !children[2].GetFile().GetSpoiler() || children[3].GetSeparator().Divider == nil || children[3].GetSeparator().GetDivider() || children[3].GetSeparator().GetSpacing() != 2 {
		t.Fatalf("file/separator: %v", children)
	}
	button := children[4].GetActionsRow().GetComponents().GetValues()[0].GetButton()
	if button.GetCustomId() != "approve" || button.GetStyle() != 3 || button.GetEmoji().GetId() != "emoji-id" || !button.GetEmoji().GetAnimated() {
		t.Fatalf("nested button: %v", button)
	}
	decoded, err := discordv2.ProtoToMessageComponent(&wire.MessageComponent{Component: &wire.MessageComponent_Container{Container: &wire.Container{AccentColor: new(int64(0)), Components: &wire.ComponentList{Values: []*wire.MessageComponent{{Component: &wire.MessageComponent_Separator{Separator: &wire.Separator{Divider: new(false), Spacing: new(uint64(2))}}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Type        int  `json:"type"`
		AccentColor *int `json:"accent_color"`
		Components  []struct {
			Type    int   `json:"type"`
			Divider *bool `json:"divider"`
			Spacing int   `json:"spacing"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.Type != 17 || body.AccentColor == nil || *body.AccentColor != 0 || body.Components[0].Type != 14 || body.Components[0].Divider == nil || *body.Components[0].Divider || body.Components[0].Spacing != 2 {
		t.Fatalf("decoded layout JSON: %s", raw)
	}
}

func TestOutboundOptionalStringsMatchSourceJSON(t *testing.T) {
	cases := []struct {
		name    string
		source  any
		convert func(any) (any, error)
	}{
		{"Button", &discordgo.Button{}, func(v any) (any, error) { return discordv2.ButtonToProto(v.(*discordgo.Button)) }},
		{"ComponentEmoji", &discordgo.ComponentEmoji{}, func(v any) (any, error) { return discordv2.ComponentEmojiToProto(v.(*discordgo.ComponentEmoji)) }},
		{"FileUpload", &discordgo.FileUpload{}, func(v any) (any, error) { return discordv2.FileUploadToProto(v.(*discordgo.FileUpload)) }},
		{"Label", &discordgo.Label{Component: discordgo.TextInput{CustomID: "input"}}, func(v any) (any, error) { return discordv2.LabelToProto(v.(*discordgo.Label)) }},
		{"SelectMenu", &discordgo.SelectMenu{}, func(v any) (any, error) { return discordv2.SelectMenuToProto(v.(*discordgo.SelectMenu)) }},
		{"SelectMenuOption", &discordgo.SelectMenuOption{}, func(v any) (any, error) { return discordv2.SelectMenuOptionToProto(v.(*discordgo.SelectMenuOption)) }},
		{"TextInput", &discordgo.TextInput{}, func(v any) (any, error) { return discordv2.TextInputToProto(v.(*discordgo.TextInput)) }},
		{"MessageSend", &discordgo.MessageSend{}, func(v any) (any, error) {
			return discordv2.MessageSendToProto(&discordv2.MessageSendView{Content: v.(*discordgo.MessageSend).Content})
		}},
		{"WebhookParams", &discordgo.WebhookParams{}, func(v any) (any, error) {
			source := v.(*discordgo.WebhookParams)
			return discordv2.WebhookParamsToProto(&discordv2.WebhookParamsView{Content: source.Content, Username: source.Username, AvatarURL: source.AvatarURL, ThreadName: source.ThreadName})
		}},
	}
	// Source JSON tags, not a duplicated omission list, identify the fields
	// covered by this outbound policy. The wire Go names normalize SDK acronyms.
	wireNames := map[string]string{"URL": "Url", "CustomID": "CustomId", "SKUID": "Skuid", "ID": "Id", "AvatarURL": "AvatarUrl"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := reflect.ValueOf(tc.source).Elem()
			for _, value := range []string{"", "source-value"} {
				for index := range source.NumField() {
					field := source.Type().Field(index)
					if source.Field(index).Kind() == reflect.String && strings.Contains(field.Tag.Get("json"), ",omitempty") {
						source.Field(index).SetString(value)
					}
				}
				raw, err := json.Marshal(tc.source)
				if err != nil {
					t.Fatal(err)
				}
				var sourceJSON map[string]json.RawMessage
				if err = json.Unmarshal(raw, &sourceJSON); err != nil {
					t.Fatal(err)
				}
				converted, err := tc.convert(tc.source)
				if err != nil {
					t.Fatal(err)
				}
				output := reflect.ValueOf(converted).Elem()
				for index := range source.NumField() {
					field := source.Type().Field(index)
					tag := field.Tag.Get("json")
					if source.Field(index).Kind() != reflect.String || !strings.Contains(tag, ",omitempty") {
						continue
					}
					jsonName := strings.Split(tag, ",")[0]
					wireName := field.Name
					if normalized, ok := wireNames[wireName]; ok {
						wireName = normalized
					}
					wireField := output.FieldByName(wireName)
					if !wireField.IsValid() || wireField.Kind() != reflect.Pointer {
						t.Fatalf("%s has no optional wire string", field.Name)
					}
					_, sourcePresent := sourceJSON[jsonName]
					if (!wireField.IsNil()) != sourcePresent || !wireField.IsNil() && wireField.Elem().String() != value {
						t.Fatalf("%s does not match source JSON omission/value", field.Name)
					}
				}
			}
		})
	}
}
