package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
)

// A complete one-pixel PNG keeps the ordinary path independent of media tools.
const samplePNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aX1sAAAAASUVORK5CYII="

func attachmentEmbed(filename string) []*discordgo.MessageEmbed {
	return []*discordgo.MessageEmbed{{Type: discordgo.EmbedTypeRich, Title: "Explicit streamed upload", Image: &discordgo.MessageEmbedImage{URL: "attachment://" + filename}}}
}
func retainedAndNew(message *discordgo.Message) ([]discord.AttachmentEditEntry, error) {
	if message == nil || len(message.Attachments) != 1 || message.Attachments[0] == nil || !snowflake(message.Attachments[0].ID) {
		return nil, errors.New("expected one returned existing attachment ID")
	}
	return []discord.AttachmentEditEntry{{Source: discord.ExistingAttachmentID(message.Attachments[0].ID)}, {Source: discord.NewFileIndex(0)}}, nil
}
func (b *GeneralBot) attachmentDemo(ctx context.Context, h *discord.InteractionHandle) (result error) {
	raw, err := base64.StdEncoding.DecodeString(samplePNG)
	if err != nil {
		return err
	}
	ref, err := b.files.Upload(ctx, &corewire.UploadMetadata{FileName: "sample.png", ContentType: "image/png", DeclaredSizeBytes: uint64(len(raw))}, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, b.files.DeleteUpload(ctx, ref)) }()
	first := []discord.FileAttachment{{Ref: ref, Filename: "sample.png", Description: new("One pixel; uploaded explicitly before the Discord call")}}
	second := []discord.FileAttachment{{Ref: ref, Filename: "second.png", Description: new("Same owner-bound completed ref, explicitly reused")}}
	initial := []discord.AttachmentEditEntry{{Source: discord.NewFileIndex(0)}}
	// The previously deferred original response gets a file via an explicit edit.
	// Discord omits files referenced by embeds/components from Message.Attachments.
	// Keep this first upload unreferenced so the retention edit uses a returned ID.
	original, err := b.api.InteractionResponseEdit(ctx, h, &discord.WebhookEditPatch{Content: new("Uploaded original response"), Files: first, Attachments: &initial, AllowedMentions: noMentions()})
	if err != nil {
		return err
	}
	entries, err := retainedAndNew(original)
	if err != nil {
		return err
	}
	if _, err = b.api.InteractionResponseEdit(ctx, h, &discord.WebhookEditPatch{Content: new(""), Files: second, Attachments: &entries, Embeds: new(attachmentEmbed("second.png")), AllowedMentions: noMentions()}); err != nil {
		return err
	}
	// Keep text nonempty while clearing all other fields: Discord rejects an
	// entirely empty message, which is different from unsupported clear presence.
	emptyEmbeds := []*discordgo.MessageEmbed{}
	emptyComponents := []discordgo.MessageComponent{}
	emptyAttachments := []discord.AttachmentEditEntry{}
	if _, err = b.api.InteractionResponseEdit(ctx, h, &discord.WebhookEditPatch{Content: new("Original response: explicit empty embed/component/attachment lists"), Embeds: &emptyEmbeds, Components: &emptyComponents, Attachments: &emptyAttachments, AllowedMentions: noMentions()}); err != nil {
		return err
	}
	followup, err := b.api.FollowupMessageCreate(ctx, h, true, &discord.WebhookParamsView{Content: "Follow-up reuses the same completed upload ref.", Embeds: attachmentEmbed("sample.png"), Files: first, Components: func() []discordgo.MessageComponent {
		if b.forms {
			return formComponents()
		}
		return nil
	}(), AllowedMentions: noMentions(), Flags: discordgo.MessageFlagsEphemeral})
	if err != nil {
		return err
	}
	if followup == nil || !snowflake(followup.ID) {
		return errors.New("follow-up returned no message ID")
	}
	defer func() { result = errors.Join(result, b.api.FollowupMessageDelete(ctx, h, followup.ID)) }()
	if _, err = b.api.FollowupMessageEdit(ctx, h, followup.ID, &discord.WebhookEditPatch{Content: new("Follow-up edited with explicit clear"), Embeds: &emptyEmbeds, Components: &emptyComponents, Attachments: &emptyAttachments, AllowedMentions: noMentions()}); err != nil {
		return err
	}
	message, err := b.api.ChannelMessageSendComplex(ctx, h.Value.ChannelID, &discord.MessageSendView{Content: "Ordinary message with explicit upload ref", Files: first, Components: func() []discordgo.MessageComponent {
		if b.forms {
			return formComponents()
		}
		return nil
	}(), AllowedMentions: noMentions(), Flags: discordgo.MessageFlagsSuppressNotifications})
	if err != nil {
		return err
	}
	if message == nil || !snowflake(message.ID) {
		return errors.New("ordinary message returned no ID")
	}
	defer func() { result = errors.Join(result, b.api.ChannelMessageDelete(ctx, h.Value.ChannelID, message.ID)) }()
	entries, err = retainedAndNew(message)
	if err != nil {
		return err
	}
	if _, err = b.api.ChannelMessageEditComplex(ctx, &discord.MessageEditPatch{ID: message.ID, ChannelID: message.ChannelID, Content: new(""), Files: second, Attachments: &entries, Embeds: new(attachmentEmbed("second.png")), AllowedMentions: noMentions()}); err != nil {
		return err
	}
	if _, err = b.api.ChannelMessageEditComplex(ctx, &discord.MessageEditPatch{ID: message.ID, ChannelID: message.ChannelID, Content: new("Explicit clear completed; only this module's demonstration messages are deleted."), Embeds: &emptyEmbeds, Components: &emptyComponents, Attachments: &emptyAttachments, AllowedMentions: noMentions()}); err != nil {
		return err
	}
	// The deferred deletion repeats this successful deletion, exercising the finite
	// owner tombstone contract without retaining the ref beyond this callback.
	return b.files.DeleteUpload(ctx, ref)
}
