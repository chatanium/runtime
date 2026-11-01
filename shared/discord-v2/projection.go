package discordv2

import (
	"context"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
)

type InteractionHandle struct {
	Value      *discordgo.Interaction
	Credential *corewire.CredentialRef
}
type WebhookHandle struct {
	Value      *discordgo.Webhook
	Credential *corewire.CredentialRef
}

// ProjectInteraction strips runtime-only nested user/voice credentials while
// minting refs only for approved interaction/webhook credentials. Policy derives
// each finite binding from that concrete source, never from reference metadata.
func ProjectInteraction(ctx context.Context, src *discordgo.Interaction, encoder core.CredentialEncoder, policy ProjectionPolicy) (*wire.Interaction, error) {
	c := newConversion("StructToProto", "Interaction")
	c.ctx = ctx
	c.encoder = encoder
	c.policy = policy
	c.projecting = true
	return c.toInteraction(src, "")
}
func ProjectWebhook(ctx context.Context, src *discordgo.Webhook, encoder core.CredentialEncoder, policy ProjectionPolicy) (*wire.Webhook, error) {
	c := newConversion("StructToProto", "Webhook")
	c.ctx = ctx
	c.encoder = encoder
	c.policy = policy
	c.projecting = true
	return c.toWebhook(src, "")
}
func ProjectVoiceState(ctx context.Context, src *discordgo.VoiceState, encoder core.CredentialEncoder, policy ProjectionPolicy) (*wire.VoiceState, error) {
	c := newConversion("StructToProto", "VoiceState")
	c.ctx = ctx
	c.encoder = encoder
	c.policy = policy
	c.projecting = true
	return c.toVoiceState(src, "")
}
func ProjectUser(ctx context.Context, src *discordgo.User, encoder core.CredentialEncoder, policy ProjectionPolicy) (*wire.User, error) {
	c := newConversion("StructToProto", "User")
	c.ctx = ctx
	c.encoder = encoder
	c.policy = policy
	c.projecting = true
	return c.toUser(src, "")
}
func ProjectMessage(ctx context.Context, src *discordgo.Message, encoder core.CredentialEncoder, policy ProjectionPolicy) (*wire.Message, error) {
	c := newConversion("StructToProto", "Message")
	c.ctx = ctx
	c.encoder = encoder
	c.policy = policy
	c.projecting = true
	return c.toMessage(src, "")
}
func InteractionHandleToProto(src *InteractionHandle) (*wire.Interaction, error) {
	return newConversion("StructToProto", "Interaction").toInteractionHandle(src, "")
}
func (c *conversion) toInteractionHandle(src *InteractionHandle, path string) (*wire.Interaction, error) {
	if src == nil {
		return nil, nil
	}
	if err := validateCredentialRef(src.Credential, c, fieldPath(path, "Credential")); err != nil {
		return nil, err
	}
	if src.Value == nil {
		return nil, c.fail("InvalidPresence", fieldPath(path, "Value"), "sanitized interaction value is required")
	}
	out, err := c.toInteraction(src.Value, path)
	if err != nil {
		return nil, err
	}
	out.CredentialRef = cloneCredential(src.Credential)
	return out, nil
}
func ProtoToInteractionHandle(src *wire.Interaction) (*InteractionHandle, error) {
	if src == nil {
		return nil, nil
	}
	c := newConversion("ProtoToStruct", "Interaction")
	value, err := c.fromInteraction(src, "")
	if err != nil {
		return nil, err
	}
	return &InteractionHandle{Value: value, Credential: cloneCredential(src.CredentialRef)}, nil
}
func WebhookHandleToProto(src *WebhookHandle) (*wire.Webhook, error) {
	return newConversion("StructToProto", "Webhook").toWebhookHandle(src, "")
}
func (c *conversion) toWebhookHandle(src *WebhookHandle, path string) (*wire.Webhook, error) {
	if src == nil {
		return nil, nil
	}
	if err := validateCredentialRef(src.Credential, c, fieldPath(path, "Credential")); err != nil {
		return nil, err
	}
	if src.Value == nil {
		return nil, c.fail("InvalidPresence", fieldPath(path, "Value"), "sanitized webhook value is required")
	}
	out, err := c.toWebhook(src.Value, path)
	if err != nil {
		return nil, err
	}
	out.CredentialRef = cloneCredential(src.Credential)
	return out, nil
}
func ProtoToWebhookHandle(src *wire.Webhook) (*WebhookHandle, error) {
	return newConversion("ProtoToStruct", "Webhook").fromWebhookHandle(src, "")
}
func (c *conversion) fromWebhookHandle(src *wire.Webhook, path string) (*WebhookHandle, error) {
	if src == nil {
		return nil, nil
	}
	value, err := c.fromWebhook(src, path)
	if err != nil {
		return nil, err
	}
	return &WebhookHandle{Value: value, Credential: cloneCredential(src.CredentialRef)}, nil
}

func validateModalComponents(components []discordgo.MessageComponent, c *conversion, path string) error {
	for i, component := range components {
		if err := validateModalComponent(component, false, c, indexPath(fieldPath(path, "Components"), i)); err != nil {
			return err
		}
	}
	return nil
}
func validateInteractionData(kind discordgo.InteractionType, data discordgo.InteractionData, c *conversion, path string) error {
	if data == nil {
		if kind == discordgo.InteractionApplicationCommand || kind == discordgo.InteractionApplicationCommandAutocomplete || kind == discordgo.InteractionMessageComponent || kind == discordgo.InteractionModalSubmit {
			return c.fail("InvalidPresence", path, "interaction data is required for this discriminator")
		}
		return nil
	}
	switch data.(type) {
	case discordgo.ApplicationCommandInteractionData, *discordgo.ApplicationCommandInteractionData:
		if kind == discordgo.InteractionApplicationCommand || kind == discordgo.InteractionApplicationCommandAutocomplete {
			return nil
		}
	case discordgo.MessageComponentInteractionData, *discordgo.MessageComponentInteractionData:
		if kind == discordgo.InteractionMessageComponent {
			return nil
		}
	case discordgo.ModalSubmitInteractionData, *discordgo.ModalSubmitInteractionData:
		if kind == discordgo.InteractionModalSubmit {
			return nil
		}
	}
	return c.fail("UnsupportedVariant", path, "interaction discriminator and data family disagree")
}
