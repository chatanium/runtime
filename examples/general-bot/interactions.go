package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const formButton = "flex.general.form.open"
const formSelect = "flex.general.form.topic"
const formRoot = "flex.general.form.submit"
const formInput = "feedback"

type commandRejection string

func (e commandRejection) Error() string { return string(e) }
func routeClaims(app string) []*wire.InteractionRouteClaim {
	return []*wire.InteractionRouteClaim{
		{ApplicationId: app, InteractionKind: wire.InteractionRouteKind_INTERACTION_ROUTE_KIND_MESSAGE_COMPONENT, CustomId: formButton},
		{ApplicationId: app, InteractionKind: wire.InteractionRouteKind_INTERACTION_ROUTE_KIND_MESSAGE_COMPONENT, CustomId: formSelect},
		{ApplicationId: app, InteractionKind: wire.InteractionRouteKind_INTERACTION_ROUTE_KIND_MODAL_SUBMIT, CustomId: formRoot},
	}
}
func formComponents() []discordgo.MessageComponent {
	return []discordgo.MessageComponent{
		discordgo.ActionsRow{Components: []discordgo.MessageComponent{discordgo.Button{Label: "Open feedback", Style: discordgo.PrimaryButton, CustomID: formButton}}},
		discordgo.ActionsRow{Components: []discordgo.MessageComponent{discordgo.SelectMenu{CustomID: formSelect, Options: []discordgo.SelectMenuOption{{Label: "Runtime", Value: "runtime"}, {Label: "Settings", Value: "settings"}}, MaxValues: 1}}},
	}
}
func presentString(v *corewire.NullableString) (string, bool) {
	if v == nil {
		return "", false
	}
	value, ok := v.Kind.(*corewire.NullableString_Value)
	if !ok {
		return "", false
	}
	return value.Value, true
}
func partialOptions(p *wire.PartialApplicationCommandInteractionData) ([]*discordgo.ApplicationCommandInteractionDataOption, error) {
	out := []*discordgo.ApplicationCommandInteractionDataOption{}
	for _, wrapped := range p.Options.GetValue().GetValues() {
		v := wrapped.GetValue()
		if v == nil || v.Type == nil {
			return nil, commandRejection("missing typed command option")
		}
		name, ok := presentString(v.Name)
		if !ok {
			return nil, commandRejection("missing command option name")
		}
		if v.Options != nil {
			return nil, commandRejection("nested options are unsupported by ordinary commands")
		}
		converted, err := discord.ProtoToApplicationCommandInteractionDataOption(&wire.ApplicationCommandInteractionDataOption{Name: new(name), Type: new(v.Type.GetValue()), Value: v.Value.GetValue(), Focused: new(v.Focused.GetValue())})
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return out, nil
}

// Consume only actual typed ingress fields. This is not a JSON roundtrip and does
// not fill absent member/user data or source cache snapshots with invented data.
func interactionHandle(p *wire.PartialInteraction) (*discord.InteractionHandle, error) {
	if p == nil {
		return nil, errors.New("missing interaction payload")
	}
	id, idOK := presentString(p.Id)
	app, appOK := presentString(p.AppId)
	if !idOK || !appOK || !snowflake(id) || !snowflake(app) || p.Type == nil || p.Type.GetValue() > 255 || p.CredentialRef.GetValue() == nil {
		return nil, errors.New("incomplete interaction identity or credential")
	}
	i := &discordgo.Interaction{ID: id, AppID: app, Type: discordgo.InteractionType(p.Type.GetValue()), GuildID: p.GuildId.GetValue(), ChannelID: p.ChannelId.GetValue()}
	if member := p.Member.GetValue(); member != nil {
		i.Member = &discordgo.Member{}
		if permissions, ok := presentString(member.Permissions); ok {
			value, err := strconv.ParseInt(permissions, 10, 64)
			if err != nil || value < 0 {
				return nil, errors.New("invalid member permissions")
			}
			i.Member.Permissions = value
		}
		if u := member.User.GetValue(); u != nil {
			if user, ok := presentString(u.Id); ok {
				i.Member.User = &discordgo.User{ID: user}
			}
		}
	}
	if u := p.User.GetValue(); u != nil {
		if user, ok := presentString(u.Id); ok {
			i.User = &discordgo.User{ID: user}
		}
	}
	switch i.Type {
	case discordgo.InteractionApplicationCommand, discordgo.InteractionApplicationCommandAutocomplete:
		data := p.Data.GetValue().GetApplicationCommand()
		if data == nil {
			return nil, errors.New("command discriminator has no command data")
		}
		options, err := partialOptions(data)
		if err != nil {
			return nil, err
		}
		i.Data = discordgo.ApplicationCommandInteractionData{ID: data.Id.GetValue(), Name: data.Name.GetValue(), CommandType: discordgo.ApplicationCommandType(data.CommandType.GetValue()), Options: options}
	case discordgo.InteractionMessageComponent:
		data := p.Data.GetValue().GetMessageComponent()
		if data == nil {
			return nil, errors.New("component discriminator has no component data")
		}
		values := []string{}
		for _, v := range data.Values.GetValue().GetValues() {
			s, ok := presentString(v)
			if !ok {
				return nil, errors.New("invalid select value")
			}
			values = append(values, s)
		}
		i.Data = discordgo.MessageComponentInteractionData{CustomID: data.CustomId.GetValue(), ComponentType: discordgo.ComponentType(data.ComponentType.GetValue()), Values: values}
	case discordgo.InteractionModalSubmit:
		data := p.Data.GetValue().GetModalSubmit()
		if data == nil {
			return nil, errors.New("modal discriminator has no modal data")
		}
		components, err := modalComponents(data.Components.GetValue().GetValues(), 0)
		if err != nil {
			return nil, err
		}
		i.Data = discordgo.ModalSubmitInteractionData{CustomID: data.CustomId.GetValue(), Components: components}
	default:
		return nil, errors.New("unsupported interaction kind")
	}
	return &discord.InteractionHandle{Value: i, Credential: p.CredentialRef.GetValue()}, nil
}
func modalComponents(values []*wire.DomainNullablePartialMessageComponent, depth int) ([]discordgo.MessageComponent, error) {
	if depth > 2 || len(values) > 5 {
		return nil, errors.New("invalid modal component depth or count")
	}
	out := []discordgo.MessageComponent{}
	for _, wrapped := range values {
		v := wrapped.GetValue()
		if v == nil {
			return nil, errors.New("missing modal component")
		}
		switch c := v.Component.(type) {
		case *wire.PartialMessageComponent_ActionsRow:
			children, err := modalComponents(c.ActionsRow.Components.GetValue().GetValues(), depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, discordgo.ActionsRow{Components: children})
		case *wire.PartialMessageComponent_TextInput:
			input := c.TextInput
			id, ok := presentString(input.CustomId)
			if !ok {
				return nil, errors.New("missing modal input ID")
			}
			value, ok := presentString(input.Value)
			if !ok {
				return nil, commandRejection("modal input value is absent")
			}
			out = append(out, discordgo.TextInput{CustomID: id, Value: value, Style: discordgo.TextInputStyle(input.Style.GetValue())})
		default:
			return nil, errors.New("unexpected modal component family")
		}
	}
	return out, nil
}
func actor(i *discordgo.Interaction) (string, error) {
	if i.GuildID != "" {
		if i.Member == nil || i.Member.User == nil || !snowflake(i.Member.User.ID) {
			return "", commandRejection("guild interaction has no acting member user")
		}
		return i.Member.User.ID, nil
	}
	if i.User == nil || !snowflake(i.User.ID) {
		return "", commandRejection("DM interaction has no acting user")
	}
	return i.User.ID, nil
}
func expectedCommandFailure(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if !expectedCommandFailure(cause) {
				return false
			}
		}
		return true
	}
	var changed *changedResourceError
	if errors.As(err, &changed) {
		return false
	}
	var rejected commandRejection
	if errors.As(err, &rejected) {
		return true
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.NotFound, codes.PermissionDenied, codes.ResourceExhausted, codes.FailedPrecondition, codes.AlreadyExists, codes.DeadlineExceeded, codes.Canceled, codes.Unavailable:
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
func safeFailure(err error) string {
	var changed *changedResourceError
	if errors.As(err, &changed) {
		return "Channel " + changed.channelID + " was changed, but its durable ownership update failed. Inspect that exact channel; no automatic retry or rollback was performed."
	}
	var rejected commandRejection
	if errors.As(err, &rejected) {
		return "Request rejected: " + truncate(string(rejected), 300)
	}
	return "The operation failed (" + status.Code(err).String() + "). No success or automatic retry is implied."
}
func (b *GeneralBot) reportFailure(ctx context.Context, h *discord.InteractionHandle, err error, deferred bool) error {
	text := safeFailure(err)
	var reporting error
	if deferred {
		_, reporting = b.api.InteractionResponseEdit(ctx, h, &discord.WebhookEditPatch{Content: new(text), AllowedMentions: noMentions()})
	} else if h.Value.Type == discordgo.InteractionApplicationCommandAutocomplete {
		reporting = b.api.InteractionRespond(ctx, h, &discord.InteractionResponseView{Type: discordgo.InteractionApplicationCommandAutocompleteResult, Data: &discord.InteractionResponseDataView{Choices: []*discordgo.ApplicationCommandOptionChoice{}, ChoiceType: discordgo.ApplicationCommandOptionString}})
	} else {
		reporting = b.reply(ctx, h, text)
	}
	if reporting != nil {
		return errors.Join(err, fmt.Errorf("interaction failure reporting failed: %w", reporting))
	}
	if !expectedCommandFailure(err) {
		return err
	}
	return nil
}
func (b *GeneralBot) reply(ctx context.Context, h *discord.InteractionHandle, text string) error {
	return b.api.InteractionRespond(ctx, h, &discord.InteractionResponseView{Type: discordgo.InteractionResponseChannelMessageWithSource, Data: &discord.InteractionResponseDataView{Content: new(text), Embeds: []*discordgo.MessageEmbed{{Type: discordgo.EmbedTypeRich, Title: "General module", Description: "Typed Discord v2 response"}}, AllowedMentions: noMentions(), Flags: new(uint64(discordgo.MessageFlagsEphemeral))}})
}
func (b *GeneralBot) handleInteraction(ctx context.Context, p *wire.PartialInteraction) error {
	h, err := interactionHandle(p)
	if err != nil {
		return err
	}
	i := h.Value
	if i.AppID != b.config.ApplicationID {
		return errors.New("interaction application mismatch")
	}
	if _, err = actor(i); err != nil {
		return b.reportFailure(ctx, h, err, false)
	}
	if i.GuildID == "" {
		if !b.config.AllowDM {
			return b.reportFailure(ctx, h, commandRejection("DM interactions are disabled"), false)
		}
	} else if !b.config.channel(i.GuildID, i.ChannelID) {
		return b.reportFailure(ctx, h, commandRejection("guild or source channel is not approved"), false)
	}
	switch i.Type {
	case discordgo.InteractionApplicationCommand, discordgo.InteractionApplicationCommandAutocomplete:
		data, ok := i.Data.(discordgo.ApplicationCommandInteractionData)
		if !ok {
			return errors.New("invalid typed command data")
		}
		binding, owned := b.commands[data.ID]
		if !owned || binding.Name != data.Name || binding.GuildID != i.GuildID {
			return b.reportFailure(ctx, h, commandRejection("command ID is not registered for this context"), false)
		}
		if required := binding.Permissions; required != nil && !required.Null && (i.Member == nil || (i.Member.Permissions&discordgo.PermissionAdministrator == 0 && (required.Value == 0 || i.Member.Permissions&required.Value != required.Value))) {
			return b.reportFailure(ctx, h, commandRejection("caller lacks the command's Discord permissions"), false)
		}
		if i.Type == discordgo.InteractionApplicationCommandAutocomplete {
			return b.autocomplete(ctx, h, data)
		}
		opts, e := optionsMap(data.Options)
		if e != nil {
			return b.reportFailure(ctx, h, e, false)
		}
		if data.Name == "form" {
			if !b.forms {
				return b.reportFailure(ctx, h, commandRejection("form feature disabled"), false)
			}
			return b.api.InteractionRespond(ctx, h, &discord.InteractionResponseView{Type: discordgo.InteractionResponseChannelMessageWithSource, Data: &discord.InteractionResponseDataView{Content: new("Choose a topic or open the feedback modal."), Components: formComponents(), AllowedMentions: noMentions(), Flags: new(uint64(discordgo.MessageFlagsEphemeral))}})
		}
		if data.Name == "hello" {
			text, e := b.executeCommand(ctx, h, data.Name, opts)
			if e != nil {
				return b.reportFailure(ctx, h, e, false)
			}
			return b.reply(ctx, h, text)
		}
		// Finite management/file calls deliberately defer before doing any work.
		if err = b.api.InteractionRespond(ctx, h, &discord.InteractionResponseView{Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, Data: &discord.InteractionResponseDataView{Flags: new(uint64(discordgo.MessageFlagsEphemeral))}}); err != nil {
			return err
		}
		text, e := b.executeCommand(ctx, h, data.Name, opts)
		if e != nil {
			return b.reportFailure(ctx, h, e, true)
		}
		_, err = b.api.InteractionResponseEdit(ctx, h, &discord.WebhookEditPatch{Content: new(text), AllowedMentions: noMentions()})
		return err
	case discordgo.InteractionMessageComponent:
		data, ok := i.Data.(discordgo.MessageComponentInteractionData)
		if !ok {
			return errors.New("invalid component data")
		}
		if !b.forms || (data.CustomID != formButton && data.CustomID != formSelect) {
			return b.reportFailure(ctx, h, commandRejection("unknown form component"), false)
		}
		if data.CustomID == formButton && data.ComponentType != discordgo.ButtonComponent {
			return b.reportFailure(ctx, h, commandRejection("invalid button kind"), false)
		}
		if data.CustomID == formSelect && (data.ComponentType != discordgo.SelectMenuComponent || len(data.Values) != 1 || !contains([]string{"runtime", "settings"}, data.Values[0])) {
			return b.reportFailure(ctx, h, commandRejection("invalid topic selection"), false)
		}
		return b.api.InteractionRespond(ctx, h, &discord.InteractionResponseView{Type: discordgo.InteractionResponseModal, Data: &discord.InteractionResponseDataView{CustomID: new(formRoot), Title: new("General module feedback"), Components: []discordgo.MessageComponent{discordgo.ActionsRow{Components: []discordgo.MessageComponent{discordgo.TextInput{CustomID: formInput, Label: "Feedback", Style: discordgo.TextInputShort, Required: new(true), MaxLength: 200}}}}}})
	case discordgo.InteractionModalSubmit:
		data, ok := i.Data.(discordgo.ModalSubmitInteractionData)
		if !ok {
			return errors.New("invalid modal data")
		}
		if !b.forms || data.CustomID != formRoot {
			return b.reportFailure(ctx, h, commandRejection("unknown modal root"), false)
		}
		value, e := feedbackValue(data.Components)
		if e != nil {
			return b.reportFailure(ctx, h, e, false)
		}
		return b.reply(ctx, h, "Feedback received: "+value)
	default:
		return errors.New("unsupported interaction kind")
	}
}
func feedbackValue(components []discordgo.MessageComponent) (string, error) {
	value := ""
	found := false
	for _, c := range components {
		row, ok := c.(discordgo.ActionsRow)
		if !ok {
			return "", commandRejection("invalid form structure")
		}
		for _, child := range row.Components {
			input, ok := child.(discordgo.TextInput)
			if !ok || input.CustomID != formInput || found {
				return "", commandRejection("unexpected or duplicate form field")
			}
			if len([]rune(input.Value)) == 0 || len([]rune(input.Value)) > 200 {
				return "", commandRejection("feedback must contain 1..200 characters")
			}
			found = true
			value = input.Value
		}
	}
	if !found {
		return "", commandRejection("feedback input missing")
	}
	return value, nil
}
func (b *GeneralBot) autocomplete(ctx context.Context, h *discord.InteractionHandle, data discordgo.ApplicationCommandInteractionData) error {
	if !b.forms || data.Name != "form" {
		return b.reportFailure(ctx, h, commandRejection("autocomplete is unavailable for this command"), false)
	}
	focused := ""
	count := 0
	for _, o := range data.Options {
		if o != nil && o.Focused {
			if o.Name != "topic" || o.Type != discordgo.ApplicationCommandOptionString {
				return b.reportFailure(ctx, h, commandRejection("unsupported focused option"), false)
			}
			value, ok := o.Value.(string)
			if !ok {
				return b.reportFailure(ctx, h, commandRejection("focused option is not a string"), false)
			}
			focused = strings.ToLower(value)
			count++
		}
	}
	if count != 1 {
		return b.reportFailure(ctx, h, commandRejection("exactly one focused option is required"), false)
	}
	choices := []*discordgo.ApplicationCommandOptionChoice{}
	for _, topic := range []string{"runtime", "settings"} {
		if strings.HasPrefix(topic, focused) {
			choices = append(choices, &discordgo.ApplicationCommandOptionChoice{Name: topic, Value: topic})
		}
	}
	return b.api.InteractionRespond(ctx, h, &discord.InteractionResponseView{Type: discordgo.InteractionApplicationCommandAutocompleteResult, Data: &discord.InteractionResponseDataView{Choices: choices, ChoiceType: discordgo.ApplicationCommandOptionString}})
}
