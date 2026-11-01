package main

import (
	"context"
	"errors"
	"strings"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
)

type messageReply struct{ ChannelID, MessageID string }

func (b *GeneralBot) handleMessage(ctx context.Context, kind string, p *wire.PartialMessage, hasBefore bool) error {
	if !b.messages || p == nil {
		return nil
	}
	guild, _ := presentString(p.GuildId)
	channel, channelPresent := presentString(p.ChannelId)
	id, idPresent := presentString(p.Id)
	if !channelPresent || !idPresent || !snowflake(channel) || !snowflake(id) {
		return nil
	}
	if guild == "" {
		if !b.config.AllowDM {
			return nil
		}
	} else if !b.config.channel(guild, channel) {
		return nil
	}
	// A missing before snapshot is normal. No readback is used to fabricate one.
	_ = hasBefore
	switch kind {
	case "create":
		author := p.Author.GetValue()
		if author == nil || author.Bot.GetValue() || !snowflake(author.Id.GetValue()) {
			return nil
		}
		content, present := presentString(p.Content)
		if !present || strings.TrimSpace(content) != "ping" {
			return nil
		}
		if b.replies == nil {
			b.replies = make(map[string]messageReply)
		}
		if len(b.replies) >= 128 {
			_, err := b.api.ChannelMessageSendComplex(ctx, channel, &discord.MessageSendView{Content: "The instance's 128 tracked ping replies are full; delete an original tracked ping before starting another demonstration.", AllowedMentions: noMentions(), Flags: discordgo.MessageFlagsSuppressNotifications})
			return err
		}
		reply, err := b.api.ChannelMessageSendComplex(ctx, channel, &discord.MessageSendView{Content: "pong — edits and deletes of this ping are tracked while this instance owns the reply.", Embeds: []*discordgo.MessageEmbed{{Type: discordgo.EmbedTypeRich, Title: "Message create", Description: "Guild and DM use their actual source channel."}}, AllowedMentions: noMentions(), Flags: discordgo.MessageFlagsSuppressNotifications})
		if err != nil {
			return err
		}
		if reply == nil || !snowflake(reply.ID) {
			return errors.New("message send returned no reply ID")
		}
		b.replies[channel+":"+id] = messageReply{ChannelID: channel, MessageID: reply.ID}
		return nil
	case "update":
		owned, ok := b.replies[channel+":"+id]
		if !ok {
			return nil
		}
		content, present := presentString(p.Content)
		if !present {
			return nil
		}
		text := "The original ping was edited: " + truncate(content, 500)
		_, err := b.api.ChannelMessageEditComplex(ctx, &discord.MessageEditPatch{ID: owned.MessageID, ChannelID: owned.ChannelID, Content: new(text), AllowedMentions: noMentions()})
		return err
	case "delete":
		owned, ok := b.replies[channel+":"+id]
		if !ok {
			return nil
		}
		if err := b.api.ChannelMessageDelete(ctx, owned.ChannelID, owned.MessageID); err != nil {
			return err
		}
		delete(b.replies, channel+":"+id)
		return nil
	default:
		return errors.New("unknown message event family")
	}
}
