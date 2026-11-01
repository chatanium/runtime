package main

import (
	"context"
	"errors"
	"strings"

	"github.com/bwmarrin/discordgo"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
)

type changedResourceError struct {
	channelID string
	cause     error
}

func (e *changedResourceError) Error() string {
	return "channel changed, but its durable ownership record failed"
}
func (e *changedResourceError) Unwrap() error { return e.cause }
func validChannelName(name string) bool {
	return strings.HasPrefix(name, "flex-test-") && len(name) <= 80
}
func (b *GeneralBot) channelCommand(ctx context.Context, g GuildConfig, name string, o commandOptions, audit discord.RequestOption) (string, error) {
	if name == "channel-create" {
		if err := b.scopedOperation("GuildChannelCreateComplex", guildScope(g.GuildID)); err != nil {
			return "", err
		}
		label, err := o.text("name", true)
		if err != nil {
			return "", err
		}
		if !validChannelName(label) {
			return "", commandRejection("channel name must start flex-test- and fit 80 bytes")
		}
		parent, err := o.text("parent", false)
		if err != nil {
			return "", err
		}
		if parent != "" && !contains(g.Moderation.AllowedParentIDs, parent) {
			return "", commandRejection("parent is not explicitly approved")
		}
		kind, err := o.text("kind", false)
		if err != nil {
			return "", err
		}
		channelType := discordgo.ChannelTypeGuildText
		switch kind {
		case "", "text":
		case "category":
			channelType = discordgo.ChannelTypeGuildCategory
			if parent != "" {
				return "", commandRejection("a category cannot have a parent")
			}
		default:
			return "", commandRejection("only text or category channel kinds are supported")
		}
		channel, err := b.api.GuildChannelCreateComplex(ctx, g.GuildID, discordgo.GuildChannelCreateData{Name: label, Type: channelType, ParentID: parent, PermissionOverwrites: []*discordgo.PermissionOverwrite{{ID: g.GuildID, Type: discordgo.PermissionOverwriteTypeRole, Deny: discordgo.PermissionSendMessages}}}, audit)
		if err != nil {
			return "", err
		}
		if channel == nil || !snowflake(channel.ID) {
			return "", errors.New("channel create returned no ID")
		}
		if err = b.store.RecordChannel(ctx, g.GuildID, channel.ID, false); err != nil {
			return "", &changedResourceError{channelID: channel.ID, cause: err}
		}
		return "Created owned channel: " + channel.ID, nil
	}
	channel, err := o.text("channel", true)
	if err != nil {
		return "", err
	}
	owned, err := b.store.OwnsChannel(ctx, g.GuildID, channel)
	if err != nil {
		return "", err
	}
	if !owned {
		return "", commandRejection("channel was not created and durably recorded by this module")
	}
	if name == "channel-delete" {
		if err = b.scopedOperation("ChannelDelete", channelScope(g.GuildID, channel)); err != nil {
			return "", err
		}
		if _, err = b.api.ChannelDelete(ctx, channel, audit); err != nil {
			return "", err
		}
		if err = b.store.RecordChannel(ctx, g.GuildID, channel, true); err != nil {
			return "", &changedResourceError{channelID: channel, cause: err}
		}
		return "Deleted owned channel: " + channel, nil
	}
	if err = b.scopedOperation("ChannelEdit", channelScope(g.GuildID, channel)); err != nil {
		return "", err
	}
	patch, err := channelPatch(g, o)
	if err != nil {
		return "", err
	}
	if patch.ParentID != nil && !patch.ParentID.Null && patch.ParentID.Value != "" {
		if err = b.scopedOperation("ChannelEdit", channelScope(g.GuildID, patch.ParentID.Value)); err != nil {
			return "", err
		}
	}
	if _, err = b.api.ChannelEdit(ctx, channel, patch, audit); err != nil {
		return "", err
	}
	return "Edited owned channel: " + channel, nil
}
func channelPatch(g GuildConfig, o commandOptions) (*discord.ChannelEditView, error) {
	patch := &discord.ChannelEditView{}
	if _, present := o["name"]; present {
		name, err := o.text("name", true)
		if err != nil {
			return nil, err
		}
		if !validChannelName(name) {
			return nil, commandRejection("invalid test channel name")
		}
		patch.Name = new(name)
	}
	if _, present := o["topic"]; present {
		topic, err := o.text("topic", false)
		if err != nil {
			return nil, err
		}
		if len([]rune(topic)) > 1024 {
			return nil, commandRejection("topic exceeds 1024 characters")
		}
		patch.Topic = &discord.Nullable[string]{Value: topic}
	}
	clear, err := o.boolean("clear-topic")
	if err != nil {
		return nil, err
	}
	if clear {
		if patch.Topic != nil {
			return nil, commandRejection("topic and clear-topic cannot be combined")
		}
		patch.Topic = &discord.Nullable[string]{Value: ""}
	}
	if _, present := o["parent"]; present {
		parent, err := o.text("parent", true)
		if err != nil {
			return nil, err
		}
		if !contains(g.Moderation.AllowedParentIDs, parent) {
			return nil, commandRejection("parent is not explicitly approved")
		}
		patch.ParentID = &discord.Nullable[string]{Value: parent}
	}
	clear, err = o.boolean("clear-parent")
	if err != nil {
		return nil, err
	}
	if clear {
		if patch.ParentID != nil {
			return nil, commandRejection("parent and clear-parent cannot be combined")
		}
		patch.ParentID = &discord.Nullable[string]{Null: true}
	}
	slow, present, err := o.integer("slowmode")
	if err != nil {
		return nil, err
	}
	if present {
		if slow < 0 || slow > 21600 {
			return nil, commandRejection("invalid slowmode")
		}
		patch.RateLimitPerUser = new(int(slow))
	}
	clear, err = o.boolean("clear-overwrites")
	if err != nil {
		return nil, err
	}
	if clear {
		patch.PermissionOverwrites = []*discordgo.PermissionOverwrite{}
	}
	if patch.Name == nil && patch.Topic == nil && patch.ParentID == nil && patch.RateLimitPerUser == nil && patch.PermissionOverwrites == nil {
		return nil, commandRejection("no channel edit was specified")
	}
	return patch, nil
}
