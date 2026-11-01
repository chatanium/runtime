package Database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/bwmarrin/discordgo"
	db "github.com/thirdscam/chatanium/src/Database/Internal"
	util "github.com/thirdscam/chatanium/src/Util"
)

func CreateMessage(ctx context.Context, m *discordgo.MessageCreate, queries *db.Queries) error {
	if m == nil || m.Message == nil || m.ID == "" || m.Author == nil || m.Author.ID == "" || m.Author.Bot || m.WebhookID != "" {
		return nil
	}
	if err := InsertUser(ctx, queries, m.Author.ID, m.Author.Username); err != nil {
		return err
	}
	if m.GuildID != "" {
		nickname := ""
		if m.Member != nil {
			nickname = m.Member.Nick
		}
		if err := InsertMember(ctx, queries, m.Author.ID, m.GuildID, nickname); err != nil {
			return err
		}
	}
	var guildID, channelID sql.NullInt64
	if m.GuildID != "" {
		guildID = sql.NullInt64{Int64: util.Str2Int64(m.GuildID), Valid: true}
	}
	if m.ChannelID != "" {
		channelID = sql.NullInt64{Int64: util.Str2Int64(m.ChannelID), Valid: true}
	}
	return queries.InsertMessage(ctx, db.InsertMessageParams{
		MessageID: util.Str2Int64(m.ID),
		Type:      int64(m.Type),
		CreatedAt: m.Timestamp,
		UserID:    util.Str2Int64(m.Author.ID),
		Contents:  sql.NullString{String: m.Content, Valid: true},
		GuildID:   guildID,
		ChannelID: channelID,
	})
}

func DeleteMessage(ctx context.Context, m *discordgo.MessageDelete, queries *db.Queries) error {
	if m == nil || m.Message == nil || m.ID == "" {
		return nil
	}
	// An uncached delete need not contain author/member data. Removing an absent
	// message is harmless, as it may have been created while the host was offline.
	_, err := queries.GetMessage(ctx, util.Str2Int64(m.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return queries.DeleteMessage(ctx, util.Str2Int64(m.ID))
}
