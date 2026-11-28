package recording

import (
	"context"
	"database/sql"
	"errors"

	"github.com/bwmarrin/discordgo"
	"github.com/thirdscam/chatanium/internal/legacy/recording/internal/sqlcgen"
)

func createMessage(ctx context.Context, m *discordgo.MessageCreate, queries *sqlcgen.Queries) error {
	if m == nil || m.Message == nil || m.ID == "" || m.Author == nil || m.Author.ID == "" || m.Author.Bot || m.WebhookID != "" {
		return nil
	}
	userID := snowflakeID(m.Author.ID)
	if err := insertUser(ctx, queries, userID, m.Author.Username); err != nil {
		return err
	}
	var guildID, channelID sql.NullInt64
	if m.GuildID != "" {
		nickname := ""
		if m.Member != nil {
			nickname = m.Member.Nick
		}
		guildID = sql.NullInt64{Int64: snowflakeID(m.GuildID), Valid: true}
		if err := insertMember(ctx, queries, userID, guildID.Int64, nickname); err != nil {
			return err
		}
	}
	if m.ChannelID != "" {
		channelID = sql.NullInt64{Int64: snowflakeID(m.ChannelID), Valid: true}
	}
	return queries.InsertMessage(ctx, sqlcgen.InsertMessageParams{
		MessageID: snowflakeID(m.ID),
		Type:      int64(m.Type),
		CreatedAt: m.Timestamp,
		UserID:    userID,
		Contents:  sql.NullString{String: m.Content, Valid: true},
		GuildID:   guildID,
		ChannelID: channelID,
	})
}

func deleteMessage(ctx context.Context, m *discordgo.MessageDelete, queries *sqlcgen.Queries) error {
	if m == nil || m.Message == nil || m.ID == "" {
		return nil
	}
	messageID := snowflakeID(m.ID)
	// An uncached delete need not contain author/member data. Removing an absent
	// message is harmless, as it may have been created while the host was offline.
	_, err := queries.GetMessage(ctx, messageID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return queries.DeleteMessage(ctx, messageID)
}
