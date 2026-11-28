package recording

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/google/uuid"
	"github.com/thirdscam/chatanium/internal/legacy/recording/internal/sqlcgen"
)

// registerGuild records the Gateway snapshot on the host database. Missing
// owner/channel data is fetched with the callback's finite cancellation context.
func registerGuild(ctx context.Context, client *discordgo.Session, conn *sql.DB, queries *sqlcgen.Queries, guild *discordgo.Guild, maxResponseBytes int64) error {
	if guild == nil || guild.ID == "" || guild.OwnerID == "" || guild.Unavailable {
		return nil
	}
	var owner *discordgo.Member
	for _, member := range guild.Members {
		if member != nil && member.User != nil && member.User.ID == guild.OwnerID {
			owner = member
			break
		}
	}
	if owner == nil {
		owner = new(discordgo.Member)
		if err := readHostJSON(ctx, client, discordgo.EndpointGuildMember(guild.ID, guild.OwnerID), maxResponseBytes, owner); err != nil {
			return fmt.Errorf("lookup guild owner: %w", err)
		}
	}
	if owner == nil || owner.User == nil {
		return errors.New("guild owner unavailable")
	}
	channels := guild.Channels
	if channels == nil {
		if err := readHostJSON(ctx, client, discordgo.EndpointGuildChannels(guild.ID), maxResponseBytes, &channels); err != nil {
			return fmt.Errorf("lookup guild channels: %w", err)
		}
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	qtx := queries.WithTx(tx)
	ownerID := snowflakeID(guild.OwnerID)
	if err := insertUser(ctx, qtx, ownerID, owner.User.Username); err != nil {
		return err
	}
	guildID := snowflakeID(guild.ID)
	if err := qtx.InsertGuild(ctx, sqlcgen.InsertGuildParams{ID: guildID, Name: guild.Name, OwnerID: ownerID}); err != nil {
		return err
	}
	if err := insertMember(ctx, qtx, ownerID, guildID, owner.Nick); err != nil {
		return err
	}
	for _, channel := range channels {
		if channel == nil || channel.ID == "" {
			continue
		}
		channelID := snowflakeID(channel.ID)
		_, err := qtx.GetChannel(ctx, channelID)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := qtx.InsertChannel(ctx, sqlcgen.InsertChannelParams{ID: channelID, GuildID: guildID, Name: channel.Name, CreatedAt: time.Now()}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertUser(ctx context.Context, queries *sqlcgen.Queries, userID int64, username string) error {
	_, err := queries.GetUser(ctx, userID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return queries.InsertUser(ctx, sqlcgen.InsertUserParams{ID: userID, Username: username, CreatedAt: time.Now()})
}

func insertMember(ctx context.Context, queries *sqlcgen.Queries, userID, guildID int64, nickname string) error {
	_, err := queries.GetGuildUser(ctx, sqlcgen.GetGuildUserParams{UserID: userID, GuildID: guildID})
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return queries.InsertGuildUser(ctx, sqlcgen.InsertGuildUserParams{Uuid: uuid.New().String(), GuildID: guildID, UserID: userID, CreatedAt: time.Now(), Nickname: nickname})
}

// readHostJSON deliberately does not enter the SDK's uncancellable rate-limit
// bucket sleeps or retries. These two trusted, read-only host lookups use the
// existing backend's credential/client, never a fabricated module principal.
func readHostJSON(ctx context.Context, session *discordgo.Session, endpoint string, maxBytes int64, out any) error {
	if session == nil || session.Client == nil || maxBytes <= 0 || maxBytes == 1<<63-1 {
		return errors.New("invalid host lookup configuration")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("invalid host lookup endpoint")
	}
	request.Header.Set("Authorization", session.Token)
	response, err := session.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxBytes {
		return errors.New("host lookup response rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > maxBytes {
		return errors.New("host lookup response exceeds bound")
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("invalid host lookup response")
	}
	return nil
}
