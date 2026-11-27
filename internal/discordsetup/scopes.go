package discordsetup

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	guildPageSize = 200
	maxGuilds     = 2000
	maxChannels   = 1000
)

type Guild struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Channel struct {
	ID      string
	GuildID string
	Name    string
	Type    int
}

// ListGuilds returns the bot's guilds or an error if the result exceeds the
// discovery limit. It never returns a partial list.
func ListGuilds(ctx context.Context, token string) ([]Guild, error) {
	return discordAPI.listGuilds(ctx, token)
}

func (a api) listGuilds(ctx context.Context, token string) ([]Guild, error) {
	if !validToken(token) {
		return nil, errInvalidToken
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	endpoint := "/users/@me/guilds?limit=" + strconv.Itoa(guildPageSize)
	guilds := []Guild{}
	var after uint64
	for {
		path := endpoint
		if after != 0 {
			path += "&after=" + strconv.FormatUint(after, 10)
		}
		var page []Guild
		if err := a.get(ctx, token, path, &page); err != nil {
			return nil, fmt.Errorf("list Discord guilds: %w", err)
		}
		if page == nil || len(page) > guildPageSize {
			return nil, errInvalidResponse
		}
		if len(guilds)+len(page) > maxGuilds {
			return nil, fmt.Errorf("Discord guild discovery is limited to %d guilds", maxGuilds)
		}

		latest := after
		seen := make(map[uint64]struct{}, len(page))
		for i, guild := range page {
			id, valid := snowflake(guild.ID)
			if !valid || id <= after {
				return nil, errInvalidResponse
			}
			if _, duplicate := seen[id]; duplicate {
				return nil, errInvalidResponse
			}
			seen[id] = struct{}{}
			latest = max(latest, id)
			page[i].Name = displayName(guild.Name, guild.ID, token)
		}
		if len(guilds) == 0 {
			guilds = page
		} else {
			guilds = append(guilds, page...)
		}
		if len(page) < guildPageSize {
			return guilds, nil
		}
		after = latest
	}
}

// ListChannels returns channels with their own message history from the given
// guild. Discord's guild endpoint does not list threads; forum and media posts
// live in threads, so their parent channels are not direct message scopes.
func ListChannels(ctx context.Context, token, guildID string) ([]Channel, error) {
	return discordAPI.listChannels(ctx, token, guildID)
}

func (a api) listChannels(ctx context.Context, token, guildID string) ([]Channel, error) {
	if !validToken(token) {
		return nil, errInvalidToken
	}
	if _, valid := snowflake(guildID); !valid {
		return nil, errors.New("enter a valid Discord guild ID")
	}
	var result []struct {
		ID      string  `json:"id"`
		GuildID *string `json:"guild_id"`
		Name    string  `json:"name"`
		Type    *int    `json:"type"`
	}
	if err := a.get(ctx, token, "/guilds/"+guildID+"/channels", &result); err != nil {
		return nil, fmt.Errorf("list Discord guild channels: %w", err)
	}
	if result == nil {
		return nil, errInvalidResponse
	}
	if len(result) > maxChannels {
		return nil, fmt.Errorf("Discord channel discovery is limited to %d channels per guild", maxChannels)
	}

	channels := make([]Channel, 0, len(result))
	seen := make(map[string]struct{}, len(result))
	for _, row := range result {
		if _, valid := snowflake(row.ID); !valid || row.Type == nil || (row.GuildID != nil && *row.GuildID != guildID) {
			return nil, errInvalidResponse
		}
		if _, duplicate := seen[row.ID]; duplicate {
			return nil, errInvalidResponse
		}
		seen[row.ID] = struct{}{}
		switch *row.Type {
		case 0, 2, 5, 13: // Text, voice text chat, announcement, and stage text chat.
			channels = append(channels, Channel{ID: row.ID, GuildID: guildID, Name: displayName(row.Name, row.ID, token), Type: *row.Type})
		}
	}
	return channels, nil
}
