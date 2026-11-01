package discordbackend

import (
	"context"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
)

func (b *Backend) resolveAsset(ctx context.Context, p runtime.InstancePrincipal, t ResourceTarget) (*corewire.ResourceScope, error) {
	ids := map[string]string{t.Kind: t.ID}
	if t.Kind == "sticker_id" {
		// EndpointSticker is part of the pinned SDK endpoint catalog. This is a
		// private relationship lookup, not an additional generic module REST RPC.
		var actual struct {
			ID      string `json:"id"`
			GuildID string `json:"guild_id"`
			Type    int    `json:"type"`
		}
		if e := b.readJSON(ctx, p, "/stickers/"+t.ID, &actual); e != nil {
			return nil, e
		}
		if actual.ID != t.ID || (actual.Type != 1 && actual.Type != 2) {
			return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
		}
		if actual.Type == 2 {
			if !snowflake(actual.GuildID) {
				return nil, denied("RESOURCE_RELATIONSHIP_UNKNOWN")
			}
			ids["guild_id"] = actual.GuildID
		}
		return scope(ids), nil
	}
	path := ""
	if t.ChannelID == "" && t.GuildID != "" {
		path = "/guilds/" + t.GuildID + "/emojis/" + t.ID
		ids["guild_id"] = t.GuildID
	} else if t.ApplicationID != "" {
		if t.ApplicationID != b.config.ApplicationID {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
		path = "/applications/" + t.ApplicationID + "/emojis/" + t.ID
		ids["application_id"] = t.ApplicationID
	} else {
		state := b.session.State
		guild := ""
		if state != nil {
			state.RLock()
			for _, g := range state.Guilds {
				if g == nil {
					continue
				}
				for _, emoji := range g.Emojis {
					if emoji != nil && emoji.ID == t.ID {
						guild = g.ID
						break
					}
				}
				if guild != "" {
					break
				}
			}
			state.RUnlock()
		}
		if guild != "" {
			ids["guild_id"] = guild
			path = "/guilds/" + guild + "/emojis/" + t.ID
		} else {
			ids["application_id"] = b.config.ApplicationID
			path = "/applications/" + b.config.ApplicationID + "/emojis/" + t.ID
		}
	}
	var actual struct {
		ID string `json:"id"`
	}
	if e := b.readJSON(ctx, p, path, &actual); e != nil {
		return nil, e
	}
	if actual.ID != t.ID {
		return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
	}
	return scope(ids), nil
}
