// Package discordacl defines the worker's mutable Discord resource limits.
package discordacl

import (
	"fmt"
	"strconv"
)

const MaxScopes = 512

// Policy is an allow list. A policy with no scopes denies all Discord resources.
// Absence of a policy is represented separately by the caller.
type Policy struct {
	Scopes []Scope `json:"scopes"`
}

// Scope names an exact guild and optionally one exact channel within it.
// A channel scope does not cover its parent, child threads, or guild-wide data.
type Scope struct {
	GuildID   string `json:"guild_id"`
	ChannelID string `json:"channel_id,omitempty"`
}

func (p Policy) Validate() error {
	if len(p.Scopes) > MaxScopes {
		return fmt.Errorf("Discord ACL supports at most %d scopes", MaxScopes)
	}
	for n, s := range p.Scopes {
		if !ValidID(s.GuildID) || s.ChannelID != "" && !ValidID(s.ChannelID) {
			return fmt.Errorf("scope %d: invalid Discord guild or channel ID", n+1)
		}
	}
	return nil
}

func ValidID(id string) bool {
	if len(id) == 0 || len(id) > 20 || id[0] < '1' || id[0] > '9' {
		return false
	}
	_, err := strconv.ParseUint(id, 10, 64)
	return err == nil
}

func (p Policy) Allows(target Scope) bool {
	if target.GuildID == "" {
		return false
	}
	for _, s := range p.Scopes {
		if s.GuildID == target.GuildID && (s.ChannelID == "" || s.ChannelID == target.ChannelID) {
			return true
		}
	}
	return false
}
