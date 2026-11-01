package main

import "fmt"

func (b *GeneralBot) interactionPreflightScopes() []map[string]string {
	var scopes []map[string]string
	for _, g := range b.config.Guilds {
		for _, channel := range g.TextChannelIDs {
			scopes = append(scopes, map[string]string{"application_id": b.config.ApplicationID, "guild_id": g.GuildID, "channel_id": channel})
		}
	}
	if b.config.AllowDM {
		// The absence of a guild is already known; the DM channel/user/interaction IDs
		// are not. A guild-only grant cannot be mistaken for a compatible DM grant.
		scopes = append(scopes, map[string]string{"application_id": b.config.ApplicationID, "guild_id": ""})
	}
	return scopes
}

// validateInteractionCapabilities is the source-visible INIT preflight. Command
// creation has a complete known target; delivered interactions acquire additional
// authenticated identities later and must not force broader approval at INIT.
func (b *GeneralBot) validateInteractionCapabilities() error {
	for _, g := range b.config.Guilds {
		if err := require(b.grants, rest("ApplicationCommandCreate"), appScope(b.config.ApplicationID, g.GuildID)); err != nil {
			return err
		}
	}
	if b.config.AllowDM {
		if err := require(b.grants, rest("ApplicationCommandCreate"), appScope(b.config.ApplicationID, "")); err != nil {
			return err
		}
	}
	for _, known := range b.interactionPreflightScopes() {
		for _, capability := range []string{rest("InteractionRespond"), rest("WebhookMessageEdit"), "discord.event.INTERACTION_CREATE"} {
			if !compatibleGrant(b.grants, capability, known) {
				return fmt.Errorf("required compatible interaction capability unavailable: %s", capability)
			}
		}
	}
	return nil
}
