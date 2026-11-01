package discordbackend

import "github.com/bwmarrin/discordgo"

// Operator IDs are expectations, not authority to impersonate a different bot.
// READY comes from the owned authenticated session, never a module DTO.
func (b *Backend) verifyReadyIdentity(value *discordgo.Ready) bool {
	valid := value != nil && value.User != nil && value.Application != nil && value.User.ID == b.config.BotUserID && value.Application.ID == b.config.ApplicationID
	b.mu.Lock()
	b.identityVerified = valid
	b.mu.Unlock()
	return valid
}
