package discordbackend

import (
	"testing"

	"github.com/bwmarrin/discordgo"
	"github.com/thirdscam/chatanium/internal/discordacl"
)

func TestDiscordACLEventGraph(t *testing.T) {
	b := &Backend{}
	root := scope(map[string]string{"guild_id": "10", "channel_id": "100"})
	allowed := discordacl.Policy{Scopes: []discordacl.Scope{{GuildID: "10", ChannelID: "100"}}}
	for _, tt := range []struct {
		name, event, raw string
		source           any
		want             bool
	}{
		{name: "message in allowed channel", event: "MESSAGE_CREATE", raw: `{"guild_id":"10","channel_id":"100","content":"hello"}`, want: true},
		{name: "same-channel reply", event: "MESSAGE_CREATE", raw: `{"guild_id":"10","channel_id":"100","message_reference":{"channel_id":"100","message_id":"1000"},"referenced_message":{"channel_id":"100","id":"1000"}}`, want: true},
		{name: "foreign reply", event: "MESSAGE_CREATE", raw: `{"guild_id":"10","channel_id":"100","referenced_message":{"guild_id":"20","channel_id":"200","id":"2000"}}`},
		{name: "forward with unverified origin", event: "MESSAGE_CREATE", raw: `{"guild_id":"10","channel_id":"100","message_reference":{"channel_id":"200"},"message_snapshots":[{"message":{"content":"elsewhere"}}]}`},
		{name: "forward from same guild other channel", event: "MESSAGE_CREATE", raw: `{"guild_id":"10","channel_id":"100","message_reference":{"guild_id":"10","channel_id":"101"},"message_snapshots":[{"message":{"content":"elsewhere"}}]}`},
		{name: "resolved interaction channels", event: "INTERACTION_CREATE", raw: `{"guild_id":"10","channel_id":"100","data":{"resolved":{"channels":{"101":{"id":"101","guild_id":"10","name":"sibling"}}}}}`},
		{name: "foreign interaction install owner", event: "INTERACTION_CREATE", raw: `{"guild_id":"10","channel_id":"100","authorizing_integration_owners":{"0":"20"}}`},
		{name: "guild data nested inside invite", event: "INVITE_CREATE", raw: `{"guild_id":"10","channel_id":"100","guild":{"id":"10","name":"guild"}}`},
		{name: "cached message references another guild", event: "MESSAGE_UPDATE", raw: `{"guild_id":"10","channel_id":"100"}`, source: &discordgo.MessageUpdate{BeforeUpdate: &discordgo.Message{GuildID: "10", ChannelID: "100", ReferencedMessage: &discordgo.Message{GuildID: "20", ChannelID: "200"}}}},
		{name: "cached voice state in another channel", event: "VOICE_STATE_UPDATE", raw: `{"guild_id":"10","channel_id":"100"}`, source: &discordgo.VoiceStateUpdate{BeforeUpdate: &discordgo.VoiceState{GuildID: "10", ChannelID: "101"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			facts := b.eventDiscordEvidence(tt.event, []byte(tt.raw), tt.source, root)
			got := len(facts) != 0
			for _, fact := range facts {
				got = got && allowed.Allows(fact)
			}
			if got != tt.want {
				t.Fatalf("allowed = %t, facts %+v, want %t", got, facts, tt.want)
			}
		})
	}
}

func TestDiscordACLUnscopableEventCannotUseGuildPolicy(t *testing.T) {
	b := &Backend{}
	for _, tt := range []struct {
		name, raw string
		target    map[string]string
	}{
		{name: "READY", raw: `{"guilds":[{"id":"10"}]}`, target: map[string]string{}},
		{name: "GUILD_AUDIT_LOG_ENTRY_CREATE", raw: `{"guild_id":"10","changes":[{"key":"channel_id","new_value":"200"}]}`, target: map[string]string{"guild_id": "10"}},
		{name: "ENTITLEMENT_UPDATE", raw: `{"guild_id":"10","id":"5"}`, target: map[string]string{"guild_id": "10"}},
	} {
		if got := b.eventDiscordEvidence(tt.name, []byte(tt.raw), nil, scope(tt.target)); len(got) != 0 {
			t.Fatalf("%s produced managed scope evidence: %+v", tt.name, got)
		}
	}
}
