package main

import (
	"testing"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	voicewire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func musicTestScope(ids map[string]string) *corewire.ResourceScope {
	return &corewire.ResourceScope{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{ResourceIds: ids}}}
}
func constrainedMusicInit(t *testing.T) (Config, *corewire.InitContext) {
	t.Helper()
	priority := int32(1)
	c := Config{ApplicationID: "1154785939399376966", Guilds: []GuildConfig{{GuildID: "919823370600742942", TextChannelIDs: []string{"1564849368903712909"}, VoiceChannelIDs: []string{"1564849419180843108"}}}, Priority: &priority, Limits: MediaLimits{Workers: 1, QueueEntries: 4, MaxArtifactBytes: 4 << 20, MaxInputBytes: 16 << 20}}
	app, guild, text, voice, user := c.ApplicationID, c.Guilds[0].GuildID, c.Guilds[0].TextChannelIDs[0], c.Guilds[0].VoiceChannelIDs[0], "1510309240491872426"
	constraints, err := anypb.New(&voicewire.VoicePlaybackConstraints{MaxPriority: priority})
	if err != nil {
		t.Fatal(err)
	}
	caps := []*corewire.CapabilityGrant{
		{Name: "discord.event.INTERACTION_CREATE", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{"application_id": app, "guild_id": guild, "channel_id": text, "user_id": user})}},
		{Name: "discord.rest.ApplicationCommandCreate", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{"application_id": app, "guild_id": guild})}},
		{Name: "discord.rest.UserVoiceState", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{"guild_id": guild, "user_id": user}), musicTestScope(map[string]string{"guild_id": guild, "channel_id": voice})}},
		{Name: "discord.rest.InteractionRespond", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{"application_id": app, "guild_id": guild, "channel_id": text})}},
		{Name: "discord.rest.WebhookMessageEdit", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{"application_id": app, "guild_id": guild, "channel_id": text})}},
		{Name: "discord.rest.ChannelMessageSendComplex", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{"guild_id": guild, "channel_id": text})}},
		{Name: "discord.voice.play", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{"guild_id": guild, "channel_id": voice})}, Constraints: constraints},
	}
	init := &corewire.InitContext{ScratchDirectory: "/var/lib/flexmodule/scratch", Grants: &corewire.Grants{
		CoreCapabilities: []*corewire.CapabilityGrant{{Name: "core.config.read", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{})}}, {Name: "core.network.public_egress", ResourceScopes: []*corewire.ResourceScope{musicTestScope(map[string]string{})}}},
		Backends:         []*corewire.BackendGrant{{BackendId: "discord", ProtocolMajor: 2, Capabilities: caps}}, EgressPolicy: corewire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET, ResourceLimits: &corewire.ResourceLimits{ScratchBytes: 64 << 20},
	}}
	return c, init
}
func TestInitAcceptsFutureAuthenticatedEventIdentityWithoutWidening(t *testing.T) {
	c, init := constrainedMusicInit(t)
	original := proto.Clone(init).(*corewire.InitContext)
	if err := validateGrants(c, init); err != nil {
		t.Fatalf("development-user-constrained event grant rejected: %v", err)
	}
	if !proto.Equal(init, original) {
		t.Fatal("preflight widened or mutated actual grants")
	}
	eventGrant := init.Grants.Backends[0].Capabilities[0]
	if got := eventGrant.ResourceScopes[0].GetSelector().ResourceIds["user_id"]; got != "1510309240491872426" {
		t.Fatalf("authenticated user constraint lost: %q", got)
	}
	// The complete event, including user_id, is still checked by host dispatch.
	// Local compatibility must not invent a module-config identity or authorize it.
	if scopeAllows([]*corewire.CapabilityGrant{eventGrant}, eventGrant.Name, map[string]string{"application_id": c.ApplicationID, "guild_id": c.Guilds[0].GuildID, "channel_id": c.Guilds[0].TextChannelIDs[0]}) != nil {
		t.Fatal("complete scope matching unexpectedly ignored authenticated identity")
	}
}
func TestInitRejectsIncompatibleEventDestinations(t *testing.T) {
	for _, key := range []string{"application_id", "guild_id", "channel_id"} {
		t.Run(key, func(t *testing.T) {
			c, init := constrainedMusicInit(t)
			init.Grants.Backends[0].Capabilities[0].ResourceScopes[0].GetSelector().ResourceIds[key] = "999999999999999999"
			if err := validateGrants(c, init); err == nil {
				t.Fatalf("incompatible configured %s accepted", key)
			}
		})
	}
}
func TestInitDoesNotPartiallyMatchHelperMutationScopes(t *testing.T) {
	c, init := constrainedMusicInit(t)
	for _, grant := range init.Grants.Backends[0].Capabilities {
		if grant.Name == "discord.rest.ChannelMessageSendComplex" {
			grant.ResourceScopes[0].GetSelector().ResourceIds["user_id"] = "1510309240491872426"
		}
	}
	if err := validateGrants(c, init); err == nil {
		t.Fatal("event-only preflight weakened mutation scope matching")
	}
}
