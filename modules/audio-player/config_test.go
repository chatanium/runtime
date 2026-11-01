package main

import (
	"context"
	"encoding/json"
	"testing"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	discordwire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func playerConfigFixture(t *testing.T) ([]byte, *corewire.InitContext) {
	t.Helper()
	priority, redirects := int32(0), 0
	cfg := playerConfig{Targets: []target{{GuildID: "101", TextChannelIDs: []string{"102"}, VoiceChannelID: "103"}}, Priority: &priority, Limits: playerLimits{
		MaxDownloadBytes: 1024, MaxArtifactBytes: 4096, MaxFrames: 50, MaxPacketBytes: 1275, MaxProcessOutputBytes: 16384, BitrateKbps: 64,
		Workers: 1, QueueEntries: 2, MaxRedirects: &redirects, HTTPTimeout: "1s", EncodeTimeout: "1s", JobLifetime: "2s", OperationTimeout: "1s", CleanupTimeout: "1s",
	}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	scope := func(channel string) *corewire.ResourceScope {
		return &corewire.ResourceScope{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{ResourceIds: map[string]string{"guild_id": "101", "channel_id": channel}}}}
	}
	constraint, err := anypb.New(&discordwire.VoicePlaybackConstraints{MaxPriority: 0})
	if err != nil {
		t.Fatal(err)
	}
	init := &corewire.InitContext{PersistentDirectory: "/var/lib/flexmodule/data", ScratchDirectory: "/var/lib/flexmodule/scratch", Grants: &corewire.Grants{
		ResourceLimits: &corewire.ResourceLimits{MemoryBytes: 1 << 20, ScratchBytes: 1 << 20, MaxPids: 16},
		EgressPolicy:   corewire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET,
		CoreCapabilities: []*corewire.CapabilityGrant{
			{Name: "core.config.read", ResourceScopes: []*corewire.ResourceScope{{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{}}}}},
			{Name: "core.network.public_egress", ResourceScopes: []*corewire.ResourceScope{{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{}}}}},
		},
		Backends: []*corewire.BackendGrant{{BackendId: "discord", ProtocolMajor: 2, Capabilities: []*corewire.CapabilityGrant{
			{Name: "discord.event.MESSAGE_CREATE", ResourceScopes: []*corewire.ResourceScope{scope("102")}},
			{Name: "discord.rest.ChannelMessageSendComplex", ResourceScopes: []*corewire.ResourceScope{scope("102")}},
			{Name: "discord.rest.Channel", ResourceScopes: []*corewire.ResourceScope{scope("102"), scope("103")}},
			{Name: "discord.voice.play", ResourceScopes: []*corewire.ResourceScope{scope("103")}, Constraints: constraint},
		}}},
	}}
	return raw, init
}

func TestPlayerAcceptsExactConfiguredGrants(t *testing.T) {
	raw, init := playerConfigFixture(t)
	if _, err := decodeConfig(raw, init); err != nil {
		t.Fatal(err)
	}
}

func TestPlayerRejectsMissingScopeOrPriorityConstraint(t *testing.T) {
	for _, mutate := range []func(*corewire.InitContext){
		func(init *corewire.InitContext) { init.Grants.EgressPolicy = corewire.EgressPolicy_EGRESS_POLICY_NONE },
		func(init *corewire.InitContext) { init.Grants.Backends[0].Capabilities[3].Constraints = nil },
		func(init *corewire.InitContext) {
			init.Grants.Backends[0].Capabilities[2].ResourceScopes = init.Grants.Backends[0].Capabilities[2].ResourceScopes[:1]
		},
		func(init *corewire.InitContext) {
			init.Grants.Backends[0].Capabilities[0].ResourceScopes[0].GetSelector().ResourceIds["guild_id"] = "999"
		},
		func(init *corewire.InitContext) {
			init.Grants.Backends[0].Capabilities[0].ResourceScopes[0].GetSelector().ResourceIds["channel_id"] = "999"
		},
		func(init *corewire.InitContext) { init.Grants.ResourceLimits.ScratchBytes = 1024 },
	} {
		raw, init := playerConfigFixture(t)
		mutate(init)
		if _, err := decodeConfig(raw, init); err == nil {
			t.Fatal("invalid or partial grant accepted")
		}
	}
}

func TestPlayerInitAcceptsIdentityRestrictedMessageEventGrant(t *testing.T) {
	raw, init := playerConfigFixture(t)
	event := init.Grants.Backends[0].Capabilities[0]
	event.ResourceScopes[0].GetSelector().ResourceIds["user_id"] = "104"
	before := proto.Clone(event)
	if _, err := decodeConfig(raw, init); err != nil {
		t.Fatalf("future event identity constraint prevented configured channel initialization: %v", err)
	}
	if !proto.Equal(before, event) {
		t.Fatal("initialization widened or removed the authenticated event constraint")
	}
	for _, key := range []string{"guild_id", "channel_id"} {
		restricted := proto.Clone(init).(*corewire.InitContext)
		restricted.Grants.Backends[0].Capabilities[0].ResourceScopes[0].GetSelector().ResourceIds[key] = "999"
		if _, err := decodeConfig(raw, restricted); err == nil {
			t.Fatalf("identity-restricted event grant accepted conflicting %s", key)
		}
	}
}

func TestPlayerInitStillRequiresCompleteHelperScopes(t *testing.T) {
	for _, name := range []string{"discord.rest.Channel", "discord.rest.ChannelMessageSendComplex", "discord.voice.play"} {
		raw, init := playerConfigFixture(t)
		grant := capability(init.Grants.Backends[0].Capabilities, name)
		for _, scope := range grant.ResourceScopes {
			scope.GetSelector().ResourceIds["user_id"] = "104"
		}
		if _, err := decodeConfig(raw, init); err == nil {
			t.Fatalf("event preflight compatibility weakened %s helper scope validation", name)
		}
	}
}

func TestPlayerRequiresExplicitFiniteConfiguration(t *testing.T) {
	for _, field := range []string{"priority", "max_redirects", "http_timeout", "max_download_bytes", "max_frames", "max_process_output_bytes", "workers"} {
		raw, init := playerConfigFixture(t)
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if field == "priority" {
			delete(doc, field)
		} else {
			delete(doc["limits"].(map[string]any), field)
		}
		raw, _ = json.Marshal(doc)
		if _, err := decodeConfig(raw, init); err == nil {
			t.Fatalf("missing %s accepted", field)
		}
	}
}

func TestPlayerManifestIsCanonicalAndIndependent(t *testing.T) {
	p := newPlayer(context.Background())
	defer p.cancel()
	a, err := p.GetManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.GetManifest(context.Background())
	if err != nil || !proto.Equal(a, b) {
		t.Fatalf("canonical manifest changed: %v", err)
	}
	a.Name = "changed"
	if a.Name == b.Name {
		t.Fatal("manifest calls share mutable data")
	}
}
