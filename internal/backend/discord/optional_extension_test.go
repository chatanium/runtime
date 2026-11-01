package discordbackend

import (
	"testing"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestOrdinaryBackendValidatesUnavailableVoiceApprovalShape(t *testing.T) {
	b := new(Backend)
	constraint := func(priority int32) *corewire.CapabilityGrant {
		t.Helper()
		v, e := anypb.New(&wire.VoicePlaybackConstraints{MaxPriority: priority})
		if e != nil {
			t.Fatal(e)
		}
		return &corewire.CapabilityGrant{Name: "discord.voice.play", Constraints: v}
	}
	low, high := constraint(-1), constraint(3)
	if e := b.validateConstraints(high); e != nil {
		t.Fatalf("valid optional approval rejected without implementation: %v", e)
	}
	if e := b.validateConstraintsSubset(low, high); e != nil {
		t.Fatalf("narrower priority rejected: %v", e)
	}
	if e := b.validateConstraintsSubset(high, low); e == nil {
		t.Fatal("broader priority accepted")
	}
	for _, grant := range []*corewire.CapabilityGrant{nil, {Name: "discord.voice.play"}, {Name: "discord.voice.unknown"}, {Name: "discord.voice.receive", Constraints: high.Constraints}} {
		if b.validateConstraints(grant) == nil {
			t.Fatal("invalid or unknown approval accepted")
		}
	}
	receive := &corewire.CapabilityGrant{Name: "discord.voice.receive"}
	if e := b.validateConstraints(receive); e != nil {
		t.Fatalf("unconstrained receive approval rejected: %v", e)
	}
	if b.validateConstraintsSubset(low, receive) == nil {
		t.Fatal("different voice capabilities accepted as subset")
	}
}
