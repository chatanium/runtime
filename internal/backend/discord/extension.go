package discordbackend

import (
	"context"
	"strings"

	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
)

// Extension is a host-only optional component of the same Discord registration.
// Its package need not import this parent package, avoiding an import cycle.
type Extension interface {
	Operations() []runtime.OperationPolicy
	Register(runtime.InstanceServices) (core.HelperRegistrar, error)
	Prepare(context.Context, runtime.InstancePrincipal, runtime.BackendPreparation) (*runtime.BackendBinding, error)
	Activate(context.Context, runtime.InstancePrincipal) error
	Drain(context.Context, runtime.InstancePrincipal) error
	Cleanup(context.Context, runtime.InstancePrincipal) error
	Close(context.Context) error
	ValidateConstraints(*corewire.CapabilityGrant) error
	ValidateConstraintsSubset(actual, ceiling *corewire.CapabilityGrant) error
}

func (b *Backend) AttachExtension(e Extension) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e == nil || b.extension != nil || b.sealed || b.closed {
		return invalid("DISCORD_EXTENSION_INVALID")
	}
	b.extension = e
	return nil
}

// HostSession is only for trusted host application and optional voice transport
// composition. It is never returned by a module helper or included in any DTO/SDK binding.
func (b *Backend) HostSession() *discordgo.Session { return b.session }
func (b *Backend) ResolveVoiceChannel(ctx context.Context, p runtime.InstancePrincipal, channelID string) (string, error) {
	resolved, e := b.resolveTarget(ctx, p, ResourceTarget{Kind: "channel_id", ID: channelID})
	if e != nil {
		return "", e
	}
	guild := resolved.GetSelector().ResourceIds["guild_id"]
	if guild == "" {
		return "", denied("DISCORD_VOICE_TARGET_INVALID")
	}
	var typ discordgo.ChannelType
	if facts, ok := b.channelFacts(channelID); ok {
		typ = facts.Type
	} else {
		channel := &discordgo.Channel{}
		if e = b.readJSON(ctx, p, "/channels/"+channelID, channel); e != nil {
			return "", e
		}
		typ = channel.Type
	}
	if typ != discordgo.ChannelTypeGuildVoice && typ != discordgo.ChannelTypeGuildStageVoice {
		return "", invalid("DISCORD_VOICE_TARGET_INVALID")
	}
	return guild, nil
}
func (b *Backend) extensionGrants(ctx context.Context, p runtime.InstancePrincipal, in runtime.BackendPreparation) ([]*corewire.CapabilityGrant, error) {
	if b.extension == nil {
		return nil, nil
	}
	binding, e := b.extension.Prepare(ctx, p, in)
	if e != nil {
		return nil, e
	}
	if binding == nil || binding.Grant == nil {
		return nil, invalid("DISCORD_EXTENSION_BINDING_INVALID")
	}
	var out []*corewire.CapabilityGrant
	for _, c := range binding.Grant.Capabilities {
		if c == nil || !strings.HasPrefix(c.Name, "discord.voice.") {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// Approval shape remains recognizable without the optional implementation.
// This validates a ceiling, never advertises or activates an unavailable grant.
func unavailableVoicePriority(c *corewire.CapabilityGrant) (int32, error) {
	if c != nil {
		switch c.Name {
		case "discord.voice.play":
			v := new(wire.VoicePlaybackConstraints)
			if c.Constraints != nil && c.Constraints.UnmarshalTo(v) == nil {
				return v.MaxPriority, nil
			}
		case "discord.voice.receive":
			if c.Constraints == nil {
				return 0, nil
			}
		}
	}
	return 0, invalid("DISCORD_CONSTRAINT_INVALID")
}
func (b *Backend) validateConstraints(c *corewire.CapabilityGrant) error {
	if c != nil && strings.HasPrefix(c.Name, "discord.voice.") && b.extension != nil {
		return b.extension.ValidateConstraints(c)
	}
	_, e := unavailableVoicePriority(c)
	return e
}
func (b *Backend) validateConstraintsSubset(actual, ceiling *corewire.CapabilityGrant) error {
	if actual != nil && strings.HasPrefix(actual.Name, "discord.voice.") && b.extension != nil {
		return b.extension.ValidateConstraintsSubset(actual, ceiling)
	}
	a, e := unavailableVoicePriority(actual)
	if e != nil {
		return e
	}
	c, e := unavailableVoicePriority(ceiling)
	if e != nil {
		return e
	}
	if actual.Name != ceiling.Name || a > c {
		return invalid("DISCORD_CONSTRAINT_INVALID")
	}
	return nil
}
