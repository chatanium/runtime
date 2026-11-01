package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	voicewire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type GuildConfig struct {
	GuildID         string   `json:"guild_id"`
	TextChannelIDs  []string `json:"text_channel_ids"`
	VoiceChannelIDs []string `json:"voice_channel_ids"`
}
type MediaLimits struct {
	MaxInputBytes         int64  `json:"max_input_bytes"`
	MaxArtifactBytes      int64  `json:"max_artifact_bytes"`
	MaxFrames             uint64 `json:"max_frames"`
	MaxPacketBytes        uint64 `json:"max_packet_bytes"`
	MaxProcessOutputBytes int64  `json:"max_process_output_bytes"`
	MaxResults            int    `json:"max_results"`
	Workers               int    `json:"workers"`
	QueueEntries          int    `json:"queue_entries"`
	MailboxEntries        int    `json:"mailbox_entries"`
	MaxQueryBytes         int    `json:"max_query_bytes"`
	ResolveTimeoutMS      int64  `json:"resolve_timeout_ms"`
	PrepareTimeoutMS      int64  `json:"prepare_timeout_ms"`
	QueueTimeoutMS        int64  `json:"queue_timeout_ms"`
	PlaybackTimeoutMS     int64  `json:"playback_timeout_ms"`
	CommandTimeoutMS      int64  `json:"command_timeout_ms"`
	ToolTimeoutMS         int64  `json:"tool_timeout_ms"`
	HTTPTimeoutMS         int64  `json:"http_timeout_ms"`
	MaxRedirects          int    `json:"max_redirects"`
	BitrateKbps           int    `json:"bitrate_kbps"`
}
type Config struct {
	ApplicationID string        `json:"application_id"`
	Guilds        []GuildConfig `json:"guilds"`
	Priority      *int32        `json:"priority"`
	Limits        MediaLimits   `json:"limits"`
}

func millis(v int64) time.Duration { return time.Duration(v) * time.Millisecond }
func decodeConfig(raw []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing config data")
	}
	if c.ApplicationID == "" || len(c.Guilds) == 0 {
		return c, errors.New("application_id and approved guilds required")
	}
	if c.Priority == nil {
		return c, errors.New("explicit playback priority is required")
	}
	l := c.Limits
	for _, v := range []int64{l.MaxInputBytes, l.MaxArtifactBytes, l.MaxProcessOutputBytes, l.ResolveTimeoutMS, l.PrepareTimeoutMS, l.QueueTimeoutMS, l.PlaybackTimeoutMS, l.CommandTimeoutMS, l.ToolTimeoutMS, l.HTTPTimeoutMS} {
		if v <= 0 || v > math.MaxInt64/int64(time.Millisecond) {
			return c, errors.New("all byte and deadline limits must be finite positive integers")
		}
	}
	if l.MaxFrames == 0 || l.MaxFrames > math.MaxInt64 || l.MaxPacketBytes == 0 || l.MaxPacketBytes > 32767 || l.Workers <= 0 || l.QueueEntries <= 0 || l.MailboxEntries <= 0 || l.MaxResults <= 0 || l.MaxResults > l.QueueEntries || l.MaxQueryBytes <= 0 || l.MaxRedirects <= 0 || l.BitrateKbps < 8 || l.BitrateKbps > 128 {
		return c, errors.New("invalid finite media count, packet, redirect or bitrate limit")
	}
	if uint64(l.QueueEntries) > math.MaxUint64/uint64(l.MaxArtifactBytes) || uint64(l.Workers) > math.MaxUint64/uint64(l.MaxInputBytes) || uint64(l.QueueEntries)*uint64(l.MaxArtifactBytes) > math.MaxUint64/uint64(len(c.Guilds)) {
		return c, errors.New("scratch reservation overflow")
	}
	if uint64(l.Workers) > math.MaxUint64/uint64(l.MaxArtifactBytes) || uint64(l.Workers)*uint64(l.MaxArtifactBytes) > math.MaxUint64/(uint64(len(c.Guilds))+1) {
		return c, errors.New("worker scratch reservation overflow")
	}
	seen := map[string]bool{}
	for _, g := range c.Guilds {
		if g.GuildID == "" || seen[g.GuildID] || len(g.TextChannelIDs) == 0 || len(g.VoiceChannelIDs) == 0 {
			return c, errors.New("unique approved guild and nonempty channel lists required")
		}
		seen[g.GuildID] = true
		channels := map[string]bool{}
		for _, id := range append(append([]string{}, g.TextChannelIDs...), g.VoiceChannelIDs...) {
			if id == "" || channels[id] {
				return c, errors.New("unique nonempty channel IDs required")
			}
			channels[id] = true
		}
	}
	return c, nil
}

var discordCapabilities = []string{"discord.event.INTERACTION_CREATE", "discord.rest.ApplicationCommandCreate", "discord.rest.UserVoiceState", "discord.rest.InteractionRespond", "discord.rest.WebhookMessageEdit", "discord.rest.ChannelMessageSendComplex", "discord.voice.play"}

func scopeAllows(grants []*corewire.CapabilityGrant, name string, resource map[string]string) *corewire.CapabilityGrant {
	for _, g := range grants {
		if g.Name != name {
			continue
		}
		for _, s := range g.ResourceScopes {
			if s.GetAllResources() {
				return g
			}
			selector := s.GetSelector()
			if selector == nil {
				continue
			}
			ok := true
			for k, v := range selector.ResourceIds {
				if resource[k] != v {
					ok = false
					break
				}
			}
			if ok {
				return g
			}
		}
	}
	return nil
}

// Event identity is known only when the host authenticates and dispatches an
// actual event. INIT can reject incompatible configured destination constraints,
// but must not require future user/interaction IDs to appear in module config.
// This is a readiness preflight only; it never authorizes an event or helper.
func interactionGrantCompatible(grants []*corewire.CapabilityGrant, resource map[string]string) *corewire.CapabilityGrant {
	for _, grant := range grants {
		if grant.Name != "discord.event.INTERACTION_CREATE" {
			continue
		}
		for _, scope := range grant.ResourceScopes {
			if scope.GetAllResources() {
				return grant
			}
			selector := scope.GetSelector()
			if selector == nil {
				continue
			}
			compatible := true
			for _, key := range []string{"application_id", "guild_id", "channel_id"} {
				if constraint, present := selector.ResourceIds[key]; present && constraint != resource[key] {
					compatible = false
					break
				}
			}
			if compatible {
				return grant
			}
		}
	}
	return nil
}

func validateGrants(c Config, init *corewire.InitContext) error {
	if init == nil || init.Grants == nil || !validScratchPath(init.ScratchDirectory) {
		return errors.New("actual grants and an authenticated absolute scratch directory required")
	}
	grants := init.Grants
	for _, name := range []string{"core.config.read", "core.network.public_egress"} {
		if scopeAllows(grants.CoreCapabilities, name, map[string]string{}) == nil {
			return fmt.Errorf("missing required grant %s", name)
		}
	}
	if grants.EgressPolicy != corewire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		return errors.New("public internet policy required for provider")
	}
	var capabilities []*corewire.CapabilityGrant
	for _, b := range grants.Backends {
		if b.BackendId == "discord" && b.ProtocolMajor == 2 {
			capabilities = b.Capabilities
		}
	}
	for _, g := range c.Guilds {
		for _, name := range discordCapabilities {
			channels := g.TextChannelIDs
			if name == "discord.voice.play" || name == "discord.rest.UserVoiceState" {
				channels = g.VoiceChannelIDs
			}
			for _, channel := range channels {
				resource := map[string]string{"guild_id": g.GuildID, "channel_id": channel, "application_id": c.ApplicationID}
				var grant *corewire.CapabilityGrant
				if name == "discord.event.INTERACTION_CREATE" {
					grant = interactionGrantCompatible(capabilities, resource)
				} else {
					grant = scopeAllows(capabilities, name, resource)
				}
				if grant == nil {
					return fmt.Errorf("configured resource exceeds required %s grant", name)
				}
				if name == "discord.voice.play" {
					var limits voicewire.VoicePlaybackConstraints
					if c.Priority == nil || grant.Constraints == nil || anypb.UnmarshalTo(grant.Constraints, &limits, proto.UnmarshalOptions{}) != nil || *c.Priority > limits.MaxPriority {
						return errors.New("voice priority grant constraint missing or exceeded")
					}
				}
			}
		}
	}
	if grants.ResourceLimits == nil {
		return errors.New("scratch byte grant required")
	}
	// Queue owners plus in-flight/cancelled result mailboxes and worker source files.
	artifacts := uint64(len(c.Guilds)) * uint64(c.Limits.QueueEntries) * uint64(c.Limits.MaxArtifactBytes)
	sources := uint64(c.Limits.Workers) * uint64(c.Limits.MaxInputBytes)
	workerArtifacts := uint64(c.Limits.Workers) * (uint64(len(c.Guilds)) + 1) * uint64(c.Limits.MaxArtifactBytes)
	if artifacts > grants.ResourceLimits.ScratchBytes || workerArtifacts > grants.ResourceLimits.ScratchBytes-artifacts || sources > grants.ResourceLimits.ScratchBytes-artifacts-workerArtifacts {
		return errors.New("configured media reservations exceed scratch grant")
	}
	return nil
}
func contains(ids []string, id string) bool {
	for _, v := range ids {
		if id == v {
			return true
		}
	}
	return false
}
