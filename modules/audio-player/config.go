package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strconv"
	"time"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	discordwire "github.com/thirdscam/chatanium/proto/discord-v2"
)

type target struct {
	GuildID        string   `json:"guild_id"`
	TextChannelIDs []string `json:"text_channel_ids"`
	VoiceChannelID string   `json:"voice_channel_id"`
}

type playerConfig struct {
	Targets  []target     `json:"targets"`
	Priority *int32       `json:"priority"`
	Limits   playerLimits `json:"limits"`
}

type playerLimits struct {
	MaxDownloadBytes                                                          int64  `json:"max_download_bytes"`
	MaxArtifactBytes                                                          int64  `json:"max_artifact_bytes"`
	MaxFrames                                                                 uint64 `json:"max_frames"`
	MaxPacketBytes                                                            uint64 `json:"max_packet_bytes"`
	MaxProcessOutputBytes                                                     int64  `json:"max_process_output_bytes"`
	BitrateKbps                                                               int    `json:"bitrate_kbps"`
	Workers                                                                   int    `json:"workers"`
	QueueEntries                                                              int    `json:"queue_entries"`
	MaxRedirects                                                              *int   `json:"max_redirects"`
	HTTPTimeout                                                               string `json:"http_timeout"`
	EncodeTimeout                                                             string `json:"encode_timeout"`
	JobLifetime                                                               string `json:"job_lifetime"`
	OperationTimeout                                                          string `json:"operation_timeout"`
	CleanupTimeout                                                            string `json:"cleanup_timeout"`
	httpTimeout, encodeTimeout, jobLifetime, operationTimeout, cleanupTimeout time.Duration
}

func decodeConfig(raw []byte, init *corewire.InitContext) (playerConfig, error) {
	var cfg playerConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid player configuration")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("invalid trailing player configuration")
	}
	if init == nil || init.Grants == nil || init.Grants.ResourceLimits == nil || !filepath.IsAbs(init.ScratchDirectory) {
		return cfg, errors.New("player requires an authenticated absolute scratch directory and finite resource limits")
	}
	l := &cfg.Limits
	if cfg.Priority == nil || len(cfg.Targets) == 0 || l.MaxDownloadBytes <= 0 || l.MaxDownloadBytes == math.MaxInt64 || l.MaxArtifactBytes <= 0 || l.MaxFrames == 0 || l.MaxPacketBytes == 0 || l.MaxPacketBytes > 32767 || l.MaxProcessOutputBytes <= 0 || l.MaxProcessOutputBytes > int64(init.Grants.ResourceLimits.MemoryBytes/4) || l.BitrateKbps < 8 || l.BitrateKbps > 128 || l.Workers <= 0 || l.QueueEntries < l.Workers || l.MaxRedirects == nil || *l.MaxRedirects < 0 {
		return cfg, errors.New("player requires explicit finite media and download limits")
	}
	if l.MaxFrames > math.MaxInt64 {
		return cfg, errors.New("player frame limit is outside encoder integer range")
	}
	for _, item := range []struct {
		text string
		out  *time.Duration
	}{
		{l.HTTPTimeout, &l.httpTimeout}, {l.EncodeTimeout, &l.encodeTimeout}, {l.JobLifetime, &l.jobLifetime}, {l.OperationTimeout, &l.operationTimeout}, {l.CleanupTimeout, &l.cleanupTimeout},
	} {
		v, err := time.ParseDuration(item.text)
		if err != nil || v <= 0 {
			return cfg, errors.New("player timeouts must be finite positive durations")
		}
		*item.out = v
	}
	resources := init.Grants.ResourceLimits
	if uint64(l.Workers) > uint64(resources.MaxPids) || uint64(l.QueueEntries) > resources.MemoryBytes/(16*1024) || uint64(l.MaxDownloadBytes) > math.MaxUint64-uint64(l.MaxArtifactBytes) || uint64(l.Workers) > resources.ScratchBytes/(uint64(l.MaxDownloadBytes)+uint64(l.MaxArtifactBytes)) {
		return cfg, errors.New("player limits exceed granted process, memory or scratch budget")
	}
	if init.Grants.EgressPolicy != corewire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET || !permits(init.Grants.CoreCapabilities, "core.config.read", nil) || !permits(init.Grants.CoreCapabilities, "core.network.public_egress", nil) {
		return cfg, errors.New("player requires approved config and public egress capabilities")
	}
	var capabilities []*corewire.CapabilityGrant
	for _, backend := range init.Grants.Backends {
		if backend.BackendId == "discord" && backend.ProtocolMajor == 2 {
			capabilities = backend.Capabilities
		}
	}
	voice := capability(capabilities, "discord.voice.play")
	constraint := new(discordwire.VoicePlaybackConstraints)
	if voice == nil || voice.Constraints == nil || voice.Constraints.UnmarshalTo(constraint) != nil || *cfg.Priority > constraint.MaxPriority {
		return cfg, errors.New("player priority requires an actual typed voice playback grant")
	}
	seen := make(map[string]bool)
	for _, t := range cfg.Targets {
		if !validID(t.GuildID) || !validID(t.VoiceChannelID) || len(t.TextChannelIDs) == 0 {
			return cfg, errors.New("player target requires explicit guild, text and voice channels")
		}
		voiceScope := map[string]string{"guild_id": t.GuildID, "channel_id": t.VoiceChannelID}
		if !permits(capabilities, "discord.voice.play", voiceScope) || !permits(capabilities, "discord.rest.Channel", voiceScope) {
			return cfg, errors.New("configured voice channel is outside actual grants")
		}
		for _, channel := range t.TextChannelIDs {
			if !validID(channel) || seen[channel] || channel == t.VoiceChannelID {
				return cfg, errors.New("player text channels must be valid and unique")
			}
			seen[channel] = true
			scope := map[string]string{"guild_id": t.GuildID, "channel_id": channel}
			if !messageEventScopeCompatible(capabilities, t.GuildID, channel) {
				return cfg, errors.New("configured text channel lacks a compatible discord.event.MESSAGE_CREATE grant")
			}
			for _, name := range []string{"discord.rest.Channel", "discord.rest.ChannelMessageSendComplex"} {
				if !permits(capabilities, name, scope) {
					return cfg, fmt.Errorf("configured text channel lacks %s grant", name)
				}
			}
		}
	}
	return cfg, nil
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 20 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	value, err := strconv.ParseUint(id, 10, 64)
	return err == nil && value != 0
}

func capability(grants []*corewire.CapabilityGrant, name string) *corewire.CapabilityGrant {
	for _, grant := range grants {
		if grant != nil && grant.Name == name {
			return grant
		}
	}
	return nil
}

func permits(grants []*corewire.CapabilityGrant, name string, resource map[string]string) bool {
	grant := capability(grants, name)
	if grant == nil {
		return false
	}
	for _, scope := range grant.ResourceScopes {
		if scope.GetAllResources() {
			return true
		}
		selector := scope.GetSelector()
		if selector == nil || (len(selector.ResourceIds) == 0) != (len(resource) == 0) {
			continue
		}
		match := true
		for k, v := range selector.ResourceIds {
			if resource[k] != v {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// INIT knows configured guild/channel IDs, not future event authors or messages.
// This only checks that an actual event grant could match this target. The host
// still enforces every selector condition against each authenticated event;
// helper authorization must continue using the complete-resource permits check.
func messageEventScopeCompatible(grants []*corewire.CapabilityGrant, guildID, channelID string) bool {
	grant := capability(grants, "discord.event.MESSAGE_CREATE")
	if grant == nil {
		return false
	}
	for _, scope := range grant.ResourceScopes {
		if scope.GetAllResources() {
			return true
		}
		selector := scope.GetSelector()
		if selector == nil || len(selector.ResourceIds) == 0 {
			continue
		}
		if guild, restricted := selector.ResourceIds["guild_id"]; restricted && guild != guildID {
			continue
		}
		if channel, restricted := selector.ResourceIds["channel_id"]; restricted && channel != channelID {
			continue
		}
		return true
	}
	return false
}
