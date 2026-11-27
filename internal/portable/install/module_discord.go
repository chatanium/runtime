package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bwmarrin/discordgo"
	"github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

const (
	discordTokenLeaf     = "discord-bot-token"
	discordTokenMaxBytes = 64 << 10
	discordEvent         = "discord.event.MESSAGE_CREATE"
	discordREST          = "discord.rest.ChannelMessageSendComplex"
	discordStarterIntents = discordgo.IntentGuilds | discordgo.IntentGuildMessages | discordgo.IntentMessageContent
)

// DiscordProfile excludes credential values and sources from the settings callback.
type DiscordProfile struct {
	ApplicationID string           `json:"application_id"`
	BotUserID     string           `json:"bot_user_id"`
	Intents       discordgo.Intent `json:"intents"`
}

type DiscordSetup struct {
	ApplicationID, BotUserID string
	Token                    []byte
}

func isDiscordStarter(m *wire.ModuleManifest) bool {
	if len(m.RequiredCapabilities)+len(m.OptionalCapabilities) != 0 || len(m.BackendRequirements) != 1 {
		return false
	}
	b := m.BackendRequirements[0]
	if b.GetBackendId() != "discord" || b.GetProtocolMajor() != 2 || !b.GetRequired() || len(b.RequiredCapabilities) != 0 || len(b.OptionalCapabilities) != 2 {
		return false
	}
	var event, rest bool
	for _, request := range b.OptionalCapabilities {
		scopes := request.GetResourceScopes()
		if len(scopes) != 1 || !scopes[0].GetAllResources() {
			return false
		}
		switch request.GetName() {
		case discordEvent:
			event = true
		case discordREST:
			rest = true
		}
	}
	return event && rest
}

func discordSnowflake(s string) bool {
	if len(s) == 0 || len(s) > 20 || s[0] == '0' {
		return false
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

func discordStarterGrants() []*wire.BackendGrant {
	return []*wire.BackendGrant{{BackendId: "discord", ProtocolMajor: 2, Capabilities: []*wire.CapabilityGrant{
		{Name: discordEvent, ResourceScopes: []*wire.ResourceScope{{SelectorKind: &wire.ResourceScope_AllResources{AllResources: true}}}},
		{Name: discordREST, ResourceScopes: []*wire.ResourceScope{{SelectorKind: &wire.ResourceScope_AllResources{AllResources: true}}}},
	}}}
}

func compatibleDiscordProfile(b runtime.BackendConfig) (DiscordProfile, error) {
	var p DiscordProfile
	if b.Major != 2 || json.Unmarshal(b.Config, &p) != nil || !discordSnowflake(p.ApplicationID) || !discordSnowflake(p.BotUserID) || p.Intents&discordStarterIntents != discordStarterIntents {
		return DiscordProfile{}, errors.New("configured Discord backend must be v2 with valid bot identity and GUILDS, GUILD_MESSAGES and MESSAGE_CONTENT intents; install will not change it")
	}
	source, ok := strings.CutPrefix(b.SecretSources["bot_token"], "file:")
	if !ok {
		return DiscordProfile{}, errors.New("configured Discord backend has no protected bot token file")
	}
	token, err := readDiscordTokenFile(source, false)
	clear(token)
	if err != nil {
		return DiscordProfile{}, errors.New("configured Discord bot token file is unavailable or invalid; install will not change it")
	}
	return p, nil
}

// ReadDiscordTokenFile reads only an explicit owner-only file. One trailing
// newline is accepted for operator input; the managed worker token has none.
func ReadDiscordTokenFile(path string) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return readDiscordTokenFile(abs, true)
}

func readDiscordTokenFile(path string, trimNewline bool) ([]byte, error) {
	f, err := OpenInput(path, true)
	if err != nil {
		return nil, errors.New("cannot open Discord bot token as an owner-only file")
	}
	data, err := io.ReadAll(io.LimitReader(f, discordTokenMaxBytes+1))
	if err = errors.Join(err, f.Close()); err != nil || len(data) > discordTokenMaxBytes {
		clear(data)
		return nil, errors.New("cannot read bounded Discord bot token file")
	}
	token := data
	if trimNewline {
		token = bytes.TrimSuffix(bytes.TrimSuffix(token, []byte("\r\n")), []byte("\n"))
	}
	if !validDiscordToken(token) {
		clear(data)
		return nil, errors.New("Discord bot token is empty or invalid")
	}
	return token, nil
}

func validDiscordToken(token []byte) bool {
	raw := bytes.TrimPrefix(token, []byte("Bot "))
	return len(token) <= discordTokenMaxBytes && len(raw) != 0 && !bytes.ContainsAny(raw, " \t\r\n\x00")
}

func (i *Installation) discordTokenSource() string {
	return "file:" + filepath.Join(i.Path, "app", discordTokenLeaf)
}

func (i *Installation) proposeDiscordBackend(s DiscordSetup, backends map[string]runtime.BackendConfig) (runtime.BackendConfig, func() error, error) {
	if !discordSnowflake(s.ApplicationID) || !discordSnowflake(s.BotUserID) || !validDiscordToken(s.Token) {
		return runtime.BackendConfig{}, nil, errors.New("Discord setup needs valid application and bot user IDs and a host bot token")
	}
	source := i.discordTokenSource()
	for _, backend := range backends {
		for _, path := range backend.SecretSources {
			if strings.EqualFold(path, source) {
				return runtime.BackendConfig{}, nil, errors.New("an existing backend already uses the managed Discord credential path")
			}
		}
	}
	config, err := json.Marshal(map[string]any{
		"application_id": s.ApplicationID, "bot_user_id": s.BotUserID,
		"ownership_directory": filepath.Join(i.Path, "app", "discord"), "intents": discordStarterIntents,
		"gateway_frame_max_bytes": 1 << 20, "gateway_decoded_max_bytes": 4 << 20,
		"credential_ttl": "5m", "interaction_ttl": "10m", "nonce_ttl": "2m",
		"nonces_per_instance": 32, "nonces_per_host": 128, "nonce_chunks_max": 32,
		"routes_per_module": 64, "routes_per_host": 256, "max_routes_per_request": 16,
		"max_files_per_request": 1, "file_max_bytes": 8 << 20, "request_max_bytes": 9 << 20,
		"http": map[string]any{
			"request_deadline": "10s", "json_max_bytes": 1 << 20, "response_max_bytes": 4 << 20,
			"header_max_bytes": 16 << 10, "requests_per_instance": 8, "requests_per_host": 32,
			"rate_limit_buckets": 512, "rate_limit_retention": "5m",
		},
	})
	if err != nil {
		return runtime.BackendConfig{}, nil, err
	}
	return runtime.BackendConfig{Major: 2, Config: config, SecretSources: map[string]string{"bot_token": source}}, func() error {
		if err := checkMetadataBudget(i, int64(len(s.Token))); err != nil {
			return err
		}
		app, err := privateChild(i.Root, "app", false)
		if err != nil {
			return err
		}
		if err := writeAtomic(app, discordTokenLeaf, s.Token); err != nil {
			return errors.Join(fmt.Errorf("publish host Discord credential: %w", err), app.Close())
		}
		return errors.Join(syncDirectory(app), app.Close())
	}, nil
}
