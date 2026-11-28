package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	discordbackend "github.com/thirdscam/chatanium/internal/backend/discord"
	"github.com/thirdscam/chatanium/internal/backend/discord/discordhttp"
	"github.com/thirdscam/chatanium/internal/portable/process"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"github.com/thirdscam/chatanium/internal/runtime/upload"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/proto"
)

type DiscordOperatorConfig struct {
	ApplicationID          string           `json:"application_id"`
	BotUserID              string           `json:"bot_user_id"`
	OwnershipDirectory     string           `json:"ownership_directory"`
	Intents                discordgo.Intent `json:"intents"`
	GatewayFrameMaxBytes   int64            `json:"gateway_frame_max_bytes"`
	GatewayDecodedMaxBytes int64            `json:"gateway_decoded_max_bytes"`
	CredentialTTL          runtime.Duration `json:"credential_ttl"`
	InteractionTTL         runtime.Duration `json:"interaction_ttl"`
	NonceTTL               runtime.Duration `json:"nonce_ttl"`
	NoncesPerInstance      int              `json:"nonces_per_instance"`
	NoncesPerHost          int              `json:"nonces_per_host"`
	NonceChunksMax         int              `json:"nonce_chunks_max"`
	RoutesPerModule        int              `json:"routes_per_module"`
	RoutesPerHost          int              `json:"routes_per_host"`
	MaxRoutesPerRequest    int              `json:"max_routes_per_request"`
	MaxFilesPerRequest     int              `json:"max_files_per_request"`
	FileMaxBytes           int64            `json:"file_max_bytes"`
	RequestMaxBytes        int64            `json:"request_max_bytes"`
	PresenceOwner          runtime.ModuleID `json:"presence_owner"`
	HTTP                   struct {
		RequestDeadline     runtime.Duration `json:"request_deadline"`
		JSONMaxBytes        int64            `json:"json_max_bytes"`
		ResponseMaxBytes    int64            `json:"response_max_bytes"`
		HeaderMaxBytes      int64            `json:"header_max_bytes"`
		RequestsPerInstance int              `json:"requests_per_instance"`
		RequestsPerHost     int              `json:"requests_per_host"`
		RateLimitBuckets    int              `json:"rate_limit_buckets"`
		RateLimitRetention  runtime.Duration `json:"rate_limit_retention"`
	} `json:"http"`
	ProvisionedSecrets map[string]struct {
		ModuleID  runtime.ModuleID       `json:"module_id"`
		Purpose   string                 `json:"purpose"`
		Resource  *wire.ResourceSelector `json:"resource"`
		ExpiresAt time.Time              `json:"expires_at"`
	} `json:"provisioned_secrets"`
	Voice json.RawMessage `json:"voice"`
}

func HostSecret(secrets map[string]string, name string) (string, error) {
	value, ok := secrets[name]
	if !ok || value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("required host secret binding unavailable")
	}
	return value, nil
}

func NewDiscordBackend(ctx context.Context, config runtime.Config, backend runtime.BackendConfig, c *DiscordOperatorConfig, files *upload.UploadStore, secretsInput map[string]string, onError func(error)) (*discordbackend.Backend, error) {
	portable := config.Host.Format == runtime.PortableFormat
	if portable {
		if c.OwnershipDirectory != filepath.Join(config.Host.ManagementDirectory, "discord") || process.CheckPrivateDir(c.OwnershipDirectory) != nil {
			return nil, errors.New("portable Discord requires the private installation app/discord directory")
		}
	} else if !IsolatedHostDirectory(c.OwnershipDirectory, config.Host.ModuleMountRoots()...) {
		return nil, errors.New("Discord ownership directory must be private and outside module mounts")
	}
	if len(backend.SecretSources) != len(c.ProvisionedSecrets)+1 {
		return nil, errors.New("unexpected Discord secret bindings")
	}
	token, err := HostSecret(secretsInput, "discord:bot_token")
	if err != nil {
		return nil, err
	}
	token = strings.TrimPrefix(token, "Bot ")
	if token == "" {
		return nil, errors.New("required host bot credential unavailable")
	}
	secrets := make(map[string]discordbackend.Secret, len(c.ProvisionedSecrets))
	values := []string{token}
	for id, metadata := range c.ProvisionedSecrets {
		if id == "bot_token" {
			return nil, errors.New("bot credential cannot be provisioned to modules")
		}
		value, e := HostSecret(secretsInput, "discord:"+id)
		if e != nil {
			return nil, e
		}
		values = append(values, value)
		secrets[id] = discordbackend.Secret{Value: value, ModuleID: metadata.ModuleID, Purpose: metadata.Purpose, Resource: metadata.Resource, ExpiresAt: metadata.ExpiresAt}
	}
	// Known host credentials must never be smuggled through module JSON, argv or
	// public installation identities. The manager separately excludes host env.
	for _, spec := range config.Modules {
		if containsSecretJSON(spec.Config.Json, values) {
			return nil, errors.New("host secret found in module configuration")
		}
		fields := [4]string{string(spec.ModuleID), spec.ImageDigest, spec.ConfigRevision, spec.ApprovalRevision}
		for _, group := range [][]string{fields[:], spec.Entrypoint, spec.Args} {
			for _, field := range group {
				for _, value := range values {
					if strings.Contains(field, value) {
						return nil, errors.New("host secret found in module installation data")
					}
				}
			}
		}
		for _, binding := range spec.CredentialBindings {
			if binding.BackendID != "discord" {
				continue
			}
			secret, ok := secrets[binding.SecretID]
			if !ok || secret.ModuleID != spec.ModuleID || secret.Purpose != binding.Purpose || !proto.Equal(secret.Resource, binding.Resource) {
				return nil, errors.New("invalid provisioned credential binding")
			}
		}
	}
	h := c.HTTP
	b, err := discordbackend.New(ctx, discordbackend.Config{
		BotToken: token, ApplicationID: c.ApplicationID, BotUserID: c.BotUserID,
		OwnershipDirectory: c.OwnershipDirectory, PortableOwnership: portable, Intents: c.Intents,
		GatewayFrameMaxBytes: c.GatewayFrameMaxBytes, GatewayDecodedMaxBytes: c.GatewayDecodedMaxBytes,
		CredentialTTL: time.Duration(c.CredentialTTL), InteractionTTL: time.Duration(c.InteractionTTL), NonceTTL: time.Duration(c.NonceTTL),
		NoncesPerInstance: c.NoncesPerInstance, NoncesPerHost: c.NoncesPerHost, NonceChunksMax: c.NonceChunksMax,
		RoutesPerModule: c.RoutesPerModule, RoutesPerHost: c.RoutesPerHost, MaxRoutesPerRequest: c.MaxRoutesPerRequest,
		MaxFilesPerRequest: c.MaxFilesPerRequest, FileMaxBytes: c.FileMaxBytes, RequestMaxBytes: c.RequestMaxBytes,
		PresenceOwner: c.PresenceOwner, Secrets: secrets, Uploads: files, OnError: onError,
		HTTP: discordhttp.Config{RequestDeadline: time.Duration(h.RequestDeadline), JSONMaxBytes: h.JSONMaxBytes,
			ResponseMaxBytes: h.ResponseMaxBytes, HeaderMaxBytes: h.HeaderMaxBytes,
			RequestsPerInstance: h.RequestsPerInstance, RequestsPerHost: h.RequestsPerHost,
			RateLimitBuckets: h.RateLimitBuckets, RateLimitRetention: time.Duration(h.RateLimitRetention)},
	})
	if err != nil {
		return nil, errors.New("Discord backend initialization failed")
	}
	if err = attachVoice(ctx, b, c.Voice, config.Limits.ControlMessageMaxBytes); err != nil {
		if b.Close() != nil {
			return nil, errors.Join(err, errors.New("Discord backend cleanup failed"))
		}
		return nil, err
	}
	return b, nil
}

func StrictJSON(raw []byte, out any) error {
	if rejectDuplicateJSON(raw) != nil {
		return errors.New("invalid JSON document")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid JSON document")
	}
	return nil
}

func rejectDuplicateJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var scan func() error
	scan = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		del, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch del {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("duplicate JSON field")
				}
				seen[s] = true
				if e = scan(); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = scan(); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := scan(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func containsSecretJSON(raw []byte, secrets []string) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	for {
		token, err := d.Token()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return true
		}
		if text, ok := token.(string); ok {
			for _, secret := range secrets {
				if strings.Contains(text, secret) {
					return true
				}
			}
		}
	}
}

func CanonicalPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != filepath.VolumeName(path)+string(filepath.Separator)
}

func IsolatedHostDirectory(path string, mounts ...string) bool {
	if !CanonicalPath(path) {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for _, mount := range mounts {
		actual, err := filepath.EvalSymlinks(mount)
		if err != nil {
			return false
		}
		for _, pair := range [][2]string{{mount, path}, {actual, resolved}} {
			relative, err := filepath.Rel(pair[0], pair[1])
			if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return false
			}
		}
	}
	return true
}
