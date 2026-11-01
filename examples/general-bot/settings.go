package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
)

const settingsSchema = 1
const maxSettingsBytes = 1 << 20

type GuildSettings struct {
	AuditReplyChannelID string `json:"audit_reply_channel_id"`
}
type ExampleState struct {
	SchemaVersion   uint32                   `json:"schema_version"`
	Guilds          map[string]GuildSettings `json:"guilds"`
	CreatedChannels map[string]string        `json:"created_channels"`
}
type SettingsStore struct {
	mu     sync.Mutex
	root   *os.Root
	state  ExampleState
	failed error
}

func decodeJSON(raw []byte, out any) error {
	object := bytes.TrimSpace(raw)
	if len(object) == 0 || object[0] != '{' {
		return errors.New("expected a JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected exactly one JSON object")
	}
	return nil
}

// openGrantedSettings is INIT's storage boundary. The authenticated host supplies
// the canonical guest path; no image-specific mount spelling is assumed.
func openGrantedSettings(ctx context.Context, init *corewire.InitContext) (*SettingsStore, error) {
	if init == nil || init.Grants == nil || init.Grants.ResourceLimits == nil || init.Grants.ResourceLimits.PersistentBytes == 0 {
		return nil, errors.New("ordinary bot requires approved persistent storage")
	}
	directory := init.PersistentDirectory
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == string(filepath.Separator) {
		return nil, errors.New("persistent directory must be a canonical absolute non-root path")
	}
	return OpenSettings(ctx, directory)
}

func OpenSettings(ctx context.Context, persistentDir string) (*SettingsStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(persistentDir)
	if err != nil {
		return nil, err
	}
	s := &SettingsStore{root: root, state: ExampleState{SchemaVersion: settingsSchema, Guilds: map[string]GuildSettings{}, CreatedChannels: map[string]string{}}}
	f, err := root.OpenFile("settings.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxSettingsBytes+1))
	closeErr := f.Close()
	if err = errors.Join(readErr, closeErr); err == nil && len(raw) > maxSettingsBytes {
		err = errors.New("settings exceed size limit")
	}
	if err == nil {
		err = decodeJSON(raw, &s.state)
	}
	if err == nil && (s.state.SchemaVersion != settingsSchema || s.state.Guilds == nil || s.state.CreatedChannels == nil) {
		err = errors.New("unsupported or invalid settings schema")
	}
	if err == nil {
		for guild, value := range s.state.Guilds {
			if !snowflake(guild) || (value.AuditReplyChannelID != "" && !snowflake(value.AuditReplyChannelID)) {
				err = errors.New("invalid stored guild settings")
				break
			}
		}
		for channel, guild := range s.state.CreatedChannels {
			if !snowflake(channel) || !snowflake(guild) {
				err = errors.New("invalid stored channel ownership")
				break
			}
		}
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	return s, nil
}
func (s *SettingsStore) GetGuildSettings(ctx context.Context, guildID string) (GuildSettings, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return GuildSettings{}, false, err
	}
	if s.failed != nil {
		return GuildSettings{}, false, s.failed
	}
	v, ok := s.state.Guilds[guildID]
	return v, ok, nil
}
func (s *SettingsStore) SetGuildSettings(ctx context.Context, guildID string, value GuildSettings) error {
	if !snowflake(guildID) || (value.AuditReplyChannelID != "" && !snowflake(value.AuditReplyChannelID)) {
		return errors.New("invalid guild settings")
	}
	return s.update(ctx, func(next *ExampleState) { next.Guilds[guildID] = value })
}
func (s *SettingsStore) OwnsChannel(ctx context.Context, guildID, channelID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.failed != nil {
		return false, s.failed
	}
	return s.state.CreatedChannels[channelID] == guildID, nil
}
func (s *SettingsStore) RecordChannel(ctx context.Context, guildID, channelID string, remove bool) error {
	if !snowflake(guildID) || !snowflake(channelID) {
		return errors.New("invalid channel ownership")
	}
	return s.update(ctx, func(next *ExampleState) {
		if remove {
			delete(next.CreatedChannels, channelID)
		} else {
			next.CreatedChannels[channelID] = guildID
		}
	})
}
func (s *SettingsStore) update(ctx context.Context, change func(*ExampleState)) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.failed != nil {
		return s.failed
	}
	next := ExampleState{SchemaVersion: settingsSchema, Guilds: make(map[string]GuildSettings, len(s.state.Guilds)), CreatedChannels: make(map[string]string, len(s.state.CreatedChannels))}
	for k, v := range s.state.Guilds {
		next.Guilds[k] = v
	}
	for k, v := range s.state.CreatedChannels {
		next.CreatedChannels[k] = v
	}
	change(&next)
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(raw) > maxSettingsBytes {
		return errors.New("settings exceed size limit")
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".settings-" + hex.EncodeToString(nonce[:])
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			if e := s.root.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
				result = errors.Join(result, e)
			}
		}
	}()
	n, writeErr := f.Write(raw)
	if writeErr == nil && n != len(raw) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	err = errors.Join(writeErr, f.Close())
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = s.root.Rename(name, "settings.json"); err != nil {
		return err
	}
	renamed = true
	dir, err := s.root.Open(".")
	if err == nil {
		err = errors.Join(dir.Sync(), dir.Close())
	}
	if err != nil {
		s.failed = fmt.Errorf("settings durability unknown after rename: %w", err)
		return s.failed
	}
	s.state = next
	return nil
}
func (s *SettingsStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	err := s.root.Close()
	s.root = nil
	return err
}

// OwnedChannels returns an independent INIT snapshot, never the mutable map.
func (s *SettingsStore) OwnedChannels(ctx context.Context, guildID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.failed != nil {
		return nil, s.failed
	}
	var channels []string
	for channel, guild := range s.state.CreatedChannels {
		if guild == guildID {
			channels = append(channels, channel)
		}
	}
	return channels, nil
}
