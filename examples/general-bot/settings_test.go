package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
)

func TestSettingsRestartAndOwnedChannelIsolation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenSettings(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := store.GetGuildSettings(ctx, "100"); err != nil || present {
		t.Fatalf("first install: present=%v err=%v", present, err)
	}
	if err = store.SetGuildSettings(ctx, "100", GuildSettings{AuditReplyChannelID: "200"}); err != nil {
		t.Fatal(err)
	}
	if err = store.RecordChannel(ctx, "100", "300", false); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSettings(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, present, err := reopened.GetGuildSettings(ctx, "100")
	if err != nil || !present || got.AuditReplyChannelID != "200" {
		t.Fatalf("durable setting: %#v %v %v", got, present, err)
	}
	owned, err := reopened.OwnsChannel(ctx, "100", "300")
	if err != nil || !owned {
		t.Fatalf("owned channel was lost: %v", err)
	}
	owned, err = reopened.OwnsChannel(ctx, "101", "300")
	if err != nil || owned {
		t.Fatalf("foreign guild gained ownership: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = reopened.SetGuildSettings(cancelled, "100", GuildSettings{AuditReplyChannelID: "201"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled update: %v", err)
	}
	got, _, err = reopened.GetGuildSettings(ctx, "100")
	if err != nil || got.AuditReplyChannelID != "200" {
		t.Fatalf("cancelled write changed state: %#v %v", got, err)
	}
}
func TestSettingsCorruptionNeverFallsBackOrOverwrites(t *testing.T) {
	for _, raw := range []string{"null", `{"schema_version":99,"guilds":{},"created_channels":{}}`, `{"schema_version":1,"guilds":null,"created_channels":{}}`, `{"schema_version":1,"guilds":{},"created_channels":{},"unknown":true}`, `{"schema_version":1,`} {
		t.Run(raw, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			store, err := OpenSettings(context.Background(), dir)
			if err == nil {
				store.Close()
				t.Fatal("corrupt settings were accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != raw {
				t.Fatal("corrupt settings were overwritten")
			}
		})
	}
}
func TestSettingsRejectSymlinkFile(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.json")
	raw := `{"schema_version":1,"guilds":{},"created_channels":{}}`
	if err := os.WriteFile(outside, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "settings.json")); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSettings(context.Background(), dir)
	if err == nil {
		store.Close()
		t.Fatal("symlink settings path was accepted")
	}
	after, err := os.ReadFile(outside)
	if err != nil || string(after) != raw {
		t.Fatalf("external data changed: %v", err)
	}
}

func TestINITSettingsUseSuppliedCanonicalDirectory(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	persistent := filepath.Join(root, "var", "lib", "flexmodule", "data")
	scratch := filepath.Join(root, "var", "lib", "flexmodule", "scratch")
	for _, directory := range []string{persistent, scratch} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	init := &corewire.InitContext{
		PersistentDirectory: persistent,
		ScratchDirectory:    scratch,
		Grants:              &corewire.Grants{ResourceLimits: &corewire.ResourceLimits{PersistentBytes: 1 << 30}},
	}
	store, err := openGrantedSettings(ctx, init)
	if err != nil {
		t.Fatalf("INIT rejected supplied non-legacy mount path: %v", err)
	}
	if err = store.SetGuildSettings(ctx, "100", GuildSettings{AuditReplyChannelID: "200"}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(persistent, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved ExampleState
	if err = decodeJSON(raw, &saved); err != nil || saved.Guilds["100"].AuditReplyChannelID != "200" {
		t.Fatalf("settings did not reach the supplied persistent mount: %#v %v", saved, err)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil || len(entries) != 0 {
		t.Fatalf("persistent write touched scratch: %v %v", entries, err)
	}
	if _, err = os.Stat(filepath.Join(root, "persistent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a legacy alias was created: %v", err)
	}
	reopened, err := openGrantedSettings(ctx, init)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, present, err := reopened.GetGuildSettings(ctx, "100")
	if err != nil || !present || got.AuditReplyChannelID != "200" {
		t.Fatalf("supplied-mount restart lost settings: %#v %v %v", got, present, err)
	}
}

func TestINITSettingsRejectUnapprovedOrNoncanonicalDirectory(t *testing.T) {
	for _, directory := range []string{"", ".", "relative/data", "/", "/var/lib/flexmodule/../data", "/var/lib/flexmodule/data/"} {
		init := &corewire.InitContext{PersistentDirectory: directory, Grants: &corewire.Grants{ResourceLimits: &corewire.ResourceLimits{PersistentBytes: 1 << 30}}}
		store, err := openGrantedSettings(context.Background(), init)
		if err == nil {
			store.Close()
			t.Fatalf("invalid supplied directory accepted: %q", directory)
		}
	}
	init := &corewire.InitContext{PersistentDirectory: t.TempDir(), Grants: &corewire.Grants{ResourceLimits: &corewire.ResourceLimits{}}}
	store, err := openGrantedSettings(context.Background(), init)
	if err == nil {
		store.Close()
		t.Fatal("missing persistent quota was accepted")
	}
}
