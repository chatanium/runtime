package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestModuleInstallArchiveDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.oci.tar")
	data := []byte("archive bytes hashed without parsing")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := digestArchive(t.Context(), file, int64(len(data)-1)); err == nil {
		t.Fatal("oversize source accepted")
	}
	got, err := digestArchive(t.Context(), file, int64(len(data)))
	if err != nil || got != hashBytes(data) {
		t.Fatalf("digest = %s, error = %v", got, err)
	}
	var first [1]byte
	if n, err := file.Read(first[:]); n != 1 || first[0] != data[0] || err != nil {
		t.Fatalf("archive was not rewound: n = %d, byte = %d, error = %v", n, first[0], err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := digestArchive(ctx, file, int64(len(data))); err != context.Canceled {
		t.Fatalf("canceled archive read = %v", err)
	}
}

func TestModuleInstallDiscordStartsWithoutAccess(t *testing.T) {
	m, err := decodeInstallDeclaration([]byte(`{
		"protocolMajor":2,"name":"ping-bot","version":"0.1.0",
		"backendRequirements":[{"backendId":"discord","protocolMajor":2,"required":true,"optionalCapabilities":[
			{"name":"discord.event.MESSAGE_CREATE","resourceScopes":[{"allResources":true}]},
			{"name":"discord.rest.ChannelMessageSendComplex","resourceScopes":[{"allResources":true}]}
		]}]
	}`), 4096)
	if err != nil || !isDiscordStarter(m) {
		t.Fatalf("Discord starter not recognized: %v", err)
	}
	profile := runtime.ResourceProfile{CPUMillicores: 321, MemoryBytes: 128 << 20, MaxPids: 32, PersistentBytes: 128 << 20, ScratchBytes: 64 << 20}
	cfg := runtime.Config{ResourceProfiles: map[string]runtime.ResourceProfile{"general": profile}}
	options, err := installModuleOptions(cfg, true, m, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var grant wire.Grants
	if err := protojson.Unmarshal(options.Grant, &grant); err != nil {
		t.Fatal(err)
	}
	if !options.discordACLRequired || grant.EgressPolicy != wire.EgressPolicy_EGRESS_POLICY_NONE || grant.ResourceLimits.CpuMillicores != profile.CPUMillicores || len(grant.Backends) != 1 || len(grant.Backends[0].Capabilities) != 2 || len(grant.CoreCapabilities) != 0 {
		t.Fatalf("unexpected grants: %v", &grant)
	}
	for _, cap := range grant.Backends[0].Capabilities {
		if len(cap.ResourceScopes) != 1 || !cap.ResourceScopes[0].GetAllResources() {
			t.Fatalf("expected capability ceiling for %s, got %v", cap.Name, cap.ResourceScopes)
		}
	}
	if string(options.ModuleConfig) != `{}` {
		t.Fatalf("unexpected module settings: %s", options.ModuleConfig)
	}
}

func TestModuleInstallOfflineDefaults(t *testing.T) {
	profile := runtime.ResourceProfile{CPUMillicores: 123, MemoryBytes: 128 << 20, MaxPids: 32, PersistentBytes: 128 << 20, ScratchBytes: 64 << 20}
	cfg := runtime.Config{ResourceProfiles: map[string]runtime.ResourceProfile{"general": profile}}
	m := &wire.ModuleManifest{ProtocolMajor: 2, Name: "offline", Version: "0.1.0"}
	o, err := installModuleOptions(cfg, false, m, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var grant wire.Grants
	if err := protojson.Unmarshal(o.Grant, &grant); err != nil {
		t.Fatal(err)
	}
	if string(o.ModuleConfig) != "{}" || len(grant.Backends)+len(grant.CoreCapabilities) != 0 || grant.ResourceLimits.CpuMillicores != profile.CPUMillicores || grant.EgressPolicy != wire.EgressPolicy_EGRESS_POLICY_NONE {
		t.Fatalf("unexpected offline defaults: config=%s grant=%v", o.ModuleConfig, &grant)
	}
	m.BackendRequirements = []*wire.BackendRequirement{{BackendId: "other", ProtocolMajor: 2, Required: true}}
	if _, err := installModuleOptions(cfg, false, m, GenerateOptions{}); err == nil {
		t.Fatal("module with other backend requirements silently received offline defaults")
	}
}

func TestModuleInstallDiscordCredentialPublication(t *testing.T) {
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	app, err := privateChild(root, "app", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	i := &Installation{Root: root, Path: path, Manifest: Manifest{MetadataBytes: 8 << 30}}
	token := []byte("discord.test.token")
	backend, publish, err := i.proposeDiscordBackend(DiscordSetup{ApplicationID: "123", BotUserID: "456", Token: token}, nil)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(path, "app", discordTokenLeaf)
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		t.Fatalf("proposal persisted the token: %v", err)
	}
	if err := publish(); err != nil {
		t.Fatal(err)
	}
	actual, err := ReadDiscordTokenFile(filename)
	if err != nil || string(actual) != string(token) {
		t.Fatalf("approved token not available as an owner-only file: %v", err)
	}
	profile, err := compatibleDiscordProfile(backend)
	if err != nil || profile.ApplicationID != "123" || profile.BotUserID != "456" || profile.Intents != discordStarterIntents {
		t.Fatalf("approved backend is not reusable: %+v, %v", profile, err)
	}
	rotation := DiscordSetup{ApplicationID: "123", BotUserID: "456", Token: []byte("discord.rotated.token")}
	if _, _, err := i.proposeDiscordBackend(rotation, map[string]runtime.BackendConfig{"discord": backend}); err == nil {
		t.Fatal("proposal would overwrite an active credential")
	}
	_, publish, err = i.proposeDiscordBackend(rotation, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := publish(); err != nil {
		t.Fatal(err)
	}
	actual, err = ReadDiscordTokenFile(filename)
	if err != nil || string(actual) != string(rotation.Token) {
		t.Fatalf("inactive credential was not replaced: %v", err)
	}
}
