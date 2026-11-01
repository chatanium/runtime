package discordbackend

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLeafScopesRetainEveryDistinctRelatedResource(t *testing.T) {
	scopes := []*corewire.ResourceScope{scope(map[string]string{"guild_id": "1"}), scope(map[string]string{"guild_id": "1", "channel_id": "2"}), scope(map[string]string{"guild_id": "1", "channel_id": "2", "message_id": "3"}), scope(map[string]string{"guild_id": "1", "channel_id": "2", "message_id": "3"}), scope(map[string]string{"guild_id": "4"})}
	got := leafScopes(scopes)
	if len(got) != 2 || got[0].GetSelector().ResourceIds["message_id"] != "3" || got[1].GetSelector().ResourceIds["guild_id"] != "4" {
		t.Fatalf("distinct leaves lost or unrelated parents merged: %v", got)
	}
	grant := &corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{scope(map[string]string{"channel_id": "2"})}}
	if grantAllows(grant, got) {
		t.Fatal("one allowed target authorized an unrelated guild")
	}
}
func TestPermissionsApplyEveryoneRoleThenMemberOverwrites(t *testing.T) {
	guild := &discordgo.Guild{ID: "1", OwnerID: "99", Roles: []*discordgo.Role{{ID: "1", Permissions: discordgo.PermissionViewChannel | discordgo.PermissionVoiceConnect}, {ID: "2", Permissions: discordgo.PermissionVoiceSpeak}}}
	member := &discordgo.Member{GuildID: "1", User: &discordgo.User{ID: "3"}, Roles: []string{"2"}}
	channel := &discordgo.Channel{ID: "4", GuildID: "1", PermissionOverwrites: []*discordgo.PermissionOverwrite{{ID: "1", Type: discordgo.PermissionOverwriteTypeRole, Deny: discordgo.PermissionVoiceConnect}, {ID: "2", Type: discordgo.PermissionOverwriteTypeRole, Allow: discordgo.PermissionVoiceConnect, Deny: discordgo.PermissionVoiceSpeak}, {ID: "3", Type: discordgo.PermissionOverwriteTypeMember, Allow: discordgo.PermissionVoiceSpeak, Deny: discordgo.PermissionVoiceConnect}}}
	got, err := calculatePermissions(guild, channel, member, "3")
	want := int64(discordgo.PermissionViewChannel | discordgo.PermissionVoiceSpeak)
	if err != nil || got != want {
		t.Fatalf("permission precedence: got %d err %v, want %d", got, err, want)
	}
	member.Roles = append(member.Roles, "404")
	if _, err = calculatePermissions(guild, channel, member, "3"); err == nil {
		t.Fatal("missing role became a partial permission success")
	}
}
func TestAdministratorDoesNotNeedUnrelatedOverwriteLookup(t *testing.T) {
	guild := &discordgo.Guild{ID: "1", OwnerID: "99", Roles: []*discordgo.Role{{ID: "1", Permissions: discordgo.PermissionAdministrator}}}
	channel := &discordgo.Channel{ID: "2", GuildID: "1"}
	member := &discordgo.Member{User: &discordgo.User{ID: "3"}}
	got, err := calculatePermissions(guild, channel, member, "3")
	if err != nil || got != int64(discordgo.PermissionAdministrator|discordgo.PermissionAll) {
		t.Fatalf("administrator incorrectly depended on overwrite data: %d %v", got, err)
	}
	guild.Roles[0].Permissions = discordgo.PermissionViewChannel
	if _, err = calculatePermissions(guild, channel, member, "3"); err != errPermissionOverwritesUnavailable {
		t.Fatalf("ordinary member accepted missing overwrite snapshot: %v", err)
	}
}
func ownershipFixture(t *testing.T) (*ownershipStore, string, Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ownership.sqlite")
	config := Config{OwnershipDirectory: dir, RoutesPerModule: 4, RoutesPerHost: 8}
	store, err := openOwnership(path, config)
	if err != nil {
		t.Fatal(err)
	}
	return store, path, config
}
func seedCommand(t *testing.T, s *ownershipStore, name, id, state string) {
	t.Helper()
	if _, err := s.db.Exec("INSERT INTO commands VALUES(?,?,?,?,?,?,?)", "100", "200", 1, name, id, "stable", state); err != nil {
		t.Fatal(err)
	}
}
func TestUnknownRemoteOutcomeKeepsDurableStableOwnership(t *testing.T) {
	store, path, config := ownershipFixture(t)
	defer func() { store.Close() }()
	seedCommand(t, store, "alpha", "", "UNKNOWN")
	store.commands <- struct{}{}
	claim := &commandClaim{store: store, mutation: &CommandMutation{ApplicationID: "100", GuildID: "200", Commands: []CommandKey{{1, "alpha"}}}, owner: runtime.ModuleID("stable")}
	if err := claim.finish(context.Background(), true, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	store, err = openOwnership(path, config)
	if err != nil {
		t.Fatal(err)
	}
	var owner, state string
	if err = store.db.QueryRow("SELECT module,state FROM commands WHERE application='100' AND guild='200' AND name='alpha'").Scan(&owner, &state); err != nil || owner != "stable" || state != "UNKNOWN" {
		t.Fatalf("restart released an uncertain remote claim: %q %q %v", owner, state, err)
	}
}
func TestPredispatchFailureRestoresExactNamespace(t *testing.T) {
	store, _, _ := ownershipFixture(t)
	defer store.Close()
	seedCommand(t, store, "old", "300", "CONFIRMED")
	seedCommand(t, store, "new", "300", "UNKNOWN")
	store.commands <- struct{}{}
	claim := &commandClaim{store: store, mutation: &CommandMutation{ApplicationID: "100", GuildID: "200", CommandID: "300", Commands: []CommandKey{{1, "new"}}}, owner: "stable", before: []commandRow{{key: CommandKey{1, "old"}, id: "300", owner: "stable", state: "CONFIRMED"}}}
	if err := claim.finish(context.Background(), false, false, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := store.rows(context.Background(), "100", "200")
	if err != nil || len(rows) != 1 || rows[0].key.Name != "old" || rows[0].state != "CONFIRMED" {
		t.Fatalf("predispatch rollback lost exact prior claim: %v %v", rows, err)
	}
}
func TestWrongApplicationResponseCannotConfirmCommandIntent(t *testing.T) {
	store, _, _ := ownershipFixture(t)
	defer store.Close()
	seedCommand(t, store, "alpha", "", "UNKNOWN")
	store.commands <- struct{}{}
	claim := &commandClaim{store: store, mutation: &CommandMutation{ApplicationID: "100", GuildID: "200", Commands: []CommandKey{{1, "alpha"}}}, owner: "stable"}
	if err := claim.finish(context.Background(), true, true, []byte(`{"id":"300","application_id":"999","guild_id":"200","type":1,"name":"alpha"}`)); err == nil {
		t.Fatal("foreign response confirmed ownership")
	}
	var state string
	if err := store.db.QueryRow("SELECT state FROM commands WHERE name='alpha'").Scan(&state); err != nil || state != "UNKNOWN" {
		t.Fatalf("invalid result released retained intent: %q %v", state, err)
	}
}
func TestRouteLeaseRejectsForeignOwnerAndReleasesOnce(t *testing.T) {
	store, _, _ := ownershipFixture(t)
	defer store.Close()
	key := RouteKey{"100", 1, "exact:custom-id"}
	if _, err := store.db.Exec("INSERT INTO routes VALUES(?,?,?,?)", key.ApplicationID, key.Kind, key.CustomID, "stable"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.leaseRoutes(context.Background(), "foreign", []RouteKey{key}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign route send was admitted: %v", err)
	}
	release, err := store.leaseRoutes(context.Background(), "stable", []RouteKey{key})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.routeDeleting[key] = true
	store.mu.Unlock()
	if _, err = store.leaseRoutes(context.Background(), "stable", []RouteKey{key}); err == nil {
		t.Fatal("new send entered a route being unregistered")
	}
	release()
	release()
	store.mu.Lock()
	readers := store.routeReaders[key]
	store.mu.Unlock()
	if readers != 0 {
		t.Fatalf("route lease did not return its one admission: %d", readers)
	}
}
