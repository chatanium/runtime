package store

import (
	"slices"
	"testing"

	"github.com/thirdscam/chatanium/internal/discordacl"
)

func TestDiscordACLRevisionPersistsAndStopsWithEpoch(t *testing.T) {
	ctx, dir, spec, s, config := fixture(t, 128<<20)
	defer s.Close()
	first, err := s.BeginEpoch(ctx, EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "first-run"})
	must(t, err)
	must(t, s.StartWorker(ctx, first.ID))
	initial := DiscordACLRecord{Binding: digest("a"), Policy: discordacl.Policy{Scopes: []discordacl.Scope{{GuildID: "123", ChannelID: "456"}}}}
	must(t, s.SetDiscordACL(ctx, first.ID, config.Revision, "first", initial))
	must(t, s.RequestStop(ctx, first.ID))
	revoke := DiscordACLRecord{Binding: initial.Binding}
	expect(t, s.SetDiscordACL(ctx, first.ID, config.Revision, "first", revoke), ErrState)
	must(t, s.FinishWorker(ctx, first.ID))
	must(t, s.EndEpoch(ctx, first.ID))

	fresh, err := Open(ctx, dir, spec.InstallationIdentity)
	must(t, err)
	defer fresh.Close()
	records, err := fresh.DiscordACLs(ctx)
	must(t, err)
	if len(records) != 1 || records["first"].Binding != initial.Binding || !slices.Equal(records["first"].Policy.Scopes, initial.Policy.Scopes) {
		t.Fatalf("unexpected restored ACLs: %+v", records)
	}
	second, err := fresh.BeginEpoch(ctx, EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "second-run"})
	must(t, err)
	must(t, fresh.StartWorker(ctx, second.ID))
	expect(t, fresh.SetDiscordACL(ctx, first.ID, config.Revision, "first", revoke), ErrIdentity)
	must(t, fresh.SetDiscordACL(ctx, second.ID, config.Revision, "first", revoke))
	records, err = fresh.DiscordACLs(ctx)
	must(t, err)
	if _, managed := records["first"]; !managed || len(records["first"].Policy.Scopes) != 0 {
		t.Fatalf("explicit deny was not retained: %+v", records)
	}
}
