package Database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	hostDB "github.com/thirdscam/chatanium/src/Database"
	db "github.com/thirdscam/chatanium/src/Database/Internal"
)

func recordingDatabase(t *testing.T) *hostDB.DB {
	t.Helper()
	store := &hostDB.DB{}
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Shutdown(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestGuildRecordingUsesGatewayChannelsAndIsRepeatable(t *testing.T) {
	store := recordingDatabase(t)
	ctx := context.Background()
	guild := &discordgo.Guild{
		ID: "100", OwnerID: "200", Name: "guild",
		Members:  []*discordgo.Member{nil, {User: &discordgo.User{ID: "200", Username: "owner"}, Nick: "host"}},
		Channels: []*discordgo.Channel{nil, {ID: "300", Name: "general"}},
	}
	// A complete snapshot needs no network session. Repeated GuildCreate events
	// must not generate duplicate owner memberships or missing channel timestamps.
	for range 2 {
		if err := RegisterGuild(ctx, nil, store.Conn, store.Queries, guild, 4096); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Queries.GetGuild(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Queries.GetChannel(ctx, 300); err != nil {
		t.Fatal(err)
	}
	member, err := store.Queries.GetGuildUser(ctx, db.GetGuildUserParams{UserID: 200, GuildID: 100})
	if err != nil || member.Uuid == nil || member.Uuid == "" {
		t.Fatalf("owner membership: %+v, %v", member, err)
	}
	var count int
	if err := store.Conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM guildusers").Scan(&count); err != nil || count != 1 {
		t.Fatalf("membership count %d: %v", count, err)
	}
}

func TestMessageRecordingHandlesPartialEventsAndMissingMembers(t *testing.T) {
	store := recordingDatabase(t)
	ctx := context.Background()
	for _, event := range []*discordgo.MessageCreate{nil, {}, {Message: &discordgo.Message{ID: "1"}}} {
		if err := CreateMessage(ctx, event, store.Queries); err != nil {
			t.Fatal(err)
		}
	}
	for _, guildID := range []string{"", "100"} {
		message := &discordgo.MessageCreate{Message: &discordgo.Message{
			ID: "400", GuildID: guildID, ChannelID: "300", Author: &discordgo.User{ID: "200", Username: "member"}, Timestamp: time.Now(), Content: "recorded",
		}}
		if err := CreateMessage(ctx, message, store.Queries); err != nil {
			t.Fatal(err)
		}
		got, err := store.Queries.GetMessage(ctx, 400)
		if err != nil || got.GuildID.Valid != (guildID != "") || got.Contents.String != "recorded" {
			t.Fatalf("recorded message: %+v, %v", got, err)
		}
		// Discord delete partials normally have no author or member.
		if err := DeleteMessage(ctx, &discordgo.MessageDelete{Message: &discordgo.Message{ID: "400"}}, store.Queries); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Queries.GetMessage(ctx, 400); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("deleted message still present: %v", err)
		}
	}
	for _, event := range []*discordgo.MessageDelete{nil, {}, {Message: &discordgo.Message{ID: "999"}}} {
		if err := DeleteMessage(ctx, event, store.Queries); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGuildRecordingHonorsCancellation(t *testing.T) {
	store := recordingDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	guild := &discordgo.Guild{ID: "100", OwnerID: "200", Members: []*discordgo.Member{{User: &discordgo.User{ID: "200"}}}, Channels: []*discordgo.Channel{}}
	if err := RegisterGuild(ctx, nil, store.Conn, store.Queries, guild, 4096); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled registration: %v", err)
	}
}
