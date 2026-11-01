package voicejobs

import (
	"strings"
	"testing"

	rt "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestQueueIsOwnerBoundSchedulingOrderedAndPaginated(t *testing.T) {
	g, _, p := fixtureGuild(t)
	a := fixtureJob(t, g, p, "a", 1)
	fixtureJob(t, g, p, "b", 9)
	fixtureJob(t, g, p, "c", 9)
	a.paused = true
	g.setState(a, wire.PlaybackState_PLAYBACK_STATE_PAUSED, wire.PlaybackReason_PLAYBACK_REASON_OWNER_PAUSED)
	entries, generation := g.service.queueSnapshot(p, g.id)
	r := &wire.PlaybackQueueRequest{GuildId: g.id, Limit: 1}
	first, err := g.service.queuePage(p, r, entries, generation)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Jobs) != 1 || first.Jobs[0].JobId != "b" || first.NextContinuation == "" {
		t.Fatal("queue order or continuation lost")
	}
	r.Continuation = first.NextContinuation
	entries, generation = g.service.queueSnapshot(p, g.id)
	second, err := g.service.queuePage(p, r, entries, generation)
	if err != nil {
		t.Fatal(err)
	}
	if second.Jobs[0].JobId != "c" {
		t.Fatal("FIFO tie order changed between pages")
	}
	r.Continuation = second.NextContinuation
	entries, generation = g.service.queueSnapshot(p, g.id)
	last, err := g.service.queuePage(p, r, entries, generation)
	if err != nil || last.Jobs[0].State != wire.PlaybackState_PLAYBACK_STATE_PAUSED || last.NextContinuation != "" {
		t.Fatal("paused entry represented as runnable or missing")
	}
	r.Continuation = first.NextContinuation
	if _, err := g.service.queuePage(rt.InstancePrincipal{InstanceID: "foreign"}, r, entries, generation); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("foreign cursor was accepted")
	}
	r.GuildId = "999"
	if _, err := g.service.queuePage(p, r, entries, generation); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("cursor moved to another guild")
	}
}
func TestQueueMutationInvalidatesOnlyAffectedGuild(t *testing.T) {
	g, _, p := fixtureGuild(t)
	a := fixtureJob(t, g, p, "a", 1)
	fixtureJob(t, g, p, "b", 1)
	entries, generation := g.service.queueSnapshot(p, g.id)
	r := &wire.PlaybackQueueRequest{GuildId: g.id, Limit: 1}
	page, err := g.service.queuePage(p, r, entries, generation)
	if err != nil {
		t.Fatal(err)
	}
	r.Continuation = page.NextContinuation
	g.service.mu.Lock()
	g.service.bumpLocked("unrelated")
	g.service.mu.Unlock()
	if _, err := g.service.queuePage(p, r, entries, generation); err != nil {
		t.Fatal("unrelated guild invalidated a cursor")
	}
	g.setState(a, wire.PlaybackState_PLAYBACK_STATE_PAUSED, wire.PlaybackReason_PLAYBACK_REASON_OWNER_PAUSED)
	if _, err := g.service.queuePage(p, r, entries, generation); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("changed queue accepted stale continuation")
	}
	if entries[0].snapshot.State == wire.PlaybackState_PLAYBACK_STATE_PAUSED {
		t.Fatal("published queue view was mutated in place")
	}
}
func TestQueueFirstPageRetainsCapturedSnapshotAcrossPublication(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit uint32
	}{
		{"complete_page", 2},
		{"continued_page", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _, p := fixtureGuild(t)
			fixtureJob(t, g, p, "a", 1)
			b := fixtureJob(t, g, p, "b", 2)
			captured := proto.Clone(b.snapshot).(*wire.PlaybackSnapshot)
			entries, generation := g.service.queueSnapshot(p, g.id)

			// Interleave an ordinary producer publication after capture, at
			// the boundary where GetPlaybackQueue performs authorization.
			// The fixture has no actor loop, so this handoff needs no sleeps.
			published := make(chan error, 1)
			go func() { published <- g.accept(b, opusInput(1)) }()
			if err := <-published; err != nil {
				t.Fatal(err)
			}
			latest, latestGeneration := g.service.queueSnapshot(p, g.id)
			if latestGeneration == generation || b.snapshot.LastAcceptedSequence != 1 {
				t.Fatal("producer publication did not advance the live queue")
			}

			request := &wire.PlaybackQueueRequest{GuildId: g.id, Limit: tc.limit}
			page, err := g.service.queuePage(p, request, entries, generation)
			if err != nil {
				t.Fatalf("first page rejected its captured snapshot after publication: %v", err)
			}
			if len(page.Jobs) != int(tc.limit) || !proto.Equal(page.Jobs[0], captured) {
				t.Fatal("first page did not retain the captured order, identity and playback cursors")
			}
			if tc.limit == 2 {
				if page.NextContinuation != "" {
					t.Fatal("complete captured page unexpectedly returned a continuation")
				}
				return
			}
			if page.NextContinuation == "" {
				t.Fatal("bounded captured page lost its continuation")
			}
			request.Continuation = page.NextContinuation
			if _, err := g.service.queuePage(p, request, latest, latestGeneration); status.Code(err) != codes.FailedPrecondition {
				t.Fatal("publication failed to invalidate the captured page's continuation")
			} else {
				staleReason := false
				for _, detail := range status.Convert(err).Details() {
					if voice, ok := detail.(*wire.VoiceError); ok {
						staleReason = voice.Reason == wire.VoiceErrorReason_VOICE_ERROR_REASON_STALE_CONTINUATION
					}
				}
				if !staleReason {
					t.Fatal("invalidated continuation lost its typed stale reason")
				}
			}
		})
	}
}
func TestQueuePaginationAlsoBoundsSerializedBytes(t *testing.T) {
	g, _, p := fixtureGuild(t)
	for _, id := range []string{strings.Repeat("a", 48), strings.Repeat("b", 48), strings.Repeat("c", 48)} {
		fixtureJob(t, g, p, id, 1)
	}
	entries, generation := g.service.queueSnapshot(p, g.id)
	one, err := g.service.queuePage(p, &wire.PlaybackQueueRequest{GuildId: g.id, Limit: 1}, entries, generation)
	if err != nil {
		t.Fatal(err)
	}
	g.service.config.MaxGRPCMessageBytes = proto.Size(one)
	entries, generation = g.service.queueSnapshot(p, g.id)
	page, err := g.service.queuePage(p, &wire.PlaybackQueueRequest{GuildId: g.id, Limit: 2}, entries, generation)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Jobs) != 1 || page.NextContinuation == "" || proto.Size(page) > g.service.config.MaxGRPCMessageBytes {
		t.Fatal("byte bound did not produce a continuation")
	}
}
func TestTerminalSnapshotCannotBeCoalescedAway(t *testing.T) {
	g, _, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	for range 10 {
		g.publish(j)
	}
	g.stopJob(j, stopped(), true)
	found := false
	for len(j.status) > 0 {
		snapshot := <-j.status
		if terminal(snapshot.State) {
			found = true
		}
	}
	if !found {
		t.Fatal("terminal snapshot disappeared behind status coalescing")
	}
}
