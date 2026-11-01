package main

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	provider "github.com/thirdscam/chatanium/modules/music-bot/provider"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
)

func testPlaylist(ctx context.Context, voice playbackAPI) *Playlist {
	return newPlaylist(ctx, "guild", MediaLimits{QueueEntries: 8, MaxResults: 2, MailboxEntries: 8, Workers: 2, MaxQueryBytes: 100, QueueTimeoutMS: 5000, PlaybackTimeoutMS: 5000, CommandTimeoutMS: 1000, MaxPacketBytes: 32}, 0, voice, nil, nil, make(chan prepareTask), nil)
}
func directCommand(p *Playlist, command playlistCommand) playlistReply {
	command.ctx = context.Background()
	command.reply = make(chan playlistReply, 1)
	p.handle(command)
	return <-command.reply
}
func TestResolveAndPreparationCompletionCannotReorderAcceptedRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := testPlaylist(ctx, nil)
	a := directCommand(p, playlistCommand{op: "enqueue", query: "first"})
	b := directCommand(p, playlistCommand{op: "enqueue", query: "second"})
	if a.err != nil || b.err != nil {
		t.Fatal(a.err, b.err)
	}
	p.prepared(prepareResult{id: b.entryID, tracks: []provider.Track{{ID: "B1", Title: "B1"}, {ID: "B2", Title: "B2"}}})
	p.prepared(prepareResult{id: a.entryID, tracks: []provider.Track{{ID: "A1", Title: "A1"}, {ID: "A2", Title: "A2"}}})
	audio := testAudio(t)
	defer audio.Release()
	p.prepared(prepareResult{id: p.waiting[3].view.ID, audio: audio})
	snapshot := p.snapshot()
	for i, want := range []string{"A1", "A2", "B1", "B2"} {
		if snapshot.Waiting[i].Title != want {
			t.Fatalf("entry %d = %q, want %q", i, snapshot.Waiting[i].Title, want)
		}
	}
	if snapshot.Waiting[3].State != "READY" || snapshot.Waiting[0].State != "PREPARING" {
		t.Fatal("late ready track displaced preparing first track")
	}
	snapshot.Waiting[0].Title = "mutated"
	if p.snapshot().Waiting[0].Title != "A1" {
		t.Fatal("snapshot exposed actor backing state")
	}
}
func TestRemoveWaitingNeverRemovesCurrentAndFailureUnblocksOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := testPlaylist(ctx, nil)
	a := directCommand(p, playlistCommand{op: "enqueue", query: "bad"})
	b := directCommand(p, playlistCommand{op: "enqueue", query: "good"})
	original := errors.New("extractor failed")
	p.prepared(prepareResult{id: a.entryID, err: original})
	if len(p.waiting) != 1 || p.waiting[0].view.ID != b.entryID || p.lastError != original.Error() {
		t.Fatal("failed reservation did not preserve and unblock next accepted request")
	}
	p.current = &playlistItem{view: PlaylistEntry{ID: "current", Title: "active"}}
	result := directCommand(p, playlistCommand{op: "remove", entryID: "current"})
	if result.err == nil || p.current == nil {
		t.Fatal("remove removed current")
	}
	result = directCommand(p, playlistCommand{op: "remove", entryID: b.entryID})
	if result.err != nil || len(p.waiting) != 0 {
		t.Fatalf("waiting remove failed: %v", result.err)
	}
}
func TestLoopRequeuesOnlyCompletedAndSnapshotCurrentIsDetached(t *testing.T) {
	for _, state := range []discord.PlaybackState{discord.PlaybackCompleted, discord.PlaybackCancelled, discord.PlaybackFailed} {
		t.Run(state.String(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := testPlaylist(ctx, nil)
			audio := testAudio(t)
			done := make(chan struct{})
			close(done)
			p.playDone = done
			p.currentCancel = func() {}
			p.loop = true
			p.used = 1
			p.current = &playlistItem{view: PlaylistEntry{ID: "entry", Title: "original"}, audio: audio, reserved: 1, cancel: func() {}}
			snapshot := p.snapshot()
			snapshot.Current.Title = "changed"
			if p.current.view.Title != "original" {
				t.Fatal("current snapshot aliases live entry")
			}
			p.played(playEvent{snapshot: discord.PlaybackSnapshot{State: state}})
			if state == discord.PlaybackCompleted {
				if len(p.waiting) != 1 || p.waiting[0].view.ID != "entry" {
					t.Fatal("normal completion lost entry identity")
				}
				if err := p.waiting[0].audio.Release(); err != nil {
					t.Fatal(err)
				}
			} else {
				if len(p.waiting) != 0 {
					t.Fatal("failed or cancelled entry looped")
				}
				if _, err := os.Stat(audio.storage.path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("terminal non-loop artifact leaked")
				}
			}
		})
	}
}

type terminalVoice struct {
	inputEnded    chan struct{}
	cancelCalled  chan struct{}
	terminalRPC   chan struct{}
	streamRelease chan struct{}
	once          sync.Once
}

func (v *terminalVoice) CreatePlaybackJob(context.Context, discord.CreatePlaybackJobRequest) (discord.PlaybackSnapshot, error) {
	return discord.PlaybackSnapshot{JobID: "job", State: discord.PlaybackQueued}, nil
}
func (v *terminalVoice) ProducePlayback(ctx context.Context, _ discord.JobRequest, _ uint64, next func(context.Context) ([]byte, error)) (discord.PlaybackSnapshot, error) {
	for {
		_, err := next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return discord.PlaybackSnapshot{}, err
		}
	}
	close(v.inputEnded)
	select {
	case <-ctx.Done():
		return discord.PlaybackSnapshot{}, ctx.Err()
	case <-v.streamRelease:
		return discord.PlaybackSnapshot{JobID: "job", State: discord.PlaybackCancelled}, context.Canceled
	}
}
func (v *terminalVoice) PausePlaybackJob(context.Context, discord.JobRequest) (discord.PlaybackSnapshot, error) {
	return discord.PlaybackSnapshot{JobID: "job", State: discord.PlaybackPaused}, nil
}
func (v *terminalVoice) ResumePlaybackJob(context.Context, discord.JobRequest) (discord.PlaybackSnapshot, error) {
	return discord.PlaybackSnapshot{JobID: "job", State: discord.PlaybackQueued}, nil
}
func (v *terminalVoice) CancelPlaybackJob(ctx context.Context, _ discord.JobRequest) (discord.PlaybackSnapshot, error) {
	v.once.Do(func() { close(v.cancelCalled) })
	select {
	case <-ctx.Done():
		return discord.PlaybackSnapshot{}, ctx.Err()
	case <-v.terminalRPC:
		return discord.PlaybackSnapshot{JobID: "job", State: discord.PlaybackCancelled}, nil
	}
}
func TestSkipWaitsForTerminalStreamAndArtifactLeaseNotDecoderEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	voice := &terminalVoice{inputEnded: make(chan struct{}), cancelCalled: make(chan struct{}), terminalRPC: make(chan struct{}), streamRelease: make(chan struct{})}
	p := testPlaylist(ctx, voice)
	audio := testAudio(t)
	path := audio.storage.path
	p.waiting = []*playlistItem{{view: PlaylistEntry{ID: "entry", State: "READY"}, audio: audio, reserved: 1, voiceChannel: "voice", ctx: ctx, cancel: func() {}}}
	p.used = 1
	p.loop = true
	go p.run()
	defer p.Close(ctx)
	select {
	case <-voice.inputEnded:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	snapshot, err := p.Snapshot(ctx)
	if err != nil || snapshot.Current == nil {
		t.Fatalf("decoder EOF advanced current: %+v %v", snapshot, err)
	}
	result := make(chan error, 1)
	go func() { result <- p.Skip(ctx) }()
	select {
	case <-voice.cancelCalled:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	close(voice.terminalRPC)
	select {
	case err := <-result:
		t.Fatalf("skip completed before stream released lease: %v", err)
	default:
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("artifact deleted while playback stream owned reader: %v", err)
	}
	close(voice.streamRelease)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("skip retained artifact after final lease: %v", err)
	}
	snapshot, err = p.Snapshot(ctx)
	if err != nil || snapshot.Current != nil || len(snapshot.Waiting) != 0 {
		t.Fatalf("cancel looped or retained entry: %+v %v", snapshot, err)
	}
}
