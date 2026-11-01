package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	discord "github.com/thirdscam/chatanium/shared/discord-v2"
)

type failedProducerVoice struct {
	terminalVoice
	cancelled chan discord.JobID
	cause     error
}

func (v *failedProducerVoice) ProducePlayback(context.Context, discord.JobRequest, uint64, func(context.Context) ([]byte, error)) (discord.PlaybackSnapshot, error) {
	return discord.PlaybackSnapshot{}, v.cause
}
func (v *failedProducerVoice) CancelPlaybackJob(_ context.Context, job discord.JobRequest) (discord.PlaybackSnapshot, error) {
	v.cancelled <- job.JobID
	return discord.PlaybackSnapshot{JobID: job.JobID, State: discord.PlaybackCancelled}, nil
}
func TestProducerFailureRetainsCreatedJobForCleanupAndOriginalError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cause := errors.New("producer failed before receiving its first snapshot")
	voice := &failedProducerVoice{cancelled: make(chan discord.JobID, 1), cause: cause}
	p := testPlaylist(ctx, voice)
	audio := testAudio(t)
	path := audio.storage.path
	reported := make(chan struct{})
	p.notify = func(context.Context, string, string) error { close(reported); return nil }
	p.waiting = []*playlistItem{{view: PlaylistEntry{ID: "entry", State: "READY"}, audio: audio, reserved: 1, voiceChannel: "voice", textChannel: "text", ctx: ctx, cancel: func() {}}}
	p.used = 1
	p.loop = true
	go p.run()
	defer p.Close(ctx)
	select {
	case job := <-voice.cancelled:
		if job != "job" {
			t.Fatalf("cleanup lost known job ID: %q", job)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-reported:
	case <-ctx.Done():
		t.Fatal("producer failure disappeared behind cleanup CANCELLED", ctx.Err())
	}
	snapshot, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Current != nil || len(snapshot.Waiting) != 0 || !strings.Contains(snapshot.LastError, cause.Error()) {
		t.Fatalf("original producer failure or terminal state lost: %+v", snapshot)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed producer retained artifact: %v", err)
	}
}
