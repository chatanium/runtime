package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	discord "github.com/thirdscam/chatanium/shared/discord-v2"
)

func TestDrainConsumesLatePreparedArtifactBeforeReturning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p := testPlaylist(ctx, nil)
	audio := testAudio(t)
	path := audio.storage.path
	work, cancelWork := context.WithCancel(p.ctx)
	p.waiting = []*playlistItem{{view: PlaylistEntry{ID: "pending", State: "PREPARING"}, reserved: 1, ctx: work, cancel: cancelWork, dispatched: true}}
	p.used = 1
	p.inFlight = 1
	delivered := make(chan struct{})
	go func() { <-work.Done(); p.results <- prepareResult{id: "pending", audio: audio}; close(delivered) }()
	go p.run()
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delivered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("drain leaked worker result artifact: %v", err)
	}
	if _, err := p.Enqueue(ctx, "new request", "text", "voice"); err == nil {
		t.Fatal("closed actor accepted new work")
	}
}
func TestSkipPreservesArtifactCleanupFailureInsteadOfFalseSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := testPlaylist(ctx, nil)
	directory := filepath.Join(t.TempDir(), "not-empty")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "owned"), []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	audio := &PreparedAudio{storage: &audioStorage{path: directory, refs: 1, frames: 1}}
	done := make(chan struct{})
	close(done)
	p.playDone = done
	p.currentCancel = func() {}
	p.used = 1
	p.current = &playlistItem{view: PlaylistEntry{ID: "current"}, audio: audio, reserved: 1, cancel: func() {}}
	p.skipReply = make(chan playlistReply, 1)
	reply := p.skipReply
	p.played(playEvent{snapshot: discord.PlaybackSnapshot{State: discord.PlaybackCancelled}, err: context.Canceled})
	result := <-reply
	if result.err == nil || p.failure == nil || p.lastError == "" {
		t.Fatal("artifact release failure was reported as successful skip")
	}
	accepted := directCommand(p, playlistCommand{op: "enqueue", query: "do not advance"})
	if accepted.err == nil {
		t.Fatal("failed cleanup allowed new reservations")
	}
}
