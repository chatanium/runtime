package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func testAudio(t *testing.T) *PreparedAudio {
	t.Helper()
	path := filepath.Join(t.TempDir(), "complete.opus")
	packet := []byte{0xf8, 0xff, 0xfe}
	raw := make([]byte, 2+len(packet))
	binary.LittleEndian.PutUint16(raw, uint16(len(packet)))
	copy(raw[2:], packet)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return &PreparedAudio{storage: &audioStorage{path: path, refs: 1, frames: 1, bytes: int64(len(raw))}}
}
func TestCompleteArtifactAcceptsOneFrameRejectsEmptyAndTruncated(t *testing.T) {
	ctx := context.Background()
	limits := MediaLimits{MaxArtifactBytes: 128, MaxPacketBytes: 32, MaxFrames: 1}
	audio := testAudio(t)
	defer audio.Release()
	frames, _, err := validateArtifact(ctx, audio.storage.path, limits)
	if err != nil || frames != 1 {
		t.Fatalf("one-frame artifact: frames=%d err=%v", frames, err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{{"empty", nil, ErrEmptyAudio}, {"truncated header", []byte{3}, io.ErrUnexpectedEOF}, {"truncated frame", []byte{3, 0, 1}, io.ErrUnexpectedEOF}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidate")
			if err := os.WriteFile(path, tc.raw, 0600); err != nil {
				t.Fatal(err)
			}
			_, _, err := validateArtifact(ctx, path, limits)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
func TestArtifactFinalLeaseOwnsDeletionAndReleaseIsPerOwner(t *testing.T) {
	audio := testAudio(t)
	path := audio.storage.path
	second, err := audio.retain()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := audio.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = audio.Release(); err != nil {
		t.Fatal(err)
	}
	if err = audio.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err = audio.Open(context.Background()); err == nil {
		t.Fatal("released owner reopened artifact")
	}
	if err = second.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatalf("file removed while reader owned a lease: %v", err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil || len(raw) == 0 {
		t.Fatalf("lease read: %v", err)
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file retained after final lease: %v", err)
	}
}
func TestCompleteArtifactBoundsAreNotReadinessThresholds(t *testing.T) {
	audio := testAudio(t)
	defer audio.Release()
	limits := MediaLimits{MaxArtifactBytes: 3, MaxPacketBytes: 32, MaxFrames: 1}
	if _, _, err := validateArtifact(context.Background(), audio.storage.path, limits); err == nil {
		t.Fatal("oversized artifact accepted")
	}
	limits.MaxArtifactBytes = 128
	limits.MaxPacketBytes = 2
	if _, _, err := validateArtifact(context.Background(), audio.storage.path, limits); err == nil {
		t.Fatal("oversized Opus packet accepted")
	}
}
