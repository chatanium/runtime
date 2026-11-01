package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestPinnedFFmpegVersionAcceptsReleaseAndPinnedGitTag(t *testing.T) {
	for _, banner := range []string{
		"ffmpeg version 9.0.2",
		"ffmpeg version n9.0.2",
		"ffmpeg version 9.0.2 Copyright (c) the FFmpeg developers\nbuilt with gcc\n",
		"ffmpeg version n9.0.2 Copyright (c) the FFmpeg developers\nbuilt with gcc\n",
	} {
		if !isPinnedFFmpegVersion(banner) {
			t.Errorf("rejected pinned FFmpeg banner %q", banner)
		}
	}
}

func TestPinnedFFmpegVersionRejectsOtherVersionsAndMalformedBanners(t *testing.T) {
	for _, banner := range []string{
		"",
		"ffmpeg version ",
		"ffprobe version n9.0.2",
		"unexpected output\nffmpeg version n9.0.2",
		"ffmpeg version 9.0.20",
		"ffmpeg version n9.0.20 Copyright (c) the FFmpeg developers",
		"ffmpeg version 9.0.3",
		"ffmpeg version n9.0.3",
		"ffmpeg version n9.0.2-dirty",
		"ffmpeg version n9.0.2-1-g946fcce07b",
		"ffmpeg version N-946fcce07b",
		"ffmpeg version n9.0.2unexpected",
	} {
		if isPinnedFFmpegVersion(banner) {
			t.Errorf("accepted unpinned FFmpeg banner %q", banner)
		}
	}
}

func TestBoundedWriterRejectsOverflowWithoutPublishingPrefix(t *testing.T) {
	var dst bytes.Buffer
	writer := &boundedWriter{writer: &dst, remaining: 3}
	if n, err := writer.Write([]byte("ab")); n != 2 || err != nil {
		t.Fatalf("write=%d err=%v", n, err)
	}
	if n, err := writer.Write([]byte("cd")); n != 0 || err == nil || !writer.exceeded {
		t.Fatalf("overflow=%d err=%v", n, err)
	}
	if dst.String() != "ab" {
		t.Fatalf("overflow published bytes: %q", dst.String())
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestBoundedWriterPreservesShortWriteFailure(t *testing.T) {
	writer := &boundedWriter{writer: shortWriter{}, remaining: 10}
	if _, err := writer.Write([]byte("abc")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write lost: %v", err)
	}
}

func TestCleanupContextRespectsDrainDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	ctx, cancel := cleanupContext(time.Hour, deadline)
	defer cancel()
	actual, ok := ctx.Deadline()
	if !ok || !actual.Equal(deadline) {
		t.Fatalf("cleanup extends drain deadline: %v", actual)
	}
	expired, stop := cleanupContext(time.Hour, time.Now().Add(-time.Second))
	defer stop()
	if !errors.Is(expired.Err(), context.DeadlineExceeded) {
		t.Fatalf("expired drain remained live: %v", expired.Err())
	}
}
