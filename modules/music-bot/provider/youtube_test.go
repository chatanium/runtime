package provider

import (
	"context"
	"testing"
)

func TestPinnedToolVersionAcceptsExactReleaseAndFFmpegGitTag(t *testing.T) {
	for _, tc := range []struct {
		prefix, output string
	}{
		{"ffmpeg version 9.0.2", "ffmpeg version 9.0.2"},
		{"ffmpeg version 9.0.2", "ffmpeg version n9.0.2 Copyright (c) the FFmpeg developers\nbuilt with gcc\n"},
		{"ffprobe version 9.0.2", "ffprobe version 9.0.2 Copyright (c) the FFmpeg developers"},
		{"ffprobe version 9.0.2", "ffprobe version n9.0.2"},
		{"2026.10.26", "2026.10.26\n"},
		{"deno 2.9.8", "deno 2.9.8 (stable, release, x86_64-unknown-linux-gnu)\nv8 version\n"},
	} {
		if !matchesPinnedToolVersion(tc.output, tc.prefix) {
			t.Errorf("rejected pinned tool banner %q for %q", tc.output, tc.prefix)
		}
	}
}

func TestPinnedToolVersionRejectsOtherReleasesAndModifiedBuilds(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		output []string
	}{
		{"ffmpeg version 9.0.2", []string{"", "ffmpeg version 9.0.20", "ffmpeg version n9.0.20", "ffmpeg version n9.0.3", "ffmpeg version n9.0.2-dirty", "ffmpeg version n9.0.2-1-g946fcce07b", "ffmpeg version N-946fcce07b", "ffprobe version n9.0.2", "unexpected output\nffmpeg version n9.0.2"}},
		{"ffprobe version 9.0.2", []string{"ffprobe version 9.0.20", "ffprobe version n9.0.20", "ffprobe version n9.0.3", "ffprobe version n9.0.2-dirty", "ffprobe version n9.0.2-1-g946fcce07b", "ffmpeg version n9.0.2"}},
		{"2026.10.26", []string{"n2026.10.26", "2026.10.260", "2026.10.27", "2026.10.26-dirty"}},
		{"deno 2.9.8", []string{"deno n2.9.8", "deno 2.9.80", "deno 2.9.9", "deno 2.9.8-dirty"}},
	} {
		for _, output := range tc.output {
			if matchesPinnedToolVersion(output, tc.prefix) {
				t.Errorf("accepted unpinned tool banner %q for %q", output, tc.prefix)
			}
		}
	}
}

func TestMetadataOrderBoundAndPartialFailure(t *testing.T) {
	first := `{"id":"first","title":"first title","url":"https://media.example/one"}`
	second := `{"id":"second","title":"second title","url":"https://media.example/two"}`
	tracks, err := parseTracks([]byte(first+"\n"+second), 2)
	if err != nil || len(tracks) != 2 || tracks[0].Title != "first title" || tracks[1].Title != "second title" {
		t.Fatalf("provider order: %+v %v", tracks, err)
	}
	if tracks[0].ID == "first" || tracks[0].ID == tracks[1].ID {
		t.Fatal("external ID treated as opaque artifact handle")
	}
	for _, raw := range []string{"", first + "\n{", first + "\n" + second + "\n" + first, `{"id":"x","title":"x","url":"file:///etc/passwd"}`} {
		if partial, err := parseTracks([]byte(raw), 2); err == nil || partial != nil {
			t.Fatalf("partial/empty/unbounded response published: %+v %v", partial, err)
		}
	}
}
func TestProcessOutputLimitCancelsInsteadOfDiscardingExcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := &cappedOutput{remaining: 3, cancel: cancel}
	if n, err := output.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	if _, err := output.Write([]byte("d")); err == nil || !output.exceeded || ctx.Err() == nil {
		t.Fatal("overflow was hidden or did not cancel owned process")
	}
	if output.data.String() != "abc" {
		t.Fatal("excess process output retained")
	}
}
