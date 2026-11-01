package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lrstanley/go-ytdlp"
)

type Youtube struct {
	Limits         Limits
	CacheDirectory string
}

// cappedOutput aborts the process on overflow; discarded stderr is not a hidden
// unbounded output allowance and is deliberately never included in diagnostics.
type cappedOutput struct {
	data      bytes.Buffer
	remaining int64
	cancel    context.CancelFunc
	exceeded  bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		w.exceeded = true
		w.cancel()
		return 0, errors.New("media process output limit exceeded")
	}
	w.remaining -= int64(len(p))
	return w.data.Write(p)
}
func (y *Youtube) run(ctx context.Context, executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := &cappedOutput{remaining: y.Limits.MaxOutputBytes, cancel: cancel}
	diagnostic := &cappedOutput{remaining: y.Limits.MaxOutputBytes, cancel: cancel}
	var cmd *exec.Cmd
	if executable == YTDLP {
		cmd = ytdlp.New().SetExecutable(YTDLP).BuildCommand(ctx, args...)
	} else {
		cmd = exec.CommandContext(ctx, executable, args...)
	}
	cmd.Env = []string{"PATH=/opt/flexmodule/bin", "LD_LIBRARY_PATH=/opt/flexmodule/lib", "HOME=" + y.CacheDirectory, "TMPDIR=" + y.CacheDirectory, "DENO_DIR=" + y.CacheDirectory, "DENO_NO_UPDATE_CHECK=1", "DENO_NO_PROMPT=1", "LANG=C.UTF-8"}
	cmd.Dir = y.CacheDirectory
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	cmd.Stdout = out
	cmd.Stderr = diagnostic
	err := cmd.Run()
	if cmd.Process != nil {
		cleanupErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if cleanupErr != nil && !errors.Is(cleanupErr, syscall.ESRCH) {
			err = errors.Join(err, cleanupErr)
		}
	}
	if out.exceeded || diagnostic.exceeded {
		return nil, errors.New("media process output limit exceeded")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("pinned media process failed: %w", err)
	}
	return out.data.Bytes(), nil
}
func (y *Youtube) Initialize(ctx context.Context) error {
	l := y.Limits
	if l.MaxResults <= 0 || l.MaxQueryBytes <= 0 || l.MaxOutputBytes <= 0 || l.ToolTimeoutMS <= 0 || l.ResolveTimeoutMS <= 0 || y.CacheDirectory == "" {
		return errors.New("finite provider limits and owned cache directory required")
	}
	for _, tool := range []struct {
		path   string
		args   []string
		prefix string
	}{
		{FFmpeg, []string{"-version"}, "ffmpeg version 9.0.2"},
		{FFprobe, []string{"-version"}, "ffprobe version 9.0.2"},
		{YTDLP, []string{"--ignore-config", "--no-update", "--version"}, "2026.10.26"},
		{Deno, []string{"--version"}, "deno 2.9.8"},
	} {
		info, err := os.Lstat(tool.path)
		if err != nil {
			return fmt.Errorf("required image tool: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return errors.New("image tool is not a regular executable")
		}
		check, cancel := context.WithTimeout(ctx, time.Duration(l.ToolTimeoutMS)*time.Millisecond)
		raw, err := y.run(check, tool.path, tool.args...)
		cancel()
		if err != nil {
			return err
		}
		if !matchesPinnedToolVersion(string(raw), tool.prefix) {
			return errors.New("image media tool version differs from pinned lock")
		}
	}
	return nil
}

func matchesPinnedToolVersion(output, prefix string) bool {
	line, _, _ := strings.Cut(strings.TrimSpace(output), "\n")
	if line == prefix || strings.HasPrefix(line, prefix+" ") {
		return true
	}
	// The locked FFmpeg git tag generates n9.0.2 for both executables.
	// Accept that exact release identity, not arbitrary tag/revision suffixes.
	// The other tools retain their original, independent version checks.
	switch prefix {
	case "ffmpeg version 9.0.2":
		prefix = "ffmpeg version n9.0.2"
	case "ffprobe version 9.0.2":
		prefix = "ffprobe version n9.0.2"
	default:
		return false
	}
	return line == prefix || strings.HasPrefix(line, prefix+" ")
}
func (y *Youtube) Resolve(ctx context.Context, query string) ([]Track, error) {
	if len(strings.TrimSpace(query)) == 0 || len(query) > y.Limits.MaxQueryBytes {
		return nil, errors.New("query is empty or exceeds limit")
	}
	query = strings.TrimSpace(query)
	if strings.Contains(query, "://") {
		u, err := url.Parse(query)
		if err != nil || u.Scheme != "https" || u.User != nil || (u.Hostname() != "youtube.com" && u.Hostname() != "www.youtube.com" && u.Hostname() != "youtu.be") || u.Port() != "" {
			return nil, errors.New("only HTTPS YouTube URLs are accepted")
		}
	} else {
		query = "ytsearch:" + query
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(y.Limits.ResolveTimeoutMS)*time.Millisecond)
	defer cancel()
	raw, err := y.run(ctx, YTDLP, "--ignore-config", "--no-update", "--no-remote-components", "--no-js-runtimes", "--js-runtimes", "deno:"+Deno, "--ffmpeg-location", FFmpeg, "--quiet", "--no-warnings", "--no-cache-dir", "--retries", "0", "--extractor-retries", "0", "--fragment-retries", "0", "--file-access-retries", "0", "--skip-download", "--format=bestaudio/best", "--playlist-end", strconv.Itoa(y.Limits.MaxResults), "--dump-json", "--", query)
	if err != nil {
		return nil, err
	}
	return parseTracks(raw, y.Limits.MaxResults)
}
func parseTracks(raw []byte, maxResults int) ([]Track, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	tracks := make([]Track, 0)
	for {
		var row struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			URL       string `json:"url"`
			Thumbnail string `json:"thumbnail"`
		}
		err := decoder.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("incomplete provider metadata: %w", err)
		}
		source, err := url.Parse(row.URL)
		if err != nil || source.Scheme != "https" || source.Hostname() == "" || source.User != nil || row.ID == "" || row.Title == "" {
			return nil, errors.New("invalid provider metadata")
		}
		if len(tracks) == maxResults {
			return nil, errors.New("provider result limit exceeded")
		}
		sum := sha256.Sum256([]byte(row.ID))
		tracks = append(tracks, Track{ID: hex.EncodeToString(sum[:]), Title: row.Title, SourceURL: row.URL, ThumbnailURL: row.Thumbnail})
	}
	if len(tracks) == 0 {
		return nil, errors.New("provider returned no tracks")
	}
	return tracks, nil
}
