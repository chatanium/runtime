package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"github.com/thirdscam/chatanium/shared/media/opus"
)

const ffmpegPath = "/opt/flexmodule/bin/ffmpeg"

// Read-only, image-pinned tools are checked inside the media container. Neither
// this command nor playback adds host PATH lookup, download or updater logic.
func validateEncoder(ctx context.Context, scratchDirectory string, limits playerLimits) error {
	info, err := os.Lstat(ffmpegPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("pinned media-image ffmpeg executable is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, limits.operationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpegPath, "-version")
	cmd.Dir = scratchDirectory
	cmd.Env = []string{"LD_LIBRARY_PATH=/opt/flexmodule/lib", "LANG=C", "LC_ALL=C", "HOME=" + scratchDirectory, "TMPDIR=" + scratchDirectory}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = limits.cleanupTimeout
	var stdout bytes.Buffer
	out := &boundedWriter{writer: &stdout, remaining: limits.MaxProcessOutputBytes}
	errout := &boundedWriter{writer: io.Discard, remaining: limits.MaxProcessOutputBytes}
	cmd.Stdout, cmd.Stderr = out, errout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pinned ffmpeg version validation failed: %w", errors.Join(ctx.Err(), err))
	}
	if out.exceeded || errout.exceeded {
		return errors.New("ffmpeg version output exceeds configured limit")
	}
	if !isPinnedFFmpegVersion(stdout.String()) {
		return errors.New("media image must provide pinned FFmpeg 9.0.2")
	}
	return nil
}

// FFmpeg's pinned git-tag build reports n9.0.2; release archives report 9.0.2.
// Compare the complete version token, never a prefix that could admit another
// release, a development revision or a locally modified build.
func isPinnedFFmpegVersion(output string) bool {
	line, _, _ := strings.Cut(output, "\n")
	version, ok := strings.CutPrefix(line, "ffmpeg version ")
	if !ok {
		return false
	}
	version, _, _ = strings.Cut(version, " ")
	return version == "9.0.2" || version == "n9.0.2"
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
	exceeded  bool
}

func (w *boundedWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.remaining {
		w.exceeded = true
		return 0, errors.New("media output exceeds configured byte limit")
	}
	n, err := w.writer.Write(b)
	w.remaining -= int64(n)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Preparation owns its file until ffmpeg has exited, all frames have been read
// back successfully and the file is closed. Partial artifacts are never exposed
// as playable audio. A single real Opus packet succeeds; an empty file does not.
func prepareAudio(ctx context.Context, input *scratchFile, dir *scratchDirectory, limits playerLimits) (artifact *scratchFile, frames uint64, err error) {
	ctx, cancel := context.WithTimeout(ctx, limits.encodeTimeout)
	defer cancel()
	artifact, out, err := dir.create()
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, artifact.Remove())
			artifact = nil
		}
	}()
	writer := &boundedWriter{writer: out, remaining: limits.MaxArtifactBytes}
	result, encodeErr := opus.Encode(ctx, input.path, writer, opus.EncodeOptions{
		Executable: ffmpegPath, BitrateKbps: limits.BitrateKbps,
		MaxInputBytes: limits.MaxDownloadBytes, MaxOutputBytes: limits.MaxArtifactBytes,
		MaxFrames: int64(limits.MaxFrames), MaxPacketBytes: int(limits.MaxPacketBytes),
		MaxDiagnosticBytes: int(limits.MaxProcessOutputBytes), Timeout: limits.encodeTimeout,
	})
	err = encodeErr
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close())
	if err != nil {
		return artifact, 0, err
	}
	file, err := dir.root.Open(artifact.name)
	if err != nil {
		return artifact, 0, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return artifact, 0, err
	}
	if info.Size() != result.Bytes {
		return artifact, 0, errors.New("encoder result does not match complete artifact byte count")
	}
	decoder := opus.NewDecoder(file)
	for {
		packet, readErr := decoder.OpusFrame(ctx)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return artifact, 0, readErr
		}
		frames++
		if frames > limits.MaxFrames || uint64(len(packet)) > limits.MaxPacketBytes {
			return artifact, 0, errors.New("encoded audio exceeds configured frame or packet limit")
		}
	}
	if frames == 0 {
		return artifact, 0, opus.ErrEmptyAudio
	}
	if frames != uint64(result.Frames) {
		return artifact, 0, errors.New("encoder result does not match complete artifact frame count")
	}
	if err = ctx.Err(); err != nil {
		return artifact, 0, err
	}
	return artifact, frames, nil
}

func (p *player) recordCleanup(err error) {
	if err == nil {
		return
	}
	p.mu.Lock()
	p.cleanupError = errors.Join(p.cleanupError, err)
	p.failure = errors.Join(p.failure, err)
	p.ready = false
	p.mu.Unlock()
	p.cancel()
}

func (p *player) play(request attachmentRequest) (err error) {
	dir, err := p.scratch.directory()
	if err != nil {
		return err
	}
	defer func() { cleanupErr := dir.Close(); p.recordCleanup(cleanupErr); err = errors.Join(err, cleanupErr) }()
	input, err := p.downloads.DownloadAttachment(p.lifetime, request.attachment, dir)
	if err != nil {
		return err
	}
	artifact, frames, err := prepareAudio(p.lifetime, input, dir, p.cfg.Limits)
	if err != nil {
		return err
	}
	if err := input.Remove(); err != nil {
		return err
	}
	file, err := dir.root.Open(artifact.name)
	if err != nil {
		return err
	}
	defer func() { cleanupErr := file.Close(); p.recordCleanup(cleanupErr); err = errors.Join(err, cleanupErr) }()
	ctx, cancel := context.WithTimeout(p.lifetime, p.cfg.Limits.jobLifetime)
	defer cancel()
	admit, stop := context.WithTimeout(ctx, p.cfg.Limits.operationTimeout)
	job, err := p.voice.CreatePlaybackJob(admit, discord.CreatePlaybackJobRequest{GuildID: request.guild, ChannelID: request.voice, Priority: *p.cfg.Priority, Lifetime: p.cfg.Limits.jobLifetime, Format: discord.Opus48kHz20ms})
	stop()
	if err != nil {
		return err
	} // Ambiguous creation is not retried.
	defer func() {
		p.mu.Lock()
		deadline := p.cleanupDeadline
		p.mu.Unlock()
		cleanup, finish := cleanupContext(p.cfg.Limits.cleanupTimeout, deadline)
		defer finish()
		terminal, cleanupErr := p.voice.CancelPlaybackJob(cleanup, discord.JobRequest{JobID: job.JobID})
		if cleanupErr == nil && !terminal.Terminal() {
			cleanupErr = errors.New("owned playback cancel did not reach terminal state")
		}
		p.recordCleanup(cleanupErr)
		err = errors.Join(err, cleanupErr)
	}()
	decoder := opus.NewDecoder(file)
	snapshot, err := p.voice.ProducePlayback(ctx, discord.JobRequest{JobID: job.JobID}, p.cfg.Limits.MaxPacketBytes, decoder.OpusFrame)
	if err != nil {
		return err
	}
	if snapshot.State != discord.PlaybackCompleted || !snapshot.InputEnded || snapshot.FinalSequence != frames || snapshot.LastUDPWrittenSequence != frames {
		return fmt.Errorf("playback did not complete the validated %d-frame artifact", frames)
	}
	return nil
}
