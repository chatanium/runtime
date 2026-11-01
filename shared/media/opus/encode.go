// Package opus provides module-side ffmpeg encoding and bounded Opus frame
// reading. It has no Discord SDK or native Go library dependency.
package opus

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

var ErrEmptyAudio = errors.New("EMPTY_AUDIO: encoder emitted no Opus audio frames")

// EncodeOptions contains required, finite limits. Executable is the absolute
// image-pinned ffmpeg path, never a name resolved through the host PATH.
type EncodeOptions struct {
	Executable         string
	BitrateKbps        int
	MaxInputBytes      int64
	MaxOutputBytes     int64
	MaxFrames          int64
	MaxPacketBytes     int
	MaxDiagnosticBytes int
	Timeout            time.Duration
}

// EncodeResult counts complete length-prefixed packets written to dst.
type EncodeResult struct {
	Frames int64
	Bytes  int64
}

// Encode writes little-endian int16 lengths followed by stereo 48kHz/20ms Opus
// packets. MaxOutputBytes bounds both actual Ogg stdout and artifact bytes.
// input must be a caller-owned, immutable local regular file within MaxInputBytes.
// ffmpeg opens only the checked descriptor through /proc/self/fd, retaining seek
// support for MP4/M4A without interpreting the input filename as a URL. The file
// size and modification time are checked again before success. No metadata or
// chapters are copied.
// Its caller-owned parent directory supplies ffmpeg's working directory, HOME,
// and TMPDIR; no sandbox mount path is assumed by the encoder.
//
// dst remains caller-owned and must not block indefinitely. The caller must
// sync/close its file and publish it only after success, discarding partial data
// on any error. Cancellation and failures kill the entire encoder process group
// and wait for ffmpeg. A failed call returns no successful result.
func Encode(ctx context.Context, input string, dst io.Writer, opts EncodeOptions) (EncodeResult, error) {
	if !filepath.IsAbs(opts.Executable) || opts.BitrateKbps < 8 || opts.BitrateKbps > 128 ||
		opts.MaxInputBytes <= 0 || opts.MaxOutputBytes <= 0 || opts.MaxFrames <= 0 ||
		opts.MaxPacketBytes <= 0 || opts.MaxDiagnosticBytes <= 0 || opts.Timeout <= 0 || dst == nil {
		return EncodeResult{}, fmt.Errorf("absolute ffmpeg executable, bitrate 8..128 and positive finite encoder limits are required")
	}
	if err := ctx.Err(); err != nil {
		return EncodeResult{}, err
	}
	input, err := filepath.Abs(input)
	if err != nil {
		return EncodeResult{}, fmt.Errorf("resolve local encoder input: %w", err)
	}
	workingDirectory := filepath.Dir(input)
	// Nonblocking open rejects FIFOs without waiting for a writer. O_NOFOLLOW
	// also refuses a replaced final-component symlink before the regular-file check.
	file, err := os.OpenFile(input, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return EncodeResult{}, fmt.Errorf("open local encoder input: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return EncodeResult{}, fmt.Errorf("stat encoder input: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > opts.MaxInputBytes {
		return EncodeResult{}, fmt.Errorf("encoder input must be a regular file within %d bytes", opts.MaxInputBytes)
	}
	if info.Size() == 0 {
		return EncodeResult{}, ErrEmptyAudio
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, opts.Executable,
		"-nostdin", "-hide_banner", "-loglevel", "error",
		"-threads", "1", "-filter_threads", "1", "-filter_complex_threads", "1",
		"-protocol_whitelist", "file,pipe", "-i", "/proc/self/fd/3",
		"-map", "0:a:0", "-vn", "-sn", "-dn", "-map_metadata", "-1", "-map_chapters", "-1",
		"-c:a", "libopus", "-ar", "48000", "-ac", "2", "-b:a", strconv.Itoa(opts.BitrateKbps*1000),
		"-application", "audio", "-frame_duration", "20", "-vbr", "on",
		"-compression_level", "10", "-packet_loss", "1", "-threads", "1", "-f", "ogg", "pipe:1")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Dir = workingDirectory
	cmd.Env = []string{"LD_LIBRARY_PATH=/opt/flexmodule/lib", "LANG=C", "LC_ALL=C", "HOME=" + workingDirectory, "TMPDIR=" + workingDirectory}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	killGroup := func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = killGroup
	cmd.WaitDelay = 2 * time.Second
	diagnostic := diagnosticBuffer{limit: opts.MaxDiagnosticBytes, overflow: func() { _ = killGroup() }}
	cmd.Stderr = &diagnostic
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return EncodeResult{}, fmt.Errorf("open ffmpeg output: %w", err)
	}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		return EncodeResult{}, fmt.Errorf("start ffmpeg: %w", err)
	}
	reader := &oggReader{
		r:                &outputReader{r: stdout, remaining: opts.MaxOutputBytes},
		maxPacketBytes:   opts.MaxPacketBytes,
		maxMetadataBytes: int(min(opts.MaxOutputBytes, int64(1<<20))),
	}
	var encodeErr error
	var result EncodeResult
	var header [2]byte
	for {
		packet, err := reader.next()
		if err != nil {
			if err != io.EOF {
				encodeErr = err
			}
			break
		}
		if err := ctx.Err(); err != nil {
			encodeErr = err
			break
		}
		if result.Frames == opts.MaxFrames {
			encodeErr = fmt.Errorf("Opus frame limit exceeded")
			break
		}
		n := int64(2 + len(packet))
		if n > opts.MaxOutputBytes-result.Bytes {
			encodeErr = fmt.Errorf("Opus artifact byte limit exceeded")
			break
		}
		binary.LittleEndian.PutUint16(header[:], uint16(len(packet)))
		if err := writeFull(dst, header[:]); err != nil {
			encodeErr = err
			break
		}
		if err := writeFull(dst, packet); err != nil {
			encodeErr = err
			break
		}
		result.Frames++
		result.Bytes += n
	}
	// Prefer the timeout/cancellation that interrupted a pipe read to the ensuing
	// truncated-stream error, but never replace a destination failure with cleanup.
	if err := ctx.Err(); err != nil && encodeErr != nil {
		encodeErr = errors.Join(encodeErr, err)
	}
	if encodeErr != nil {
		_ = killGroup()
	}
	stdout.Close()
	waitErr := cmd.Wait()
	// Reap the direct child above, and kill descendants even when ffmpeg exited
	// normally or a descendant kept a diagnostic pipe open until WaitDelay.
	_ = killGroup()
	if diagnostic.err != nil {
		encodeErr = errors.Join(encodeErr, diagnostic.err)
	}
	if encodeErr == nil {
		if err := ctx.Err(); err != nil {
			encodeErr = err
		}
	}
	if encodeErr == nil && waitErr == nil {
		after, err := file.Stat()
		if err != nil {
			encodeErr = fmt.Errorf("stat encoder input after encoding: %w", err)
		} else if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			encodeErr = fmt.Errorf("encoder input changed during encoding")
		}
	}
	if encodeErr == nil && waitErr == nil && result.Frames == 0 {
		encodeErr = ErrEmptyAudio
	}
	if encodeErr != nil || waitErr != nil {
		return EncodeResult{}, fmt.Errorf("ffmpeg Opus encoding failed: %w; stderr: %s", errors.Join(encodeErr, waitErr), diagnostic.data)
	}
	return result, nil
}

func writeFull(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

// outputReader bounds bytes consumed, including metadata and empty Ogg pages.
// At the boundary it probes one byte, distinguishing exact EOF from overflow.
type outputReader struct {
	r         io.Reader
	remaining int64
}

func (r *outputReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.r.Read(probe[:])
		if n != 0 {
			return 0, fmt.Errorf("ffmpeg output byte limit exceeded")
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
}

// Keep stderr bounded and sanitized while draining it. Overflow is an explicit
// failure and immediately kills the group; it is never silently truncated into
// successful encoding. Access data/err only after Wait joins the copying goroutine.
type diagnosticBuffer struct {
	data     []byte
	limit    int
	err      error
	overflow func()
}

func (b *diagnosticBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if len(p) > remaining && b.err == nil {
		b.err = fmt.Errorf("ffmpeg diagnostic byte limit exceeded")
		if b.overflow != nil {
			b.overflow()
		}
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	if need := len(b.data) + len(p); need > cap(b.data) {
		capacity := max(need, 2*cap(b.data))
		if capacity > b.limit {
			capacity = b.limit
		}
		data := make([]byte, len(b.data), capacity)
		copy(data, b.data)
		b.data = data
	}
	for _, value := range p {
		if value < 32 || value > 126 {
			value = '?'
		}
		b.data = append(b.data, value)
	}
	return n, nil
}
