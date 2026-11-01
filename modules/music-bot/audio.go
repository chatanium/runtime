package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	provider "github.com/thirdscam/chatanium/modules/music-bot/provider"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"github.com/thirdscam/chatanium/shared/media/opus"
)

var ErrEmptyAudio = errors.New("EMPTY_AUDIO")

// Each handle is one owner. Open leases keep the complete file alive independently
// of the queue owner, and repeated Release on the same handle is harmless.
type audioStorage struct {
	mu     sync.Mutex
	path   string
	refs   int
	frames uint64
	bytes  int64
}
type PreparedAudio struct {
	storage  *audioStorage
	once     sync.Once
	released atomic.Bool
	err      error
}

func (a *PreparedAudio) FrameCount() uint64         { return a.storage.frames }
func (a *PreparedAudio) ByteCount() int64           { return a.storage.bytes }
func (a *PreparedAudio) Format() discord.OpusFormat { return discord.Opus48kHz20ms }
func (a *PreparedAudio) retain() (*PreparedAudio, error) {
	if a.released.Load() {
		return nil, errors.New("artifact owner already released")
	}
	a.storage.mu.Lock()
	defer a.storage.mu.Unlock()
	if a.released.Load() || a.storage.refs == 0 {
		return nil, errors.New("artifact already released")
	}
	a.storage.refs++
	return &PreparedAudio{storage: a.storage}, nil
}
func (a *PreparedAudio) Release() error {
	a.once.Do(func() { a.released.Store(true); a.err = a.storage.release() })
	return a.err
}
func (s *audioStorage) release() error {
	s.mu.Lock()
	s.refs--
	remove := s.refs == 0
	path := s.path
	s.mu.Unlock()
	if !remove {
		return nil
	}
	return os.Remove(path)
}

type audioReader struct {
	*os.File
	storage *audioStorage
	once    sync.Once
	err     error
}

func (r *audioReader) Close() error {
	r.once.Do(func() { r.err = errors.Join(r.File.Close(), r.storage.release()) })
	return r.err
}
func (a *PreparedAudio) Open(ctx context.Context) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.released.Load() {
		return nil, errors.New("artifact owner already released")
	}
	s := a.storage
	s.mu.Lock()
	if a.released.Load() || s.refs == 0 {
		s.mu.Unlock()
		return nil, errors.New("artifact already released")
	}
	s.refs++
	path := s.path
	s.mu.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Join(err, s.release())
	}
	return &audioReader{File: f, storage: s}, nil
}

type Preparer struct {
	directory string
	limits    MediaLimits
	client    *http.Client
}

func newPreparer(directory string, limits MediaLimits) *Preparer {
	return &Preparer{directory: directory, limits: limits, client: &http.Client{
		Timeout:   millis(limits.HTTPTimeoutMS),
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: limits.Workers, TLSHandshakeTimeout: millis(limits.HTTPTimeoutMS), ResponseHeaderTimeout: millis(limits.HTTPTimeoutMS)},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > limits.MaxRedirects {
				return errors.New("media redirect limit exceeded")
			}
			if req.URL.Scheme != "https" || req.URL.User != nil {
				return errors.New("media redirect must be HTTPS without credentials")
			}
			return nil
		},
	}}
}
func (p *Preparer) Prepare(ctx context.Context, track provider.Track) (audio *PreparedAudio, err error) {
	ctx, cancel := context.WithTimeout(ctx, millis(p.limits.PrepareTimeoutMS))
	defer cancel()
	u, e := url.Parse(track.SourceURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("invalid media source URL")
	}
	input, e := os.CreateTemp(p.directory, "source-*")
	if e != nil {
		return nil, e
	}
	defer func() {
		err = errors.Join(err, input.Close(), os.Remove(input.Name()))
		if err != nil && audio != nil {
			err = errors.Join(err, audio.Release())
			audio = nil
		}
	}()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, track.SourceURL, nil)
	if e != nil {
		return nil, e
	}
	response, e := p.client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("media fetch failed: %w", safeFetchError(e))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.Join(fmt.Errorf("media HTTP status %d", response.StatusCode), response.Body.Close())
	}
	if response.ContentLength > p.limits.MaxInputBytes {
		return nil, errors.Join(errors.New("media Content-Length exceeds limit"), response.Body.Close())
	}
	n, copyErr := io.Copy(input, io.LimitReader(response.Body, p.limits.MaxInputBytes+1))
	bodyErr := response.Body.Close()
	if n > p.limits.MaxInputBytes {
		return nil, errors.Join(errors.New("media input byte limit exceeded"), copyErr, bodyErr)
	}
	if copyErr != nil || bodyErr != nil {
		return nil, errors.Join(copyErr, bodyErr)
	}
	if response.ContentLength >= 0 && n != response.ContentLength {
		return nil, io.ErrUnexpectedEOF
	}
	if n == 0 {
		return nil, ErrEmptyAudio
	}
	output, e := os.CreateTemp(p.directory, "partial-*")
	if e != nil {
		return nil, e
	}
	committed, closed := false, false
	defer func() {
		if !committed {
			if !closed {
				err = errors.Join(err, output.Close())
			}
			err = errors.Join(err, os.Remove(output.Name()))
		}
	}()
	encoded, e := opus.Encode(ctx, input.Name(), output, opus.EncodeOptions{
		Executable: provider.FFmpeg, BitrateKbps: p.limits.BitrateKbps,
		MaxInputBytes: p.limits.MaxInputBytes, MaxOutputBytes: p.limits.MaxArtifactBytes,
		MaxFrames: int64(p.limits.MaxFrames), MaxPacketBytes: int(p.limits.MaxPacketBytes),
		MaxDiagnosticBytes: int(p.limits.MaxProcessOutputBytes), Timeout: millis(p.limits.PrepareTimeoutMS),
	})
	if e != nil {
		if errors.Is(e, opus.ErrEmptyAudio) {
			return nil, errors.Join(ErrEmptyAudio, e)
		}
		return nil, e
	}
	if e = output.Sync(); e != nil {
		return nil, e
	}
	e = output.Close()
	closed = true
	if e != nil {
		return nil, e
	}
	count, size, e := validateArtifact(ctx, output.Name(), p.limits)
	if e != nil {
		return nil, e
	}
	if encoded.Frames != int64(count) || encoded.Bytes != size {
		return nil, errors.New("completed artifact differs from encoder result")
	}
	complete := output.Name() + ".opus"
	if e = os.Rename(output.Name(), complete); e != nil {
		return nil, e
	}
	committed = true
	return &PreparedAudio{storage: &audioStorage{path: complete, refs: 1, frames: count, bytes: size}}, nil
}
func safeFetchError(err error) error {
	// net/http's url.Error embeds signed source URLs; retain the underlying cause.
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err
	}
	return err
}
func validateArtifact(ctx context.Context, path string, limits MediaLimits) (frames uint64, size int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	stat, err := file.Stat()
	if err != nil {
		return 0, 0, err
	}
	if stat.Size() > limits.MaxArtifactBytes {
		return 0, 0, errors.New("artifact byte limit exceeded")
	}
	decoder := opus.NewDecoder(file)
	for {
		packet, err := decoder.OpusFrame(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, err
		}
		if uint64(len(packet)) > limits.MaxPacketBytes {
			return 0, 0, errors.New("Opus packet limit exceeded")
		}
		frames++
		if frames > limits.MaxFrames {
			return 0, 0, errors.New("Opus frame limit exceeded")
		}
	}
	if frames == 0 {
		return 0, 0, ErrEmptyAudio
	}
	return frames, stat.Size(), nil
}
func PlayPrepared(ctx context.Context, voice playbackAPI, audio *PreparedAudio, job discord.JobRequest, maxPacketBytes uint64) (snapshot discord.PlaybackSnapshot, err error) {
	reader, err := audio.Open(ctx)
	if err != nil {
		return snapshot, err
	}
	defer func() { err = errors.Join(err, reader.Close()) }()
	decoder := opus.NewDecoder(reader)
	return voice.ProducePlayback(ctx, job, maxPacketBytes, decoder.OpusFrame)
}
func validScratchPath(parent string) bool {
	return filepath.IsAbs(parent) && filepath.Clean(parent) == parent && parent != string(filepath.Separator)
}
func openScratch(parent string) (string, error) {
	if !validScratchPath(parent) {
		return "", errors.New("authenticated scratch directory must be an absolute clean non-root path")
	}
	stat, err := os.Lstat(parent)
	if err != nil {
		return "", err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("scratch mount is not a directory")
	}
	return os.MkdirTemp(parent, "music-*")
}
