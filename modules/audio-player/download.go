package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type attachment struct {
	URL, Filename string
	Size          int64
}

type attachmentDownloader struct {
	client    *http.Client
	transport *http.Transport
	limits    playerLimits
}

func newAttachmentDownloader(limits playerLimits) *attachmentDownloader {
	dialer := &net.Dialer{Timeout: limits.httpTimeout, KeepAlive: limits.httpTimeout}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		MaxIdleConns: limits.Workers, MaxIdleConnsPerHost: limits.Workers,
		MaxConnsPerHost: limits.Workers, IdleConnTimeout: limits.httpTimeout,
		TLSHandshakeTimeout: limits.httpTimeout, ResponseHeaderTimeout: limits.httpTimeout,
		MaxResponseHeaderBytes: 64 * 1024, DisableCompression: true,
	}
	client := &http.Client{Transport: transport, Timeout: limits.httpTimeout}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		req.Header.Del("Referer")
		if len(via) > *limits.MaxRedirects {
			return errors.New("attachment redirect limit exceeded")
		}
		return validateAttachmentURL(req.URL)
	}
	return &attachmentDownloader{client: client, transport: transport, limits: limits}
}

func (d *attachmentDownloader) close() { d.transport.CloseIdleConnections() }

func validateAttachmentURL(u *url.URL) error {
	if u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("attachment URL must be an absolute HTTP(S) URL without credentials or fragment")
	}
	return nil
}

// The URL is only an HTTP input. Destination enforcement, including DNS changes,
// redirects and IPv6, remains the real sandbox firewall's responsibility.
func (d *attachmentDownloader) DownloadAttachment(ctx context.Context, a attachment, dir *scratchDirectory) (file *scratchFile, err error) {
	if len(a.URL) > 8192 || len(a.Filename) > 512 || a.Size < 0 || a.Size > d.limits.MaxDownloadBytes {
		return nil, errors.New("attachment metadata exceeds configured limits")
	}
	u, err := url.Parse(a.URL)
	if err != nil {
		return nil, errors.New("attachment URL is invalid")
	}
	if err := validateAttachmentURL(u); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.limits.httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("cannot construct attachment request")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attachment fetch failed: %w", withoutURL(err))
	}
	defer func() {
		err = errors.Join(err, resp.Body.Close())
		if err != nil && file != nil {
			err = errors.Join(err, file.Remove())
			file = nil
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("attachment HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > d.limits.MaxDownloadBytes {
		return nil, errors.New("attachment Content-Length exceeds configured limit")
	}
	file, out, err := dir.create()
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, out.Close())
		if err != nil {
			err = errors.Join(err, file.Remove())
			file = nil
		}
	}()
	n, err := io.Copy(out, io.LimitReader(resp.Body, d.limits.MaxDownloadBytes+1))
	if err != nil {
		return file, fmt.Errorf("attachment body read failed: %w", withoutURL(err))
	}
	if n > d.limits.MaxDownloadBytes {
		return file, errors.New("attachment actual bytes exceed configured limit")
	}
	if n == 0 {
		return file, errors.New("attachment body is empty")
	}
	if err = ctx.Err(); err != nil {
		return file, err
	}
	return file, nil
}

func withoutURL(err error) error {
	var remote *url.Error
	if errors.As(err, &remote) {
		return remote.Err
	}
	return err
}

func isAudioFile(filename string) bool {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac", ".opus", ".webm":
		return true
	default:
		return false
	}
}

// os.Root confines filesystem operations even if a symlink is introduced. Every
// child name comes from cryptographic randomness, never attachment metadata.
// Each module removes only its generated subtree of the authenticated INIT scratch directory.
type scratchSpace struct {
	root       *os.Root
	parent     *os.Root
	name, path string
	mu         sync.Mutex
	closed     bool
}

type scratchDirectory struct {
	owner      *scratchSpace
	root       *os.Root
	name, path string
}
type scratchFile struct {
	dir        *scratchDirectory
	name, path string
}

func randomName() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func openScratch(path string) (*scratchSpace, error) {
	parent, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	name, err := randomName()
	if err != nil {
		parent.Close()
		return nil, err
	}
	name = "player-" + name
	if err := parent.Mkdir(name, 0700); err != nil {
		parent.Close()
		return nil, err
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		parent.RemoveAll(name)
		parent.Close()
		return nil, err
	}
	return &scratchSpace{root: root, parent: parent, name: name, path: filepath.Join(path, name)}, nil
}

func (s *scratchSpace) directory() (*scratchDirectory, error) {
	name, err := randomName()
	if err != nil {
		return nil, err
	}
	if err := s.root.Mkdir(name, 0700); err != nil {
		return nil, err
	}
	root, err := s.root.OpenRoot(name)
	if err != nil {
		s.root.RemoveAll(name)
		return nil, err
	}
	return &scratchDirectory{owner: s, root: root, name: name, path: filepath.Join(s.path, name)}, nil
}

func (d *scratchDirectory) create() (*scratchFile, *os.File, error) {
	name, err := randomName()
	if err != nil {
		return nil, nil, err
	}
	file, err := d.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, nil, err
	}
	return &scratchFile{dir: d, name: name, path: filepath.Join(d.path, name)}, file, nil
}
func (f *scratchFile) Remove() error {
	err := f.dir.root.Remove(f.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func (d *scratchDirectory) Close() error {
	return errors.Join(d.root.Close(), d.owner.root.RemoveAll(d.name))
}
func (s *scratchSpace) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	err := errors.Join(s.root.Close(), s.parent.RemoveAll(s.name), s.parent.Close())
	s.closed = true
	return err
}

// Kept separate from event contexts so workers never retain a delivery work-ref.
func cleanupContext(timeout time.Duration, deadline time.Time) (context.Context, context.CancelFunc) {
	if !deadline.IsZero() && time.Until(deadline) < timeout {
		return context.WithDeadline(context.Background(), deadline)
	}
	return context.WithTimeout(context.Background(), timeout)
}
