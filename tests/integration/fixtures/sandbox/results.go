package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Reports contain observations, never verdicts about host enforcement. In
// particular, the last durable record before fatal task/OOM termination remains
// an intent, not a successful result. The parent must correlate container exit,
// cgroup events, project accounting, and its ownership journal.
type probeSession struct {
	mu         sync.Mutex
	file       *os.File
	sequence   int
	persistent string
	scratch    string
	artifact   string
}

type observation struct {
	Sequence int            `json:"sequence"`
	Time     string         `json:"time"`
	Probe    string         `json:"probe"`
	State    string         `json:"state"`
	Outcome  string         `json:"outcome"`
	Errno    int            `json:"errno,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

func canonicalDirectory(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
}

func newProbeSession(persistent, scratch string) (*probeSession, error) {
	if !canonicalDirectory(persistent) || !canonicalDirectory(scratch) || persistent == scratch {
		return nil, errors.New("invalid authenticated probe paths")
	}
	f, err := os.CreateTemp(persistent, "probe-results-*.ndjson")
	if err != nil {
		return nil, errors.New("private probe report creation failed")
	}
	return &probeSession{file: f, persistent: persistent, scratch: scratch}, nil
}

func safeOutcome(err error) (string, int) {
	switch {
	case err == nil:
		return "syscall-or-operation-returned", 0
	case errors.Is(err, context.Canceled):
		return "cancelled", 0
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline", 0
	default:
		var errno unix.Errno
		if errors.As(err, &errno) {
			return "syscall-error", int(errno)
		}
		return "operation-error", 0
	}
}

// Bounded append-only NDJSON: at most 128 records of at most 4096 bytes each.
// Failure to write (including persistent EDQUOT) cannot become a fabricated pass.
// Earlier synced intents remain usable; the host is the authority on termination.
func (p *probeSession) record(probe, state string, err error, data map[string]any) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil || p.sequence >= 128 {
		return
	}
	p.sequence++
	outcome, errno := safeOutcome(err)
	b, e := json.Marshal(observation{p.sequence, time.Now().UTC().Format(time.RFC3339Nano), probe, state, outcome, errno, data})
	if e != nil || len(b) >= 4096 {
		return
	}
	b = append(b, '\n')
	if _, e = p.file.Write(b); e == nil {
		_ = p.file.Sync()
	}
}

func (p *probeSession) initArtifact() error {
	f, err := os.CreateTemp(p.scratch, "probe-init-artifact-")
	if err != nil {
		p.record("init-artifact", "create", err, nil)
		return errors.New("fixture artifact creation failed")
	}
	p.artifact = f.Name()
	_, writeErr := f.WriteString("owned partial INIT fixture resource\n")
	syncErr, closeErr := f.Sync(), f.Close()
	p.record("init-artifact", "created-retained-until-stop-or-host-cleanup", writeErr, map[string]any{"path": p.artifact})
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("fixture artifact write failed")
	}
	return nil
}

func (p *probeSession) cleanupArtifact() {
	if p.artifact != "" {
		p.record("init-artifact", "stop-remove", os.Remove(p.artifact), nil)
		p.artifact = ""
	}
}

func (p *probeSession) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file != nil {
		_ = p.file.Close()
		p.file = nil
	}
}

// PLUGIN_UNIX_SOCKET_DIR is injected by the authenticated go-plugin runner and
// translated to the guest broker directory by bootstrapEnvironment. Do not use
// guessed mount aliases, TMPDIR, host socket paths, or unrelated environment.
func guestIPCDirectory() (string, error) {
	path := os.Getenv("PLUGIN_UNIX_SOCKET_DIR")
	if !canonicalDirectory(path) {
		return "", errors.New("runner broker directory is unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("runner broker directory is not a real directory")
	}
	return path, nil
}
