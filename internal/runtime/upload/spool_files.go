// Package upload implements the backend-neutral, instance-owned core file store.
package upload

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// spool holds the directory and an exclusive process lock. The lock file is
// never unlinked: replacing it would permit two independent owners.
type spool struct {
	directory *os.File
	lock      *os.File
	portable  bool
}

// No references survive a worker epoch. The sole portable slot cannot be reused
// until we have exclusive ownership and have removed any known-owned file.
func (s *spool) recover(ctx context.Context, portable bool) error {
	if portable {
		// The owner file plus at most one upload must fit. Read the entire
		// namespace before mutating it; extra artifacts block startup.
		entries, err := s.directory.ReadDir(3)
		if err != nil && err != io.EOF {
			return internal()
		}
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		var orphan string
		var owner bool
		for _, entry := range entries {
			name := entry.Name()
			if name == ".owner" {
				owner = true
				continue
			}
			if orphan != "" || !spoolName(name) || name != strings.ToLower(name) {
				return invalid()
			}
			orphan = name
		}
		if !owner {
			return invalid()
		}
		if orphan != "" {
			return s.removeOrphan(orphan)
		}
		return nil
	}
	for {
		entries, err := s.directory.ReadDir(1)
		if len(entries) == 0 {
			if err != nil && err != io.EOF {
				return internal()
			}
			return nil
		}
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		name := entries[0].Name()
		if name == ".owner" {
			continue
		}
		if !spoolName(name) {
			return invalid()
		}
		if err := s.removeOrphan(name); err != nil {
			return err
		}
	}
}

func spoolName(name string) bool {
	if !strings.HasPrefix(name, "file-") || len(name) != len("file-")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, "file-"))
	return err == nil
}

func newID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", internal()
	}
	return hex.EncodeToString(bytes[:]), nil
}

func (s *spool) close() error {
	var result error
	if s.lock != nil {
		if err := s.lock.Close(); err != nil {
			result = internal()
		}
	}
	if s.directory != nil {
		if err := s.directory.Close(); err != nil {
			result = internal()
		}
	}
	return result
}
