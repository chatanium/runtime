//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

type BootEphemeralRecord struct {
	Path              string `json:"path"`
	BootID            string `json:"boot_id"`
	DirectoryRecordID string `json:"directory_record_id"`
	Dev               uint64 `json:"dev"`
	Ino               uint64 `json:"ino"`
	FilesystemType    int64  `json:"filesystem_type"`
}

func (s *Store) bootEphemeralPath(ctx context.Context, path string) error {
	m, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path != m.Paths.RunRoot && path != filepath.Join(m.Paths.RunRoot, "netns") && path != filepath.Join(m.Paths.RunRoot, "instances") {
		return invalid("ephemeral boot evidence is limited to installed run root, netns and instances")
	}
	return nil
}
func (s *Store) BootEphemeral(ctx context.Context, path string) (BootEphemeralRecord, error) {
	var r BootEphemeralRecord
	if err := s.bootEphemeralPath(ctx, path); err != nil {
		return r, err
	}
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "boot_ephemeral:"+path).Scan(&raw); err != nil {
		return r, err
	}
	if err := gvxcontract.DecodeStrict(raw, 64<<10, 8, &r); err != nil {
		return r, err
	}
	if r.Path != path || r.BootID == "" || !validLedgerID(r.DirectoryRecordID) || r.Dev == 0 || r.Ino == 0 || r.FilesystemType != unix.TMPFS_MAGIC {
		return r, errors.New("invalid durable boot ephemeral evidence")
	}
	return r, nil
}

// RecordBootEphemeral records an already-probed owned tmpfs directory. It never
// authorizes recreation; the root coordinator must prove old-boot disappearance
// and journal the new exclusive creation before recording the new observation.
func (s *Store) RecordBootEphemeral(ctx context.Context, r BootEphemeralRecord) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if err := s.bootEphemeralPath(ctx, r.Path); err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if r.BootID != strings.TrimSpace(string(boot)) || r.Dev == 0 || r.Ino == 0 || r.FilesystemType != unix.TMPFS_MAGIC {
		return invalid("boot ephemeral evidence requires current native tmpfs identity")
	}
	record, err := s.Provision(ctx, r.DirectoryRecordID)
	if err != nil {
		return err
	}
	if record.Kind != "directory" || record.Identity != r.Path || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" || !record.ProductCreated || record.ExistedBefore {
		return errors.New("boot ephemeral evidence lacks live owned directory observation")
	}
	var observed ProvisionProperties
	if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
		return err
	}
	if observed.Path != r.Path || observed.Dev != r.Dev || observed.Ino != r.Ino || observed.UID != 0 || observed.Volume != nil {
		return errors.New("boot ephemeral evidence differs from native observed directory")
	}
	previous, err := s.BootEphemeral(ctx, r.Path)
	if err == nil {
		prior, err := s.Provision(ctx, previous.DirectoryRecordID)
		if err != nil {
			return err
		}
		if prior.CleanupState == "COMPLETE" {
			return errors.New("completed directory removal cannot authorize ephemeral resurrection")
		}
		if previous.BootID == r.BootID && (previous.Dev != r.Dev || previous.Ino != r.Ino) {
			return errors.New("same-boot ephemeral directory identity replacement")
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", "boot_ephemeral:"+r.Path, raw)
	return err
}
func (r *MetadataReader) BootEphemeral(ctx context.Context, path string) (BootEphemeralRecord, error) {
	return r.store.BootEphemeral(ctx, path)
}
