//go:build linux

package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

type sqliteBackupReceipt struct {
	IntentID     string `json:"intent_id"`
	ProductID    string `json:"product_id"`
	Path         string `json:"path"`
	Stage        string `json:"stage"`
	BaseRevision string `json:"base_revision"`
	State        string `json:"state"`
	Dev          uint64 `json:"dev"`
	Ino          uint64 `json:"ino"`
	SizeBytes    int64  `json:"size_bytes"`
	Digest       string `json:"digest"`
}

func (s *Store) saveSQLiteBackupReceipt(ctx context.Context, r sqliteBackupReceipt) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", "sqlite_backup:"+r.IntentID, raw)
	return err
}
func openPinnedSQLiteBackup(parent *os.File, name string, r sqliteBackupReceipt) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "owned-sqlite-snapshot")
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || uint64(stat.Dev) != r.Dev || stat.Ino != r.Ino {
		file.Close()
		return nil, errors.New("SQLite snapshot native identity or protection changed")
	}
	return file, nil
}
func sqliteBackupFileDigest(file *os.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}
func validateSQLiteBackupDatabase(ctx context.Context, path, product, base string) error {
	locator := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", locator.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var check string
	if err = db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return errors.New("SQLite snapshot integrity proof failed")
	}
	for key, want := range map[string]string{"format": "chatanium-gvx", "format_version": "1", "schema_version": "1"} {
		var got string
		if err = db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&got); err != nil {
			return err
		}
		if got != want {
			return errors.New("SQLite snapshot format changed")
		}
	}
	var raw []byte
	if err = db.QueryRowContext(ctx, "SELECT manifest FROM runtime_installations WHERE id=?", product).Scan(&raw); err != nil {
		return err
	}
	var manifest InstallationManifest
	if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &manifest); err != nil {
		return err
	}
	if manifest.RuntimeInstallationID != product || manifest.ActiveRevision != base || manifest.PendingRevision != "" || manifest.DesiredRunState != "STOPPED" {
		return errors.New("SQLite snapshot is not the original stopped base installation")
	}
	return nil
}
func verifySQLiteBackupFile(ctx context.Context, parent *os.File, name string, r sqliteBackupReceipt) error {
	file, err := openPinnedSQLiteBackup(parent, name, r)
	if err != nil {
		return err
	}
	defer file.Close()
	digest, size, err := sqliteBackupFileDigest(file)
	if err != nil {
		return err
	}
	if size != r.SizeBytes || digest != r.Digest {
		return errors.New("SQLite snapshot content differs from durable receipt")
	}
	return validateSQLiteBackupDatabase(ctx, filepath.Join(filepath.Dir(r.Path), name), r.ProductID, r.BaseRevision)
}
func (s *Store) backupSQLite(ctx context.Context, path string) error {
	if err := s.AssertRemovable(ctx); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return invalid("backup destination must be canonical absolute path")
	}
	parent, err := trustedDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	records, err := s.ObjectProvisions(ctx, "config", path)
	if err != nil {
		return err
	}
	var intent ProvisionRecord
	var desired ProvisionProperties
	for _, record := range records {
		if record.CleanupState == "COMPLETE" || !record.ProductCreated || record.ExistedBefore {
			continue
		}
		var p ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &p); err != nil {
			return err
		}
		if p.Path != path || p.Source != filepath.Join(s.dir, "supervisor.sqlite") || p.Revision == "" {
			continue
		}
		if intent.ID != "" {
			return errors.New("ambiguous SQLite backup creation intent")
		}
		intent, desired = record, p
	}
	if intent.ID == "" {
		return errors.New("SQLite backup destination lacks exact original durable intent")
	}
	receipt := sqliteBackupReceipt{IntentID: intent.ID, ProductID: s.productID, Path: path, Stage: path + ".gvx-snapshot-" + intent.ID, BaseRevision: desired.Revision, State: "INTENT"}
	var raw []byte
	err = s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "sqlite_backup:"+intent.ID).Scan(&raw)
	if err == nil {
		var saved sqliteBackupReceipt
		if err = gvxcontract.DecodeStrict(raw, 64<<10, 8, &saved); err != nil {
			return err
		}
		if saved.IntentID != receipt.IntentID || saved.ProductID != receipt.ProductID || saved.Path != receipt.Path || saved.Stage != receipt.Stage || saved.BaseRevision != receipt.BaseRevision {
			return errors.New("SQLite backup receipt binding changed")
		}
		receipt = saved
	} else if errors.Is(err, sql.ErrNoRows) {
		if err = s.saveSQLiteBackupReceipt(ctx, receipt); err != nil {
			return err
		}
	} else {
		return err
	}
	switch receipt.State {
	case "INTENT", "PINNED", "READY", "PUBLISHED":
	default:
		return errors.New("unknown SQLite backup replay state")
	}
	if receipt.State == "PUBLISHED" {
		return verifySQLiteBackupFile(ctx, parent, filepath.Base(path), receipt)
	}
	if receipt.State == "INTENT" {
		var final unix.Stat_t
		if err = unix.Fstatat(int(parent.Fd()), filepath.Base(path), &final, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return errors.New("unobserved SQLite backup destination already exists")
		} else if !errors.Is(err, unix.ENOENT) {
			return err
		}
		fd, err := unix.Openat(int(parent.Fd()), filepath.Base(receipt.Stage), unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "new-sqlite-snapshot")
		var stat unix.Stat_t
		err = unix.Fstat(fd, &stat)
		if err == nil {
			err = file.Sync()
		}
		err = errors.Join(err, file.Close())
		if err != nil {
			return err
		}
		if err = parent.Sync(); err != nil {
			return err
		}
		receipt.Dev, receipt.Ino, receipt.State = uint64(stat.Dev), stat.Ino, "PINNED"
		if err = s.saveSQLiteBackupReceipt(ctx, receipt); err != nil {
			return err
		}
	}
	if receipt.State == "PINNED" {
		manifest, err := s.Installation(ctx)
		if err != nil {
			return err
		}
		if manifest.ActiveRevision != receipt.BaseRevision || manifest.PendingRevision != "" || manifest.DesiredRunState != "STOPPED" {
			return errors.New("SQLite backup cannot resnapshot a changed release")
		}
		file, err := openPinnedSQLiteBackup(parent, filepath.Base(receipt.Stage), receipt)
		if err != nil {
			return err
		}
		if err = file.Truncate(0); err == nil {
			err = file.Sync()
		}
		err = errors.Join(err, file.Close())
		if err != nil {
			return err
		}
		if _, err = s.db.ExecContext(ctx, "VACUUM INTO ?", receipt.Stage); err != nil {
			return err
		}
		file, err = openPinnedSQLiteBackup(parent, filepath.Base(receipt.Stage), receipt)
		if err != nil {
			return err
		}
		receipt.Digest, receipt.SizeBytes, err = sqliteBackupFileDigest(file)
		if err == nil {
			err = file.Sync()
		}
		err = errors.Join(err, file.Close())
		if err != nil {
			return err
		}
		if err = validateSQLiteBackupDatabase(ctx, receipt.Stage, receipt.ProductID, receipt.BaseRevision); err != nil {
			return err
		}
		if err = parent.Sync(); err != nil {
			return err
		}
		receipt.State = "READY"
		if err = s.saveSQLiteBackupReceipt(ctx, receipt); err != nil {
			return err
		}
	}
	if err = verifySQLiteBackupFile(ctx, parent, filepath.Base(receipt.Stage), receipt); err != nil {
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
			return err
		}
		if err = verifySQLiteBackupFile(ctx, parent, filepath.Base(path), receipt); err != nil {
			return err
		}
	} else {
		if err = unix.Renameat2(int(parent.Fd()), filepath.Base(receipt.Stage), int(parent.Fd()), filepath.Base(path), unix.RENAME_NOREPLACE); err != nil {
			return err
		}
	}
	if err = parent.Sync(); err != nil {
		return err
	}
	receipt.State = "PUBLISHED"
	return s.saveSQLiteBackupReceipt(ctx, receipt)
}
