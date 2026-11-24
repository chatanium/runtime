package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"modernc.org/sqlite"
)

// SnapshotDatabase creates the SQLite member of a current, admitted backup.
// The caller creates and holds the verified private backup directory and
// handles hashing, synchronization, and cleanup of an interrupted copy.
// The destination is exclusively created at backups/<id>/supervisor.sqlite.
func (s *Store) SnapshotDatabase(ctx context.Context, epochID, backupID string) error {
	if !lowerHex(backupID, 32) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		_, b, err := snapshotBackup(ctx, tx, epochID, backupID)
		if err != nil {
			return err
		}

		// The immediate transaction took a reservation on the source database
		// and resolved a hot rollback journal through SQLite. Keep it for the
		// entire backup to exclude RequestStop and any other ledger writer.
		var pages, size int64
		if err := tx.QueryRowContext(ctx, `PRAGMA main.page_count`).Scan(&pages); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `PRAGMA main.page_size`).Scan(&size); err != nil {
			return err
		}
		if pages <= 0 || size != pageBytes || pages > b.SQLiteBytes/pageBytes || b.SQLiteBytes > b.MaxBytes {
			return fmt.Errorf("%w: backup SQLite page ceiling", ErrBudgetExceeded)
		}
		if err := noSQLiteSidecars(s.path); err != nil {
			return err
		}

		path, err := s.backupDatabasePath(backupID, true)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := copySQLiteSnapshot(ctx, s.path, path, pages); err != nil {
			return err
		}
		file, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !file.Mode().IsRegular() || file.Size() != pages*pageBytes {
			return ErrIdentity
		}
		return noSQLiteSidecars(path)
	})
}

func snapshotBackup(ctx context.Context, tx *sql.Tx, epochID, backupID string) (InstallationRecord, Backup, error) {
	install, err := requireEpoch(ctx, tx, epochID)
	if err != nil {
		return InstallationRecord{}, Backup{}, err
	}
	if err := requireStopped(ctx, tx, install); err != nil {
		return InstallationRecord{}, Backup{}, err
	}
	b, err := scanBackup(tx.QueryRowContext(ctx, backupQuery+` AND b.id=?`, backupID))
	if err != nil {
		return InstallationRecord{}, Backup{}, err
	}
	if b.EpochID != epochID || b.State != Writing || b.InstallationIdentity != install.InstallationIdentity ||
		b.PlanDigest != install.PlanDigest || b.ConfigRevision != install.ConfigRevision || b.ConfigDigest != install.ConfigDigest {
		return InstallationRecord{}, Backup{}, ErrApprovalMismatch
	}
	return install, b, nil
}

func (s *Store) backupDatabasePath(backupID string, creating bool) (string, error) {
	root := filepath.Join(filepath.Dir(s.path), "backups")
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrIdentity
	}
	return databasePath(filepath.Join(root, backupID), creating)
}

func noSQLiteSidecars(path string) error {
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		_, err := os.Lstat(path + suffix)
		if err == nil {
			return fmt.Errorf("%w: SQLite sidecar %s remains", ErrCleanupPending, suffix)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func copySQLiteSnapshot(ctx context.Context, source, destination string, pages int64) (result error) {
	// Use SQLite itself to read the source. An unrelated native open/close
	// on the source inode could drop fcntl locks for all same-process handles.
	u := sqliteURL(source)
	u.RawQuery = "mode=ro"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, db.Close()) }()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, conn.Close()) }()

	out := sqliteURL(destination)
	q := out.Query()
	q.Set("mode", "rw")
	// Only the disposable, O_EXCL destination has no rollback journal. It
	// has no prior contents to preserve and cannot be verified after an
	// interrupted copy. Avoid a second uncharged disk file during backup.
	q.Add("_pragma", "journal_mode(OFF)")
	q.Add("_pragma", "synchronous(EXTRA)")
	q.Add("_pragma", "page_size(4096)")
	q.Add("_pragma", fmt.Sprintf("max_page_count(%d)", pages))
	out.RawQuery = q.Encode()

	return conn.Raw(func(raw any) (err error) {
		c, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return ErrFormat
		}
		b, err := c.NewBackup(out.String())
		if err != nil {
			return err
		}
		finished := false
		defer func() {
			if !finished {
				err = errors.Join(err, b.Finish())
			}
		}()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err := b.Step(256)
			if err != nil {
				return err
			}
			if int64(b.PageCount()) != pages {
				return ErrIdentity
			}
			if !more {
				finished = true
				dst, err := b.Commit()
				if err != nil {
					return err
				}
				return dst.Close()
			}
		}
	})
}
