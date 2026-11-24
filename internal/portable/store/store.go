package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"modernc.org/sqlite"
)

const (
	applicationID = 0x43545032 // CTP2
	schemaVersion = 1
	pageBytes     = 4096
	maxSector     = 65536 // SQLite MAX_SECTOR_SIZE
	minMetadata   = 1 << 20
)

// Store limits each handle to one configured SQLite connection. Immediate
// transactions also serialize budget writers in separate Store handles.
type Store struct {
	db   *sql.DB
	path string
}

// MetadataFileBudget is the part of the installation's metadata allocation
// available to the caller for config, manifest and other non-SQLite files.
func MetadataFileBudget(metadataBytes int64) (int64, error) {
	_, overhead, err := sqliteBudget(metadataBytes)
	if err != nil {
		return 0, err
	}
	return metadataBytes - overhead, nil
}

func sqliteBudget(metadataBytes int64) (pages, peak int64, err error) {
	if metadataBytes < minMetadata {
		return 0, 0, fmt.Errorf("%w: metadata budget must be at least %d bytes", ErrInvalid, minMetadata)
	}
	// DELETE rollback journal, spilling disabled, no ATTACH and no VACUUM:
	// each original page is journaled at most once, with 8 bytes of framing.
	// Reserve two maximum-size sectors for the header/padding and keep one
	// quarter of the metadata allocation for files outside SQLite. Temp and
	// statement journals are in memory. WAL and SHM are never allowed.
	const fixed = 2 * maxSector
	const perPage = 2*pageBytes + 8
	pages = min((metadataBytes-metadataBytes/4-fixed)/perPage, 4294967294)
	return pages, fixed + pages*perPage, nil
}

// SQLiteFileBudget is the maximum logical length of a clean database file.
// SnapshotDatabase checks the page count and rollback sidecars before writing.
func SQLiteFileBudget(metadataBytes int64) (int64, error) {
	pages, _, err := sqliteBudget(metadataBytes)
	return pages * pageBytes, err
}

// Create initializes a fresh portable-v2 ledger in the approved, private
// installation directory. The caller holds the native installation guard and
// verifies ownership of the root and every path component before calling.
func Create(ctx context.Context, installationDir string, spec Installation) (*Store, error) {
	if !spec.InstallationIdentity.valid() || !validDigest(spec.PlanDigest) || spec.BudgetBytes <= 0 || spec.MetadataBytes > spec.BudgetBytes || spec.LogBytes < 0 || spec.LogBytes > spec.BudgetBytes-spec.MetadataBytes {
		return nil, ErrInvalid
	}
	pages, _, err := sqliteBudget(spec.MetadataBytes)
	if err != nil {
		return nil, err
	}
	path, err := databasePath(installationDir, true)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	s, err := connect(ctx, path, pages)
	if err != nil {
		return nil, err
	}
	err = s.write(ctx, func(tx *sql.Tx) error { return initialize(ctx, tx, spec) })
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

// Open checks the portable format before SQLite is allowed to open the
// database read/write. In particular it never opens a v1 database for recovery
// or creates a new database at a markerless or missing path.
func Open(ctx context.Context, installationDir string, expected InstallationIdentity) (*Store, error) {
	if !expected.valid() {
		return nil, ErrIdentity
	}
	path, err := databasePath(installationDir, false)
	if err != nil {
		return nil, err
	}
	if err := checkFormat(ctx, path); err != nil {
		return nil, err
	}
	s, err := connect(ctx, path, 0)
	if err != nil {
		return nil, err
	}
	record, err := s.Installation(ctx)
	err = errors.Join(err, s.Close())
	if err != nil {
		return nil, err
	}
	if record.InstallationIdentity != expected {
		return nil, ErrIdentity
	}
	pages, _, err := sqliteBudget(record.MetadataBytes)
	if err != nil {
		return nil, err
	}
	s, err = connect(ctx, path, pages)
	if err != nil {
		return nil, err
	}
	current, err := s.Installation(ctx)
	if err == nil && (current.InstallationIdentity != expected || current.MetadataBytes != record.MetadataBytes) {
		err = ErrIdentity
	}
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func databasePath(installationDir string, creating bool) (string, error) {
	if !filepath.IsAbs(installationDir) || filepath.Clean(installationDir) != installationDir || runtime.GOOS == "windows" && strings.HasPrefix(installationDir, `\\`) {
		return "", fmt.Errorf("%w: expected a canonical local installation directory", ErrInvalid)
	}
	root, err := os.Lstat(installationDir)
	if err != nil {
		return "", err
	}
	if !root.IsDir() || root.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && root.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%w: installation directory is not private", ErrIdentity)
	}
	path := filepath.Join(installationDir, DatabaseName)
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) && (creating || suffix != "") {
			continue
		}
		if err != nil {
			return "", err
		}
		if creating && suffix == "" {
			return "", os.ErrExist
		}
		if creating || suffix == "-wal" || suffix == "-shm" || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("%w: unexpected supervisor ledger file or sidecar", ErrIdentity)
		}
	}
	return path, nil
}

// Do not use os.Open/Close on the database outside SQLite: on Unix that can
// drop SQLite's fcntl locks held by another handle in this same process.
// The immutable read-only probe checks only stable format markers, not
// runtime metadata. The regular connection subsequently handles hot-journal
// recovery with SQLite's normal locks.
func checkFormat(ctx context.Context, path string) error {
	u := sqliteURL(path)
	u.RawQuery = "mode=ro&immutable=1"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	for pragma, expected := range map[string]int{"application_id": applicationID, "user_version": schemaVersion, "page_size": pageBytes} {
		var actual int
		if err := db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&actual); err != nil || actual != expected {
			return errors.Join(ErrFormat, err)
		}
	}
	return nil
}

func sqliteURL(path string) url.URL {
	uriPath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	return url.URL{Scheme: "file", Path: uriPath}
}

func connect(ctx context.Context, path string, pages int64) (*Store, error) {
	return connectMode(ctx, path, pages, false)
}

func connectMode(ctx context.Context, path string, pages int64, disposable bool) (*Store, error) {
	u := sqliteURL(path)
	q := u.Query()
	q.Set("mode", "rw")
	q.Set("_txlock", "immediate")
	for _, pragma := range []string{"busy_timeout(5000)", "synchronous(EXTRA)", "foreign_keys(ON)",
		"trusted_schema(OFF)", "cache_spill(OFF)", "temp_store(MEMORY)", "mmap_size(0)"} {
		q.Add("_pragma", pragma)
	}
	expectedJournal := "delete"
	if disposable {
		q.Add("_pragma", "journal_mode(OFF)")
		expectedJournal = "off"
	}
	if pages > 0 {
		q.Add("_pragma", "page_size(4096)")
		q.Add("_pragma", fmt.Sprintf("max_page_count(%d)", pages))
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || journal != expectedJournal {
		return nil, errors.Join(ErrFormat, err, db.Close())
	}
	if pages > 0 {
		var actual int64
		if err := db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&actual); err != nil || actual != pageBytes {
			return nil, errors.Join(ErrFormat, err, db.Close())
		}
		if err := db.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&actual); err != nil {
			return nil, errors.Join(err, db.Close())
		}
		if actual != pages {
			return nil, errors.Join(fmt.Errorf("%w: ledger exceeds metadata page capacity", ErrBudgetExceeded), db.Close())
		}
	}
	return &Store{db: db, path: path}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) write(ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return translate(err)
	}
	defer tx.Rollback()
	if err := operation(tx); err != nil {
		return translate(err)
	}
	return translate(tx.Commit())
}

func translate(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code()&255 == 13 { // SQLITE_FULL
		return fmt.Errorf("%w: SQLite metadata capacity: %w", ErrBudgetExceeded, err)
	}
	return err
}

func exactlyOne(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrState
	}
	return err
}

func newID() string {
	var b [16]byte
	rand.Read(b[:]) // crypto/rand.Read cannot return an error in the supported Go toolchain
	return hex.EncodeToString(b[:])
}

type rowReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type queryReader interface {
	rowReader
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}
type scanner interface{ Scan(...any) error }

func initialize(ctx context.Context, tx *sql.Tx, spec Installation) error {
	for _, statement := range schema {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO installation (
			singleton,format,id,owner,target,bundle_digest,engine_digest,plan_digest,budget_bytes,metadata_bytes,log_bytes,state,desired)
		VALUES (1,?,?,?,?,?,?,?,?,?,?,'INITIALIZING','STOPPED')`, Format, spec.ID, spec.Owner, spec.Target,
		spec.BundleDigest, spec.EngineDigest, spec.PlanDigest, spec.BudgetBytes, spec.MetadataBytes, spec.LogBytes)
	return err
}

var schema = [...]string{
	fmt.Sprintf("PRAGMA application_id=%d", applicationID),
	fmt.Sprintf("PRAGMA user_version=%d", schemaVersion),
	`CREATE TABLE epochs (
		id TEXT PRIMARY KEY NOT NULL,
		boot_id TEXT NOT NULL,
		pid INTEGER NOT NULL CHECK(pid>0),
		start_identity TEXT NOT NULL,
		worker_pending INTEGER NOT NULL DEFAULT 0 CHECK(worker_pending IN (0,1))
	) STRICT`,
	`CREATE TABLE installation (
		singleton INTEGER PRIMARY KEY CHECK(singleton=1),
		format TEXT NOT NULL CHECK(format='portable-v2'),
		id TEXT NOT NULL, owner TEXT NOT NULL, target TEXT NOT NULL,
		bundle_digest TEXT NOT NULL, engine_digest TEXT NOT NULL, plan_digest TEXT NOT NULL,
		budget_bytes INTEGER NOT NULL CHECK(budget_bytes>0),
		metadata_bytes INTEGER NOT NULL CHECK(metadata_bytes>0 AND metadata_bytes<=budget_bytes),
		log_bytes INTEGER NOT NULL CHECK(log_bytes>=0 AND log_bytes<=budget_bytes-metadata_bytes),
		state TEXT NOT NULL CHECK(state IN ('INITIALIZING','READY','UNINSTALLING','UNINSTALLED','PURGING','PURGED')),
		desired TEXT NOT NULL CHECK(desired IN ('RUNNING','STOPPED')),
		epoch_id TEXT REFERENCES epochs(id),
		config_revision TEXT NOT NULL DEFAULT '', config_digest TEXT NOT NULL DEFAULT '',
		purge_digest TEXT NOT NULL DEFAULT ''
	) STRICT`,
	`CREATE TABLE preparations (
		id TEXT PRIMARY KEY NOT NULL,
		epoch_id TEXT NOT NULL REFERENCES epochs(id),
		state TEXT NOT NULL CHECK(state IN ('WRITING','CLEANUP_PENDING')),
		max_bytes INTEGER NOT NULL CHECK(max_bytes>0)
	) STRICT`,
	`CREATE TABLE images (
		id TEXT PRIMARY KEY NOT NULL,
		epoch_id TEXT NOT NULL REFERENCES epochs(id),
		preparation_id TEXT NOT NULL,
		digest TEXT NOT NULL, engine_digest TEXT NOT NULL,
		state TEXT NOT NULL CHECK(state IN ('WRITING','PREPARED','PUBLISHED','CLEANUP_PENDING')),
		may_write INTEGER NOT NULL DEFAULT 1 CHECK(may_write IN (0,1)),
		max_bytes INTEGER NOT NULL CHECK(max_bytes>0)
	) STRICT`,
	`CREATE TABLE approvals (
		module_id TEXT PRIMARY KEY NOT NULL,
		image_id TEXT NOT NULL REFERENCES images(id),
		review_digest TEXT NOT NULL,
		record BLOB NOT NULL
	) STRICT`,
	`CREATE TABLE volumes (
		id TEXT PRIMARY KEY NOT NULL,
		module_id TEXT NOT NULL UNIQUE,
		uid INTEGER NOT NULL CHECK(uid>0), gid INTEGER NOT NULL CHECK(gid>0),
		native_id TEXT NOT NULL DEFAULT '',
		creation_run_id TEXT NOT NULL DEFAULT '',
		initialized INTEGER NOT NULL DEFAULT 0 CHECK(initialized IN (0,1)),
		max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 16777216 AND 70368744177664 AND max_bytes%16777216=0),
		CHECK (
			initialized=0 AND ((native_id='' AND creation_run_id='') OR (native_id<>'' AND creation_run_id<>'')) OR
			initialized=1 AND native_id<>'' AND creation_run_id=''
		)
	) STRICT`,
	`CREATE UNIQUE INDEX volume_native ON volumes(native_id) WHERE native_id<>''`,
	`CREATE TABLE run_identities (
		instance_id TEXT PRIMARY KEY NOT NULL,
		epoch_id TEXT NOT NULL REFERENCES epochs(id) ON DELETE CASCADE
	) STRICT`,
	`CREATE TABLE runs (
		id TEXT PRIMARY KEY NOT NULL,
		epoch_id TEXT NOT NULL REFERENCES epochs(id),
		instance_id TEXT NOT NULL UNIQUE,
		volume_id TEXT NOT NULL UNIQUE REFERENCES volumes(id),
		image_id TEXT NOT NULL REFERENCES images(id),
		config_revision TEXT NOT NULL,
		approval BLOB NOT NULL,
		state TEXT NOT NULL CHECK(state IN ('RESERVED','STARTING','RUNNING','UNKNOWN')),
		desired TEXT NOT NULL CHECK(desired IN ('RUNNING','STOPPED')),
		cleanup INTEGER NOT NULL DEFAULT 0 CHECK(cleanup IN (0,1)),
		launch_begun INTEGER NOT NULL DEFAULT 0 CHECK(launch_begun IN (0,1)),
		persistent_verified INTEGER NOT NULL DEFAULT 0 CHECK(persistent_verified IN (0,1)),
		engine_id TEXT NOT NULL DEFAULT '',
		egress_generation TEXT NOT NULL,
		egress_state TEXT NOT NULL CHECK(egress_state IN ('CLOSED','OPEN','SEALED')),
		scratch_bytes INTEGER NOT NULL CHECK(scratch_bytes BETWEEN 16777216 AND 70368744177664 AND scratch_bytes%16777216=0),
		log_bytes INTEGER NOT NULL CHECK(log_bytes>=0)
	) STRICT`,
	`CREATE UNIQUE INDEX run_engine ON runs(epoch_id,engine_id) WHERE engine_id<>''`,
	`CREATE TABLE backups (
		id TEXT PRIMARY KEY NOT NULL,
		epoch_id TEXT NOT NULL REFERENCES epochs(id),
		state TEXT NOT NULL CHECK(state IN ('WRITING','VERIFIED','CLEANUP_PENDING')),
		update_fence INTEGER NOT NULL CHECK(update_fence IN (0,1)),
		for_update INTEGER NOT NULL CHECK(for_update IN (0,1)),
		max_bytes INTEGER NOT NULL CHECK(max_bytes>0),
		sqlite_bytes INTEGER NOT NULL CHECK(sqlite_bytes>0),
		bundle_digest TEXT NOT NULL, engine_digest TEXT NOT NULL, plan_digest TEXT NOT NULL,
		config_revision TEXT NOT NULL, config_digest TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE backup_volumes (
		backup_id TEXT NOT NULL REFERENCES backups(id) ON DELETE CASCADE,
		volume_id TEXT NOT NULL REFERENCES volumes(id),
		max_bytes INTEGER NOT NULL,
		native_id TEXT NOT NULL,
		PRIMARY KEY(backup_id,volume_id)
	) WITHOUT ROWID, STRICT`,
	`CREATE TABLE backup_images (
		backup_id TEXT NOT NULL REFERENCES backups(id) ON DELETE CASCADE,
		image_id TEXT NOT NULL REFERENCES images(id),
		PRIMARY KEY(backup_id,image_id)
	) WITHOUT ROWID, STRICT`,
	`CREATE TABLE snapshot_origin (
		singleton INTEGER PRIMARY KEY CHECK(singleton=1),
		backup_id TEXT NOT NULL,
		epoch_id TEXT NOT NULL,
		state TEXT NOT NULL CHECK(state IN ('PENDING','BOUND','ACTIVE')),
		receipt_digest TEXT NOT NULL DEFAULT '',
		CHECK ((state='PENDING' AND receipt_digest='') OR (state IN ('BOUND','ACTIVE') AND receipt_digest<>''))
	) STRICT`,
	`CREATE TABLE snapshot_volumes (
		volume_id TEXT PRIMARY KEY NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
		digest TEXT NOT NULL,
		size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 16777216 AND 70368744177664 AND size_bytes%16777216=0)
	) STRICT`,
}
