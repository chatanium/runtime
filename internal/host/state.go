//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	sqlite "modernc.org/sqlite"
)

// SQLite v1.61.0 requires its documented modernc.org/libc v1.79.0 pairing.
// A single physical connection applies the PRAGMAs to every transaction.
type Store struct {
	db                *sql.DB
	dir, productID    string
	mu                sync.Mutex
	manifestMu        sync.Mutex
	installationLease *InstallationLease
	gate              *ManagementGuard
	gateOwned         bool
	terminalOnly      bool
	closed            bool
	sourceControl     TerminalNativeIdentity
	sourceDatabase    TerminalNativeIdentity
	incarnation       string
}

var errInstanceAbsent = errors.New("instance absent from authoritative journal")

func openStoreDB(ctx context.Context, dir string, create bool, g *ManagementGuard) (*Store, error) {
	return openStoreDBMode(ctx, dir, create, g, false)
}
func openStoreDBMode(ctx context.Context, dir string, create bool, g *ManagementGuard, terminal bool) (*Store, error) {
	if err := g.require(terminal); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(dir, "supervisor.sqlite")}
	hasFence := false
	if !create {
		probeURL := u
		probeURL.RawQuery = "mode=ro"
		probe, err := sql.Open("sqlite", probeURL.String())
		if err != nil {
			return nil, err
		}
		var format string
		var version int
		var formatVersion int
		versionErr := probe.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='format_version'").Scan(&formatVersion)
		formatErr := probe.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='format'").Scan(&format)
		schemaErr := probe.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='schema_version'").Scan(&version)
		var fence string
		fenceErr := probe.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='terminal_fence'").Scan(&fence)
		var incarnation string
		incarnationErr := probe.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='incarnation'").Scan(&incarnation)
		var activeProbe string
		activeProbeErr := probe.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='terminal_probe_active'").Scan(&activeProbe)
		if keepErr := keepStoreWAL(ctx, probe); keepErr != nil {
			probe.Close()
			return nil, keepErr
		}
		probe.Close()
		if formatErr != nil || schemaErr != nil || versionErr != nil || format != "chatanium-gvx" || formatVersion != 1 || version != 1 {
			return nil, errors.New("unsupported or markerless installation; explicit migration required")
		}
		if incarnationErr != nil || !safeID(incarnation) {
			return nil, errors.New("installation lacks guarded incarnation; explicit migration required")
		}
		hasFence = fenceErr == nil
		if hasFence && !terminal {
			return nil, ErrTerminalPurge
		}
		if fenceErr != nil && !errors.Is(fenceErr, sql.ErrNoRows) {
			return nil, fenceErr
		}
		if activeProbeErr != nil && !errors.Is(activeProbeErr, sql.ErrNoRows) {
			return nil, activeProbeErr
		}
		if terminal && !hasFence && errors.Is(activeProbeErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		if !terminal && activeProbeErr == nil && g.Mode() != ManagementExclusive {
			return nil, ErrTerminalPurge
		}
		u.RawQuery = "mode=rw"
	}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, dir: dir, gate: g, gateOwned: g.Mode() == ManagementShared, terminalOnly: hasFence}
	s.sourceControl, err = terminalObserve(dir, false)
	if err != nil {
		db.Close()
		return nil, err
	}
	s.sourceDatabase, err = terminalObserve(filepath.Join(dir, "supervisor.sqlite"), false)
	if err != nil {
		db.Close()
		return nil, err
	}
	if s.sourceControl.Absent || s.sourceControl.Kind != "directory" || s.sourceDatabase.Absent || s.sourceDatabase.Kind != "file" || s.sourceDatabase.Links != 1 || s.sourceControl.UID != g.uid || s.sourceDatabase.UID != g.uid {
		db.Close()
		return nil, errors.New("guarded Store source native identity is unsafe")
	}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = keepStoreWAL(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (j *Store) initialize(ctx context.Context) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = initializeSchemaTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}
func initializeSchemaTx(ctx context.Context, tx *sql.Tx) error {
	for _, q := range []string{
		`CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)`,
		`INSERT INTO metadata VALUES('format','chatanium-gvx'),('format_version','1'),('schema_version','1'),('next_project','1')`,
		`CREATE TABLE runtime_installations(id TEXT PRIMARY KEY,manifest BLOB NOT NULL)`,
		`CREATE TABLE revisions(id TEXT PRIMARY KEY,record BLOB NOT NULL)`,
		`CREATE TABLE approved_image_candidates(revision TEXT NOT NULL REFERENCES revisions(id),module TEXT NOT NULL,selector TEXT NOT NULL,image TEXT NOT NULL REFERENCES image_records(id),binding BLOB NOT NULL,policy BLOB NOT NULL,PRIMARY KEY(revision,module,selector))`,
		`CREATE TABLE provisioning_ledger(id TEXT PRIMARY KEY,kind TEXT NOT NULL,identity TEXT NOT NULL,record BLOB NOT NULL)`,
		`CREATE INDEX provisioning_identity ON provisioning_ledger(kind,identity)`,
		`CREATE TABLE installations(module_id TEXT PRIMARY KEY,storage_key TEXT NOT NULL UNIQUE,project INTEGER NOT NULL UNIQUE,uid INTEGER NOT NULL,gid INTEGER NOT NULL,image TEXT NOT NULL,config_revision TEXT NOT NULL,approval_revision TEXT NOT NULL)`,
		`CREATE TABLE runtime_epochs(id TEXT PRIMARY KEY,boot_id TEXT NOT NULL,pid INTEGER NOT NULL,start_identity TEXT NOT NULL,started INTEGER NOT NULL,state TEXT NOT NULL)`,
		`CREATE TABLE instances(id TEXT PRIMARY KEY,module_id TEXT NOT NULL REFERENCES installations(module_id),epoch TEXT NOT NULL REFERENCES runtime_epochs(id),lease TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',cleanup TEXT NOT NULL,cleanup_errors TEXT NOT NULL DEFAULT '',started INTEGER NOT NULL,ended INTEGER)`,
		`CREATE TABLE retired_instances(id TEXT PRIMARY KEY,epoch TEXT NOT NULL REFERENCES runtime_epochs(id))`,
		`CREATE UNIQUE INDEX exclusive_installation ON instances(module_id) WHERE cleanup!='COMPLETE'`,
		`CREATE TABLE resource_claims(instance TEXT NOT NULL REFERENCES instances(id),kind TEXT NOT NULL,identity TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(instance,kind))`,
		`CREATE TABLE persistent_provisions(module_id TEXT PRIMARY KEY REFERENCES installations(module_id),state TEXT NOT NULL,bytes INTEGER NOT NULL,inodes INTEGER NOT NULL)`,
		`CREATE TABLE create_submissions(instance TEXT NOT NULL REFERENCES instances(id),kind TEXT NOT NULL CHECK(kind IN ('service','network')),identity TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('SUBMITTED','OBSERVED','REJECTED')),object_id TEXT NOT NULL,rejection TEXT NOT NULL DEFAULT '',CHECK(state!='REJECTED' OR (object_id='' AND rejection!='')),PRIMARY KEY(instance,kind),UNIQUE(kind,identity))`,
		`CREATE TABLE unit_observations(instance TEXT PRIMARY KEY REFERENCES instances(id),generation TEXT NOT NULL UNIQUE,invocation TEXT NOT NULL UNIQUE,record BLOB NOT NULL)`,
		`CREATE TABLE network_records(instance TEXT PRIMARY KEY REFERENCES instances(id),generation TEXT NOT NULL UNIQUE,record BLOB NOT NULL)`,
		`CREATE TABLE native_endpoints(instance TEXT PRIMARY KEY REFERENCES instances(id),record BLOB NOT NULL,transfer_state TEXT NOT NULL DEFAULT 'PINNED',transports_closed INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE guest_root_intents(instance TEXT PRIMARY KEY REFERENCES instances(id),intent TEXT NOT NULL UNIQUE,record BLOB NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE image_records(id TEXT PRIMARY KEY,record BLOB NOT NULL)`,
		`CREATE TABLE cache_generations(id TEXT PRIMARY KEY,image TEXT NOT NULL REFERENCES image_records(id),record BLOB NOT NULL)`,
		`CREATE TABLE generation_references(kind TEXT NOT NULL CHECK(kind IN ('live','recovery','preparation')),id TEXT NOT NULL,claim TEXT NOT NULL,PRIMARY KEY(kind,id,claim))`,
		`CREATE TABLE storage_claims(id TEXT PRIMARY KEY,kind TEXT NOT NULL,bytes INTEGER NOT NULL,inodes INTEGER NOT NULL,project INTEGER NOT NULL UNIQUE,state TEXT NOT NULL)`,
		`CREATE TABLE storage_generations(claim TEXT NOT NULL REFERENCES storage_claims(id),generation TEXT NOT NULL,PRIMARY KEY(claim,generation))`,
	} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO metadata VALUES('incarnation',?)", newID())
	return err
}
func nextProject(ctx context.Context, tx *sql.Tx) (uint32, error) {
	var n uint64
	if err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='next_project'").Scan(&n); err != nil {
		return 0, err
	}
	if n == 0 || n > uint64(^uint32(0)) {
		return 0, errors.New("XFS project ID space exhausted")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE metadata SET value=? WHERE key='next_project'", n+1); err != nil {
		return 0, err
	}
	return uint32(n), nil
}
func (j *Store) epoch(ctx context.Context, id, boot string, pid int, start string) error {
	if err := j.requireLease(); err != nil {
		return err
	}
	_, err := j.db.ExecContext(ctx, "INSERT INTO runtime_epochs VALUES(?,?,?,?,?, 'LIVE')", id, boot, pid, start, time.Now().UnixNano())
	return err
}
func (j *Store) allocate(ctx context.Context, epoch string, s LaunchSpec, c SupervisorConfig) (Lease, error) {
	if err := j.requireLease(); err != nil {
		return Lease{}, err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return Lease{}, err
	}
	defer tx.Rollback()
	var retired int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM retired_instances WHERE id=?", s.InstanceID).Scan(&retired); err != nil {
		return Lease{}, err
	}
	if retired != 0 {
		return Lease{}, invalid("instance identifier was already retired")
	}
	var key string
	var persistent uint32
	var uid, gid uint32
	err = tx.QueryRowContext(ctx, "SELECT storage_key,project,uid,gid FROM installations WHERE module_id=?", s.ModuleID).Scan(&key, &persistent, &uid, &gid)
	if errors.Is(err, sql.ErrNoRows) {
		key = newID()
		persistent, err = nextProject(ctx, tx)
		if err != nil {
			return Lease{}, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO installations(module_id,storage_key,project,uid,gid,image,config_revision,approval_revision) VALUES(?,?,?,?,?,?,?,?)", s.ModuleID, key, persistent, s.UID, s.GID, s.ImageDigest, s.ConfigRevision, s.ApprovalRevision)
		if err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO persistent_provisions(module_id,state,bytes,inodes) VALUES(?,'RESERVED',0,0)", s.ModuleID)
		}
	} else if err == nil {
		if uid != s.UID || gid != s.GID {
			return Lease{}, invalid("installation UID/GID cannot change while retaining persistent data")
		}
		_, err = tx.ExecContext(ctx, "UPDATE installations SET image=?,config_revision=?,approval_revision=? WHERE module_id=?", s.ImageDigest, s.ConfigRevision, s.ApprovalRevision, s.ModuleID)
	}
	if err != nil {
		return Lease{}, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM instances WHERE module_id=? AND cleanup!='COMPLETE'", s.ModuleID).Scan(&active); err != nil {
		return Lease{}, err
	}
	if active != 0 {
		return Lease{}, failure("MODULE_ALREADY_ACTIVE", errors.New("installation remains owned"))
	}
	scratch, err := nextProject(ctx, tx)
	if err != nil {
		return Lease{}, err
	}
	lease := Lease{Ownership: Ownership{RuntimeInstallationID: j.productID, InstallationID: key, EpochID: epoch, InstanceID: s.InstanceID}, Spec: s, PersistentPath: filepath.Join(c.StorageRoot, "persistent", key), ScratchPath: filepath.Join(c.StorageRoot, "instances", s.InstanceID, "scratch"), IPCPath: filepath.Join(c.StorageRoot, "instances", s.InstanceID, "ipc"), LogPath: filepath.Join(c.StorageRoot, "instances", s.InstanceID, "logs"), PersistentProject: persistent, ScratchProject: scratch, SocketGID: c.RuntimeGID, SandboxUID: c.Sandbox.UID, SandboxGID: c.Sandbox.GID, NetworkGeneration: newID(), Topology: NetworkNone}
	lease.BootstrapPath = filepath.Join(c.StorageRoot, "instances", s.InstanceID, "bootstrap")
	if s.InitialEgress == EgressPublicInternet {
		lease.Topology = c.PublicProfile
		if lease.Topology != NetworkPublicV4 && lease.Topology != NetworkPublicDual {
			return Lease{}, invalid("approved public family profile is missing")
		}
	}
	if err = j.resolveLeaseImage(ctx, tx, &lease); err != nil {
		return Lease{}, err
	}
	if c.StartupTimeout <= 0 {
		return Lease{}, invalid("finite startup timeout required")
	}
	bootNS, err := bootTimeNS()
	if err != nil {
		return Lease{}, err
	}
	if bootNS > int64(^uint64(0)>>1)-int64(c.StartupTimeout) {
		return Lease{}, invalid("startup deadline overflow")
	}
	lease.StartupDeadlineBootNS = bootNS + int64(c.StartupTimeout)
	if err = j.reserveInstanceStorage(ctx, tx, lease); err != nil {
		return Lease{}, err
	}
	data, err := json.Marshal(lease)
	if err != nil {
		return Lease{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO instances(id,module_id,epoch,lease,state,cleanup,started) VALUES(?,?,?,?, 'PREPARING','PENDING',?)", s.InstanceID, s.ModuleID, epoch, string(data), time.Now().UnixNano()); err != nil {
		return Lease{}, err
	}
	for kind, identity := range map[string]string{"scratch": fmt.Sprint(scratch), "ipc": lease.IPCPath, "service": s.InstanceID, "network": lease.NetworkGeneration, "logs": lease.LogPath, "persistent": fmt.Sprint(persistent)} {
		if _, err = tx.ExecContext(ctx, "INSERT INTO resource_claims VALUES(?,?,?,'INTENT')", s.InstanceID, kind, identity); err != nil {
			return Lease{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Lease{}, err
	}
	return lease, nil
}
func (j *Store) lease(ctx context.Context, epoch, id string) (Lease, string, error) {
	var data, state, owner string
	err := j.db.QueryRowContext(ctx, "SELECT lease,state,epoch FROM instances WHERE id=?", id).Scan(&data, &state, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, "", errInstanceAbsent
	}
	if err != nil {
		return Lease{}, "", err
	}
	if owner != epoch {
		return Lease{}, "", failure("UNAUTHENTICATED_INSTANCE", errors.New("instance belongs to another runtime epoch"))
	}
	var l Lease
	if err = json.Unmarshal([]byte(data), &l); err != nil {
		return Lease{}, "", err
	}
	return l, state, nil
}
func (j *Store) state(ctx context.Context, id, state, reason string) error {
	if err := j.requireLease(); err != nil {
		return err
	}
	switch state {
	case "PREPARING", "CREATED", "STARTING", "READY", "STOPPING", "CLEANUP_PENDING", "STOPPED":
	default:
		return errors.New("invalid durable instance state")
	}
	_, err := j.db.ExecContext(ctx, "UPDATE instances SET state=CASE WHEN reason!='' AND ? IN ('PREPARING','CREATED','STARTING','READY') THEN state ELSE ? END,reason=CASE WHEN reason='' THEN ? ELSE reason END WHERE id=?", state, state, reason, id)
	return err
}
func (j *Store) claim(ctx context.Context, id, kind, state string) error {
	if err := j.requireLease(); err != nil {
		return err
	}
	_, err := j.db.ExecContext(ctx, "UPDATE resource_claims SET state=? WHERE instance=? AND kind=?", state, id, kind)
	return err
}
func (j *Store) cleanup(ctx context.Context, id string, complete bool, cause error) error {
	if err := j.requireLease(); err != nil {
		return err
	}
	if !complete {
		status := "INCOMPLETE"
		if errors.Is(cause, ErrCreateUnresolved) {
			status = "UNRESOLVED_CREATE"
		}
		// Cleanup status is independent of the original failure. Never replace
		// an unrecorded launch failure with a secondary reclamation error.
		reason := failureReason(cause, FailureCleanupPlatform)
		_, err := j.db.ExecContext(ctx, "UPDATE instances SET cleanup=?,state='CLEANUP_PENDING' WHERE id=?", status, id)
		return errors.Join(err, j.recordCleanupCode(ctx, id, reason))
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var unresolved int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM create_submissions WHERE instance=? AND state='SUBMITTED'", id).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved != 0 {
		return ErrCreateUnresolved
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM generation_references WHERE kind='live' AND claim=?", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE storage_claims SET state='RELEASED' WHERE id=? AND kind='scratch'", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE native_endpoints SET transports_closed=1 WHERE instance=?", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE resource_claims SET state='RELEASED' WHERE instance=? AND kind!='persistent'", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE resource_claims SET state=CASE WHEN state IN ('ALLOCATED','PERSISTENT_READY','RETAINED') THEN 'RETAINED' ELSE state END WHERE instance=? AND kind='persistent'", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE instances SET cleanup='COMPLETE',state='STOPPED',ended=? WHERE id=?", time.Now().UnixNano(), id); err != nil {
		return err
	}
	return tx.Commit()
}
func (j *Store) pending(ctx context.Context, epoch string) ([]Lease, error) {
	query := "SELECT lease FROM instances WHERE cleanup!='COMPLETE'"
	args := []any{}
	if epoch != "" {
		query += " AND epoch=?"
		args = append(args, epoch)
	}
	rows, err := j.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Lease
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		var l Lease
		if err = json.Unmarshal([]byte(data), &l); err != nil {
			return nil, err
		}
		result = append(result, l)
	}
	return result, rows.Err()
}

// retireAbsent commits a non-reusable ID before acknowledging absent cleanup.
// A delayed Acquire cannot create resources after that acknowledgment.
func (j *Store) retireAbsent(ctx context.Context, epoch, id string) error {
	if err := j.requireLease(); err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO retired_instances(id,epoch) VALUES(?,?)", id, epoch); err != nil {
		return err
	}
	var owner string
	if err = tx.QueryRowContext(ctx, "SELECT epoch FROM retired_instances WHERE id=?", id).Scan(&owner); err != nil {
		return err
	}
	if owner != epoch {
		return failure("UNAUTHENTICATED_INSTANCE", errors.New("retired instance belongs to another runtime epoch"))
	}
	return tx.Commit()
}

func keepStoreWAL(ctx context.Context, db *sql.DB) error {
	connection, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	return connection.Raw(func(raw any) error {
		control, ok := raw.(sqlite.FileControl)
		if !ok {
			return errors.New("SQLite driver lacks required persistent WAL identity control")
		}
		mode, err := control.FileControlPersistWAL("main", 1)
		if err != nil {
			return err
		}
		if mode != 1 {
			return errors.New("SQLite persistent WAL identity could not be enabled")
		}
		return nil
	})
}
