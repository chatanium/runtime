package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SQLite v1.61.0 requires its documented modernc.org/libc v1.79.0 pairing.
// A single physical connection applies the PRAGMAs to every transaction.
type journal struct{ db *sql.DB }

var errInstanceAbsent = errors.New("instance absent from authoritative journal")

func openJournal(ctx context.Context, dir string) (*journal, error) {
	u := url.URL{Scheme: "file", Path: filepath.Join(dir, "supervisor.sqlite")}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	j := &journal{db: db}
	for _, s := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON", `CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS installations(module_id TEXT PRIMARY KEY, storage_key TEXT NOT NULL UNIQUE, project INTEGER NOT NULL UNIQUE, uid INTEGER NOT NULL, gid INTEGER NOT NULL, image TEXT NOT NULL, config_revision TEXT NOT NULL, approval_revision TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS runtime_epochs(id TEXT PRIMARY KEY,boot_id TEXT NOT NULL,pid INTEGER NOT NULL,start_identity TEXT NOT NULL,started INTEGER NOT NULL,state TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS instances(id TEXT PRIMARY KEY,module_id TEXT NOT NULL REFERENCES installations(module_id),epoch TEXT NOT NULL REFERENCES runtime_epochs(id),lease TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',cleanup TEXT NOT NULL,started INTEGER NOT NULL,ended INTEGER)`,
		`CREATE TABLE IF NOT EXISTS retired_instances(id TEXT PRIMARY KEY,epoch TEXT NOT NULL REFERENCES runtime_epochs(id))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS exclusive_installation ON instances(module_id) WHERE cleanup!='COMPLETE'`,
		`CREATE TABLE IF NOT EXISTS resource_claims(instance TEXT NOT NULL REFERENCES instances(id),kind TEXT NOT NULL,identity TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(instance,kind))`,
		`CREATE TABLE IF NOT EXISTS persistent_provisions(module_id TEXT PRIMARY KEY REFERENCES installations(module_id),state TEXT NOT NULL,bytes INTEGER NOT NULL,inodes INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS create_submissions(instance TEXT NOT NULL REFERENCES instances(id),kind TEXT NOT NULL CHECK(kind IN ('container','network')),identity TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('SUBMITTED','OBSERVED')),object_id TEXT NOT NULL,PRIMARY KEY(instance,kind),UNIQUE(kind,identity))`,
		`INSERT OR IGNORE INTO metadata(key,value) VALUES('next_project','1')`} {
		if _, err = db.ExecContext(ctx, s); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = j.initializeCreateJournal(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err = j.initializeCreateRejections(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return j, nil
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
func (j *journal) epoch(ctx context.Context, id, boot string, pid int, start string) error {
	_, err := j.db.ExecContext(ctx, "INSERT INTO runtime_epochs VALUES(?,?,?,?,?, 'LIVE')", id, boot, pid, start, time.Now().UnixNano())
	return err
}
func (j *journal) allocate(ctx context.Context, epoch string, s LaunchSpec, c SupervisorConfig) (Lease, error) {
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
	lease := Lease{Ownership: Ownership{InstallationID: key, EpochID: epoch, InstanceID: s.InstanceID}, Spec: s, PersistentPath: filepath.Join(c.StorageRoot, "persistent", key), ScratchPath: filepath.Join(c.StorageRoot, "instances", s.InstanceID, "scratch"), IPCPath: filepath.Join(c.IPCRoot, s.InstanceID), LogPath: filepath.Join(c.ManagementDirectory, "logs", s.InstanceID), PersistentProject: persistent, ScratchProject: scratch}
	lease.SocketGID = c.RuntimeGID
	data, err := json.Marshal(lease)
	if err != nil {
		return Lease{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO instances(id,module_id,epoch,lease,state,cleanup,started) VALUES(?,?,?,?, 'ALLOCATING','PENDING',?)", s.InstanceID, s.ModuleID, epoch, string(data), time.Now().UnixNano()); err != nil {
		return Lease{}, err
	}
	for kind, identity := range map[string]string{"scratch": fmt.Sprint(scratch), "ipc": lease.IPCPath, "container": s.InstanceID, "network": s.InstanceID, "logs": lease.LogPath, "persistent": fmt.Sprint(persistent)} {
		if _, err = tx.ExecContext(ctx, "INSERT INTO resource_claims VALUES(?,?,?,'INTENT')", s.InstanceID, kind, identity); err != nil {
			return Lease{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Lease{}, err
	}
	return lease, nil
}
func (j *journal) lease(ctx context.Context, epoch, id string) (Lease, string, error) {
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
func (j *journal) state(ctx context.Context, id, state, reason string) error {
	_, err := j.db.ExecContext(ctx, "UPDATE instances SET state=CASE WHEN state='FAILED' THEN state ELSE ? END,reason=CASE WHEN reason='' THEN ? ELSE reason END WHERE id=?", state, reason, id)
	return err
}
func (j *journal) claim(ctx context.Context, id, kind, state string) error {
	_, err := j.db.ExecContext(ctx, "UPDATE resource_claims SET state=? WHERE instance=? AND kind=?", state, id, kind)
	return err
}
func (j *journal) container(ctx context.Context, l Lease, id string) error {
	l.Ownership.ContainerID = id
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE instances SET lease=?,state=CASE WHEN state='FAILED' THEN state ELSE 'CREATED' END WHERE id=?", string(b), l.Spec.InstanceID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE resource_claims SET identity=?,state='ALLOCATED' WHERE instance=? AND kind='container'", id, l.Spec.InstanceID); err != nil {
		return err
	}
	if l.Spec.InitialEgress == EgressPublicInternet {
		if _, err = tx.ExecContext(ctx, "UPDATE resource_claims SET state='CLOSED_TOPOLOGY' WHERE instance=? AND kind='network'", l.Spec.InstanceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (j *journal) cleanup(ctx context.Context, id string, complete bool, cause error) error {
	if !complete {
		status := "INCOMPLETE"
		if errors.Is(cause, ErrCreateUnresolved) {
			status = "UNRESOLVED_CREATE"
		}
		// Cleanup status is independent of the original failure. Never replace
		// an unrecorded launch failure with a secondary reclamation error.
		_, err := j.db.ExecContext(ctx, "UPDATE instances SET cleanup=?,state='FAILED' WHERE id=?", status, id)
		return err
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
	if _, err = tx.ExecContext(ctx, "UPDATE resource_claims SET state='RELEASED' WHERE instance=? AND kind!='persistent'", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE resource_claims SET state=CASE WHEN state IN ('ALLOCATED','PERSISTENT_READY','RETAINED') THEN 'RETAINED' ELSE state END WHERE instance=? AND kind='persistent'", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE instances SET cleanup='COMPLETE',state=CASE WHEN state='FAILED' THEN state ELSE 'STOPPED' END,ended=? WHERE id=?", time.Now().UnixNano(), id); err != nil {
		return err
	}
	return tx.Commit()
}
func (j *journal) pending(ctx context.Context, epoch string) ([]Lease, error) {
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
func (j *journal) retireAbsent(ctx context.Context, epoch, id string) error {
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
