//go:build linux

package host

import (
	"context"
	"database/sql"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
)

type persistentProvision struct {
	State  string
	Bytes  int64
	Inodes int64
}

func (j *Store) persistentProvision(ctx context.Context, l sharedhost.Lease) (persistentProvision, error) {
	var provision persistentProvision
	err := j.db.QueryRowContext(ctx, "SELECT p.state,p.bytes,p.inodes FROM persistent_provisions p JOIN installations i ON i.module_id=p.module_id WHERE p.module_id=? AND i.storage_key=? AND i.project=? AND i.uid=? AND i.gid=?", l.Spec.ModuleID, l.Ownership.InstallationID, l.PersistentProject, l.Spec.UID, l.Spec.GID).Scan(&provision.State, &provision.Bytes, &provision.Inodes)
	if errors.Is(err, sql.ErrNoRows) {
		return provision, errors.New("installation has no durable persistent provisioning checkpoint; explicit operator-attested migration is required")
	}
	return provision, err
}

func (j *Store) persistentTransition(ctx context.Context, l sharedhost.Lease, from, to string, bytes, inodes int64) error {
	result, err := j.db.ExecContext(ctx, "UPDATE persistent_provisions SET state=?,bytes=?,inodes=? WHERE module_id=? AND state=? AND EXISTS(SELECT 1 FROM installations i WHERE i.module_id=persistent_provisions.module_id AND i.storage_key=? AND i.project=? AND i.uid=? AND i.gid=?)", to, bytes, inodes, l.Spec.ModuleID, from, l.Ownership.InstallationID, l.PersistentProject, l.Spec.UID, l.Spec.GID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("persistent provisioning phase changed unexpectedly")
	}
	return nil
}

func (s *Store) reserveStorageTx(ctx context.Context, tx *sql.Tx, id, kind string, bytes, inodes int64, project uint32) (uint32, error) {
	if id == "" || bytes <= 0 || inodes <= 0 {
		return 0, invalid("finite positive storage reservation required")
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT manifest FROM runtime_installations WHERE id=?", s.productID).Scan(&raw); err != nil {
		return 0, err
	}
	var m InstallationManifest
	if err := gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &m); err != nil {
		return 0, err
	}
	var maxBytes, maxInodes int64
	group := kind
	switch kind {
	case "persistent", "scratch", "native-app":
		group = "data"
		maxBytes = m.Budget.DataBytes
		maxInodes = m.Budget.DataInodes
		if m.Budget.AppBytes <= 0 || m.Budget.AppInodes <= 0 || m.Budget.AppBytes > maxBytes || m.Budget.AppInodes > maxInodes {
			return 0, invalid("invalid persistent app subreservation")
		}
		if kind == "native-app" && (id != s.productID+":app" || bytes != m.Budget.AppBytes || inodes != m.Budget.AppInodes) {
			return 0, invalid("app reservation differs from installed allowance")
		}
	case "source":
		maxBytes = m.Budget.SourceBytes
		maxInodes = m.Budget.SourceInodes
	case "cache":
		maxBytes = m.Budget.CacheBytes
		maxInodes = m.Budget.CacheInodes
	case "preparation":
		maxBytes = m.Budget.PreparationBytes
		maxInodes = m.Budget.PreparationInodes
	default:
		return 0, invalid("unknown storage reservation kind")
	}
	var oldKind, state string
	var oldBytes, oldInodes int64
	var oldProject uint32
	err := tx.QueryRowContext(ctx, "SELECT kind,bytes,inodes,project,state FROM storage_claims WHERE id=?", id).Scan(&oldKind, &oldBytes, &oldInodes, &oldProject, &state)
	if err == nil {
		if oldKind != kind || oldBytes != bytes || oldInodes != inodes || state != "RESERVED" || project != 0 && oldProject != project {
			return 0, errors.New("storage claim reuse or incompatible reservation")
		}
		return oldProject, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	var usedBytes, usedInodes int64
	query := "SELECT coalesce(sum(bytes),0),coalesce(sum(inodes),0) FROM storage_claims WHERE state!='RELEASED' AND kind=?"
	if group == "data" {
		query = "SELECT coalesce(sum(bytes),0),coalesce(sum(inodes),0) FROM storage_claims WHERE state!='RELEASED' AND kind IN ('persistent','scratch','native-app')"
	}
	if group == "data" {
		err = tx.QueryRowContext(ctx, query).Scan(&usedBytes, &usedInodes)
	} else {
		err = tx.QueryRowContext(ctx, query, kind).Scan(&usedBytes, &usedInodes)
	}
	if err != nil {
		return 0, err
	}
	if maxBytes <= 0 || maxInodes <= 0 || bytes > maxBytes || inodes > maxInodes || usedBytes > maxBytes-bytes || usedInodes > maxInodes-inodes {
		return 0, errors.New("installation storage budget exhausted")
	}
	if project == 0 {
		project, err = nextProject(ctx, tx)
		if err != nil {
			return 0, err
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO storage_claims VALUES(?,?,?,?,?,'RESERVED')", id, kind, bytes, inodes, project)
	return project, err
}
func (s *Store) ReserveStorage(ctx context.Context, id, kind string, bytes, inodes int64) (uint32, error) {
	if err := s.requireLease(); err != nil {
		return 0, err
	}
	if kind != "source" && kind != "cache" && kind != "preparation" {
		return 0, invalid("invalid external storage reservation kind")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	project, err := s.reserveStorageTx(ctx, tx, id, kind, bytes, inodes, 0)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return project, nil
}
func (s *Store) ReleaseStorage(ctx context.Context, id string, e CleanupEvidence) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if err := validateCleanup(e); err != nil {
		return err
	}
	if err := s.CheckStorageRelease(ctx, id); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, "UPDATE storage_claims SET state='RELEASED' WHERE id=?", id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		err = errors.New("unknown storage claim")
	}
	return err
}
func (s *Store) reserveInstanceStorage(ctx context.Context, tx *sql.Tx, l sharedhost.Lease) error {
	var appState string
	var appBytes, appInodes int64
	if err := tx.QueryRowContext(ctx, "SELECT state,bytes,inodes FROM storage_claims WHERE id=? AND kind='native-app'", s.productID+":app").Scan(&appState, &appBytes, &appInodes); err != nil {
		return errors.Join(errors.New("native app quota must be reserved before module allocation"), err)
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT manifest FROM runtime_installations WHERE id=?", s.productID).Scan(&raw); err != nil {
		return err
	}
	var manifest InstallationManifest
	if err := gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &manifest); err != nil {
		return err
	}
	if appState != "RESERVED" || appBytes != manifest.Budget.AppBytes || appInodes != manifest.Budget.AppInodes {
		return errors.New("persistent app claim differs from installed allowance")
	}
	if _, err := s.reserveStorageTx(ctx, tx, l.Ownership.InstallationID, "persistent", l.Spec.Resources.PersistentBytes, l.Spec.Resources.PersistentInodes, l.PersistentProject); err != nil {
		return err
	}
	_, err := s.reserveStorageTx(ctx, tx, l.Spec.InstanceID, "scratch", l.Spec.Resources.ScratchBytes, l.Spec.Resources.ScratchInodes, l.ScratchProject)
	return err
}

func (s *Store) BindStorageGeneration(ctx context.Context, claimID, generationID string) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if claimID == "" || generationID == "" {
		return invalid("empty storage generation binding")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = checkGenerationAvailableTx(ctx, tx, generationID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO storage_generations SELECT id,? FROM storage_claims WHERE id=? AND state='RESERVED'", generationID, claimID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM storage_generations g JOIN storage_claims c ON c.id=g.claim WHERE g.claim=? AND g.generation=? AND c.state='RESERVED'", claimID, generationID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("storage claim absent or retiring")
		}
	}
	return tx.Commit()
}
func (s *Store) CheckStorageRelease(ctx context.Context, claimID string) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state, kind string
	if err = tx.QueryRowContext(ctx, "SELECT state,kind FROM storage_claims WHERE id=?", claimID).Scan(&state, &kind); err != nil {
		return err
	}
	if state == "RELEASED" {
		return nil
	}
	if kind == "native-app" {
		return errors.New("persistent app quota may retire only with approved primary-volume purge")
	}
	var refs int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM generation_references r WHERE r.id=? OR r.id IN (SELECT generation FROM storage_generations WHERE claim=?)", claimID, claimID).Scan(&refs); err != nil {
		return err
	}
	if refs != 0 {
		return errors.New("storage generation remains referenced")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE storage_claims SET state='RETIRING' WHERE id=?", claimID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) TemporaryStorageProjects(ctx context.Context) ([]uint32, error) {
	if err := s.requireLease(); err != nil {
		return nil, err
	}
	var active int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM instances WHERE cleanup!='COMPLETE'").Scan(&active); err != nil {
		return nil, err
	}
	if active != 0 {
		return nil, sharedhost.ErrCleanupIncomplete
	}
	rows, err := s.db.QueryContext(ctx, "SELECT project,state FROM storage_claims WHERE kind IN ('scratch','preparation') ORDER BY project")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var projects []uint32
	for rows.Next() {
		var p uint32
		var state string
		if err = rows.Scan(&p, &state); err != nil {
			return nil, err
		}
		if state != "RELEASED" {
			return nil, sharedhost.ErrCleanupIncomplete
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}
func (s *Store) StorageProject(ctx context.Context, claimID string) (uint32, bool, error) {
	var p uint32
	err := s.db.QueryRowContext(ctx, "SELECT project FROM storage_claims WHERE id=?", claimID).Scan(&p)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return p, err == nil, err
}

// CheckStorageReservation admits only the exact live reserved project. Historical
// project identities remain available through StorageProject for disposal.
func (s *Store) CheckStorageReservation(ctx context.Context, claimID string, project uint32) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if claimID == "" || project == 0 {
		return invalid("exact positive storage reservation identity required")
	}
	var actual uint32
	var state string
	if err := s.db.QueryRowContext(ctx, "SELECT project,state FROM storage_claims WHERE id=?", claimID).Scan(&actual, &state); err != nil {
		return err
	}
	if actual != project || state != "RESERVED" {
		return errors.New("storage claim is not the exact live reserved project")
	}
	return nil
}

func (s *Store) StorageGeneration(ctx context.Context, claimID string) (string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT g.generation FROM storage_generations g JOIN storage_claims c ON c.id=g.claim WHERE c.id=? AND c.kind IN ('source','cache') AND c.state='RESERVED'", claimID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var id string
	for rows.Next() {
		var next string
		if err = rows.Scan(&next); err != nil {
			return "", err
		}
		if id != "" {
			return "", errors.New("committed source/cache claim has ambiguous generation binding")
		}
		id = next
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	if id == "" {
		return "", errors.New("source/cache claim has no live immutable generation")
	}
	return id, nil
}
func (s *Store) CheckNoStorageAllocations(ctx context.Context) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM storage_claims)+(SELECT count(*) FROM instances)").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return errors.New("installation has previously allocated storage")
	}
	return nil
}
func (s *Store) AvailableStorage(ctx context.Context, kind string) (int64, int64, error) {
	if err := s.requireLease(); err != nil {
		return 0, 0, err
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return 0, 0, err
	}
	var bytes, inodes int64
	switch kind {
	case "source":
		bytes = m.Budget.SourceBytes
		inodes = m.Budget.SourceInodes
	case "cache":
		bytes = m.Budget.CacheBytes
		inodes = m.Budget.CacheInodes
	case "preparation":
		bytes = m.Budget.PreparationBytes
		inodes = m.Budget.PreparationInodes
	default:
		return 0, 0, invalid("unknown temporary storage budget")
	}
	var usedBytes, usedInodes int64
	if err = s.db.QueryRowContext(ctx, "SELECT coalesce(sum(bytes),0),coalesce(sum(inodes),0) FROM storage_claims WHERE kind=? AND state!='RELEASED'", kind).Scan(&usedBytes, &usedInodes); err != nil {
		return 0, 0, err
	}
	if bytes < usedBytes || inodes < usedInodes {
		return 0, 0, errors.New("storage reservations exceed installed budget")
	}
	return bytes - usedBytes, inodes - usedInodes, nil
}

func (s *Store) ReserveAppStorage(ctx context.Context) (uint32, error) {
	if err := s.requireLease(); err != nil {
		return 0, err
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return 0, err
	}
	if m.Budget.AppBytes <= 0 || m.Budget.AppInodes <= 0 || m.Budget.AppBytes > m.Budget.DataBytes || m.Budget.AppInodes > m.Budget.DataInodes {
		return 0, invalid("finite app subreservation must fit data pool")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	project, err := s.reserveStorageTx(ctx, tx, s.productID+":app", "native-app", m.Budget.AppBytes, m.Budget.AppInodes, 0)
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO storage_generations VALUES(?,?)", s.productID+":app", "native-app:"+s.productID); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return project, nil
}

func (s *Store) AppStorageProject(ctx context.Context) (uint32, error) {
	if err := s.requireLease(); err != nil {
		return 0, err
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return 0, err
	}
	if m.Budget.AppBytes <= 0 || m.Budget.AppInodes <= 0 || m.Budget.AppBytes > m.Budget.DataBytes || m.Budget.AppInodes > m.Budget.DataInodes {
		return 0, invalid("invalid installed persistent app allowance")
	}
	var project uint32
	err = s.db.QueryRowContext(ctx, "SELECT project FROM storage_claims WHERE id=? AND kind='native-app' AND state='RESERVED' AND bytes=? AND inodes=?", s.productID+":app", m.Budget.AppBytes, m.Budget.AppInodes).Scan(&project)
	if err != nil {
		return 0, err
	}
	if project == 0 {
		return 0, errors.New("native app claim has invalid project")
	}
	return project, nil
}
