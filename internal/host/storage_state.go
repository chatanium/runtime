package host

import (
	"context"
	"database/sql"
	"errors"
)

type persistentProvision struct {
	State  string
	Bytes  int64
	Inodes int64
}

func (j *journal) persistentProvision(ctx context.Context, l Lease) (persistentProvision, error) {
	var provision persistentProvision
	err := j.db.QueryRowContext(ctx, "SELECT p.state,p.bytes,p.inodes FROM persistent_provisions p JOIN installations i ON i.module_id=p.module_id WHERE p.module_id=? AND i.storage_key=? AND i.project=? AND i.uid=? AND i.gid=?", l.Spec.ModuleID, l.Ownership.InstallationID, l.PersistentProject, l.Spec.UID, l.Spec.GID).Scan(&provision.State, &provision.Bytes, &provision.Inodes)
	if errors.Is(err, sql.ErrNoRows) {
		return provision, errors.New("installation has no durable persistent provisioning checkpoint; explicit operator-attested migration is required")
	}
	return provision, err
}

func (j *journal) persistentTransition(ctx context.Context, l Lease, from, to string, bytes, inodes int64) error {
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
