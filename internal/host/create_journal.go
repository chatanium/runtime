//go:build linux

package host

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func validCreateKind(kind CreateKind) bool { return kind == CreateService || kind == CreateNetwork }

func (j *Store) creationOwner(ctx context.Context, o Ownership) error {
	if err := j.requireLease(); err != nil {
		return err
	}
	if o.RuntimeInstallationID != j.productID {
		return errors.New("product installation ownership mismatch")
	}
	var count int
	err := j.db.QueryRowContext(ctx, `SELECT count(*) FROM instances i JOIN installations p ON p.module_id=i.module_id WHERE i.id=? AND i.epoch=? AND p.storage_key=?`, o.InstanceID, o.EpochID, o.InstallationID).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("create submission ownership mismatch")
	}
	return nil
}
func (j *Store) SubmitCreate(ctx context.Context, o Ownership, kind CreateKind, identity string) error {
	if err := j.requireLease(); err != nil {
		return err
	}
	if !validCreateKind(kind) || identity == "" {
		return invalid("invalid create submission identity")
	}
	if err := j.creationOwner(ctx, o); err != nil {
		return err
	}
	// Never UPSERT or retry a submitted operation. Its deterministic name and
	// ownership bind any late result. Only the trusted platform's completed
	// negative-response evidence can reject it without an observed object.
	result, err := j.db.ExecContext(ctx, `INSERT INTO create_submissions(instance,kind,identity,state,object_id) SELECT ?,?,?,'SUBMITTED','' FROM instances WHERE id=? AND cleanup!='COMPLETE' ON CONFLICT(instance,kind) DO NOTHING`, o.InstanceID, kind, identity, o.InstanceID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCreateAlreadySubmitted
	}
	return nil
}
func (j *Store) LookupCreate(ctx context.Context, o Ownership, kind CreateKind) (CreateRecord, bool, error) {
	if !validCreateKind(kind) {
		return CreateRecord{}, false, invalid("invalid create submission kind")
	}
	if err := j.creationOwner(ctx, o); err != nil {
		return CreateRecord{}, false, err
	}
	var record CreateRecord
	err := j.db.QueryRowContext(ctx, `SELECT identity,state,object_id,rejection FROM create_submissions WHERE instance=? AND kind=?`, o.InstanceID, kind).Scan(&record.Identity, &record.State, &record.ObjectID, &record.Rejection)
	if errors.Is(err, sql.ErrNoRows) {
		return CreateRecord{}, false, nil
	}
	if err != nil {
		return CreateRecord{}, false, err
	}
	if record.Identity == "" || (record.State != CreateSubmitted && record.State != CreateObserved && record.State != CreateRejected) || (record.State == CreateObserved && record.ObjectID == "") || (record.State == CreateRejected && (record.ObjectID != "" || record.Rejection == "")) {
		return CreateRecord{}, false, errors.New("invalid durable create submission state")
	}
	return record, true, nil
}
func (j *Store) ObserveCreated(ctx context.Context, o Ownership, kind CreateKind, identity, id string) error {
	if kind == CreateService {
		observation, err := j.Unit(ctx, o)
		if err != nil {
			return errors.Join(errors.New("service resolution requires durable native observation"), err)
		}
		if identity != observation.Unit.Name || id != unitObjectID(observation.Unit) {
			return errors.New("service resolution identity mismatch")
		}
		return j.RecordUnit(ctx, o, observation)
	}
	if id == "" {
		return errors.New("created object identity is missing")
	}
	record, found, err := j.LookupCreate(ctx, o, kind)
	if err != nil {
		return err
	}
	if !found || record.Identity != identity {
		return errors.New("created object has no matching submitted operation")
	}
	if record.State == CreateObserved && record.ObjectID != id {
		return errors.New("created object does not match the resolved submitted operation")
	}
	result, err := j.db.ExecContext(ctx, `UPDATE create_submissions SET state='OBSERVED',object_id=? WHERE instance=? AND kind=? AND identity=? AND (state IN ('SUBMITTED','REJECTED') OR (state='OBSERVED' AND object_id=?))`, id, o.InstanceID, kind, identity, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("created object resolution conflicted")
	}
	return nil
}

// RejectCreate is a trusted-platform transition, not an operator force reset.
// Evidence must fence this exact dispatched request's completion. Cleanup still
// verifies ownership and absence, including any object left by failed rollback.
func (j *Store) RejectCreate(ctx context.Context, o Ownership, kind CreateKind, identity, evidence string) error {
	if evidence == "" {
		return errors.New("completed create rejection evidence is missing")
	}
	record, found, err := j.LookupCreate(ctx, o, kind)
	if err != nil {
		return err
	}
	if !found || record.Identity != identity || record.ObjectID != "" {
		return errors.New("rejected create has no matching unresolved operation")
	}
	result, err := j.db.ExecContext(ctx, `UPDATE create_submissions SET state='REJECTED',rejection=? WHERE instance=? AND kind=? AND identity=? AND object_id='' AND (state='SUBMITTED' OR (state='REJECTED' AND rejection=?))`, evidence, o.InstanceID, kind, identity, evidence)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("create rejection resolution conflicted")
	}
	return nil
}

func requireCreateResolved(ctx context.Context, j CreateJournal, o Ownership, kind CreateKind, identity string) error {
	if j == nil {
		return prerequisite(errors.New("durable create journal is not bound"))
	}
	record, found, err := j.LookupCreate(ctx, o, kind)
	if err != nil {
		return err
	}
	if !found {
		return nil
	} // No request was submitted under the write-ahead contract.
	if record.Identity != identity {
		return errors.New("create cleanup identity mismatch")
	}
	if record.State == CreateSubmitted {
		return fmt.Errorf("%w: %s", ErrCreateUnresolved, kind)
	}
	return nil
}
func (j *Store) unresolvedCreates(ctx context.Context, id string) error {
	var count int
	if err := j.db.QueryRowContext(ctx, `SELECT count(*) FROM create_submissions WHERE instance=? AND state='SUBMITTED'`, id).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrCreateUnresolved
	}
	return nil
}

// Only this recoverable class may leave startup reconciliation pending while
// the supervisor serves and continues polling. Other host failures fail closed.
func unresolvedCleanupOnly(err error) bool {
	if err == nil || !errors.Is(err, ErrCreateUnresolved) {
		return false
	}
	var allowed func(error) bool
	allowed = func(current error) bool {
		if multiple, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range multiple.Unwrap() {
				if !allowed(child) {
					return false
				}
			}
			return true
		}
		if single, ok := current.(interface{ Unwrap() error }); ok {
			return allowed(single.Unwrap())
		}
		return current == ErrCreateUnresolved || current == ErrCleanupIncomplete
	}
	return allowed(err)
}

func (j *Store) RecordFailure(ctx context.Context, o Ownership, phase FailurePhase, reason FailureReason) error {
	if !validFailurePhase(phase) || !validFailureReason(reason) {
		return invalid("invalid sandbox failure diagnostic code")
	}
	if err := j.creationOwner(ctx, o); err != nil {
		return err
	}
	return j.state(ctx, o.InstanceID, "CLEANUP_PENDING", string(phase)+":"+string(reason))
}
