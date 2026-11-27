//go:build linux

package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/provision"
)

const managementPlanBytesMax = 32 << 20
const managementStateBytesMax = 1 << 20

// ManagementPlanRecord is root-only replay metadata, never executable authority.
// Plan and Snapshot are immutable; State contains bounded phase receipts.
type ManagementPlanRecord struct {
	Kind                string               `json:"kind"`
	ID                  string               `json:"id"`
	Digest              string               `json:"digest"`
	Plan                []byte               `json:"plan"`
	Snapshot            InstallationManifest `json:"snapshot"`
	Phase               string               `json:"phase"`
	Step                uint32               `json:"step"`
	State               []byte               `json:"state,omitempty"`
	RetainedGenerations []string             `json:"retained_generations"`
}

func managementKey(kind, id string) (string, error) {
	switch kind {
	case "init", "update", "configure", "operator-preparation":
	default:
		return "", invalid("unknown management plan kind")
	}
	if len(id) == 0 || len(id) > 128 || strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" || strings.ContainsAny(id[:1], "-_") {
		return "", invalid("invalid management plan ID")
	}
	return "management_plan:" + kind + ":" + id, nil
}
func managementClaim(r ManagementPlanRecord) string { return "management:" + r.Kind + ":" + r.ID }
func validateManagementState(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	var value any
	return gvxcontract.DecodeStrict(raw, managementStateBytesMax, 32, &value)
}
func validateManagementPlan(r ManagementPlanRecord, product string) error {
	if _, err := managementKey(r.Kind, r.ID); err != nil {
		return err
	}
	if !provision.ValidDigest(r.Digest) || len(r.Plan) == 0 || len(r.Plan) > managementPlanBytesMax || !validLedgerID(r.Phase) || len(r.Phase) > 64 || len(r.RetainedGenerations) > 4096 {
		return invalid("invalid management plan bounds")
	}
	var value any
	if err := gvxcontract.DecodeStrict(r.Plan, managementPlanBytesMax, 32, &value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(r.Plan, &fields); err != nil || fields == nil {
		return invalid("management plan must be an object")
	}
	for name, want := range map[string]string{"plan_id": r.ID, "plan_digest": r.Digest, "installation_id": product} {
		var got string
		if err := json.Unmarshal(fields[name], &got); err != nil || got != want {
			return invalid("management plan header differs from its durable binding")
		}
	}
	delete(fields, "plan_digest")
	canonical, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	if provision.DomainDigest("chatanium-"+r.Kind+"-plan-v1", canonical) != r.Digest {
		return invalid("management approval digest does not match exact plan")
	}
	if r.Snapshot.RuntimeInstallationID != "" && r.Snapshot.RuntimeInstallationID != product {
		return invalid("management snapshot belongs to another installation")
	}
	for _, generation := range r.RetainedGenerations {
		if generation == "" || len(generation) > 4096 || strings.ContainsAny(generation, "\x00\r\n") {
			return invalid("invalid management generation reference")
		}
	}
	return validateManagementState(r.State)
}
func decodeManagementPlan(raw []byte, product, kind, id string) (ManagementPlanRecord, error) {
	var r ManagementPlanRecord
	if err := gvxcontract.DecodeStrict(raw, revisionJSONMax, 40, &r); err != nil {
		return r, err
	}
	if r.Kind != kind || r.ID != id {
		return r, errors.New("management journal key mismatch")
	}
	return r, validateManagementPlan(r, product)
}
func (s *Store) ManagementPlan(ctx context.Context, kind, id string) (ManagementPlanRecord, error) {
	key, err := managementKey(kind, id)
	if err != nil {
		return ManagementPlanRecord{}, err
	}
	var raw []byte
	if err = s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&raw); err != nil {
		return ManagementPlanRecord{}, err
	}
	return decodeManagementPlan(raw, s.productID, kind, id)
}
func (s *Store) ManagementPlans(ctx context.Context, kind string) ([]ManagementPlanRecord, error) {
	if _, err := managementKey(kind, "lookup"); err != nil {
		return nil, err
	}
	prefix := "management_plan:" + kind + ":"
	rows, err := s.db.QueryContext(ctx, "SELECT key,value FROM metadata WHERE substr(key,1,?)=? ORDER BY key", len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []ManagementPlanRecord
	for rows.Next() {
		var key string
		var raw []byte
		if err = rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		r, e := decodeManagementPlan(raw, s.productID, kind, strings.TrimPrefix(key, prefix))
		if e != nil {
			return nil, e
		}
		records = append(records, r)
	}
	return records, rows.Err()
}
func readManagementManifest(ctx context.Context, tx *sql.Tx, product string) (InstallationManifest, error) {
	var m InstallationManifest
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT manifest FROM runtime_installations WHERE id=?", product).Scan(&raw); err != nil {
		return m, err
	}
	err := gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &m)
	return m, err
}
func managementGenerations(ctx context.Context, tx *sql.Tx, m InstallationManifest, r ManagementPlanRecord) ([]string, error) {
	ids := append([]string(nil), r.RetainedGenerations...)
	if m.BundleDigest != "" {
		ids = append(ids, m.BundleDigest)
	}
	var revisions []RevisionRecord
	if m.ActiveRevision != "" {
		var raw []byte
		if err := tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", m.ActiveRevision).Scan(&raw); err != nil {
			return nil, err
		}
		var revision RevisionRecord
		if err := gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &revision); err != nil {
			return nil, err
		}
		revisions = append(revisions, revision)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(r.Plan, &fields); err != nil {
		return nil, err
	}
	if raw := fields["candidate_bundle_digest"]; raw != nil {
		var digest string
		if err := json.Unmarshal(raw, &digest); err != nil || !provision.ValidDigest(digest) {
			return nil, invalid("invalid management candidate bundle digest")
		}
		ids = append(ids, digest)
	}
	if raw := fields["candidate_revision"]; raw != nil {
		var revision RevisionRecord
		if err := gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &revision); err != nil {
			return nil, err
		}
		revisions = append(revisions, revision)
	}
	if raw := fields["preparation_bundle_digest"]; raw != nil {
		var digest string
		if err := json.Unmarshal(raw, &digest); err != nil || !provision.ValidDigest(digest) {
			return nil, invalid("invalid reviewed preparation bundle digest")
		}
		ids = append(ids, digest)
	}
	for _, revision := range revisions {
		if revision.BundleDigest != "" {
			ids = append(ids, revision.BundleDigest)
		}
		for _, binding := range revision.Images {
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM image_records WHERE id=?", binding.ImageRecordID).Scan(&count); err != nil {
				return nil, err
			}
			if count != 1 {
				return nil, errors.New("management plan references an uncommitted image")
			}
			ids = append(ids, binding.ImageRecordID)
			rows, err := tx.QueryContext(ctx, "SELECT record FROM cache_generations WHERE image=?", binding.ImageRecordID)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var raw []byte
				if err = rows.Scan(&raw); err != nil {
					rows.Close()
					return nil, err
				}
				var c CacheGeneration
				if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &c); err != nil {
					rows.Close()
					return nil, err
				}
				if c.State == "READY" && c.BundleDigest == revision.BundleDigest {
					ids = append(ids, c.ID)
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, err
			}
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}
func beginManagementPlanTx(ctx context.Context, tx *sql.Tx, product string, r ManagementPlanRecord) error {
	if err := validateManagementPlan(r, product); err != nil {
		return err
	}
	key, _ := managementKey(r.Kind, r.ID)
	var existing []byte
	err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&existing)
	if err == nil {
		old, e := decodeManagementPlan(existing, product, r.Kind, r.ID)
		if e != nil {
			return e
		}
		if old.Digest != r.Digest || !bytes.Equal(old.Plan, r.Plan) || r.Snapshot.RuntimeInstallationID != "" && old.Snapshot != r.Snapshot {
			return errors.New("management plan identity or original snapshot reuse")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if r.Phase != "APPROVED" || r.Step != 0 {
		return invalid("new management plan must begin at APPROVED")
	}
	var active string
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='management_active'").Scan(&active)
	if err == nil {
		return errors.New("another approved management transaction remains incomplete")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	m, err := readManagementManifest(ctx, tx, product)
	if err != nil {
		return err
	}
	if r.Snapshot.RuntimeInstallationID != "" && r.Snapshot != m {
		return errors.New("management approval snapshot differs from current installation")
	}
	r.Snapshot = m
	reacquisition := false
	if r.Kind == "operator-preparation" {
		approval, e := operatorPreparationApproval(r)
		if e != nil {
			return e
		}
		if approval.Reacquisition != nil {
			var reviewed []byte
			if e = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "operator_reacquisition_set:"+r.ID).Scan(&reviewed); e != nil {
				return e
			}
			var set LegacyQuarantineSet
			if e = gvxcontract.DecodeStrict(reviewed, managementStateBytesMax, 16, &set); e != nil {
				return e
			}
			if e = validateLegacyQuarantineSet(ctx, tx, set, product); e != nil {
				return e
			}
			reacquisition = set.Digest == approval.Reacquisition.QuarantineSetDigest && set.ActiveRevision == m.ActiveRevision && m.State == approval.Reacquisition.ExpectedState
			if !reacquisition {
				return errors.New("reacquisition approval differs from atomic quarantine admission")
			}
		}
	}
	if m.DesiredRunState != "STOPPED" || m.PendingRevision != "" || r.Kind == "init" && m.State != "PROVISIONING" || r.Kind != "init" && m.State != "READY" && !reacquisition {
		return errors.New("management approval requires stopped idle base installation")
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM instances WHERE cleanup!='COMPLETE'").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrCleanupIncomplete
	}
	if r.Kind != "init" {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(r.Plan, &fields)
		var base string
		if err = json.Unmarshal(fields["expected_active_revision"], &base); err != nil || base != m.ActiveRevision {
			return errors.New("management plan active revision binding changed")
		}
	}
	r.RetainedGenerations, err = managementGenerations(ctx, tx, m, r)
	if err != nil {
		return err
	}
	for _, generation := range r.RetainedGenerations {
		if err = retainGenerationTx(ctx, tx, "recovery", generation, managementClaim(r)); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > revisionJSONMax {
		return invalid("management transaction exceeds durable bound")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?)", key, raw); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES('management_active',?)", key)
	return err
}
func (s *Store) BeginManagementPlan(ctx context.Context, r ManagementPlanRecord) error {
	if r.Kind == "operator-preparation" {
		approval, err := operatorPreparationApproval(r)
		if err != nil {
			return err
		}
		if approval.Reacquisition != nil {
			return s.BeginOperatorReacquisition(ctx, r)
		}
	}
	if err := s.requireLease(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = beginManagementPlanTx(ctx, tx, s.productID, r); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) changeManagementPlan(ctx context.Context, kind, id, digest string, change func(*ManagementPlanRecord, *sql.Tx) error) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	key, err := managementKey(kind, id)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old []byte
	if err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&old); err != nil {
		return err
	}
	r, err := decodeManagementPlan(old, s.productID, kind, id)
	if err != nil {
		return err
	}
	if r.Digest != digest {
		return errors.New("management plan digest changed")
	}
	if err = change(&r, tx); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > revisionJSONMax {
		return invalid("management transaction exceeds durable bound")
	}
	result, err := tx.ExecContext(ctx, "UPDATE metadata SET value=? WHERE key=? AND value=?", raw, key, old)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("management phase compare-and-swap failed")
	}
	return tx.Commit()
}
func (s *Store) AdvanceManagementPlan(ctx context.Context, kind, id, digest, expectedPhase, nextPhase string) error {
	return s.advanceManagementPlan(ctx, kind, id, digest, expectedPhase, nextPhase, nil, false)
}
func (s *Store) AdvanceManagementPlanState(ctx context.Context, kind, id, digest, expectedPhase, nextPhase string, state []byte) error {
	return s.advanceManagementPlan(ctx, kind, id, digest, expectedPhase, nextPhase, state, true)
}
func (s *Store) advanceManagementPlan(ctx context.Context, kind, id, digest, expectedPhase, nextPhase string, state []byte, replaceState bool) error {
	if !validLedgerID(nextPhase) || len(nextPhase) > 64 || nextPhase == "COMMITTED" || nextPhase == "APPROVED" {
		return invalid("invalid management phase transition")
	}
	if err := validateManagementState(state); err != nil {
		return err
	}
	return s.changeManagementPlan(ctx, kind, id, digest, func(r *ManagementPlanRecord, tx *sql.Tx) error {
		if r.Phase == nextPhase && (!replaceState || bytes.Equal(r.State, state)) {
			return nil
		}
		if r.Phase != expectedPhase || r.Phase == "COMMITTED" || r.Phase == nextPhase || r.Step == ^uint32(0) {
			return errors.New("management phase compare-and-swap failed")
		}
		generations, err := managementGenerations(ctx, tx, r.Snapshot, *r)
		if err != nil {
			return err
		}
		if len(generations) > 4096 {
			return invalid("too many management generation references")
		}
		for _, generation := range generations {
			if err = retainGenerationTx(ctx, tx, "recovery", generation, managementClaim(*r)); err != nil {
				return err
			}
		}
		r.RetainedGenerations = generations
		r.Phase = nextPhase
		r.Step++
		if replaceState {
			r.State = append([]byte(nil), state...)
		}
		return nil
	})
}
func (s *Store) RetainManagementGenerations(ctx context.Context, kind, id, digest string, generations []string) error {
	if len(generations) > 4096 {
		return invalid("too many management generation references")
	}
	return s.changeManagementPlan(ctx, kind, id, digest, func(r *ManagementPlanRecord, tx *sql.Tx) error {
		if r.Phase == "COMMITTED" {
			return errors.New("completed management plan cannot acquire references")
		}
		for _, generation := range generations {
			if generation == "" || len(generation) > 4096 || strings.ContainsAny(generation, "\x00\r\n") {
				return invalid("invalid management generation")
			}
			if err := retainGenerationTx(ctx, tx, "recovery", generation, managementClaim(*r)); err != nil {
				return err
			}
			r.RetainedGenerations = append(r.RetainedGenerations, generation)
		}
		slices.Sort(r.RetainedGenerations)
		r.RetainedGenerations = slices.Compact(r.RetainedGenerations)
		if len(r.RetainedGenerations) > 4096 {
			return invalid("too many management generation references")
		}
		return nil
	})
}
func (s *Store) CompleteManagementPlan(ctx context.Context, kind, id, digest, expectedPhase string, e CleanupEvidence) error {
	return s.changeManagementPlan(ctx, kind, id, digest, func(r *ManagementPlanRecord, tx *sql.Tx) error {
		if r.Phase == "COMMITTED" {
			return nil
		}
		if r.Phase != expectedPhase || r.Step == ^uint32(0) {
			return errors.New("management completion compare-and-swap failed")
		}
		if err := validateCleanup(e); err != nil {
			return err
		}
		m, err := readManagementManifest(ctx, tx, s.productID)
		if err != nil {
			return err
		}
		reacquisition := false
		if r.Kind == "operator-preparation" {
			approval, e := operatorPreparationApproval(*r)
			if e != nil {
				return e
			}
			reacquisition = approval.Reacquisition != nil
			if reacquisition && (m.ActiveRevision != approval.ExpectedActiveRevision || m.ActiveRevision != r.Snapshot.ActiveRevision) {
				return errors.New("reacquisition cannot change its approved base release")
			}
		}
		if m.DesiredRunState != "STOPPED" || m.PendingRevision != "" || (m.State != "READY" && !(reacquisition && m.State == "RECOVERY_REQUIRED")) || m.ActiveRevision == "" {
			return errors.New("management completion requires stopped committed release")
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM instances WHERE cleanup!='COMPLETE'").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrCleanupIncomplete
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(r.Plan, &fields)
		if raw := fields["candidate_revision"]; raw != nil {
			var revision RevisionRecord
			if err = gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &revision); err != nil {
				return err
			}
			if revision.ID != m.ActiveRevision || revision.BundleDigest != m.BundleDigest {
				return errors.New("management candidate release is not the activated release")
			}
		}
		if r.Kind == "operator-preparation" && m.ActiveRevision != r.Snapshot.ActiveRevision {
			return errors.New("operator preparation cannot replace active release")
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM generation_references WHERE kind='recovery' AND claim=?", managementClaim(*r)); err != nil {
			return err
		}
		key, _ := managementKey(kind, id)
		result, err := tx.ExecContext(ctx, "DELETE FROM metadata WHERE key='management_active' AND value=?", key)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("management active transaction binding changed")
		}
		r.Phase = "COMMITTED"
		r.Step++
		return nil
	})
}
