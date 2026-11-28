//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
)

func (s *Store) BeginRootIntent(ctx context.Context, o sharedhost.Ownership, roots []NativeRootIntent) (gvxcontract.RootInitManifest, error) {
	var empty gvxcontract.RootInitManifest
	if err := s.creationOwner(ctx, o); err != nil {
		return empty, err
	}
	if err := s.requireLease(); err != nil {
		return empty, err
	}
	roots = append([]NativeRootIntent(nil), roots...)
	sort.Slice(roots, func(i, j int) bool { return roots[i].Guest.RootID < roots[j].Guest.RootID })
	p := gvxcontract.RootInitPayload{Version: 1, RuntimeInstallationID: o.RuntimeInstallationID, EpochID: o.EpochID, InstanceID: o.InstanceID, IntentID: newID(), Nonce: newID()}
	for _, r := range roots {
		if r.StorageIntentID == "" || r.Native.RootID != r.Guest.RootID || r.Native.HostPath == "" || r.Native.Dev == 0 || r.Native.Ino == 0 || r.Native.UID == 0 || r.Native.GID == 0 {
			return empty, errors.New("missing native root/storage intent identity")
		}
		p.Roots = append(p.Roots, r.Guest)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return empty, err
	}
	m := gvxcontract.RootInitManifest{Digest: gvxcontract.RootDigest(raw), Payload: raw}
	if _, err = gvxcontract.DecodeRootManifest(m, durableJSONMax, 16); err != nil {
		return empty, err
	}
	record := RootIntentRecord{Ownership: o, Manifest: m, Native: roots}
	raw, err = json.Marshal(record)
	if err != nil {
		return empty, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT g.instance,g.record,i.cleanup,e.state FROM guest_root_intents g JOIN instances i ON i.id=g.instance JOIN runtime_epochs e ON e.id=i.epoch WHERE g.revoked=0")
	if err != nil {
		return empty, err
	}
	var revoke []string
	for rows.Next() {
		var instance, cleanup, epochState string
		var priorRaw []byte
		if err = rows.Scan(&instance, &priorRaw, &cleanup, &epochState); err != nil {
			rows.Close()
			return empty, err
		}
		var prior RootIntentRecord
		if err = gvxcontract.DecodeStrict(priorRaw, durableJSONMax, 32, &prior); err != nil {
			rows.Close()
			return empty, err
		}
		for _, old := range prior.Native {
			for _, next := range roots {
				if old.StorageIntentID != next.StorageIntentID {
					continue
				}
				if prior.Confirmed {
					continue
				}
				if cleanup != "COMPLETE" || epochState != "REVOKED" && epochState != "DEAD" || prior.Ownership.EpochID == o.EpochID || prior.Ownership.InstallationID != o.InstallationID || old.Native != next.Native || old.Guest != next.Guest {
					rows.Close()
					return empty, errors.New("pending root rebinding lacks fenced identical durable intent")
				}
				revoke = append(revoke, instance)
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return empty, err
	}
	for _, instance := range revoke {
		if _, err = tx.ExecContext(ctx, "UPDATE guest_root_intents SET revoked=1 WHERE instance=?", instance); err != nil {
			return empty, err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO guest_root_intents(instance,intent,record) VALUES(?,?,?)", o.InstanceID, p.IntentID, raw); err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return m, nil
}
func (s *Store) RootIntent(ctx context.Context, o sharedhost.Ownership) (RootIntentRecord, error) {
	var r RootIntentRecord
	if err := s.creationOwner(ctx, o); err != nil {
		return r, err
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM guest_root_intents WHERE instance=? AND revoked=0", o.InstanceID).Scan(&raw)
	if err == nil {
		err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &r)
	}
	if err == nil && (r.Ownership.RuntimeInstallationID != o.RuntimeInstallationID || r.Ownership.InstallationID != o.InstallationID || r.Ownership.EpochID != o.EpochID || r.Ownership.InstanceID != o.InstanceID) {
		err = errors.New("root intent ownership mismatch")
	}
	return r, err
}
func (s *Store) ConfirmRootIntent(ctx context.Context, o sharedhost.Ownership, result gvxcontract.RootInitResult, native []NativeRootIdentity) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	r, err := s.RootIntent(ctx, o)
	if err != nil {
		return err
	}
	p, err := gvxcontract.DecodeRootManifest(r.Manifest, durableJSONMax, 16)
	if err != nil {
		return err
	}
	if result.Digest != r.Manifest.Digest || result.Nonce != p.Nonce || len(result.Results) != len(p.Roots) || len(native) != len(r.Native) {
		return errors.New("root confirmation binding/count mismatch")
	}
	seen := map[string]bool{}
	expected := map[string]gvxcontract.RootInitEntry{}
	for _, v := range p.Roots {
		expected[v.RootID] = v
	}
	for _, v := range result.Results {
		want, ok := expected[v.RootID]
		if !ok || seen[v.RootID] || v.Step != 2 || v.Observed != want.Target {
			return errors.New("root confirmation does not prove exact target attributes")
		}
		seen[v.RootID] = true
	}
	natives := map[string]NativeRootIdentity{}
	for _, v := range native {
		if _, ok := natives[v.RootID]; ok {
			return errors.New("duplicate native root evidence")
		}
		natives[v.RootID] = v
	}
	for _, v := range r.Native {
		if natives[v.Native.RootID] != v.Native {
			return errors.New("native root identity changed")
		}
	}
	if r.Confirmed {
		prior, _ := json.Marshal(r.Result)
		current, _ := json.Marshal(result)
		if string(prior) != string(current) {
			return errors.New("root confirmation cannot change")
		}
		return nil
	}
	r.Confirmed = true
	r.Result = &result
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "UPDATE guest_root_intents SET record=? WHERE instance=? AND intent=?", raw, o.InstanceID, p.IntentID)
	return err
}

// RetainedRoot returns committed virtual attributes only after the old instance
// has completed native cleanup. Pending initialization is never adopted.
func (s *Store) RetainedRoot(ctx context.Context, installationID, rootID string) (NativeRootIntent, bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT g.record FROM guest_root_intents g JOIN instances i ON i.id=g.instance WHERE i.cleanup='COMPLETE' ORDER BY i.started DESC")
	if err != nil {
		return NativeRootIntent{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return NativeRootIntent{}, false, err
		}
		var r RootIntentRecord
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &r); err != nil {
			return NativeRootIntent{}, false, err
		}
		if r.Ownership.RuntimeInstallationID != s.productID || r.Ownership.InstallationID != installationID || !r.Confirmed {
			continue
		}
		for _, v := range r.Native {
			if v.Guest.RootID == rootID {
				return v, true, nil
			}
		}
	}
	return NativeRootIntent{}, false, rows.Err()
}

func (s *Store) PendingRoot(ctx context.Context, installationID, rootID string) (NativeRootIntent, bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT g.record FROM guest_root_intents g JOIN instances i ON i.id=g.instance JOIN runtime_epochs e ON e.id=i.epoch WHERE g.revoked=0 AND i.cleanup='COMPLETE' AND e.state IN ('REVOKED','DEAD') ORDER BY i.started DESC")
	if err != nil {
		return NativeRootIntent{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return NativeRootIntent{}, false, err
		}
		var r RootIntentRecord
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &r); err != nil {
			return NativeRootIntent{}, false, err
		}
		if r.Ownership.RuntimeInstallationID != s.productID || r.Ownership.InstallationID != installationID || r.Confirmed {
			continue
		}
		for _, v := range r.Native {
			if v.Guest.RootID == rootID {
				return v, true, nil
			}
		}
	}
	return NativeRootIntent{}, false, rows.Err()
}
