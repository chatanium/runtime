//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

func validProvision(kind string, raw []byte) error {
	var p ProvisionProperties
	if err := gvxcontract.DecodeStrict(raw, 64<<10, 16, &p); err != nil {
		return err
	}
	if err := validatePreparationWriterProperties(p); err != nil {
		return err
	}
	return validProvisionShape(kind, raw, p)
}

func validProvisionShape(kind string, raw []byte, p ProvisionProperties) error {
	if len(p.Rejection) > 256 || strings.ContainsAny(p.Rejection, "\x00\r\n") || p.Rejection != "" && p.Exit != nil {
		return invalid("invalid helper rejection evidence")
	}
	if p.Exit != nil && !validProcessExit(*p.Exit) {
		return invalid("invalid native helper exit evidence")
	}
	if err := validateNativePipeIdentities(p.TransportPipes); err != nil {
		return err
	}
	if err := validateNamespaceObservation(p.MountNamespace, p.MountNamespaceDisposition); err != nil {
		return err
	}
	allowed := " product_created "
	if p.Source == "remove" {
		if kind == "shared-network-anchor" || kind == "management-anchor" || !validLedgerID(p.Revision) {
			return invalid("invalid scoped removal intent")
		}
		allowed += "source revision "
	}
	switch kind {
	case "account":
		allowed += "name uid gid "
		if p.Source == "group" {
			allowed += "source "
			if p.Name == "" || p.UID != 0 || p.GID == 0 {
				return invalid("invalid partial group observation")
			}
		}
	case "directory":
		if p.Name == imageCacheExposureName {
			allowed = " product_created name path parent source dev ino uid gid mode "
			if err := validateImageCacheExposureShape(p); err != nil {
				return err
			}
		} else {
			allowed += "path parent uid gid mode dev ino read_only volume "
			if p.Volume != nil && (p.Volume.Dev == 0 || p.Volume.Ino == 0 || p.Volume.XFSUUID == "" || p.Volume.SizeBytes <= 0) {
				return invalid("incomplete native backing association")
			}
			if p.Source == "purge-helper" || p.Source == "remove" && p.Digest != "" {
				allowed += "source digest "
				if err := validatePurgeHelperProperties(kind, p); err != nil {
					return err
				}
			}
		}
	case "shared-network-anchor", "management-anchor":
		allowed += "path parent uid gid mode dev ino digest read_only "
	case "backing":
		allowed += "path size_bytes uuid mode dev ino uid gid source revision "
		if p.Source != "" && p.Source != "remove" && (!strings.HasPrefix(p.Source, "/") || strings.ContainsRune(p.Source, 0) || !validLedgerID(p.Revision)) {
			return invalid("invalid backing snapshot source binding")
		}
	case "loop":
		allowed += "path source dev ino uuid "
	case "mount":
		allowed += "source target uuid read_only dev ino "
	case "unit":
		if p.Path != "" {
			allowed += "path digest uid gid mode dev ino size_bytes "
		} else {
			allowed += "name source revision unit exit cgroup_empty job_path limits ownership rejection transport_pipes absence mount_namespace mount_namespace_disposition writer "
		}
	case "bundle":
		allowed += "path digest dev ino mode uid gid "
		if p.Source == "purge-helper" || p.Parent != "" {
			allowed += "parent source "
			if err := validatePurgeHelperProperties(kind, p); err != nil {
				return err
			}
		}
	case "config", "secret":
		allowed += "path source target digest revision uid gid mode dev ino size_bytes "
		if kind == "config" && p.Parent != "" {
			allowed += "parent "
			if !filepath.IsAbs(p.Parent) || filepath.Clean(p.Parent) != p.Parent || p.Path != filepath.Join(p.Parent, ".bundle-publication.lock") || !validLedgerID(p.Source) || p.Mode != 0600 || p.UID != 0 || p.GID != 0 || p.SizeBytes != 0 || p.Digest != "" || p.Target != "" || p.Source != "remove" && p.Revision != "" {
				return invalid("invalid fixed bundle publication lock")
			}
		}
	case "image":
		allowed += "name path source target digest revision image_space prepare_limits approved_image_input "
		if err := validateImageAcquisitionProperties(p); err != nil {
			return err
		}
	case "development-worker":
		allowed += "name path source target digest revision image_space prepare_limits "
	default:
		return invalid("unknown provisioning kind")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for key := range fields {
		if !strings.Contains(allowed, " "+key+" ") {
			return invalid("field does not belong to provisioning kind")
		}
	}
	return nil
}

const imageCacheExposureName = "image-cache-exposure"

func validateImageCacheExposureShape(p ProvisionProperties) error {
	if p.Name != imageCacheExposureName || !safeID(p.Source) || !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path ||
		!safeID(filepath.Base(p.Path)) || p.Parent != filepath.Dir(p.Path) || filepath.Base(p.Parent) != "prepared" ||
		p.Dev == 0 || p.Ino == 0 || p.UID != 0 || p.GID == 0 || p.Mode != 0710 || !p.ProductCreated {
		return invalid("invalid fixed image cache exposure identity")
	}
	return nil
}

// Exposure observes the same root-created envelope; it creates no new path,
// account, project or executable authority. C owns the native publication barrier.
func (s *Store) validateImageCacheExposureScope(ctx context.Context, tx *sql.Tx, record ProvisionRecord, p ProvisionProperties) error {
	if record.Kind != "directory" || record.Identity != p.Path || !record.ProductCreated || record.ExistedBefore {
		return invalid("cache exposure lacks exact owned directory intent")
	}
	if err := validateImageCacheExposureShape(p); err != nil {
		return err
	}
	source, space, err := preparationSpaceRecord(ctx, tx, p.Source)
	if err != nil {
		return err
	}
	if source.State != "OBSERVED" || source.CleanupState == "COMPLETE" || space.Cache != p.Path || space.JobID != filepath.Base(p.Path) || space.CacheProject == 0 {
		return errors.New("cache exposure lacks its live observed image-space origin")
	}
	manifest, err := readManagementManifest(ctx, tx, s.productID)
	if err != nil {
		return err
	}
	if p.Path != filepath.Join(manifest.Paths.StorageRoot, "prepared", space.JobID) || p.GID != manifest.Identities.App.GID {
		return errors.New("cache exposure differs from installed storage root/runtime group")
	}
	var project uint32
	var state string
	if err = tx.QueryRowContext(ctx, "SELECT project,state FROM storage_claims WHERE id=?", space.JobID+":cache").Scan(&project, &state); err != nil {
		return err
	}
	if project != space.CacheProject || state != "RESERVED" {
		return errors.New("cache exposure project is not its live reserved claim")
	}
	rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='directory' AND identity=? ORDER BY rowid", p.Path)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		var birth ProvisionRecord
		if err = decodeProvisionRecord(raw, &birth); err != nil {
			return err
		}
		if birth.ID == record.ID || birth.State != "OBSERVED" || birth.CleanupState == "COMPLETE" || !birth.ProductCreated || birth.ExistedBefore {
			continue
		}
		var desired, observed ProvisionProperties
		if err = gvxcontract.DecodeStrict(birth.Desired, 64<<10, 16, &desired); err != nil {
			return err
		}
		if desired.Name != "" || desired.Source != "" || desired.Path != p.Path || desired.Parent != p.Parent || desired.UID != 0 || desired.GID != 0 || desired.Mode != 0700 {
			continue
		}
		if err = gvxcontract.DecodeStrict(birth.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return err
		}
		if birth.Identity != p.Path || birth.Observed.Identity != p.Path || observed.Path != p.Path || observed.Parent != p.Parent ||
			observed.UID != 0 || observed.GID != 0 || observed.Mode != 0700 || observed.Dev != p.Dev || observed.Ino != p.Ino {
			return errors.New("cache exposure changed its original private-birth native identity")
		}
		return nil
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return errors.New("cache exposure lacks original root-private observed directory birth")
}
func validatePurgeHelperProperties(kind string, p ProvisionProperties) error {
	if p.Source != "purge-helper" && p.Source != "remove" || len(p.Digest) != 71 || !strings.HasPrefix(p.Digest, "sha256:") || strings.ToLower(p.Digest) != p.Digest {
		return invalid("invalid cleanup-only helper binding")
	}
	if _, err := hex.DecodeString(p.Digest[len("sha256:"):]); err != nil {
		return invalid("invalid cleanup helper bundle digest")
	}
	if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || p.Parent != filepath.Dir(p.Path) || p.UID != 0 || p.GID != 0 {
		return invalid("invalid cleanup-only helper path identity")
	}
	root := p.Path
	if kind == "bundle" {
		if filepath.Base(p.Path) != strings.TrimPrefix(p.Digest, "sha256:") {
			return invalid("cleanup helper bundle path differs from its exact digest")
		}
		root = p.Parent
	}
	if filepath.Base(root) == ".purge-helper" && kind == "directory" {
		return nil
	}
	id := filepath.Base(root)
	if filepath.Base(filepath.Dir(root)) != ".purge-helper" || len(id) != 32 || strings.ToLower(id) != id {
		return invalid("invalid private cleanup helper attempt")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return invalid("invalid private cleanup helper attempt")
	}
	return nil
}
func (s *Store) BeginProvision(ctx context.Context, p ProvisionIntent) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if !validLedgerID(p.ID) || p.Identity == "" || len(p.Identity) > 4096 || p.ExistedBefore && p.ProductCreated {
		return invalid("invalid provisioning intent")
	}
	if err := validProvision(p.Kind, p.Desired); err != nil {
		return err
	}
	var properties ProvisionProperties
	if err := gvxcontract.DecodeStrict(p.Desired, 64<<10, 16, &properties); err != nil {
		return err
	}
	if properties.Absence != nil {
		return errors.New("absence evidence cannot precede native observation")
	}
	if properties.ApprovedImageInput != nil {
		if p.Kind != "image" || p.Identity != properties.ApprovedImageInput.JobID || !p.ProductCreated || p.ExistedBefore {
			return invalid("original image acquisition intent identity differs from approved input")
		}
		if err := s.validateImageAcquisitionScope(ctx, properties); err != nil {
			return err
		}
		records, err := s.ObjectProvisions(ctx, "image", p.Identity)
		if err != nil {
			return err
		}
		if len(records) != 0 {
			original, err := s.ImagePreparationInput(ctx, p.Identity)
			if err != nil {
				return errors.Join(errors.New("existing image job has no adoptable original acquisition input"), err)
			}
			if original != *properties.ApprovedImageInput {
				return errors.New("image job cannot adopt a different acquisition input")
			}
		}
	}
	if p.Kind == "image" && properties.ApprovedImageInput == nil {
		records, err := s.ObjectProvisions(ctx, "image", p.Identity)
		if err != nil {
			return err
		}
		for _, record := range records {
			var original ProvisionProperties
			if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &original); err != nil {
				return err
			}
			if original.ApprovedImageInput != nil {
				return errors.New("an acquisition job cannot become an input-less cache rebuild")
			}
		}
	}
	if properties.Volume != nil {
		m, err := s.Installation(ctx)
		if err != nil {
			return err
		}
		if p.Kind != "directory" || properties.Path != m.Paths.StorageRoot || *properties.Volume != m.Backing {
			return invalid("mounted-root backing association differs from installed native backing")
		}
	}
	if p.Kind == "account" && properties.Source == "group" {
		return invalid("partial group evidence is observation-only")
	}
	if (p.Kind == "directory" || p.Kind == "bundle") && properties.Source == "purge-helper" {
		m, e := s.Installation(ctx)
		if e != nil {
			return e
		}
		container := filepath.Join(m.Paths.Control, ".purge-helper")
		root := properties.Path
		if p.Kind == "bundle" {
			root = properties.Parent
		}
		if properties.Digest != m.BundleDigest || root != container && filepath.Dir(root) != container || p.Kind == "directory" && properties.Mode != 0700 || !p.ProductCreated || p.ExistedBefore {
			return invalid("cleanup helper intent is outside this installation's fixed closure")
		}
	}
	if p.Kind == "config" && properties.Parent != "" && properties.Source != "remove" {
		parent, e := s.Provision(ctx, properties.Source)
		if e != nil {
			return e
		}
		if parent.Kind != "directory" || parent.State != "OBSERVED" || parent.CleanupState == "COMPLETE" || parent.Identity != properties.Parent {
			return invalid("publication lock lacks its live observed parent directory binding")
		}
	}
	if properties.Writer != nil && (properties.Writer.Birth != nil || properties.Writer.Evidence != nil || properties.Writer.StartIntent || properties.Writer.StartForbidden) {
		return invalid("native writer proof cannot precede dispatch intent")
	}
	if p.Kind == "unit" && preparationUnitName(p.Identity) && strings.HasPrefix(p.ID, "systemd-") && properties.Writer == nil {
		return invalid("new preparation dispatch requires current immutable launch intent")
	}
	r := ProvisionRecord{ProvisionIntent: p, State: "INTENT", CleanupState: "PENDING"}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if properties.Writer != nil || p.Kind == "directory" && properties.Name == imageCacheExposureName {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if properties.Writer != nil {
			if err = s.validatePreparationScope(ctx, tx, r, properties, false); err != nil {
				return err
			}
		}
		if p.Kind == "directory" && properties.Name == imageCacheExposureName {
			if err = s.validateImageCacheExposureScope(ctx, tx, r, properties); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO provisioning_ledger VALUES(?,?,?,?)", p.ID, p.Kind, p.Identity, raw); err != nil {
			return err
		}
		return tx.Commit()
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO provisioning_ledger VALUES(?,?,?,?)", p.ID, p.Kind, p.Identity, raw)
	return err
}
func (s *Store) ObserveProvision(ctx context.Context, id string, o ObjectObservation) error {
	return s.changeProvision(ctx, id, func(tx *sql.Tx, r *ProvisionRecord) error {
		if r.CleanupState == "COMPLETE" || o.Identity != r.Identity {
			return errors.New("provision observation identity/state mismatch")
		}
		if err := validProvision(r.Kind, o.Attributes); err != nil {
			return err
		}
		var desired, observed ProvisionProperties
		if err := gvxcontract.DecodeStrict(r.Desired, 64<<10, 16, &desired); err != nil {
			return err
		}
		if err := gvxcontract.DecodeStrict(o.Attributes, 64<<10, 16, &observed); err != nil {
			return err
		}
		if r.Kind == "directory" && (desired.Name == imageCacheExposureName || observed.Name == imageCacheExposureName) {
			if desired.Name != imageCacheExposureName || observed.Name != imageCacheExposureName ||
				desired.Source != observed.Source || desired.Path != observed.Path || desired.Parent != observed.Parent ||
				desired.Dev != observed.Dev || desired.Ino != observed.Ino || desired.UID != observed.UID || desired.GID != observed.GID ||
				desired.Mode != observed.Mode || desired.ProductCreated != observed.ProductCreated {
				return errors.New("cache exposure observation changed its exact publication intent")
			}
			if err := s.validateImageCacheExposureScope(ctx, tx, *r, observed); err != nil {
				return err
			}
		}
		var old ProvisionProperties
		if r.State == "OBSERVED" {
			if err := gvxcontract.DecodeStrict(r.Observed.Attributes, 64<<10, 16, &old); err != nil {
				return err
			}
		}
		if err := s.mergePreparationObservation(ctx, tx, *r, desired, old, &observed); err != nil {
			return err
		}
		if observed.Writer != nil {
			raw, err := jsonPreparationProperties(observed)
			if err != nil {
				return err
			}
			o.Attributes = raw
		}
		if desired.ApprovedImageInput != nil || observed.ApprovedImageInput != nil {
			if desired.ApprovedImageInput == nil || observed.ApprovedImageInput == nil || *desired.ApprovedImageInput != *observed.ApprovedImageInput {
				return errors.New("original image acquisition input cannot be introduced, replaced or discarded by observation")
			}
		}
		if desired.Volume != nil || observed.Volume != nil {
			if desired.Volume == nil || observed.Volume == nil || *desired.Volume != *observed.Volume || desired.Path != observed.Path {
				return errors.New("mounted-root observation changed its native backing association")
			}
		}
		if r.Kind == "account" {
			if observed.Name != desired.Name || observed.GID != desired.GID || observed.Source == "group" && (!r.ProductCreated || r.ExistedBefore || desired.Source != "" || desired.UID == 0 || observed.UID != 0) || observed.Source != "group" && observed.UID != desired.UID {
				return errors.New("account/group observation differs from approved numeric identity")
			}
		}
		if observed.Source == "purge-helper" && (desired.Source != observed.Source || desired.Path != observed.Path || desired.Parent != observed.Parent || desired.Digest != observed.Digest) {
			return errors.New("cleanup-only helper observation differs from its fixed intent")
		}
		if len(desired.TransportPipes) != 0 && !slices.Equal(desired.TransportPipes, observed.TransportPipes) {
			return errors.New("transport pipe observations differ from durable dispatch intent")
		}
		if observed.Absence != nil && r.State != "OBSERVED" {
			return errors.New("unobserved invocation cannot acquire absence evidence")
		}
		if r.State == "OBSERVED" {
			next := observed
			if old.Unit != nil && (next.Unit == nil || *old.Unit != *next.Unit) || old.Exit != nil && (next.Exit == nil || *old.Exit != *next.Exit) || old.Dev != 0 && next.Dev != old.Dev || old.Ino != 0 && next.Ino != old.Ino {
				return errors.New("observed native identity/terminal result cannot change")
			}
			if old.Rejection != "" && old.Rejection != next.Rejection || old.Ownership != nil && (next.Ownership == nil || *old.Ownership != *next.Ownership) {
				return errors.New("observed helper ownership/rejection cannot change")
			}
			if len(old.TransportPipes) != 0 && !slices.Equal(old.TransportPipes, next.TransportPipes) {
				return errors.New("observed native transport pipes cannot change")
			}
			if err := validateNamespaceTransition(old.MountNamespace, old.MountNamespaceDisposition, next.MountNamespace, next.MountNamespaceDisposition); err != nil {
				return err
			}
			if next.Absence != nil {
				if old.Unit == nil || !validUnit(*old.Unit) || old.Rejection != "" || next.Unit == nil || *next.Unit != *old.Unit || !equalProcessExit(old.Exit, next.Exit) || old.JobPath != next.JobPath || !next.CgroupEmpty {
					return errors.New("absence evidence cannot replace native invocation/result fields")
				}
				if err := validateUnitAbsenceEvidence(*old.Unit, old.TransportPipes, old.MountNamespace, old.MountNamespaceDisposition, *next.Absence); err != nil {
					return err
				}
			} else if old.Absence != nil {
				return errors.New("observed absence evidence cannot be discarded")
			}
		}
		r.Observed = o
		r.State = "OBSERVED"
		return nil
	})
}
func (s *Store) CompleteProvisionCleanup(ctx context.Context, id string, e CleanupEvidence) error {
	if record, err := s.Provision(ctx, id); err != nil {
		return err
	} else if record.Kind == "management-anchor" {
		return errors.New("shared management anchor is retained infrastructure")
	}
	return s.changeProvision(ctx, id, func(tx *sql.Tx, r *ProvisionRecord) error {
		mounts, quota := false, false
		switch r.Kind {
		case "image", "development-worker":
			mounts = true
			quota = true
		case "mount", "loop", "backing":
			mounts = true
		}
		if err := validateScopedCleanup(e, mounts, quota); err != nil {
			return err
		}
		if r.Kind == "unit" && r.State == "OBSERVED" {
			var p ProvisionProperties
			if err := gvxcontract.DecodeStrict(r.Observed.Attributes, 64<<10, 16, &p); err != nil {
				return err
			}
			if p.Unit != nil {
				found := false
				for _, u := range e.Units {
					if u == *p.Unit {
						found = true
					}
				}
				if !found {
					return errors.New("unit cleanup evidence has different invocation")
				}
			}
		}
		if err := s.validatePreparationCompletion(ctx, tx, *r, e); err != nil {
			return err
		}
		r.CleanupState = "COMPLETE"
		return nil
	})
}
func (s *Store) changeProvision(ctx context.Context, id string, fn func(*sql.Tx, *ProvisionRecord) error) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", id).Scan(&raw); err != nil {
		return err
	}
	var r ProvisionRecord
	if err = decodeProvisionRecord(raw, &r); err != nil {
		return err
	}
	if err = fn(tx, &r); err != nil {
		return err
	}
	raw, err = json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", raw, id); err != nil {
		return err
	}
	return tx.Commit()
}
func decodeProvisionRecord(raw []byte, r *ProvisionRecord) error {
	// Embedded intent fields are flattened by encoding/json. Decode through an
	// explicitly flattened closed shape to retain strict field matching.
	var v struct {
		ID             string            `json:"id"`
		Kind           string            `json:"kind"`
		Identity       string            `json:"identity"`
		ExistedBefore  bool              `json:"existed_before"`
		ProductCreated bool              `json:"product_created"`
		Desired        []byte            `json:"desired"`
		Observed       ObjectObservation `json:"observed"`
		State          string            `json:"state"`
		CleanupState   string            `json:"cleanup_state"`
		FirstFailure   string            `json:"first_failure"`
	}
	if err := gvxcontract.DecodeStrict(raw, durableJSONMax, 16, &v); err != nil {
		return err
	}
	*r = ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: v.ID, Kind: v.Kind, Identity: v.Identity, ExistedBefore: v.ExistedBefore, ProductCreated: v.ProductCreated, Desired: v.Desired}, Observed: v.Observed, State: v.State, CleanupState: v.CleanupState, FirstFailure: v.FirstFailure}
	return nil
}
func (s *Store) PendingProvisions(ctx context.Context) ([]ProvisionRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM provisioning_ledger ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProvisionRecord
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r ProvisionRecord
		if err = decodeProvisionRecord(raw, &r); err != nil {
			return nil, err
		}
		if r.CleanupState != "COMPLETE" {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}
func unitObjectID(u UnitIdentity) string { return u.Generation + ":" + u.InvocationID }
func validUnit(u UnitIdentity) bool {
	return u.Name != "" && u.Generation != "" && u.InvocationID != "" && u.BootID != "" && u.CgroupPath != "" && u.ExecutableDigest != "" && u.ResourceFingerprint != "" && u.MainPID > 0 && u.StartTime > 0
}
func (s *Store) RecordUnit(ctx context.Context, o Ownership, v UnitObservation) error {
	if v.Writer != nil {
		return invalid("preparation writer evidence cannot authorize a module unit")
	}
	if err := validateNamespaceObservation(v.MountNamespace, v.MountNamespaceDisposition); err != nil {
		return err
	}
	if v.Exit != nil && !validProcessExit(*v.Exit) {
		return errors.New("invalid observed native exit evidence")
	}
	if err := s.creationOwner(ctx, o); err != nil {
		return err
	}
	if !validUnit(v.Unit) || o.Unit.Name != "" && o.Unit != v.Unit {
		return errors.New("invalid observed unit identity")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var identity, state, object string
	if err = tx.QueryRowContext(ctx, "SELECT identity,state,object_id FROM create_submissions WHERE instance=? AND kind='service'", o.InstanceID).Scan(&identity, &state, &object); err != nil {
		return err
	}
	if identity != v.Unit.Name || state == string(CreateRejected) || state == string(CreateObserved) && object != unitObjectID(v.Unit) {
		return errors.New("unit observation does not resolve submitted service")
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, "SELECT record FROM unit_observations WHERE instance=?", o.InstanceID).Scan(&previous)
	if err == nil {
		var old UnitObservation
		if err = gvxcontract.DecodeStrict(previous, durableJSONMax, 24, &old); err != nil {
			return err
		}
		if old.Unit != v.Unit {
			return errors.New("unit invocation replacement forbidden")
		}
		if err = validateNamespaceTransition(old.MountNamespace, old.MountNamespaceDisposition, v.MountNamespace, v.MountNamespaceDisposition); err != nil {
			return err
		}
		if old.Exit != nil && !equalProcessExit(old.Exit, v.Exit) {
			return errors.New("terminal unit evidence cannot change")
		}
		if old.Absence != nil {
			if !v.CgroupEmpty {
				return errors.New("absence-fenced invocation cannot regain resources")
			}
			if v.Absence != nil {
				a, _ := json.Marshal(old.Absence)
				b, _ := json.Marshal(v.Absence)
				if string(a) != string(b) {
					return errors.New("use scoped absence recorder to change evidence")
				}
			}
			v.Absence = old.Absence
		} else if v.Absence != nil {
			return errors.New("absence evidence requires scoped prior-observation validation")
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	} else if v.Absence != nil {
		return errors.New("unobserved invocation cannot acquire absence evidence")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO unit_observations VALUES(?,?,?,?) ON CONFLICT(instance) DO UPDATE SET record=excluded.record", o.InstanceID, v.Unit.Generation, v.Unit.InvocationID, raw); err != nil {
		return err
	}
	var leaseRaw []byte
	if err = tx.QueryRowContext(ctx, "SELECT lease FROM instances WHERE id=?", o.InstanceID).Scan(&leaseRaw); err != nil {
		return err
	}
	var l Lease
	if err = gvxcontract.DecodeStrict(leaseRaw, durableJSONMax, 24, &l); err != nil {
		return err
	}
	l.Ownership.Unit = v.Unit
	leaseRaw, err = json.Marshal(l)
	if err != nil {
		return err
	}
	for _, q := range []struct {
		q    string
		args []any
	}{
		{"UPDATE instances SET lease=?,state=CASE WHEN state='PREPARING' AND reason='' THEN 'CREATED' ELSE state END WHERE id=?", []any{leaseRaw, o.InstanceID}},
		{"UPDATE create_submissions SET state='OBSERVED',object_id=? WHERE instance=? AND kind='service'", []any{unitObjectID(v.Unit), o.InstanceID}},
		{"UPDATE resource_claims SET identity=?,state='ALLOCATED' WHERE instance=? AND kind='service'", []any{unitObjectID(v.Unit), o.InstanceID}},
	} {
		if _, err = tx.ExecContext(ctx, q.q, q.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Unit(ctx context.Context, o Ownership) (UnitObservation, error) {
	var v UnitObservation
	if err := s.creationOwner(ctx, o); err != nil {
		return v, err
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM unit_observations WHERE instance=?", o.InstanceID).Scan(&raw)
	if err == nil {
		err = gvxcontract.DecodeStrict(raw, durableJSONMax, 24, &v)
	}
	if err == nil && o.Unit.Name != "" && o.Unit != v.Unit {
		err = errors.New("unit ownership mismatch")
	}
	return v, err
}
func (s *Store) RecordUnitExit(ctx context.Context, o Ownership, u UnitIdentity, e ProcessExit) error {
	if e.Kind != "exit" && e.Kind != "signal" || e.Kind == "signal" && (e.Value == 0 || e.Value > 64) || e.Kind == "exit" && e.Value > 255 {
		return errors.New("invalid native exit evidence")
	}
	v, err := s.Unit(ctx, o)
	if err != nil {
		return err
	}
	if v.Unit != u {
		return errors.New("terminal invocation identity mismatch")
	}
	v.Exit = &e
	return s.RecordUnit(ctx, o, v)
}
func (s *Store) ReserveNetwork(ctx context.Context, o Ownership, n NetworkRecord) error {
	if err := s.creationOwner(ctx, o); err != nil {
		return err
	}
	l, _, err := s.lease(ctx, o.EpochID, o.InstanceID)
	if err != nil {
		return err
	}
	var boot string
	if err = s.db.QueryRowContext(ctx, "SELECT boot_id FROM runtime_epochs WHERE id=?", o.EpochID).Scan(&boot); err != nil {
		return err
	}
	if n.Generation != l.NetworkGeneration || n.Profile != l.Topology || n.BootID == "" || n.BootID != boot {
		return errors.New("network reservation differs from fixed lease/boot")
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	if len(raw) > durableJSONMax {
		return errors.New("network record exceeds metadata bound")
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO network_records VALUES(?,?,?)", o.InstanceID, n.Generation, raw)
	return err
}
func (s *Store) RecordNetwork(ctx context.Context, o Ownership, n NetworkRecord) error {
	if err := s.creationOwner(ctx, o); err != nil {
		return err
	}
	if (n.NetnsPlaceholderDev == 0) != (n.NetnsPlaceholderIno == 0) || (n.NetnsDev == 0) != (n.NetnsIno == 0) {
		return errors.New("incomplete native namespace identity pair")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous []byte
	if err = tx.QueryRowContext(ctx, "SELECT record FROM network_records WHERE instance=?", o.InstanceID).Scan(&previous); err != nil {
		return err
	}
	var old NetworkRecord
	if err = gvxcontract.DecodeStrict(previous, durableJSONMax, 24, &old); err != nil {
		return err
	}
	if old.Generation != n.Generation || old.Profile != n.Profile || old.BootID != n.BootID || old.IPv4Prefix != n.IPv4Prefix || old.IPv6Prefix != n.IPv6Prefix {
		return errors.New("network allocation/profile/boot mutation forbidden")
	}
	if old.NetnsPath != "" && old.NetnsPath != n.NetnsPath || old.NetnsPlaceholderDev != 0 && (old.NetnsPlaceholderDev != n.NetnsPlaceholderDev || old.NetnsPlaceholderIno != n.NetnsPlaceholderIno) || old.NetnsDev != 0 && (old.NetnsDev != n.NetnsDev || old.NetnsIno != n.NetnsIno) {
		return errors.New("observed native namespace identity cannot change")
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	if len(raw) > durableJSONMax {
		return errors.New("network record exceeds metadata bound")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE network_records SET record=? WHERE instance=? AND generation=?", raw, o.InstanceID, n.Generation); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Network(ctx context.Context, o Ownership) (NetworkRecord, error) {
	var n NetworkRecord
	if err := s.creationOwner(ctx, o); err != nil {
		return n, err
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM network_records WHERE instance=?", o.InstanceID).Scan(&raw)
	if err == nil {
		err = gvxcontract.DecodeStrict(raw, durableJSONMax, 24, &n)
	}
	return n, err
}
func (s *Store) RecordEndpoint(ctx context.Context, o Ownership, e EndpointIdentity) error {
	if err := s.creationOwner(ctx, o); err != nil {
		return err
	}
	if e.Directory == "" || !strings.HasPrefix(e.Path, e.Directory+"/") || e.DirectoryDev == 0 || e.DirectoryIno == 0 || e.SocketDev == 0 || e.SocketIno == 0 {
		return fmt.Errorf("invalid native endpoint identity")
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO native_endpoints(instance,record) VALUES(?,?)", o.InstanceID, raw)
	return err
}
func (s *Store) endpointTransfer(ctx context.Context, id string, sent bool) error {
	state := "UNKNOWN"
	if sent {
		state = "SENT"
	}
	_, err := s.db.ExecContext(ctx, "UPDATE native_endpoints SET transfer_state=? WHERE instance=? AND transports_closed=0", state, id)
	return err
}

func validLedgerID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

func (s *Store) RecordProvisionFailure(ctx context.Context, id string, reason FailureReason) error {
	if !validFailureReason(reason) {
		return invalid("invalid provisioning failure code")
	}
	return s.changeProvision(ctx, id, func(_ *sql.Tx, r *ProvisionRecord) error {
		if r.FirstFailure == "" {
			r.FirstFailure = string(reason)
		}
		return nil
	})
}

func validProcessExit(e ProcessExit) bool {
	return e.Kind == "exit" && e.Value <= 255 || e.Kind == "signal" && e.Value > 0 && e.Value <= 64
}

func (s *Store) UnitProvisions(ctx context.Context, name string) ([]ProvisionRecord, error) {
	if err := s.requireLease(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='unit' AND identity=? ORDER BY rowid", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ProvisionRecord
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var record ProvisionRecord
		if err = decodeProvisionRecord(raw, &record); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

// Provision includes completed history so removal recovery can verify the exact
// original observation after its owned pathname has already been unlinked.
func (s *Store) Provision(ctx context.Context, id string) (ProvisionRecord, error) {
	var record ProvisionRecord
	if !validLedgerID(id) {
		return record, invalid("invalid provisioning record ID")
	}
	if _, err := s.Installation(ctx); err != nil {
		return record, err
	}
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", id).Scan(&raw); err != nil {
		return record, err
	}
	if err := decodeProvisionRecord(raw, &record); err != nil {
		return record, err
	}
	if record.ID != id {
		return record, errors.New("provisioning record identity mismatch")
	}
	if record.State == "OBSERVED" && record.Observed.Identity != record.Identity {
		return record, errors.New("provisioning observation identity mismatch")
	}
	validation := validProvision(record.Kind, record.Desired)
	if validation == nil && record.State == "OBSERVED" {
		validation = validProvision(record.Kind, record.Observed.Attributes)
	}
	if validation != nil {
		if err := s.validateUnsupportedPreparationHistory(ctx, record); err != nil {
			return record, errors.Join(validation, err)
		}
	}
	return record, nil
}

func (s *Store) ObjectProvisions(ctx context.Context, kind, identity string) ([]ProvisionRecord, error) {
	if kind == "" || identity == "" || len(identity) > 4096 {
		return nil, invalid("invalid exact provisioning object lookup")
	}
	if _, err := s.Installation(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind=? AND identity=? ORDER BY rowid", kind, identity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []ProvisionRecord
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r ProvisionRecord
		if err = decodeProvisionRecord(raw, &r); err != nil {
			return nil, err
		}
		if r.Kind != kind || r.Identity != identity {
			return nil, errors.New("provisioning object lookup identity mismatch")
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func validateNativePipeIdentities(identities []string) error {
	if len(identities) > 3 {
		return invalid("too many native transport pipe identities")
	}
	for _, identity := range identities {
		if len(identity) >= 64 || !strings.HasPrefix(identity, "pipe:[") || !strings.HasSuffix(identity, "]") {
			return invalid("invalid native transport pipe identity")
		}
		raw := identity[len("pipe:[") : len(identity)-1]
		inode, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || inode == 0 || strconv.FormatUint(inode, 10) != raw {
			return invalid("noncanonical native transport pipe identity")
		}
	}
	return nil
}
func equalProcessExit(a, b *ProcessExit) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func validateUnitAbsenceEvidence(unit UnitIdentity, pipes []string, namespace *NamespaceIdentity, disposition string, e CleanupEvidence) error {
	if !validUnit(unit) || len(e.Units) != 1 || e.Units[0] != unit {
		return errors.New("absence evidence must identify one exact previously observed invocation")
	}
	if err := validateScopedCleanup(e, true, false); err != nil {
		return err
	}
	if unit.BootID == e.BootID && (namespace == nil || namespace.Device == 0 || namespace.Inode == 0 || disposition != NamespacePrivate && disposition != NamespaceSharedHost) {
		return errors.New("same-boot absence requires captured native mount namespace identity and explicit disposition")
	}
	if err := validateNamespaceObservation(namespace, disposition); err != nil {
		return err
	}
	var details UnitAbsenceDetails
	if err := gvxcontract.DecodeStrict(e.Details, 64<<10, 8, &details); err != nil {
		return err
	}
	if !details.UnitAbsent || !details.CgroupEmpty || !slices.Equal(details.TransportPipes, pipes) {
		return errors.New("unit/cgroup/transport absence evidence does not match saved identities")
	}
	if details.WriterUserNamespace != nil || details.WriterUserNamespaceAbsent {
		if details.WriterUserNamespace == nil || !details.WriterUserNamespaceAbsent || !validPreparationNamespace(*details.WriterUserNamespace) {
			return invalid("incomplete preparation writer user namespace absence evidence")
		}
	}
	return validateNativePipeIdentities(details.TransportPipes)
}

func (s *Store) RecordUnitAbsence(ctx context.Context, o Ownership, unit UnitIdentity, e CleanupEvidence) error {
	if err := s.creationOwner(ctx, o); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state, object string
	if err = tx.QueryRowContext(ctx, "SELECT state,object_id FROM create_submissions WHERE instance=? AND kind='service'", o.InstanceID).Scan(&state, &object); err != nil {
		return err
	}
	if state != string(CreateObserved) || object != unitObjectID(unit) {
		return ErrCreateUnresolved
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT record FROM unit_observations WHERE instance=?", o.InstanceID).Scan(&raw); err != nil {
		return err
	}
	var observed UnitObservation
	if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 24, &observed); err != nil {
		return err
	}
	if observed.Unit != unit || o.Unit.Name != "" && o.Unit != unit {
		return errors.New("absence evidence changed observed invocation identity")
	}
	if observed.Exit != nil {
		return errors.New("native exit is already recorded; use normal terminal settlement")
	}
	rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='unit' AND identity=?", unit.Name)
	if err != nil {
		return err
	}
	var pipes []string
	for rows.Next() {
		var value []byte
		if err = rows.Scan(&value); err != nil {
			rows.Close()
			return err
		}
		var record ProvisionRecord
		if err = decodeProvisionRecord(value, &record); err != nil {
			rows.Close()
			return err
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			rows.Close()
			return err
		}
		if desired.Unit == nil || desired.Unit.Name != unit.Name || desired.Unit.Generation != unit.Generation || desired.Unit.BootID != unit.BootID || len(desired.TransportPipes) == 0 {
			continue
		}
		if pipes != nil && !slices.Equal(pipes, desired.TransportPipes) {
			rows.Close()
			return errors.New("conflicting saved invocation pipe identities")
		}
		pipes = desired.TransportPipes
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(pipes) == 0 {
		return errors.New("module invocation lacks durable pre-dispatch pipe identity evidence")
	}
	if err = validateUnitAbsenceEvidence(unit, pipes, observed.MountNamespace, observed.MountNamespaceDisposition, e); err != nil {
		return err
	}
	observed.Absence = &e
	observed.CgroupEmpty = true
	raw, err = json.Marshal(observed)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE unit_observations SET record=? WHERE instance=? AND generation=? AND invocation=?", raw, o.InstanceID, unit.Generation, unit.InvocationID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE instances SET state='CLEANUP_PENDING',reason=CASE WHEN reason='' THEN ? ELSE reason END WHERE id=? AND cleanup!='COMPLETE'", string(PhaseRunning)+":"+string(FailureOutcomeUnknown), o.InstanceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UnitAbsence(ctx context.Context, o Ownership) (CleanupEvidence, error) {
	observed, err := s.Unit(ctx, o)
	if err != nil {
		return CleanupEvidence{}, err
	}
	if observed.Absence == nil {
		return CleanupEvidence{}, sql.ErrNoRows
	}
	var details UnitAbsenceDetails
	if err = gvxcontract.DecodeStrict(observed.Absence.Details, 64<<10, 8, &details); err != nil {
		return CleanupEvidence{}, err
	}
	if !observed.CgroupEmpty {
		return CleanupEvidence{}, errors.New("stored absence evidence lacks empty cgroup observation")
	}
	if err = validateUnitAbsenceEvidence(observed.Unit, details.TransportPipes, observed.MountNamespace, observed.MountNamespaceDisposition, *observed.Absence); err != nil {
		return CleanupEvidence{}, err
	}
	return *observed.Absence, nil
}

func validateNamespaceObservation(namespace *NamespaceIdentity, disposition string) error {
	if disposition != "" && disposition != NamespacePrivate && disposition != NamespaceSharedHost {
		return errors.New("unknown native mount namespace disposition")
	}
	if namespace != nil && (namespace.Device == 0 || namespace.Inode == 0 || disposition == "") {
		return errors.New("incomplete captured native mount namespace identity")
	}
	return nil
}
func validateNamespaceTransition(old *NamespaceIdentity, oldDisposition string, next *NamespaceIdentity, nextDisposition string) error {
	if err := validateNamespaceObservation(next, nextDisposition); err != nil {
		return err
	}
	if oldDisposition != "" && oldDisposition != nextDisposition || old != nil && (next == nil || *old != *next) {
		return errors.New("captured native mount namespace identity/disposition cannot change")
	}
	return nil
}
