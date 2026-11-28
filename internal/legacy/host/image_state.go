//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

func (s *Store) StoreImage(ctx context.Context, r provision.ImageRecord) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if r.Version != 1 || r.ID == "" || r.ConfigDigest == "" || r.ManifestDigest == "" || r.CanonicalArchiveDigest == "" || r.ExecutionRef == "" || len(r.Config) == 0 || len(r.Declaration) == 0 {
		return errors.New("incomplete immutable image record")
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	if err = provision.ValidateRecord(r, provision.PrepareLimits{JSONBytes: durableJSONMax, InputBytes: m.Budget.SourceBytes, DescriptorCount: 4096, IndexDepth: 32}); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > durableJSONMax {
		return errors.New("image record exceeds bound")
	}
	if err = s.CheckGenerationAvailable(ctx, r.ID); err != nil {
		return err
	}
	return s.insertImmutable(ctx, "image_records", r.ID, raw)
}
func (s *Store) insertImmutable(ctx context.Context, table, id string, raw []byte) error {
	var old []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM "+table+" WHERE id=?", id).Scan(&old)
	if err == nil {
		if string(old) != string(raw) {
			return errors.New("immutable record identity reuse")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO "+table+"(id,record) VALUES(?,?)", id, raw)
	return err
}
func (s *Store) Image(ctx context.Context, id string) (provision.ImageRecord, error) {
	var r provision.ImageRecord
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM image_records WHERE id=?", id).Scan(&raw)
	if err == nil {
		err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &r)
	}
	return r, err
}
func (s *Store) PublishCache(ctx context.Context, c CacheGeneration) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	r, err := s.Image(ctx, c.ImageRecordID)
	if err != nil {
		return err
	}
	if c.ID == "" || c.State != "READY" || c.Directory == "" || c.InventoryDigest == "" || c.BundleDigest == "" || c.CanonicalArchiveDigest != r.CanonicalArchiveDigest || c.ManifestDigest != r.ManifestDigest || len(c.Files) == 0 {
		return errors.New("incomplete verified cache generation")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if len(raw) > durableJSONMax {
		return errors.New("cache inventory exceeds metadata bound")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, generation := range []string{c.ID, r.ID, c.BundleDigest} {
		if err = checkGenerationAvailableTx(ctx, tx, generation); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT record FROM cache_generations WHERE image=?", c.ImageRecordID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var oldRaw []byte
		if err = rows.Scan(&oldRaw); err != nil {
			rows.Close()
			return err
		}
		var old CacheGeneration
		if err = gvxcontract.DecodeStrict(oldRaw, durableJSONMax, 32, &old); err != nil {
			rows.Close()
			return err
		}
		if old.ID == c.ID {
			rows.Close()
			if string(oldRaw) != string(raw) {
				return errors.New("cache generation identity reuse")
			}
			return tx.Commit()
		}
		if old.BundleDigest == c.BundleDigest && old.State == "READY" {
			rows.Close()
			return errors.New("image already has a committed generation for this bundle")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO cache_generations VALUES(?,?,?)", c.ID, c.ImageRecordID, raw); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Cache(ctx context.Context, id string) (CacheGeneration, error) {
	var c CacheGeneration
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM cache_generations WHERE id=?", id).Scan(&raw)
	if err == nil {
		err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &c)
	}
	return c, err
}
func (s *Store) RetainGeneration(ctx context.Context, kind, id, claim string) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = retainGenerationTx(ctx, tx, kind, id, claim); err != nil {
		return err
	}
	return tx.Commit()
}
func retainGenerationTx(ctx context.Context, tx *sql.Tx, kind, id, claim string) error {
	if (kind != "live" && kind != "recovery" && kind != "preparation") || id == "" || claim == "" {
		return invalid("invalid generation reference")
	}
	check := checkGenerationAvailableTx
	if kind == "recovery" {
		check = checkGenerationRetainableTx
	}
	if err := check(ctx, tx, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO generation_references VALUES(?,?,?)", kind, id, claim)
	return err
}
func (s *Store) ReleaseGeneration(ctx context.Context, kind, id, claim string, e CleanupEvidence) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if kind != "live" && kind != "recovery" && kind != "preparation" {
		return invalid("invalid generation reference kind")
	}
	if err := validateScopedCleanup(e, true, kind != "preparation"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM generation_references WHERE kind=? AND id=? AND claim=?", kind, id, claim)
	return err
}
func (s *Store) resolveLeaseImage(ctx context.Context, tx *sql.Tx, l *sharedhost.Lease) error {
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT manifest FROM runtime_installations WHERE id=?", s.productID).Scan(&raw); err != nil {
		return err
	}
	var m InstallationManifest
	if err := gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &m); err != nil {
		return err
	}
	if m.State != "READY" || m.DesiredRunState != "RUNNING" {
		return errors.New("installation does not admit runtime instances")
	}
	if err := tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", m.ActiveRevision).Scan(&raw); err != nil {
		return err
	}
	var r RevisionRecord
	if err := gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &r); err != nil {
		return err
	}
	var policy sharedhost.LaunchSpec
	for _, b := range r.Images {
		if b.ModuleID == l.Spec.ModuleID && b.ImageSelector == l.Spec.ImageDigest && b.ConfigRevision == l.Spec.ConfigRevision && b.ApprovalRevision == l.Spec.ApprovalRevision {
			if l.ImageRecordID != "" {
				return errors.New("ambiguous image approval binding")
			}
			l.ImageRecordID = b.ImageRecordID
			for _, p := range r.LaunchPolicies {
				if policyMatchesBinding(p, b) {
					if policy.ModuleID != "" {
						return errors.New("ambiguous approved launch policy")
					}
					policy = p
				}
			}
		}
	}
	if l.ImageRecordID == "" {
		var candidate, approved []byte
		err := tx.QueryRowContext(ctx, "SELECT binding,policy FROM approved_image_candidates WHERE revision=? AND module=? AND selector=?", m.ActiveRevision, l.Spec.ModuleID, l.Spec.ImageDigest).Scan(&candidate, &approved)
		if err != nil {
			return errors.Join(errors.New("image selector is not committed in current approval"), err)
		}
		var b ApprovedImageBinding
		if err = gvxcontract.DecodeStrict(candidate, 64<<10, 8, &b); err != nil {
			return err
		}
		if err = gvxcontract.DecodeStrict(approved, revisionJSONMax, 16, &policy); err != nil {
			return err
		}
		if !policyMatchesBinding(policy, b) {
			return errors.New("candidate policy binding mismatch")
		}
		l.ImageRecordID = b.ImageRecordID
	}
	if err := validateLaunchRequest(l.Spec, policy); err != nil {
		return err
	}
	if policy.InitialEgress == sharedhost.EgressPublicInternet && l.Topology != r.PublicProfile {
		return errors.New("lease topology differs from installed family approval")
	}
	rows, err := tx.QueryContext(ctx, "SELECT record FROM cache_generations WHERE image=?", l.ImageRecordID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var c CacheGeneration
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &c); err != nil {
			rows.Close()
			return err
		}
		if c.State == "READY" && c.BundleDigest == m.BundleDigest {
			if l.CacheGenerationID != "" {
				rows.Close()
				return errors.New("ambiguous cache generation")
			}
			l.CacheGenerationID = c.ID
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if l.CacheGenerationID == "" {
		return errors.New("approved image has no published compatible cache")
	}
	for _, id := range []string{l.ImageRecordID, l.CacheGenerationID, m.BundleDigest} {
		if err = retainGenerationTx(ctx, tx, "live", id, l.Spec.InstanceID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GenerationReferences(ctx context.Context) ([]GenerationReference, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT kind,id,claim FROM generation_references ORDER BY kind,id,claim")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []GenerationReference
	for rows.Next() {
		var r GenerationReference
		if err = rows.Scan(&r.Kind, &r.ID, &r.Claim); err != nil {
			return nil, err
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

func (s *Store) AuthorizePreparedCandidate(ctx context.Context, b ApprovedImageBinding, policy sharedhost.LaunchSpec) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if err := ValidateLaunchPolicy(policy); err != nil {
		return err
	}
	if !policyMatchesBinding(policy, b) {
		return errors.New("candidate policy binding mismatch")
	}
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	m, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	if m.State != "READY" {
		return errors.New("candidate preparation requires READY installation")
	}
	revision, err := s.Revision(ctx, m.ActiveRevision)
	if err != nil {
		return err
	}
	record, err := s.Image(ctx, b.ImageRecordID)
	if err != nil {
		return err
	}
	if err = s.CheckGenerationAvailable(ctx, b.ImageRecordID); err != nil {
		return err
	}
	expectedSelector := "record:" + record.ID
	if record.SourceKind == "registry" {
		expectedSelector = record.SourceRef
	}
	if b.ImageSelector != expectedSelector {
		return errors.New("candidate selector does not identify committed record")
	}
	matched := false
	for _, base := range revision.Images {
		if base.ModuleID != b.ModuleID || base.ConfigRevision != b.ConfigRevision || base.ApprovalRevision != b.ApprovalRevision {
			continue
		}
		original, e := s.Image(ctx, base.ImageRecordID)
		if e != nil {
			return e
		}
		if original.SourceKind != record.SourceKind {
			return errors.New("candidate cannot change installed source kind")
		}
		if record.SourceKind == "registry" {
			approvedRepository, _, exact := strings.Cut(base.ImageSelector, "@")
			repository, _, candidateExact := strings.Cut(b.ImageSelector, "@")
			if !exact || !candidateExact || approvedRepository != repository {
				return errors.New("candidate repository differs from installed approval")
			}
		}
		for _, ceiling := range revision.LaunchPolicies {
			if !policyMatchesBinding(ceiling, base) {
				continue
			}
			if policy.UID != ceiling.UID || policy.GID != ceiling.GID || policy.InitialEgress != ceiling.InitialEgress || !resourcesWithin(policy.Resources, ceiling.Resources) {
				return errors.New("candidate increases installed guest authority or resource ceiling")
			}
			matched = true
		}
	}
	if !matched {
		return errors.New("candidate module/revisions lack current installed launch policy")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM cache_generations WHERE image=?", b.ImageRecordID)
	if err != nil {
		return err
	}
	var caches []string
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var c CacheGeneration
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &c); err != nil {
			rows.Close()
			return err
		}
		if c.State == "READY" && c.BundleDigest == m.BundleDigest {
			caches = append(caches, c.ID)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(caches) != 1 {
		return errors.New("candidate requires one published compatible generation")
	}
	cache, err := s.Cache(ctx, caches[0])
	if err != nil {
		return err
	}
	if err = s.requireCommittedImageCacheWriter(ctx, record, cache, nil); err != nil {
		return err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	approved, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range []string{b.ImageRecordID, caches[0], m.BundleDigest} {
		if err = checkGenerationAvailableTx(ctx, tx, id); err != nil {
			return err
		}
	}
	var old, oldPolicy []byte
	err = tx.QueryRowContext(ctx, "SELECT binding,policy FROM approved_image_candidates WHERE revision=? AND module=? AND selector=?", m.ActiveRevision, b.ModuleID, b.ImageSelector).Scan(&old, &oldPolicy)
	if err == nil {
		if string(old) != string(raw) || string(oldPolicy) != string(approved) {
			return errors.New("candidate binding/policy identity reuse")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if _, err = tx.ExecContext(ctx, "INSERT INTO approved_image_candidates VALUES(?,?,?,?,?,?)", m.ActiveRevision, b.ModuleID, b.ImageSelector, b.ImageRecordID, raw, approved); err != nil {
			return err
		}
	} else {
		return err
	}
	claim := "candidate:" + m.ActiveRevision + ":" + b.ModuleID + ":" + b.ImageRecordID
	for _, id := range []string{b.ImageRecordID, caches[0], m.BundleDigest} {
		if err = retainGenerationTx(ctx, tx, "recovery", id, claim); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func policyMatchesBinding(p sharedhost.LaunchSpec, b ApprovedImageBinding) bool {
	return p.ModuleID == b.ModuleID && p.ImageDigest == b.ImageSelector && p.ConfigRevision == b.ConfigRevision && p.ApprovalRevision == b.ApprovalRevision
}
func resourcesWithin(r, c sharedhost.ResourceLimits) bool {
	return r.NanoCPUs <= c.NanoCPUs && r.MemoryBytes <= c.MemoryBytes && r.Pids <= c.Pids && r.PersistentBytes <= c.PersistentBytes && r.ScratchBytes <= c.ScratchBytes && r.PersistentInodes <= c.PersistentInodes && r.ScratchInodes <= c.ScratchInodes && r.ControlMessageMaxBytes <= c.ControlMessageMaxBytes && r.LogBufferBytes <= c.LogBufferBytes && r.LogFileMaxBytes <= c.LogFileMaxBytes && r.LogRetainedFiles <= c.LogRetainedFiles
}
func validateLaunchRequest(s, p sharedhost.LaunchSpec) error {
	if err := validateSpec(s); err != nil {
		return err
	}
	if err := ValidateLaunchPolicy(p); err != nil {
		return errors.Join(errors.New("missing or invalid installed launch policy"), err)
	}
	if s.ModuleID != p.ModuleID || s.ImageDigest != p.ImageDigest || s.UID != p.UID || s.GID != p.GID || s.ConfigRevision != p.ConfigRevision || s.ApprovalRevision != p.ApprovalRevision || s.InitialEgress != p.InitialEgress || !slices.Equal(s.Entrypoint, p.Entrypoint) || !slices.Equal(s.Args, p.Args) || !resourcesWithin(s.Resources, p.Resources) {
		return errors.New("launch exceeds or differs from installed root approval")
	}
	return nil
}

func (s *Store) ResolveApprovedImage(ctx context.Context, selector string) (provision.ImageRecord, error) {
	var zero provision.ImageRecord
	if err := validateImageDigest(selector); err != nil {
		return zero, err
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return zero, err
	}
	r, err := s.Revision(ctx, m.ActiveRevision)
	if err != nil {
		return zero, err
	}
	var ids []string
	for _, b := range r.Images {
		if b.ImageSelector == selector {
			ids = append(ids, b.ImageRecordID)
		}
	}
	rows, err := s.db.QueryContext(ctx, "SELECT image FROM approved_image_candidates WHERE revision=? AND selector=?", m.ActiveRevision, selector)
	if err != nil {
		return zero, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return zero, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return zero, err
	}
	if len(ids) == 0 {
		return zero, errors.New("image selector is not committed in current approval")
	}
	for _, id := range ids {
		if e := s.CheckGenerationAvailable(ctx, id); e != nil {
			return zero, e
		}
		candidate, e := s.Image(ctx, id)
		if e != nil {
			return zero, e
		}
		if zero.ID != "" && (zero.OriginalDigest != candidate.OriginalDigest || zero.ManifestDigest != candidate.ManifestDigest || zero.ConfigDigest != candidate.ConfigDigest || zero.DeclarationDigest != candidate.DeclarationDigest) {
			return zero, errors.New("ambiguous approved image identity")
		}
		zero = candidate
	}
	return zero, nil
}

func validateRevisionLaunchPolicies(r RevisionRecord) error {
	if len(r.Images) != len(r.LaunchPolicies) {
		return errors.New("each approved image requires one root launch policy")
	}
	for i, b := range r.Images {
		if b.ModuleID == "" || b.ImageRecordID == "" {
			return errors.New("incomplete approved image binding")
		}
		matches := 0
		for _, p := range r.LaunchPolicies {
			if !policyMatchesBinding(p, b) {
				continue
			}
			if err := ValidateLaunchPolicy(p); err != nil {
				return err
			}
			if p.InitialEgress == sharedhost.EgressPublicInternet && r.PublicProfile != sharedhost.NetworkPublicV4 && r.PublicProfile != sharedhost.NetworkPublicDual {
				return errors.New("public launch policy lacks installed family approval")
			}
			matches++
		}
		if matches != 1 {
			return errors.New("missing or ambiguous root launch policy")
		}
		for _, previous := range r.Images[:i] {
			if previous.ModuleID == b.ModuleID && previous.ImageSelector == b.ImageSelector {
				return errors.New("duplicate approved image binding")
			}
		}
	}
	return nil
}
func checkRevisionUsableTx(ctx context.Context, tx *sql.Tx, r RevisionRecord) error {
	if err := checkGenerationAvailableTx(ctx, tx, r.BundleDigest); err != nil {
		return err
	}
	for _, b := range r.Images {
		if err := checkGenerationAvailableTx(ctx, tx, b.ImageRecordID); err != nil {
			return err
		}
	}
	if r.DevelopmentWorker != nil {
		return checkGenerationAvailableTx(ctx, tx, "development-worker:"+r.DevelopmentWorker.JobID)
	}
	return nil
}

func retainRevisionTx(ctx context.Context, tx *sql.Tx, r RevisionRecord) error {
	claim := "revision:" + r.ID
	if err := retainGenerationTx(ctx, tx, "recovery", r.BundleDigest, claim); err != nil {
		return err
	}
	for _, b := range r.Images {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM image_records WHERE id=?", b.ImageRecordID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("approved revision image is not committed")
		}
		if err := retainGenerationTx(ctx, tx, "recovery", b.ImageRecordID, claim); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT record FROM cache_generations WHERE image=?", b.ImageRecordID)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			var c CacheGeneration
			if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &c); err != nil {
				rows.Close()
				return err
			}
			if c.State == "READY" && c.BundleDigest == r.BundleDigest {
				ids = append(ids, c.ID)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(ids) != 1 {
			return errors.New("revision requires one committed compatible cache generation")
		}
		if err = retainGenerationTx(ctx, tx, "recovery", ids[0], claim); err != nil {
			return err
		}
	}
	return nil
}

type purgeRetirementObject struct {
	IntentID   string `json:"intent_id"`
	OriginalID string `json:"original_id"`
	Kind       string `json:"kind"`
	Path       string `json:"path"`
}
type purgeRetirementRecord struct {
	ID            string                  `json:"id"`
	State         string                  `json:"state"`
	Objects       []purgeRetirementObject `json:"objects"`
	Generations   []string                `json:"generations"`
	References    []GenerationReference   `json:"references"`
	StorageClaims []string                `json:"storage_claims"`
}

func purgeRetirementKey(intentIDs []string) (string, []string, error) {
	if len(intentIDs) == 0 || len(intentIDs) > 4096 {
		return "", nil, invalid("bounded exact purge removal intents required")
	}
	ids := slices.Clone(intentIDs)
	slices.Sort(ids)
	for i, id := range ids {
		if !validLedgerID(id) || i > 0 && ids[i-1] == id {
			return "", nil, invalid("invalid or duplicate purge removal intent")
		}
	}
	raw, err := json.Marshal(ids)
	if err != nil {
		return "", nil, err
	}
	return "purge_retirement:" + provision.DomainDigest("chatanium-purge-retirement-v1", raw), ids, nil
}

// RetirePurgeGenerations authorizes no deletion by itself. It moves only the
// references covered by durable, approved backing/bundle/backup removal intents
// behind a permanent admission fence. Physical removal and reclaim come later.
func (s *Store) RetirePurgeGenerations(ctx context.Context, intentIDs []string, e CleanupEvidence) error {
	if err := validateCleanup(e); err != nil {
		return err
	}
	if err := s.AssertRemovable(ctx); err != nil {
		return err
	}
	key, ids, err := purgeRetirementKey(intentIDs)
	if err != nil {
		return err
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		if m.DesiredRunState != "STOPPED" {
			return sharedhost.ErrCleanupIncomplete
		}
		var existing []byte
		err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&existing)
		if err == nil {
			var record purgeRetirementRecord
			return gvxcontract.DecodeStrict(existing, revisionJSONMax, 32, &record)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		record := purgeRetirementRecord{ID: key, State: "RETIRING"}
		generations := map[string]bool{}
		backupFiles := map[string]map[string]bool{}
		primaryBacking := false
		load := func(id string) (ProvisionRecord, error) {
			var r ProvisionRecord
			var raw []byte
			if err := tx.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", id).Scan(&raw); err != nil {
				return r, err
			}
			if err := decodeProvisionRecord(raw, &r); err != nil {
				return r, err
			}
			if r.ID != id {
				return r, errors.New("purge ledger identity mismatch")
			}
			return r, nil
		}
		for _, id := range ids {
			intent, err := load(id)
			if err != nil {
				return err
			}
			var desired ProvisionProperties
			if err = validProvision(intent.Kind, intent.Desired); err != nil {
				return err
			}
			if err = gvxcontract.DecodeStrict(intent.Desired, 64<<10, 16, &desired); err != nil {
				return err
			}
			if desired.Source != "remove" || !intent.ExistedBefore || intent.ProductCreated || intent.CleanupState == "COMPLETE" {
				return errors.New("purge retirement requires a pending exact removal intent")
			}
			original, err := load(desired.Revision)
			if err != nil {
				return err
			}
			if original.Kind != intent.Kind || original.Identity != intent.Identity || !original.ProductCreated || original.ExistedBefore || original.State != "OBSERVED" || original.CleanupState == "COMPLETE" {
				return errors.New("purge removal is not bound to original product ownership")
			}
			var observed ProvisionProperties
			if err = gvxcontract.DecodeStrict(original.Observed.Attributes, 64<<10, 16, &observed); err != nil {
				return err
			}
			if observed.Path != desired.Path || observed.Digest != desired.Digest || observed.Dev != desired.Dev || observed.Ino != desired.Ino || observed.UUID != desired.UUID {
				return errors.New("purge removal changed original native object identity")
			}
			path := original.Identity
			switch original.Kind {
			case "bundle":
				path = observed.Path
				if !provision.ValidDigest(observed.Digest) || !filepath.IsAbs(path) || path == m.Paths.EngineRoot || !strings.HasPrefix(path, m.Paths.EngineRoot+string(os.PathSeparator)) {
					return errors.New("purge bundle is outside installed owned generation root")
				}
				generations[observed.Digest] = true
			case "backing":
				if path == m.Paths.BackingFile {
					if observed.Dev == 0 || observed.Ino == 0 {
						return errors.New("primary backing has no observed native identity")
					}
					if m.Backing.Dev != 0 && (observed.Dev != m.Backing.Dev || observed.Ino != m.Backing.Ino || observed.UUID != m.Backing.XFSUUID) {
						return errors.New("purge primary backing differs from installed identity")
					}
					if m.Backing.Dev == 0 {
						var allocated int
						if err = tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM storage_claims)+(SELECT count(*) FROM instances)").Scan(&allocated); err != nil {
							return err
						}
						if allocated != 0 {
							return errors.New("unidentified backing has historical storage allocations")
						}
					}
					primaryBacking = true
				} else if err = recordBackupPurgeFile(backupFiles, m.Paths.Installation, path, ".xfs"); err != nil {
					return err
				}
			case "config":
				extension := filepath.Ext(path)
				if extension != ".sqlite" && extension != ".json" {
					return errors.New("only exact backup metadata belongs to generation retirement")
				}
				if err = recordBackupPurgeFile(backupFiles, m.Paths.Installation, path, extension); err != nil {
					return err
				}
			default:
				return errors.New("unsupported object in generation purge retirement")
			}
			record.Objects = append(record.Objects, purgeRetirementObject{IntentID: id, OriginalID: original.ID, Kind: original.Kind, Path: path})
		}
		backups := map[string]bool{}
		for claim, files := range backupFiles {
			if !files[".xfs"] || !files[".sqlite"] || !files[".json"] {
				return errors.New("backup retirement requires all three exact approved backup objects")
			}
			backups[claim] = true
		}
		if primaryBacking {
			rows, err := tx.QueryContext(ctx, "SELECT DISTINCT generation FROM storage_generations")
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				generations[id] = true
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			rows, err = tx.QueryContext(ctx, "SELECT id FROM storage_claims WHERE state!='RELEASED'")
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				record.StorageClaims = append(record.StorageClaims, id)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
		rows, err := tx.QueryContext(ctx, "SELECT kind,id,claim FROM generation_references")
		if err != nil {
			return err
		}
		for rows.Next() {
			var ref GenerationReference
			if err = rows.Scan(&ref.Kind, &ref.ID, &ref.Claim); err != nil {
				rows.Close()
				return err
			}
			covered := generations[ref.ID]
			if strings.HasPrefix(ref.Claim, "backup-") {
				if covered && !backups[ref.Claim] {
					rows.Close()
					return errors.New("generation is still required by a preserved backup")
				}
				covered = covered || backups[ref.Claim]
			}
			if !covered {
				continue
			}
			if ref.Kind == "live" {
				rows.Close()
				return sharedhost.ErrCleanupIncomplete
			}
			prepared, proofErr := preparedImageReferenceTx(ctx, tx, ref)
			if proofErr != nil {
				rows.Close()
				return proofErr
			}
			if ref.Kind == "recovery" && !strings.HasPrefix(ref.Claim, "revision:") && !strings.HasPrefix(ref.Claim, "candidate:") && !backups[ref.Claim] && !prepared {
				rows.Close()
				return errors.New("unrecognized recovery reference is not authorized by this purge scope")
			}
			record.References = append(record.References, ref)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for id := range generations {
			record.Generations = append(record.Generations, id)
		}
		slices.Sort(record.Generations)
		slices.Sort(record.StorageClaims)
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if len(raw) > revisionJSONMax {
			return errors.New("purge retirement evidence exceeds bounded journal record")
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES(?,?)", key, raw); err != nil {
			return err
		}
		for _, id := range record.Generations {
			if _, err = tx.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING", "retiring_generation:"+id, key); err != nil {
				return err
			}
		}
		for _, ref := range record.References {
			if _, err = tx.ExecContext(ctx, "DELETE FROM generation_references WHERE kind=? AND id=? AND claim=?", ref.Kind, ref.ID, ref.Claim); err != nil {
				return err
			}
		}
		for _, id := range record.StorageClaims {
			if _, err = tx.ExecContext(ctx, "UPDATE storage_claims SET state='RETIRING' WHERE id=? AND state!='RELEASED'", id); err != nil {
				return err
			}
		}
		m.State = "RECOVERY_REQUIRED"
		return nil
	})
}

func recordBackupPurgeFile(groups map[string]map[string]bool, installation, path, extension string) error {
	if filepath.Dir(path) != installation || filepath.Clean(path) != path {
		return errors.New("backup purge target is outside installed backup root")
	}
	claim := strings.TrimSuffix(filepath.Base(path), extension)
	if !strings.HasPrefix(claim, "backup-") || !validLedgerID(claim) {
		return errors.New("invalid exact backup identity")
	}
	if groups[claim] == nil {
		groups[claim] = map[string]bool{}
	}
	if groups[claim][extension] {
		return errors.New("duplicate backup purge object")
	}
	groups[claim][extension] = true
	return nil
}

func (s *Store) CompletePurgeRetirement(ctx context.Context, intentIDs []string, e CleanupEvidence) error {
	if err := validateCleanup(e); err != nil {
		return err
	}
	key, _, err := purgeRetirementKey(intentIDs)
	if err != nil {
		return err
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		if m.DesiredRunState != "STOPPED" {
			return sharedhost.ErrCleanupIncomplete
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&raw); err != nil {
			return err
		}
		var record purgeRetirementRecord
		if err := gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &record); err != nil {
			return err
		}
		if record.ID != key {
			return errors.New("purge retirement receipt identity mismatch")
		}
		if record.State == "COMPLETE" {
			return nil
		}
		if record.State != "RETIRING" {
			return errors.New("invalid purge retirement state")
		}
		for _, object := range record.Objects {
			if _, err := os.Lstat(object.Path); !errors.Is(err, os.ErrNotExist) {
				if err != nil {
					return err
				}
				return errors.New("purge retirement still has a native object")
			}
			for _, id := range []string{object.OriginalID, object.IntentID} {
				var value []byte
				if err := tx.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", id).Scan(&value); err != nil {
					return err
				}
				var p ProvisionRecord
				if err := decodeProvisionRecord(value, &p); err != nil {
					return err
				}
				p.CleanupState = "COMPLETE"
				value, err := json.Marshal(p)
				if err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", value, id); err != nil {
					return err
				}
			}
		}
		for _, id := range record.StorageClaims {
			if _, err := tx.ExecContext(ctx, "UPDATE storage_claims SET state='RELEASED' WHERE id=? AND state='RETIRING'", id); err != nil {
				return err
			}
		}
		record.State = "COMPLETE"
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE metadata SET value=? WHERE key=?", raw, key)
		return err
	})
}
