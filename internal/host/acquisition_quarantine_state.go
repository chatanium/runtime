//go:build linux

package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/provision"
)

const legacyQuarantineMembersMax = 4096

type LegacyAcquisitionLineage struct {
	Kind                string   `json:"kind"`
	JobID               string   `json:"job_id"`
	AcquisitionID       string   `json:"acquisition_id"`
	ProvisionID         string   `json:"provision_id"`
	ImageRecordID       string   `json:"image_record_id"`
	CacheIDs            []string `json:"cache_ids"`
	DerivedJobIDs       []string `json:"derived_job_ids"`
	DerivedProvisionIDs []string `json:"derived_provision_ids"`
}
type LegacyQuarantineSet struct {
	Version                     uint32                     `json:"version"`
	InstallationID              string                     `json:"installation_id"`
	ActiveRevision              string                     `json:"active_revision"`
	Digest                      string                     `json:"digest"`
	RequiredWriterDomainVersion uint32                     `json:"required_writer_domain_version"`
	Lineages                    []LegacyAcquisitionLineage `json:"lineages"`
}
type LegacyAcquisitionQuarantineRecord struct {
	Version             uint32                   `json:"version"`
	PlanID              string                   `json:"plan_id"`
	PlanDigest          string                   `json:"plan_digest"`
	QuarantineSetDigest string                   `json:"quarantine_set_digest"`
	Lineage             LegacyAcquisitionLineage `json:"lineage"`
}
type OperatorReacquisition struct {
	Version                     uint32 `json:"version"`
	ExpectedState               string `json:"expected_state"`
	QuarantineSetDigest         string `json:"quarantine_set_digest"`
	RequiredWriterDomainVersion uint32 `json:"required_writer_domain_version"`
	ReplacesImageRecordID       string `json:"replaces_image_record_id"`
}

type operatorPreparationAuthority struct {
	Input                  provision.ApprovedImageInput
	BundleDigest           string
	ExpectedActiveRevision string
	Reacquisition          *OperatorReacquisition
}

func operatorPreparationApproval(r ManagementPlanRecord) (operatorPreparationAuthority, error) {
	var a operatorPreparationAuthority
	if r.Kind != "operator-preparation" {
		return a, invalid("operator preparation approval required")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(r.Plan, &fields); err != nil {
		return a, err
	}
	if err := gvxcontract.DecodeStrict(fields["input"], managementPlanBytesMax, 32, &a.Input); err != nil {
		return a, err
	}
	if err := a.Input.Validate(); err != nil {
		return a, err
	}
	if err := json.Unmarshal(fields["preparation_bundle_digest"], &a.BundleDigest); err != nil || !provision.ValidDigest(a.BundleDigest) {
		return a, invalid("operator preparation requires exact reviewed helper bundle")
	}
	if err := json.Unmarshal(fields["expected_active_revision"], &a.ExpectedActiveRevision); err != nil || a.ExpectedActiveRevision == "" {
		return a, invalid("operator preparation requires exact base revision")
	}
	if raw := fields["reacquisition"]; len(raw) != 0 && string(raw) != "null" {
		if err := gvxcontract.DecodeStrict(raw, 64<<10, 8, &a.Reacquisition); err != nil {
			return a, err
		}
		q := a.Reacquisition
		if q == nil || q.Version != 1 || q.RequiredWriterDomainVersion != gvxcontract.PreparationWriterDomainVersion || !provision.ValidDigest(q.QuarantineSetDigest) || (q.ExpectedState != "READY" && q.ExpectedState != "RECOVERY_REQUIRED") {
			return a, invalid("invalid reviewed operator reacquisition")
		}
		if q.ReplacesImageRecordID != "" && !provision.ValidDigest(q.ReplacesImageRecordID) {
			return a, invalid("invalid reviewed replacement image")
		}
	}
	return a, nil
}

type quarantineAcquisition struct {
	record   ProvisionRecord
	desired  ProvisionProperties
	observed ProvisionProperties
	space    ImageSpace
}

func quarantineHistoryTx(ctx context.Context, tx *sql.Tx) ([]ProvisionRecord, error) {
	rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind IN ('image','development-worker','unit') ORDER BY id")
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
		var r ProvisionRecord
		if err = decodeProvisionRecord(raw, &r); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func quarantineAcquisitions(records []ProvisionRecord) ([]quarantineAcquisition, error) {
	var result []quarantineAcquisition
	for _, r := range records {
		if r.Kind == "unit" || strings.HasPrefix(r.Identity, "image-space:") || r.State != "OBSERVED" {
			continue
		}
		var d, o ProvisionProperties
		if err := gvxcontract.DecodeStrict(r.Desired, 64<<10, 16, &d); err != nil {
			return nil, err
		}
		if err := gvxcontract.DecodeStrict(r.Observed.Attributes, 64<<10, 16, &o); err != nil {
			return nil, err
		}
		if o.ImageSpace == nil {
			continue
		}
		space := *o.ImageSpace
		committed, err := committedImageSpace(records, space)
		if err != nil {
			return nil, err
		}
		if !committed {
			continue
		}
		if !safeID(space.JobID) || !safeID(space.ProvisionID) || r.Identity != space.JobID || !r.ProductCreated || r.ExistedBefore || d.ImageSpace == nil || !samePreparationSpace(*d.ImageSpace, space) {
			return nil, errors.New("committed acquisition changed its original space binding")
		}
		if o.ApprovedImageInput != nil && (d.ApprovedImageInput == nil || *o.ApprovedImageInput != *d.ApprovedImageInput) || d.ApprovedImageInput != nil && o.ApprovedImageInput == nil {
			return nil, errors.New("committed acquisition changed its authenticated original input")
		}
		for _, old := range result {
			if old.space.JobID == space.JobID {
				return nil, errors.New("ambiguous committed acquisition job")
			}
		}
		result = append(result, quarantineAcquisition{r, d, o, space})
	}
	return result, nil
}

// The original dispatch and its correlated systemd receipt must both already be
// COMPLETE. Quarantine never repairs, completes, or manufactures helper proof.
func quarantineHelpers(records []ProvisionRecord, job string) (bool, error) {
	legacy, count := false, 0
	for _, r := range records {
		if r.Kind != "unit" {
			continue
		}
		var d, o ProvisionProperties
		if err := gvxcontract.DecodeStrict(r.Desired, 64<<10, 16, &d); err != nil {
			return false, err
		}
		if d.Source != job {
			continue
		}
		count++
		if !preparationUnitName(r.Identity) || !r.ProductCreated || r.ExistedBefore || r.State != "OBSERVED" || r.CleanupState != "COMPLETE" || d.Unit == nil || d.Name != r.Identity || d.Unit.Name != r.Identity || !safeID(d.Unit.Generation) || d.Unit.BootID == "" {
			return false, errors.New("legacy quarantine requires settled original helper history")
		}
		if err := gvxcontract.DecodeStrict(r.Observed.Attributes, 64<<10, 16, &o); err != nil {
			return false, err
		}
		if o.Unit == nil || o.Unit.Name != r.Identity || o.Unit.Generation != d.Unit.Generation || o.Unit.BootID != d.Unit.BootID {
			return false, errors.New("legacy helper changed original native identity")
		}
		internalCount := 0
		for _, internal := range records {
			if internal.ID != "systemd-"+o.Unit.Generation {
				continue
			}
			internalCount++
			var captured, dispatch ProvisionProperties
			if internal.Kind != "unit" || internal.Identity != r.Identity || internal.State != "OBSERVED" || internal.CleanupState != "COMPLETE" {
				return false, errors.New("legacy internal helper is not COMPLETE")
			}
			if err := gvxcontract.DecodeStrict(internal.Observed.Attributes, 64<<10, 16, &captured); err != nil {
				return false, err
			}
			if err := gvxcontract.DecodeStrict(internal.Desired, 64<<10, 16, &dispatch); err != nil {
				return false, err
			}
			program := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(r.Identity, ".service"), "-"+o.Unit.Generation), "chatanium-image-")
			if !internal.ProductCreated || internal.ExistedBefore || dispatch.Source != program || dispatch.Name != r.Identity || dispatch.Unit == nil || dispatch.Unit.Generation != o.Unit.Generation || dispatch.Unit.BootID != o.Unit.BootID {
				return false, errors.New("legacy internal helper changed its original dispatch authority")
			}
			if captured.Unit == nil || *captured.Unit != *o.Unit {
				return false, errors.New("legacy helper internal native identity mismatch")
			}
			if (o.Writer == nil) != (captured.Writer == nil) {
				return false, errors.New("legacy helper has contradictory original writer evidence")
			}
			if o.Writer == nil {
				if d.Writer != nil || dispatch.Writer != nil {
					return false, errors.New("legacy helper dropped original declared writer evidence")
				}
				legacy = true
			} else {
				if dispatch.Writer == nil || dispatch.Writer.Launch != captured.Writer.Launch || dispatch.Writer.Birth != nil || dispatch.Writer.Evidence != nil || dispatch.Writer.StartIntent || dispatch.Writer.StartForbidden || d.Writer != nil && d.Writer.Launch != o.Writer.Launch || !preparationWriterPrefix(o.Writer, captured.Writer) || !preparationWriterPrefix(captured.Writer, o.Writer) {
					return false, errors.New("quarantine helper changed its immutable declared/native writer identity")
				}
				unsupported := o.Writer.Evidence != nil && o.Writer.Evidence.FilterVersion == 1
				if unsupported {
					if err := validateUnsupportedPreparationWriterV1(o); err != nil {
						return false, err
					}
					if err := validateUnsupportedPreparationWriterV1(captured); err != nil {
						return false, err
					}
					legacy = true
				} else {
					if err := validatePreparationSettlement(o); err != nil {
						return false, err
					}
					if err := validatePreparationSettlement(captured); err != nil {
						return false, err
					}
				}
			}
		}
		if internalCount != 1 {
			return false, errors.New("legacy helper lacks unique internal receipt")
		}
	}
	if count == 0 {
		return false, errors.New("committed acquisition lacks original helper history")
	}
	return legacy, nil
}

func quarantineCacheTx(ctx context.Context, tx *sql.Tx, a quarantineAcquisition, image provision.ImageRecord) (CacheGeneration, error) {
	var c CacheGeneration
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT record FROM cache_generations WHERE id=?", a.observed.Revision).Scan(&raw); err != nil {
		return c, err
	}
	if err := gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &c); err != nil {
		return c, err
	}
	if c.ID != a.observed.Revision || c.ImageRecordID != a.observed.Digest || c.ImageRecordID != image.ID || c.CanonicalArchiveDigest != image.CanonicalArchiveDigest || c.ManifestDigest != image.ManifestDigest || c.BundleDigest != a.desired.Revision || c.State != "READY" || c.Directory != filepath.Join(a.space.Cache, "generation") {
		return c, errors.New("cache differs from exact committed image/acquisition receipt")
	}
	var generation string
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM storage_generations WHERE claim=?", a.space.JobID+":cache").Scan(&generation); err != nil {
		return c, err
	}
	if generation != c.ID {
		return c, errors.New("legacy cache storage binding changed")
	}
	return c, nil
}

func (s *Store) legacyQuarantineSetTx(ctx context.Context, tx *sql.Tx) (LegacyQuarantineSet, error) {
	m, err := readManagementManifest(ctx, tx, s.productID)
	set := LegacyQuarantineSet{Version: 1, InstallationID: s.productID, ActiveRevision: m.ActiveRevision, RequiredWriterDomainVersion: gvxcontract.PreparationWriterDomainVersion}
	if err != nil {
		return set, err
	}
	records, err := quarantineHistoryTx(ctx, tx)
	if err != nil {
		return set, err
	}
	acquisitions, err := quarantineAcquisitions(records)
	if err != nil {
		return set, err
	}
	members := 0
	for _, a := range acquisitions {
		if a.space.Cache != filepath.Join(m.Paths.StorageRoot, "prepared", a.space.JobID) || a.space.Work != filepath.Join(m.Paths.StorageRoot, "preparation", a.space.JobID) || !a.space.ReusedSource && a.space.Source != filepath.Join(m.Paths.StorageRoot, "images", a.space.JobID) {
			return set, errors.New("committed acquisition changed fixed owned storage paths")
		}
	}
	for _, a := range acquisitions {
		if a.space.ReusedSource {
			continue
		}
		// Current acquisitions are not legacy merely because cleanup is pending.
		history, err := preparationUnitHistory(ctx, tx, a.space.JobID)
		if err != nil {
			return set, err
		}
		legacy := false
		for _, h := range history {
			var p ProvisionProperties
			if err = gvxcontract.DecodeStrict(h.Observed.Attributes, 64<<10, 16, &p); err != nil {
				return set, err
			}
			legacy = legacy || p.Writer == nil || p.Writer.Evidence != nil && p.Writer.Evidence.FilterVersion == 1
		}
		if !legacy {
			if err = s.requirePreparationWriterHistory(ctx, tx, a.space, true); err != nil {
				return set, err
			}
			continue
		}
		if _, err = quarantineHelpers(records, a.space.JobID); err != nil {
			return set, err
		}
		lineage := LegacyAcquisitionLineage{Kind: a.record.Kind, JobID: a.space.JobID, AcquisitionID: a.record.ID, ProvisionID: a.space.ProvisionID}
		if a.record.Kind == "image" {
			var raw []byte
			if err = tx.QueryRowContext(ctx, "SELECT record FROM image_records WHERE id=?", a.observed.Digest).Scan(&raw); err != nil {
				return set, err
			}
			var image provision.ImageRecord
			if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &image); err != nil {
				return set, err
			}
			if image.ID != a.observed.Digest || image.ID != provision.RecordID(image) {
				return set, errors.New("legacy image receipt identity changed")
			}
			if err = verifyPreparationRecordBinding(a.desired, image); err != nil {
				return set, err
			}
			lineage.ImageRecordID = image.ID
			var sourceGeneration string
			if err = tx.QueryRowContext(ctx, "SELECT generation FROM storage_generations WHERE claim=?", a.space.JobID+":source").Scan(&sourceGeneration); err != nil {
				return set, err
			}
			if sourceGeneration != image.ID {
				return set, errors.New("legacy acquisition original source claim changed")
			}
			cache, e := quarantineCacheTx(ctx, tx, a, image)
			if e != nil {
				return set, e
			}
			lineage.CacheIDs = append(lineage.CacheIDs, cache.ID)
			for _, derived := range acquisitions {
				if !derived.space.ReusedSource || derived.record.Kind != "image" || derived.observed.Digest != image.ID {
					continue
				}
				if derived.space.SourceGenerationID != image.ID || derived.space.Source != a.space.Source || derived.space.SourceProject != a.space.SourceProject {
					return set, errors.New("derived legacy cache changed original source lineage")
				}
				if err = verifyPreparationRecordBinding(derived.desired, image); err != nil {
					return set, err
				}
				if _, err = quarantineHelpers(records, derived.space.JobID); err != nil {
					return set, err
				}
				cache, e = quarantineCacheTx(ctx, tx, derived, image)
				if e != nil {
					return set, e
				}
				lineage.CacheIDs = append(lineage.CacheIDs, cache.ID)
				lineage.DerivedJobIDs = append(lineage.DerivedJobIDs, derived.space.JobID)
				lineage.DerivedProvisionIDs = append(lineage.DerivedProvisionIDs, derived.space.ProvisionID)
			}
			rows, e := tx.QueryContext(ctx, "SELECT id FROM cache_generations WHERE image=? ORDER BY id", image.ID)
			if e != nil {
				return set, e
			}
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					rows.Close()
					return set, e
				}
				if !slices.Contains(lineage.CacheIDs, id) {
					rows.Close()
					return set, errors.New("legacy image cache has no exact committed acquisition lineage")
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return set, e
			}
		} else if a.record.Kind == "development-worker" {
			if !provision.ValidDigest(a.observed.Digest) || a.desired.Revision != a.observed.Revision {
				return set, errors.New("legacy development receipt changed its exact base")
			}
			for _, kind := range []string{"source", "cache"} {
				var generation string
				if err = tx.QueryRowContext(ctx, "SELECT generation FROM storage_generations WHERE claim=?", a.space.JobID+":"+kind).Scan(&generation); err != nil {
					return set, err
				}
				if generation != "development-worker:"+a.space.JobID {
					return set, errors.New("legacy development storage lineage changed")
				}
			}
		} else {
			return set, invalid("invalid legacy acquisition kind")
		}
		// Acquisition ordering is by immutable ledger ID; sort derived pairs by job.
		for i := 1; i < len(lineage.DerivedJobIDs); i++ {
			for j := i; j > 0 && lineage.DerivedJobIDs[j] < lineage.DerivedJobIDs[j-1]; j-- {
				lineage.DerivedJobIDs[j], lineage.DerivedJobIDs[j-1] = lineage.DerivedJobIDs[j-1], lineage.DerivedJobIDs[j]
				lineage.DerivedProvisionIDs[j], lineage.DerivedProvisionIDs[j-1] = lineage.DerivedProvisionIDs[j-1], lineage.DerivedProvisionIDs[j]
			}
		}
		slices.Sort(lineage.CacheIDs)
		lineage.CacheIDs = slices.Compact(lineage.CacheIDs)
		members += 1 + len(lineage.CacheIDs) + len(lineage.DerivedJobIDs) + len(lineage.DerivedProvisionIDs)
		if members > legacyQuarantineMembersMax {
			return set, invalid("legacy quarantine membership exceeds bound")
		}
		set.Lineages = append(set.Lineages, lineage)
	}
	slices.SortFunc(set.Lineages, func(a, b LegacyAcquisitionLineage) int {
		if n := strings.Compare(a.Kind, b.Kind); n != 0 {
			return n
		}
		return strings.Compare(a.JobID, b.JobID)
	})
	set.Digest, err = legacyQuarantineDigestTx(ctx, tx, set, records)
	if err != nil {
		return set, err
	}
	return set, nil
}

func (s *Store) LegacyAcquisitionQuarantineSet(ctx context.Context) (LegacyQuarantineSet, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return LegacyQuarantineSet{}, err
	}
	defer tx.Rollback()
	set, err := s.legacyQuarantineSetTx(ctx, tx)
	if err != nil {
		return set, err
	}
	return set, tx.Commit()
}
func (r *MetadataReader) LegacyAcquisitionQuarantineSet(ctx context.Context) (LegacyQuarantineSet, error) {
	return r.store.LegacyAcquisitionQuarantineSet(ctx)
}

func quarantineKey(kind, job string) (string, error) {
	if (kind != "image" && kind != "development-worker") || !safeID(job) {
		return "", invalid("exact legacy acquisition kind and job required")
	}
	return "legacy_acquisition_quarantine:" + kind + ":" + job, nil
}
func lineageGenerations(l LegacyAcquisitionLineage) []string {
	ids := append([]string(nil), l.CacheIDs...)
	if l.ImageRecordID != "" {
		ids = append(ids, l.ImageRecordID)
	} else {
		ids = append(ids, "development-worker:"+l.JobID)
	}
	for _, job := range append([]string{l.JobID}, l.DerivedJobIDs...) {
		ids = append(ids, "image-preparation:"+job)
	}
	return ids
}
func immutableMetadataTx(ctx context.Context, tx *sql.Tx, key string, raw []byte) error {
	var old []byte
	err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&old)
	if err == nil {
		if !bytes.Equal(old, raw) {
			return errors.New("immutable quarantine authority reuse")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?)", key, raw)
	return err
}

type legacyQuarantineHelperIdentity struct {
	JobID          string `json:"job_id"`
	OuterID        string `json:"outer_id"`
	OuterDigest    string `json:"outer_digest"`
	InternalID     string `json:"internal_id"`
	InternalDigest string `json:"internal_digest"`
}

func legacyQuarantineDigestTx(ctx context.Context, tx *sql.Tx, set LegacyQuarantineSet, records []ProvisionRecord) (string, error) {
	set.Digest = ""
	if records == nil {
		var err error
		records, err = quarantineHistoryTx(ctx, tx)
		if err != nil {
			return "", err
		}
	}
	var helpers []legacyQuarantineHelperIdentity
	members := 0
	for _, l := range set.Lineages {
		members += 1 + len(l.CacheIDs) + len(l.DerivedJobIDs) + len(l.DerivedProvisionIDs)
		for _, job := range append([]string{l.JobID}, l.DerivedJobIDs...) {
			if _, err := quarantineHelpers(records, job); err != nil {
				return "", err
			}
			for _, r := range records {
				if r.Kind != "unit" {
					continue
				}
				var desired, observed ProvisionProperties
				if err := gvxcontract.DecodeStrict(r.Desired, 64<<10, 16, &desired); err != nil {
					return "", err
				}
				if desired.Source != job {
					continue
				}
				if err := gvxcontract.DecodeStrict(r.Observed.Attributes, 64<<10, 16, &observed); err != nil {
					return "", err
				}
				outerRaw, err := json.Marshal(r)
				if err != nil {
					return "", err
				}
				for _, internal := range records {
					if internal.ID != "systemd-"+observed.Unit.Generation {
						continue
					}
					internalRaw, err := json.Marshal(internal)
					if err != nil {
						return "", err
					}
					helpers = append(helpers, legacyQuarantineHelperIdentity{JobID: job, OuterID: r.ID, OuterDigest: provision.Digest(outerRaw), InternalID: internal.ID, InternalDigest: provision.Digest(internalRaw)})
					members += 2
					if members > legacyQuarantineMembersMax {
						return "", invalid("quarantine full immutable helper membership exceeds bound")
					}
				}
			}
		}
	}
	slices.SortFunc(helpers, func(a, b legacyQuarantineHelperIdentity) int {
		if n := strings.Compare(a.JobID, b.JobID); n != 0 {
			return n
		}
		return strings.Compare(a.OuterID, b.OuterID)
	})
	payload := struct {
		Set     LegacyQuarantineSet              `json:"set"`
		Helpers []legacyQuarantineHelperIdentity `json:"helpers"`
	}{Set: set, Helpers: helpers}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return provision.DomainDigest("chatanium-legacy-acquisition-quarantine-v1", raw), nil
}

func validateLegacyQuarantineSet(ctx context.Context, tx *sql.Tx, set LegacyQuarantineSet, product string) error {
	if set.Version != 1 || set.InstallationID != product || set.ActiveRevision == "" || set.RequiredWriterDomainVersion != gvxcontract.PreparationWriterDomainVersion || !provision.ValidDigest(set.Digest) {
		return invalid("invalid immutable reviewed quarantine set")
	}
	members := 0
	for i, l := range set.Lineages {
		if _, err := quarantineKey(l.Kind, l.JobID); err != nil {
			return err
		}
		if !safeID(l.AcquisitionID) || !safeID(l.ProvisionID) || len(l.DerivedJobIDs) != len(l.DerivedProvisionIDs) || l.Kind == "image" && (!provision.ValidDigest(l.ImageRecordID) || len(l.CacheIDs) == 0) || l.Kind == "development-worker" && (l.ImageRecordID != "" || len(l.CacheIDs) != 0 || len(l.DerivedJobIDs) != 0) {
			return invalid("invalid immutable quarantine lineage")
		}
		if i > 0 {
			previous := set.Lineages[i-1]
			if previous.Kind > l.Kind || previous.Kind == l.Kind && previous.JobID >= l.JobID {
				return invalid("quarantine lineages are not canonical")
			}
		}
		for j, id := range l.CacheIDs {
			if !provision.ValidDigest(id) || j > 0 && l.CacheIDs[j-1] >= id {
				return invalid("quarantine caches are not canonical")
			}
		}
		for j, job := range l.DerivedJobIDs {
			if !safeID(job) || job == l.JobID || !safeID(l.DerivedProvisionIDs[j]) || j > 0 && l.DerivedJobIDs[j-1] >= job {
				return invalid("quarantine derived lineage is not canonical")
			}
		}
		members += 1 + len(l.CacheIDs) + len(l.DerivedJobIDs) + len(l.DerivedProvisionIDs)
		if members > legacyQuarantineMembersMax {
			return invalid("quarantine membership exceeds bound")
		}
	}
	digest := set.Digest
	actual, err := legacyQuarantineDigestTx(ctx, tx, set, nil)
	if err != nil {
		return err
	}
	if actual != digest {
		return errors.New("quarantine digest differs from exact canonical membership")
	}
	return nil
}

func (s *Store) legacyQuarantineTx(ctx context.Context, tx *sql.Tx, kind, job string) (LegacyAcquisitionQuarantineRecord, bool, error) {
	var receipt LegacyAcquisitionQuarantineRecord
	key, err := quarantineKey(kind, job)
	if err != nil {
		return receipt, false, err
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, err
	}
	if err = gvxcontract.DecodeStrict(raw, managementStateBytesMax, 16, &receipt); err != nil {
		return receipt, false, err
	}
	if receipt.Version != 1 || receipt.Lineage.Kind != kind || (receipt.Lineage.JobID != job && !slices.Contains(receipt.Lineage.DerivedJobIDs, job)) {
		return receipt, false, errors.New("quarantine receipt key identity changed")
	}
	planKey, err := managementKey("operator-preparation", receipt.PlanID)
	if err != nil {
		return receipt, false, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", planKey).Scan(&raw); err != nil {
		return receipt, false, err
	}
	plan, err := decodeManagementPlan(raw, s.productID, "operator-preparation", receipt.PlanID)
	if err != nil {
		return receipt, false, err
	}
	a, err := operatorPreparationApproval(plan)
	if err != nil {
		return receipt, false, err
	}
	if a.Reacquisition == nil || plan.Digest != receipt.PlanDigest || a.Reacquisition.QuarantineSetDigest != receipt.QuarantineSetDigest {
		return receipt, false, errors.New("quarantine receipt differs from immutable reviewed authority")
	}
	if err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "operator_reacquisition_set:"+receipt.PlanID).Scan(&raw); err != nil {
		return receipt, false, err
	}
	var reviewed LegacyQuarantineSet
	if err = gvxcontract.DecodeStrict(raw, managementStateBytesMax, 16, &reviewed); err != nil {
		return receipt, false, err
	}
	if err = validateLegacyQuarantineSet(ctx, tx, reviewed, s.productID); err != nil {
		return receipt, false, err
	}
	if reviewed.Digest != receipt.QuarantineSetDigest || reviewed.ActiveRevision != a.ExpectedActiveRevision || reviewed.ActiveRevision != plan.Snapshot.ActiveRevision {
		return receipt, false, errors.New("quarantine receipt changed original approval snapshot")
	}
	approved := false
	for _, l := range reviewed.Lineages {
		want, _ := json.Marshal(l)
		got, _ := json.Marshal(receipt.Lineage)
		approved = approved || bytes.Equal(want, got)
	}
	if !approved {
		return receipt, false, errors.New("quarantine receipt lineage was not in the approved set")
	}
	set, err := s.legacyQuarantineSetTx(ctx, tx)
	if err != nil {
		return receipt, false, err
	}
	for _, l := range set.Lineages {
		if l.Kind == kind && l.JobID == receipt.Lineage.JobID {
			want, _ := json.Marshal(l)
			got, _ := json.Marshal(receipt.Lineage)
			if !bytes.Equal(want, got) {
				return receipt, false, errors.New("quarantined immutable acquisition lineage changed")
			}
			return receipt, true, nil
		}
	}
	return receipt, false, errors.New("quarantined original acquisition is missing")
}
func (s *Store) LegacyAcquisitionQuarantine(ctx context.Context, kind, job string) (LegacyAcquisitionQuarantineRecord, bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return LegacyAcquisitionQuarantineRecord{}, false, err
	}
	defer tx.Rollback()
	r, found, err := s.legacyQuarantineTx(ctx, tx, kind, job)
	if err != nil {
		return r, false, err
	}
	return r, found, tx.Commit()
}
func (r *MetadataReader) LegacyAcquisitionQuarantine(ctx context.Context, kind, job string) (LegacyAcquisitionQuarantineRecord, bool, error) {
	return r.store.LegacyAcquisitionQuarantine(ctx, kind, job)
}

func freshReacquisitionJobTx(ctx context.Context, tx *sql.Tx, input provision.ApprovedImageInput) error {
	records, err := quarantineHistoryTx(ctx, tx)
	if err != nil {
		return err
	}
	for _, r := range records {
		var p ProvisionProperties
		if err = gvxcontract.DecodeStrict(r.Desired, 64<<10, 16, &p); err != nil {
			return err
		}
		if r.Identity == input.JobID || r.Identity == "image-space:"+input.JobID || p.Source == input.JobID || p.ImageSpace != nil && p.ImageSpace.JobID == input.JobID || p.ApprovedImageInput != nil && p.ApprovedImageInput.JobID == input.JobID {
			return errors.New("reacquisition job already has immutable history")
		}
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM storage_claims WHERE id IN (?,?,?))+(SELECT count(*) FROM storage_generations WHERE claim IN (?,?,?) OR generation IN (?,?))+(SELECT count(*) FROM generation_references WHERE id IN (?,?) OR claim IN (?,?,?))", input.JobID+":source", input.JobID+":cache", input.JobID+":preparation", input.JobID+":source", input.JobID+":cache", input.JobID+":preparation", "image-preparation:"+input.JobID, "development-worker:"+input.JobID, "image-preparation:"+input.JobID, "development-worker:"+input.JobID, input.JobID, "dev-upload:"+input.JobID, "prepared-image:"+provision.Revision(input)).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return errors.New("reacquisition job already has claims or references")
	}
	prefix := "management_plan:operator-preparation:"
	rows, err := tx.QueryContext(ctx, "SELECT value FROM metadata WHERE substr(key,1,?)=?", len(prefix), prefix)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		var r ManagementPlanRecord
		if err = gvxcontract.DecodeStrict(raw, revisionJSONMax, 40, &r); err != nil {
			return err
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(r.Plan, &fields); err != nil {
			return err
		}
		var old provision.ApprovedImageInput
		if err = json.Unmarshal(fields["input"], &old); err != nil {
			return err
		}
		if old.JobID == input.JobID {
			return errors.New("reacquisition job already reserved by another approval")
		}
	}
	return rows.Err()
}

func archiveQuarantinedCandidatesTx(ctx context.Context, tx *sql.Tx, l LegacyAcquisitionLineage, receipt LegacyAcquisitionQuarantineRecord) error {
	if l.ImageRecordID == "" {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT revision,module,selector,binding,policy FROM approved_image_candidates WHERE image=? ORDER BY revision,module,selector", l.ImageRecordID)
	if err != nil {
		return err
	}
	type archivedCandidate struct {
		Revision   string                            `json:"revision"`
		Module     string                            `json:"module"`
		Selector   string                            `json:"selector"`
		Binding    json.RawMessage                   `json:"binding"`
		Policy     json.RawMessage                   `json:"policy"`
		Quarantine LegacyAcquisitionQuarantineRecord `json:"quarantine"`
	}
	var archives []archivedCandidate
	for rows.Next() {
		a := archivedCandidate{Quarantine: receipt}
		if err = rows.Scan(&a.Revision, &a.Module, &a.Selector, &a.Binding, &a.Policy); err != nil {
			rows.Close()
			return err
		}
		var b ApprovedImageBinding
		var p LaunchSpec
		if err = gvxcontract.DecodeStrict(a.Binding, 64<<10, 8, &b); err != nil {
			rows.Close()
			return err
		}
		if err = gvxcontract.DecodeStrict(a.Policy, revisionJSONMax, 16, &p); err != nil {
			rows.Close()
			return err
		}
		if b.ImageRecordID != l.ImageRecordID || b.ModuleID != a.Module || b.ImageSelector != a.Selector || !policyMatchesBinding(p, b) {
			rows.Close()
			return errors.New("quarantined candidate binding/policy changed")
		}
		archives = append(archives, a)
		if len(archives) > legacyQuarantineMembersMax {
			rows.Close()
			return invalid("quarantined candidate archive exceeds bound")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, a := range archives {
		raw, e := json.Marshal(a)
		if e != nil {
			return e
		}
		identity, _ := json.Marshal([]string{a.Revision, a.Module, a.Selector})
		if err = immutableMetadataTx(ctx, tx, "legacy_quarantined_candidate:"+provision.DomainDigest("chatanium-quarantined-candidate-v1", identity), raw); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM approved_image_candidates WHERE revision=? AND module=? AND selector=? AND image=? AND binding=? AND policy=?", a.Revision, a.Module, a.Selector, l.ImageRecordID, []byte(a.Binding), []byte(a.Policy)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) BeginOperatorReacquisition(ctx context.Context, r ManagementPlanRecord) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if err := validateManagementPlan(r, s.productID); err != nil {
		return err
	}
	a, err := operatorPreparationApproval(r)
	if err != nil {
		return err
	}
	if a.Reacquisition == nil {
		return invalid("reviewed reacquisition authority required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	key, _ := managementKey(r.Kind, r.ID)
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&raw)
	if err == nil {
		old, e := decodeManagementPlan(raw, s.productID, r.Kind, r.ID)
		if e != nil {
			return e
		}
		if old.Digest != r.Digest || !bytes.Equal(old.Plan, r.Plan) || r.Snapshot.RuntimeInstallationID != "" && r.Snapshot != old.Snapshot {
			return errors.New("reacquisition replay changed immutable approval")
		}
		if old.Phase != "APPROVED" && old.Phase != "PREPARED" && old.Phase != "FAILED_CLEAN" && old.Phase != "COMMITTED" {
			return errors.New("reacquisition replay has invalid durable phase")
		}
		if old.Phase != "COMMITTED" {
			m, e := readManagementManifest(ctx, tx, s.productID)
			if e != nil {
				return e
			}
			var active string
			if e = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='management_active'").Scan(&active); e != nil {
				return e
			}
			if active != key || m.DesiredRunState != "STOPPED" || m.PendingRevision != "" || m.ActiveRevision != old.Snapshot.ActiveRevision || m.State != "READY" && m.State != "RECOVERY_REQUIRED" {
				return errors.New("reacquisition replay changed its active transaction/base")
			}
		}
		// Replay authenticates original receipts, never re-runs unused-job or the
		// original ExpectedState predicates against this transaction's own work.
		if e = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "operator_reacquisition_set:"+r.ID).Scan(&raw); e != nil {
			return e
		}
		var reviewed LegacyQuarantineSet
		if e = gvxcontract.DecodeStrict(raw, managementStateBytesMax, 16, &reviewed); e != nil {
			return e
		}
		if e = validateLegacyQuarantineSet(ctx, tx, reviewed, s.productID); e != nil {
			return e
		}
		if reviewed.Digest != a.Reacquisition.QuarantineSetDigest || reviewed.ActiveRevision != old.Snapshot.ActiveRevision || len(reviewed.Lineages) == 0 {
			return errors.New("reacquisition replay lost original reviewed set")
		}
		for _, l := range reviewed.Lineages {
			receipt, found, e := s.legacyQuarantineTx(ctx, tx, l.Kind, l.JobID)
			if e != nil {
				return e
			}
			want, _ := json.Marshal(l)
			got, _ := json.Marshal(receipt.Lineage)
			if !found || !bytes.Equal(want, got) {
				return errors.New("reacquisition replay lost original quarantine authority")
			}
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	m, err := readManagementManifest(ctx, tx, s.productID)
	if err != nil {
		return err
	}
	if m.State != a.Reacquisition.ExpectedState || m.ActiveRevision != a.ExpectedActiveRevision {
		return errors.New("reacquisition approval base state changed")
	}
	if err = freshReacquisitionJobTx(ctx, tx, a.Input); err != nil {
		return err
	}
	set, err := s.legacyQuarantineSetTx(ctx, tx)
	if err != nil {
		return err
	}
	if len(set.Lineages) == 0 || set.Digest != a.Reacquisition.QuarantineSetDigest {
		return errors.New("reviewed legacy quarantine membership changed")
	}
	if replacement := a.Reacquisition.ReplacesImageRecordID; replacement != "" {
		member := false
		for _, l := range set.Lineages {
			member = member || l.Kind == "image" && l.ImageRecordID == replacement
		}
		if !member {
			return errors.New("reviewed replacement is not an exact quarantined image")
		}
		var revisionRaw []byte
		if err = tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", m.ActiveRevision).Scan(&revisionRaw); err != nil {
			return err
		}
		var revision RevisionRecord
		if err = gvxcontract.DecodeStrict(revisionRaw, revisionJSONMax, 32, &revision); err != nil {
			return err
		}
		matches := 0
		for _, b := range revision.Images {
			if b.ModuleID == a.Input.ModuleID && b.ImageRecordID == replacement {
				matches++
			}
		}
		if matches != 1 {
			return errors.New("reviewed replacement differs from exact base module binding")
		}
	}
	for _, l := range set.Lineages {
		receipt := LegacyAcquisitionQuarantineRecord{Version: 1, PlanID: r.ID, PlanDigest: r.Digest, QuarantineSetDigest: set.Digest, Lineage: l}
		receiptRaw, e := json.Marshal(receipt)
		if e != nil {
			return e
		}
		for _, job := range append([]string{l.JobID}, l.DerivedJobIDs...) {
			qkey, _ := quarantineKey(l.Kind, job)
			var existing []byte
			e = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", qkey).Scan(&existing)
			if e == nil {
				// A later reviewed preparation does not acquire or replace the
				// first transaction's permanent quarantine authority.
				var prior LegacyAcquisitionQuarantineRecord
				if e = gvxcontract.DecodeStrict(existing, managementStateBytesMax, 16, &prior); e != nil {
					return e
				}
				want, _ := json.Marshal(l)
				got, _ := json.Marshal(prior.Lineage)
				if !bytes.Equal(want, got) {
					return errors.New("permanent quarantine lineage changed")
				}
				if _, found, e := s.legacyQuarantineTx(ctx, tx, l.Kind, job); e != nil {
					return e
				} else if !found {
					return errors.New("existing quarantine lacks immutable original approval")
				}
				continue
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if e = immutableMetadataTx(ctx, tx, qkey, receiptRaw); e != nil {
				return e
			}
		}
		for _, generation := range lineageGenerations(l) {
			if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO metadata VALUES(?,?)", "quarantined_generation:"+generation, receiptRaw); err != nil {
				return err
			}
		}
		if err = archiveQuarantinedCandidatesTx(ctx, tx, l, receipt); err != nil {
			return err
		}
	}
	// Keep this transaction's reviewed set even when all permanent lineages
	// were fenced by an earlier completed preparation.
	setRaw, err := json.Marshal(set)
	if err != nil {
		return err
	}
	if err = immutableMetadataTx(ctx, tx, "operator_reacquisition_set:"+r.ID, setRaw); err != nil {
		return err
	}
	if err = beginManagementPlanTx(ctx, tx, s.productID, r); err != nil {
		return err
	}
	return tx.Commit()
}

// validatePreparationLaunchBundleTx is new-dispatch authority only. Historical
// immutable writer proof deliberately does not depend on today's active bundle.
func validatePreparationLaunchBundleTx(ctx context.Context, tx *sql.Tx, product string, launch PreparationWriterLaunch, space ImageSpace) error {
	m, err := readManagementManifest(ctx, tx, product)
	if err != nil {
		return err
	}
	for _, id := range []string{launch.BundleDigest, "image-preparation:" + launch.JobID} {
		if err = checkGenerationAvailableTx(ctx, tx, id); err != nil {
			return err
		}
	}
	if space.ReusedSource {
		if err = checkGenerationAvailableTx(ctx, tx, space.SourceGenerationID); err != nil {
			return err
		}
	}
	if launch.BundleDigest == m.BundleDigest {
		return nil
	}
	if m.DesiredRunState != "STOPPED" {
		return errors.New("staged helper dispatch requires stopped reviewed management transaction")
	}
	var key string
	if err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='management_active'").Scan(&key); err != nil {
		return err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&raw); err != nil {
		return err
	}
	var header ManagementPlanRecord
	if err = gvxcontract.DecodeStrict(raw, revisionJSONMax, 40, &header); err != nil {
		return err
	}
	wantKey, e := managementKey(header.Kind, header.ID)
	if e != nil || wantKey != key {
		return errors.New("staged helper active management identity changed")
	}
	plan, err := decodeManagementPlan(raw, product, header.Kind, header.ID)
	if err != nil {
		return err
	}
	if plan.Phase == "COMMITTED" || plan.Phase == "FAILED_CLEAN" {
		return errors.New("completed management approval cannot dispatch staged helpers")
	}
	rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='image' AND identity=?", launch.JobID)
	if err != nil {
		return err
	}
	var acquisitions []ProvisionProperties
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
		if record.ProductCreated && !record.ExistedBefore && desired.ImageSpace != nil && samePreparationSpace(*desired.ImageSpace, space) && desired.ImageSpace.ProvisionID == launch.ProvisionID && desired.ImageSpace.JobID == launch.JobID && desired.Revision == launch.BundleDigest {
			acquisitions = append(acquisitions, desired)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(acquisitions) != 1 {
		return errors.New("staged helper lacks unique exact immutable acquisition input")
	}
	acquisition := acquisitions[0]
	if plan.Kind == "operator-preparation" {
		a, e := operatorPreparationApproval(plan)
		if e != nil {
			return e
		}
		if a.BundleDigest != launch.BundleDigest || a.Input.JobID != launch.JobID || acquisition.ApprovedImageInput == nil || *acquisition.ApprovedImageInput != a.Input || acquisition.ImageSpace.ReusedSource || m.ActiveRevision != a.ExpectedActiveRevision || m.PendingRevision != "" || plan.Snapshot.ActiveRevision != a.ExpectedActiveRevision {
			return errors.New("staged helper differs from exact reviewed preparation job/bundle/base")
		}
		if m.State != "READY" && !(a.Reacquisition != nil && m.State == "RECOVERY_REQUIRED") {
			return errors.New("staged helper preparation state is not admitted")
		}
		return nil
	}
	if plan.Kind == "update" {
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(plan.Plan, &fields); err != nil {
			return err
		}
		var bundleDigest, base string
		var candidate RevisionRecord
		if err = json.Unmarshal(fields["candidate_bundle_digest"], &bundleDigest); err != nil {
			return err
		}
		if err = json.Unmarshal(fields["expected_active_revision"], &base); err != nil {
			return err
		}
		if err = gvxcontract.DecodeStrict(fields["candidate_revision"], revisionJSONMax, 32, &candidate); err != nil {
			return err
		}
		// Cache construction is confined to this exact pre-cutover phase. A
		// failed attempt may have durably required recovery without changing
		// its approved stopped base or authorizing a different transaction.
		if plan.Phase != "PUBLISHED" || m.State != "READY" && m.State != "RECOVERY_REQUIRED" {
			return errors.New("staged update helper requires exact PUBLISHED replay authority")
		}
		if bundleDigest != launch.BundleDigest || candidate.BundleDigest != bundleDigest || base != plan.Snapshot.ActiveRevision || m.ActiveRevision != base || m.PendingRevision != "" && m.PendingRevision != candidate.ID || !acquisition.ImageSpace.ReusedSource || acquisition.ApprovedImageInput != nil || acquisition.Digest != acquisition.ImageSpace.SourceGenerationID {
			return errors.New("staged helper differs from exact reviewed update/source/bundle/base")
		}
		for _, binding := range candidate.Images {
			if binding.ImageRecordID == acquisition.Digest {
				return checkGenerationAvailableTx(ctx, tx, binding.ImageRecordID)
			}
		}
		return errors.New("staged helper source is absent from reviewed update candidate")
	}
	return errors.New("management approval cannot dispatch a staged preparation bundle")
}
