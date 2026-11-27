//go:build linux

package host

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/provision"
)

// MetadataReader exposes no lease or lifecycle mutations. Opening it never
// mounts storage, creates an owner, repairs a mirror, or changes SQL pragmas.
type MetadataReader struct{ store *Store }

func OpenMetadata(ctx context.Context, dir, id string, g *ManagementGuard) (*MetadataReader, error) {
	return openMetadataMode(ctx, dir, id, g, false)
}
func OpenTerminalPurgeMetadata(ctx context.Context, dir, id string, g *ManagementGuard) (*MetadataReader, error) {
	return openMetadataMode(ctx, dir, id, g, true)
}
func openMetadataMode(ctx context.Context, dir, id string, g *ManagementGuard, terminal bool) (*MetadataReader, error) {
	if err := g.require(terminal); err != nil {
		return nil, err
	}
	if err := g.checkNoReceipt(id); err != nil {
		return nil, err
	}
	if !safeID(id) || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, invalid("invalid passive installation locator")
	}
	if terminal {
		control, err := terminalObserve(dir, false)
		if err != nil {
			return nil, err
		}
		if control.Absent {
			return nil, os.ErrNotExist
		}
		if control.Kind != "directory" || control.UID != g.uid || control.Mode&0022 != 0 {
			return nil, errors.New("passive terminal control is not protected")
		}
		database, err := terminalObserve(filepath.Join(dir, "supervisor.sqlite"), false)
		if err != nil {
			return nil, err
		}
		if database.Absent {
			return nil, os.ErrNotExist
		}
	} else {
		directory, err := trustedDirectory(dir)
		if err != nil {
			return nil, err
		}
		directory.Close()
	}
	locator := url.URL{Scheme: "file", Path: filepath.Join(dir, "supervisor.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", locator.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (*MetadataReader, error) { db.Close(); return nil, err }
	if err = keepStoreWAL(ctx, db); err != nil {
		return fail(err)
	}
	for key, want := range map[string]string{"format": "chatanium-gvx", "format_version": "1", "schema_version": "1"} {
		var got string
		if err = db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&got); err != nil {
			return fail(err)
		}
		if got != want {
			return fail(errors.New("unsupported or markerless passive installation"))
		}
	}
	store := &Store{db: db, dir: dir, productID: id, gate: g, gateOwned: g.Mode() == ManagementShared}
	store.sourceControl, err = terminalObserve(dir, false)
	if err != nil {
		return fail(err)
	}
	store.sourceDatabase, err = terminalObserve(filepath.Join(dir, "supervisor.sqlite"), false)
	if err != nil {
		return fail(err)
	}
	if !terminal {
		if err = store.checkSourceAdmission(ctx, false); err != nil {
			return fail(err)
		}
	}
	if err = db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='incarnation'").Scan(&store.incarnation); err != nil {
		return fail(err)
	}
	manifest, err := store.Installation(ctx)
	if err != nil {
		return fail(err)
	}
	if manifest.Paths.Control != dir {
		return fail(errors.New("passive installation locator mismatch"))
	}
	if terminal {
		if err = store.validateTerminalPurgeMetadata(ctx); err != nil {
			return fail(err)
		}
	}
	return &MetadataReader{store: store}, nil
}
func (r *MetadataReader) Close() error { return r.store.Close() }
func (r *MetadataReader) Installation(ctx context.Context) (InstallationManifest, error) {
	return r.store.Installation(ctx)
}
func (r *MetadataReader) Revision(ctx context.Context, id string) (RevisionRecord, error) {
	return r.store.Revision(ctx, id)
}
func (r *MetadataReader) ManagementPlan(ctx context.Context, kind, id string) (ManagementPlanRecord, error) {
	return r.store.ManagementPlan(ctx, kind, id)
}
func (r *MetadataReader) ManagementPlans(ctx context.Context, kind string) ([]ManagementPlanRecord, error) {
	return r.store.ManagementPlans(ctx, kind)
}
func (r *MetadataReader) PendingProvisions(ctx context.Context) ([]ProvisionRecord, error) {
	return r.store.PendingProvisions(ctx)
}
func (r *MetadataReader) Provision(ctx context.Context, id string) (ProvisionRecord, error) {
	return r.store.Provision(ctx, id)
}
func (r *MetadataReader) ObjectProvisions(ctx context.Context, kind, identity string) ([]ProvisionRecord, error) {
	return r.store.ObjectProvisions(ctx, kind, identity)
}
func (r *MetadataReader) Image(ctx context.Context, id string) (provision.ImageRecord, error) {
	image, err := r.store.Image(ctx, id)
	if err != nil {
		return image, err
	}
	manifest, err := r.store.Installation(ctx)
	if err != nil {
		return image, err
	}
	if err = provision.ValidateRecord(image, provision.PrepareLimits{JSONBytes: durableJSONMax, InputBytes: manifest.Budget.SourceBytes, DescriptorCount: 4096, IndexDepth: 32}); err != nil {
		return image, err
	}
	return image, nil
}
func (r *MetadataReader) Images(ctx context.Context) ([]provision.ImageRecord, error) {
	manifest, err := r.store.Installation(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := r.store.db.QueryContext(ctx, "SELECT record FROM image_records ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var images []provision.ImageRecord
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var image provision.ImageRecord
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &image); err != nil {
			return nil, err
		}
		if err = provision.ValidateRecord(image, provision.PrepareLimits{JSONBytes: durableJSONMax, InputBytes: manifest.Budget.SourceBytes, DescriptorCount: 4096, IndexDepth: 32}); err != nil {
			return nil, err
		}
		images = append(images, image)
	}
	return images, rows.Err()
}
func (r *MetadataReader) Cache(ctx context.Context, id string) (CacheGeneration, error) {
	cache, err := r.store.Cache(ctx, id)
	if err != nil {
		return cache, err
	}
	if cache.ID != id {
		return cache, errors.New("cache metadata identity mismatch")
	}
	for _, generation := range []string{cache.ID, cache.ImageRecordID, cache.BundleDigest} {
		var unavailable bool
		if err = r.store.db.QueryRowContext(ctx, generationUnavailableQuery, "retiring_generation:"+generation, generation, generation).Scan(&unavailable); err != nil {
			return cache, err
		}
		if unavailable {
			return cache, errors.New("immutable generation is permanently retiring or released")
		}
	}
	return cache, nil
}
func (s *Store) CacheForImage(ctx context.Context, imageID, bundleDigest string) (CacheGeneration, error) {
	for _, generation := range []string{imageID, bundleDigest} {
		if err := s.CheckGenerationAvailable(ctx, generation); err != nil {
			return CacheGeneration{}, err
		}
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM cache_generations WHERE image=? ORDER BY id", imageID)
	if err != nil {
		return CacheGeneration{}, err
	}
	var found CacheGeneration
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return CacheGeneration{}, err
		}
		var c CacheGeneration
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &c); err != nil {
			rows.Close()
			return CacheGeneration{}, err
		}
		if c.ImageRecordID != imageID {
			rows.Close()
			return CacheGeneration{}, errors.New("cache metadata image binding mismatch")
		}
		if c.BundleDigest != bundleDigest {
			continue
		}
		if c.State != "READY" {
			rows.Close()
			return CacheGeneration{}, errors.New("matching image cache exists in non-READY state")
		}
		if found.ID != "" {
			rows.Close()
			return CacheGeneration{}, errors.New("ambiguous committed image cache")
		}
		found = c
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return CacheGeneration{}, err
	}
	if found.ID == "" {
		return found, sql.ErrNoRows
	}
	if err = s.CheckGenerationAvailable(ctx, found.ID); err != nil {
		return found, err
	}
	return found, nil
}
func (r *MetadataReader) CacheForImage(ctx context.Context, imageID, bundleDigest string) (CacheGeneration, error) {
	return r.store.CacheForImage(ctx, imageID, bundleDigest)
}

// PreparationUnitProvisions includes COMPLETE history. Empty means no outer
// dispatch intent was ever recorded, not merely that no loaded unit remains.
func (s *Store) PreparationUnitProvisions(ctx context.Context, jobID string) ([]ProvisionRecord, error) {
	if err := s.requireLease(); err != nil {
		return nil, err
	}
	if jobID == "" || len(jobID) > 4096 || strings.ContainsAny(jobID, "./\\\x00\r\n") {
		return nil, invalid("invalid preparation job ID")
	}
	if _, err := s.Installation(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='unit' ORDER BY rowid")
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
		var record ProvisionRecord
		if err = decodeProvisionRecord(raw, &record); err != nil {
			return nil, err
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return nil, err
		}
		if desired.Source != jobID {
			continue
		}
		prefix := ""
		for _, candidate := range []string{"chatanium-image-preparer-", "chatanium-image-rungv-"} {
			if strings.HasPrefix(record.Identity, candidate) {
				prefix = candidate
				break
			}
		}
		generation := strings.TrimSuffix(strings.TrimPrefix(record.Identity, prefix), ".service")
		if prefix == "" || !strings.HasSuffix(record.Identity, ".service") || !safeID(generation) || desired.Name != record.Identity || desired.Unit == nil || desired.Unit.Name != record.Identity || desired.Unit.Generation != generation || desired.Unit.BootID == "" || !record.ProductCreated || record.ExistedBefore {
			return nil, errors.New("preparation unit history has inconsistent immutable dispatch identity")
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (r *MetadataReader) LeaseOwner(ctx context.Context) (UnitIdentity, error) {
	return r.store.LeaseOwner(ctx)
}

func (r *MetadataReader) TerminalPurgeFence(ctx context.Context) (TerminalFence, error) {
	return r.store.TerminalPurgeFence(ctx)
}
func (r *MetadataReader) ActiveTerminalPublicationProbe(ctx context.Context) (TerminalProbeRecord, error) {
	return r.store.ActiveTerminalPublicationProbe(ctx)
}
func (r *MetadataReader) TerminalPurgePublication(ctx context.Context) (TerminalPublicationBinding, error) {
	return r.store.TerminalPurgePublication(ctx)
}
