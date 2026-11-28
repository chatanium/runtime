//go:build linux

package host

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

const generationUnavailableQuery = `SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?) OR EXISTS(SELECT 1 FROM storage_claims c WHERE c.state!='RESERVED' AND (c.id=? OR c.id IN (SELECT claim FROM storage_generations WHERE generation=?)))`

func checkGenerationRetainableTx(ctx context.Context, tx *sql.Tx, id string) error {
	if id == "" || len(id) > 4096 || strings.ContainsAny(id, "\x00\r\n") {
		return invalid("invalid immutable generation ID")
	}
	var unavailable bool
	if err := tx.QueryRowContext(ctx, generationUnavailableQuery, "retiring_generation:"+id, id, id).Scan(&unavailable); err != nil {
		return err
	}
	if unavailable {
		return errors.New("immutable generation is permanently retiring or released")
	}
	return nil
}

func checkGenerationAvailableTx(ctx context.Context, tx *sql.Tx, id string) error {
	if err := checkGenerationRetainableTx(ctx, tx, id); err != nil {
		return err
	}
	var quarantined bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?)", "quarantined_generation:"+id).Scan(&quarantined); err != nil {
		return err
	}
	if quarantined {
		return errors.New("immutable generation is permanently quarantined from use")
	}
	return nil
}

// CheckGenerationAvailable is a passive fence lookup, not authority to recreate
// an absent generation. Historical retired claim bindings are never ignored.
func (s *Store) CheckGenerationAvailable(ctx context.Context, id string) error {
	if id == "" || len(id) > 4096 || strings.ContainsAny(id, "\x00\r\n") {
		return invalid("invalid immutable generation ID")
	}
	var unavailable bool
	if err := s.db.QueryRowContext(ctx, generationUnavailableQuery+" OR EXISTS(SELECT 1 FROM metadata WHERE key=?)", "retiring_generation:"+id, id, id, "quarantined_generation:"+id).Scan(&unavailable); err != nil {
		return err
	}
	if unavailable {
		return errors.New("immutable generation is retiring, released, or quarantined from use")
	}
	return nil
}

// ImageCaches returns immutable full history, including retired generations.
func (s *Store) ImageCaches(ctx context.Context, recordID, bundleDigest string) ([]CacheGeneration, error) {
	if recordID == "" || bundleDigest == "" || len(recordID) > 4096 || len(bundleDigest) > 4096 {
		return nil, invalid("exact image/cache binding required")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM cache_generations WHERE image=? ORDER BY id", recordID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []CacheGeneration
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var cache CacheGeneration
		if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &cache); err != nil {
			return nil, err
		}
		if cache.ImageRecordID != recordID {
			return nil, errors.New("image cache history identity mismatch")
		}
		if cache.BundleDigest == bundleDigest {
			result = append(result, cache)
		}
	}
	return result, rows.Err()
}
func (r *MetadataReader) ImageCaches(ctx context.Context, recordID, bundleDigest string) ([]CacheGeneration, error) {
	return r.store.ImageCaches(ctx, recordID, bundleDigest)
}
func (r *MetadataReader) CheckGenerationAvailable(ctx context.Context, id string) error {
	return r.store.CheckGenerationAvailable(ctx, id)
}
func (r *MetadataReader) StorageGeneration(ctx context.Context, claimID string) (string, error) {
	return r.store.StorageGeneration(ctx, claimID)
}
