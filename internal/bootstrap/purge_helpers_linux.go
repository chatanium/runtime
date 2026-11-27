//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const purgeHelperSource = "purge-helper"

func hasPurgeBundleLineage(ctx context.Context, store *host.Store, m host.InstallationManifest) (bool, error) {
	for _, identity := range []string{m.Paths.EngineRoot, filepath.Join(m.Paths.EngineRoot, strings.TrimPrefix(m.BundleDigest, "sha256:"))} {
		records, e := store.ObjectProvisions(ctx, "bundle", identity)
		if e != nil {
			return false, e
		}
		for _, record := range records {
			if !record.ProductCreated || record.State != "OBSERVED" {
				continue
			}
			var p host.ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
				return false, e
			}
			if p.Digest != m.BundleDigest {
				continue
			}
			if _, exists, e := removalFor(ctx, store, record); e != nil {
				return false, e
			} else if exists {
				return true, nil
			}
		}
	}
	return false, nil
}
func publishPurgeHelpers(ctx context.Context, store *host.Store, m host.InstallationManifest, source bundle.Source) (bundle.Verified, error) {
	container := filepath.Join(m.Paths.Control, ".purge-helper")
	create := func(path, parent string) error {
		p := host.ProvisionProperties{Path: path, Parent: parent, Source: purgeHelperSource, Digest: m.BundleDigest, Mode: 0700, ProductCreated: true}
		intent, e := recordIntent(ctx, store, "directory", path, p, false)
		if e != nil {
			return e
		}
		if e = os.Mkdir(path, 0700); e != nil {
			return e
		}
		directory, e := os.Open(parent)
		if e != nil {
			return e
		}
		e = directory.Sync()
		directory.Close()
		if e != nil {
			return e
		}
		return observePath(ctx, store, intent, path, p)
	}
	if _, e := os.Lstat(container); os.IsNotExist(e) {
		if e = create(container, m.Paths.Control); e != nil {
			return bundle.Verified{}, e
		}
	} else if e != nil {
		return bundle.Verified{}, e
	} else {
		record, e := ownedRecord(ctx, store, "directory", container)
		if e != nil {
			return bundle.Verified{}, e
		}
		helper, e := purgeHelperArtifact(ctx, store, m, record)
		if e != nil {
			return bundle.Verified{}, e
		}
		if !helper {
			return bundle.Verified{}, errors.New("cleanup helper container is not owned")
		}
		if e = matchRecord(record); e != nil {
			return bundle.Verified{}, e
		}
	}
	id := newID()
	if !validID(id) {
		return bundle.Verified{}, errors.New("cannot allocate cleanup helper identity")
	}
	root := filepath.Join(container, id)
	if e := create(root, container); e != nil {
		return bundle.Verified{}, e
	}
	target := filepath.Join(root, strings.TrimPrefix(m.BundleDigest, "sha256:"))
	intent, e := recordIntent(ctx, store, "bundle", target, host.ProvisionProperties{Path: target, Parent: root, Source: purgeHelperSource, Digest: m.BundleDigest, ProductCreated: true}, false)
	if e != nil {
		return bundle.Verified{}, e
	}
	verified, e := publishBundle(ctx, store, source, root)
	if e != nil {
		return bundle.Verified{}, e
	}
	if e = observeBundle(ctx, store, intent, target, verified); e != nil {
		return bundle.Verified{}, e
	}
	return verified, nil
}
func purgeHelperArtifact(ctx context.Context, store *host.Store, m host.InstallationManifest, record host.ProvisionRecord) (bool, error) {
	var p host.ProvisionProperties
	if e := gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &p); e != nil {
		return false, e
	}
	container := filepath.Join(m.Paths.Control, ".purge-helper")
	if record.Kind == "config" && filepath.Base(record.Identity) == ".bundle-publication.lock" {
		root := filepath.Dir(record.Identity)
		if filepath.Dir(root) != container || !validID(filepath.Base(root)) || !validID(p.Source) {
			return false, nil
		}
		parent, e := store.Provision(ctx, p.Source)
		if e != nil {
			return false, e
		}
		if record.Identity != filepath.Join(parent.Identity, ".bundle-publication.lock") {
			return false, nil
		}
		return purgeHelperArtifact(ctx, store, m, parent)
	}
	if p.Source != purgeHelperSource || p.Digest != m.BundleDigest || !record.ProductCreated || record.ExistedBefore {
		return false, nil
	}
	root := record.Identity
	if record.Kind == "bundle" {
		root = filepath.Dir(record.Identity)
	} else if record.Kind != "directory" {
		return false, nil
	}
	if record.Kind == "directory" && root == container {
		return true, nil
	}
	if filepath.Dir(root) != container || !validID(filepath.Base(root)) {
		return false, errors.New("invalid private purge helper identity")
	}
	return true, nil
}
func removePurgeHelpers(ctx context.Context, s *ownedSession, records []host.ProvisionRecord) error {
	sort.SliceStable(records, func(i, j int) bool {
		order := func(r host.ProvisionRecord) int {
			switch r.Kind {
			case "config":
				return 0
			case "bundle":
				return 1
			default:
				return 2
			}
		}
		a, b := order(records[i]), order(records[j])
		if a == b {
			return len(records[i].Identity) > len(records[j].Identity)
		}
		return a < b
	})
	for _, record := range records {
		if record.State != "OBSERVED" {
			return errors.New("private purge helper creation remains uncertain")
		}
		if record.Kind == "bundle" {
			if e := removeBundle(ctx, s, record, s.cleanupEvidence); e != nil {
				return e
			}
		} else if e := removeRecorded(ctx, s, record, s.cleanupEvidence); e != nil {
			return e
		}
		var p host.ProvisionProperties
		if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return e
		}
		path := record.Identity
		if record.Kind == "bundle" {
			path = p.Path
		}
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return errors.Join(errors.New("private cleanup closure absence not established"), e)
		}
	}
	return nil
}
func bundleRemovalRootMatches(path string, p host.ProvisionProperties) bool {
	var st unix.Stat_t
	return unix.Lstat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == p.UID && st.Gid == p.GID && uint64(st.Dev) == p.Dev && st.Ino == p.Ino && (st.Mode&07777 == 0555 || st.Mode&07777 == 0700)
}
func validateControlAncestors(control string, ancestors []host.ProvisionRecord) error {
	allowed := map[string]bool{control: true}
	for _, record := range ancestors {
		allowed[record.Identity] = true
	}
	for _, record := range ancestors {
		entries, e := os.ReadDir(record.Identity)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		for _, entry := range entries {
			child := filepath.Join(record.Identity, entry.Name())
			if !allowed[child] {
				return errors.New("selected ancestor contains preserved or foreign objects; ownership evidence retained")
			}
		}
	}
	return nil
}
