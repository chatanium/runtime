//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func publishBundle(ctx context.Context, store *host.Store, source bundle.Source, root string) (verified bundle.Verified, retErr error) {
	parent, e := ownedRecord(ctx, store, "directory", root)
	if e != nil {
		return verified, e
	}
	if e = matchRecord(parent); e != nil {
		return verified, e
	}
	path := filepath.Join(root, ".bundle-publication.lock")
	intent := ""
	records, e := store.PendingProvisions(ctx)
	if e != nil {
		return verified, e
	}
	raw, e := source.Manifest()
	if e != nil {
		return verified, e
	}
	manifest, e := bundle.VerifyManifest(raw)
	if e != nil {
		return verified, e
	}
	final := filepath.Join(root, strings.TrimPrefix(manifest.Digest, "sha256:"))
	authorized := false
	for _, record := range records {
		if record.Kind != "bundle" || (record.Identity != root && record.Identity != final) || !record.ProductCreated || record.ExistedBefore || record.CleanupState == "COMPLETE" {
			continue
		}
		var desired host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return verified, e
		}
		if desired.Digest != manifest.Digest {
			continue
		}
		if record.State == "OBSERVED" {
			if e = matchRecord(record); e != nil {
				return verified, e
			}
		}
		authorized = true
	}
	if !authorized {
		return verified, errors.New("bundle publication lacks exact durable digest intent")
	}
	for _, record := range records {
		if record.Kind == "config" && record.Identity == path && record.ProductCreated && !record.ExistedBefore {
			if record.State == "OBSERVED" {
				if e = matchRecord(record); e != nil {
					return verified, e
				}
			}
			intent = record.ID
			break
		}
	}
	properties := host.ProvisionProperties{Path: path, Parent: root, Source: parent.ID, Mode: 0600, ProductCreated: true}
	if intent == "" {
		if _, e = os.Lstat(path); e == nil {
			return verified, errors.New("unowned bundle publication lock cannot be adopted")
		} else if !os.IsNotExist(e) {
			return verified, e
		}
		intent, e = recordIntent(ctx, store, "config", path, properties, false)
		if e != nil {
			return verified, e
		}
	}
	defer func() {
		var st unix.Stat_t
		e := unix.Lstat(path, &st)
		if os.IsNotExist(e) {
			return
		}
		if e == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Size != 0) {
			e = errors.New("bundle publication lock metadata changed")
		}
		if e == nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			e = observePath(cleanup, store, intent, path, properties)
		}
		retErr = errors.Join(retErr, e)
	}()
	return bundle.Publish(ctx, source, root)
}
func observeBundle(ctx context.Context, store *host.Store, intent, identity string, verified bundle.Verified) error {
	var st unix.Stat_t
	if e := unix.Lstat(verified.Root, &st); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&07777 != 0555 {
		return errors.New("published bundle root metadata mismatch")
	}
	properties := host.ProvisionProperties{Path: verified.Root, Digest: verified.Digest, Dev: uint64(st.Dev), Ino: st.Ino, Mode: st.Mode & 07777, UID: st.Uid, GID: st.Gid, ProductCreated: true}
	return store.ObserveProvision(ctx, intent, host.ObjectObservation{Identity: identity, Attributes: provisionJSON(properties)})
}
