//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func removeBundle(ctx context.Context, s *ownedSession, record host.ProvisionRecord, evidence host.CleanupEvidence) error {
	if complete, e := rejectCompletedReappearance(ctx, s.store, record); complete || e != nil {
		return e
	}
	if e := matchPurgeRecord(ctx, s.store, record); e != nil {
		return e
	}
	intent, e := beginRemoval(ctx, s.store, record)
	if e != nil {
		return e
	}
	var p host.ProvisionProperties
	if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return e
	}
	if removedPath(p.Path) {
		return finishBundleRemoval(ctx, s, record, intent, evidence)
	}
	raw, e := readProtected(filepath.Join(p.Path, "manifest.json"), bundle.MaxManifestBytes)
	if os.IsNotExist(e) {
		entries, readErr := os.ReadDir(p.Path)
		if readErr != nil {
			return readErr
		}
		if len(entries) != 0 {
			return errors.New("bundle manifest missing before all listed content was removed")
		}
		if e = os.Remove(p.Path); e != nil {
			return e
		}
		return finishBundleRemoval(ctx, s, record, intent, evidence)
	}
	if e != nil {
		return e
	}
	manifest, e := bundle.VerifyManifest(raw)
	if e != nil {
		return e
	}
	if manifest.Digest != p.Digest {
		return errors.New("bundle removal manifest identity mismatch")
	}
	files := map[string]bundle.File{}
	directories := map[string]bool{".": true}
	for _, file := range manifest.Files {
		files[file.Path] = file
		for parent := filepath.Dir(file.Path); parent != "."; parent = filepath.Dir(parent) {
			directories[parent] = true
		}
	}
	var dirs []string
	count := 0
	e = filepath.WalkDir(p.Path, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		count++
		if count > len(files)+len(directories)+1 {
			return errors.New("unlisted bundle removal content")
		}
		relative, e := filepath.Rel(p.Path, path)
		if e != nil {
			return e
		}
		var st unix.Stat_t
		if e = unix.Lstat(path, &st); e != nil {
			return e
		}
		if st.Uid != 0 {
			return errors.New("bundle member owner changed")
		}
		if entry.IsDir() {
			if !directories[relative] || st.Mode&07777 != 0555 && st.Mode&07777 != 0700 {
				return errors.New("bundle directory no longer belongs to immutable inventory")
			}
			dirs = append(dirs, path)
			return nil
		}
		if relative == "manifest.json" {
			return nil
		}
		expected, ok := files[relative]
		if !ok || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&07777 != expected.Mode || st.Size != expected.Size {
			return errors.New("bundle member metadata changed before removal")
		}
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		file := os.NewFile(uintptr(fd), path)
		actual, e := streamDigest(io.LimitReader(file, expected.Size+1))
		file.Close()
		if e != nil {
			return e
		}
		if actual != expected.Digest {
			return errors.New("bundle member digest changed before removal")
		}
		return nil
	})
	if e != nil {
		return e
	}
	for _, dir := range dirs {
		if e = os.Chmod(dir, 0700); e != nil {
			return e
		}
	}
	for _, file := range manifest.Files {
		if e = os.Remove(filepath.Join(p.Path, file.Path)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		if dir == p.Path {
			continue
		}
		if e = syncDirectory(dir); e != nil {
			return e
		}
		if e = os.Remove(dir); e != nil {
			return e
		}
	}
	if e = os.Remove(filepath.Join(p.Path, "manifest.json")); e != nil {
		return e
	}
	if e = syncDirectory(p.Path); e != nil {
		return e
	}
	if e = os.Remove(p.Path); e != nil {
		return e
	}
	return finishBundleRemoval(ctx, s, record, intent, evidence)
}
func finishBundleRemoval(ctx context.Context, s *ownedSession, record host.ProvisionRecord, intent string, evidence host.CleanupEvidence) error {
	var p host.ProvisionProperties
	if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return e
	}
	if _, e := os.Lstat(filepath.Dir(p.Path)); e == nil {
		if e = syncDirectory(filepath.Dir(p.Path)); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if s.purgeRetirements[record.ID] {
		return nil
	}
	return errors.Join(s.store.CompleteProvisionCleanup(ctx, record.ID, evidence), s.store.CompleteProvisionCleanup(ctx, intent, evidence))
}
func syncDirectory(path string) error {
	directory, e := os.Open(path)
	if e != nil {
		return e
	}
	defer directory.Close()
	return directory.Sync()
}
