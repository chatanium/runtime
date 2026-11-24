package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

const (
	cacheLeaf     = "cache"
	cwdLeaf       = "cwd"
	logLeaf       = "logs"
	controlRecord = "control-path"
	controlOwner  = "owner"
	controlSocket = "s"
	controlToken  = "t"
	denyLeaf      = "deny.json"

	provisionalLeaf = "new-data.ext4"
	reclaimLeaf     = "uninitialized-data.ext4"

	// A run's bounded ancillary files include the compiled deny policy, the
	// GVX token, and control endpoint identity. Their combined size is < 1 KiB.
	ancillaryBytes int64 = 4096
)

func localPath(name string) (string, error) {
	path := filepath.FromSlash(name)
	if !filepath.IsLocal(path) || path == "." || filepath.Clean(path) != path {
		return "", errors.New("invalid installation-owned sandbox path")
	}
	return path, nil
}

// Check each component independently: os.Root prevents escape, but following a
// link to a different object inside the installation is also unauthorized.
func privateParents(root *os.Root, path string, create bool) error {
	if path == "." {
		return nil
	}
	if _, err := localPath(path); err != nil {
		return err
	}
	current := ""
	for part := range strings.SplitSeq(path, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if create && errors.Is(err, os.ErrNotExist) {
			if err = root.Mkdir(current, 0700); err == nil {
				if err = process.ProtectPrivateDir(filepath.Join(root.Name(), current)); err != nil {
					return err
				}
				if err = syncPath(root, filepath.Dir(current)); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = root.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("sandbox path traverses a link or non-directory")
		}
		if err = process.CheckPrivateDir(filepath.Join(root.Name(), current)); err != nil {
			return err
		}
	}
	return nil
}

func observeVolume(root *os.Root, path string) (store.PersistentObservation, error) {
	var zero store.PersistentObservation
	if err := privateParents(root, filepath.Dir(path), false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return zero, nil
		}
		return zero, err
	}
	before, err := root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return zero, nil
	}
	if err != nil {
		return zero, err
	}
	if !before.Mode().IsRegular() {
		return zero, errors.New("persistent backing is not a regular file")
	}
	file, err := openVolume(root, path)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return zero, errors.New("persistent backing changed during protected observation")
	}
	id, err := nativeFileID(file, info)
	if err != nil {
		return zero, err
	}
	return store.PersistentObservation{Exists: true, NativeID: id, SizeBytes: info.Size()}, nil
}

func validateVolume(volume store.Volume, actual store.PersistentObservation) error {
	if (!volume.Initialized && (actual.Exists || volume.NativeID != "")) ||
		(volume.Initialized && (!actual.Exists || volume.NativeID == "" || actual.NativeID != volume.NativeID ||
			actual.SizeBytes < store.MinVolumeBytes || actual.SizeBytes > volume.MaxBytes || actual.SizeBytes%store.VolumeAlignmentBytes != 0)) {
		return errors.New("persistent backing is missing, unrecognized, or outside the approved size; it will not be opened by GVX")
	}
	return nil
}

// createPersistent creates the only empty backing the stock engine may
// format: a run-private O_EXCL file bound to its store birth intent before
// its name can appear in the canonical volume directory.
func createPersistent(ctx context.Context, db *store.Store, root, workspace *os.Root, run store.Run, runPath, final string) (store.PersistentObservation, error) {
	var zero store.PersistentObservation
	file, err := workspace.OpenFile(provisionalLeaf, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return zero, err
	}
	info, err := file.Stat()
	if err != nil {
		return zero, errors.Join(err, file.Close())
	}
	id, err := nativeFileID(file, info)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return zero, errors.Join(err, file.Close(), errors.New("new persistent candidate is not a private empty file"))
	}
	if err = errors.Join(file.Sync(), file.Close()); err != nil {
		return zero, err
	}
	created := store.PersistentObservation{Exists: true, NativeID: id}
	if err = db.RecordPersistentCreation(ctx, run.Key, created); err != nil {
		return zero, err
	}
	if err = moveExclusive(root, filepath.Join(runPath, provisionalLeaf), final); err != nil {
		return zero, fmt.Errorf("publish empty persistent candidate without replacement: %w", err)
	}
	actual, err := observeVolume(root, final)
	if err != nil || actual != created {
		return zero, errors.Join(err, errors.New("published persistent candidate identity differs from its birth intent"))
	}
	return actual, nil
}

func controlDir(root *os.Root, run store.Run) (string, error) {
	return ipcpath.Directory(root.Name(), "sandbox:"+run.Key.ID)
}

func controlMarker(run store.Run) string { return run.Key.EpochID + ":" + run.Key.ID }

func makeControl(root *os.Root, run store.Run, dir string) (bool, error) {
	// The run journal locates the external temp endpoint even if TMPDIR differs
	// after a reboot. Track it before mkdir; retain ambiguity on a partial setup.
	if err := writeRecord(root, controlRecord, []byte(dir)); err != nil {
		return false, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return false, err
	}
	if err := process.ProtectPrivateDir(dir); err != nil {
		return true, err
	}
	control, err := os.OpenRoot(dir)
	if err != nil {
		return true, err
	}
	defer control.Close()
	return true, writeRecord(control, controlOwner, []byte(controlMarker(run)))
}

func writeRecord(root *os.Root, name string, data []byte) error {
	temp := name + ".new"
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return err
	}
	return commitRecord(root, temp, name)
}

func publishCache(ctx context.Context, root *os.Root, runPath string, i *instance) error {
	image := i.module.Image
	imageDir, err := localPath(image.Directory)
	if err != nil {
		return err
	}
	cacheDir := filepath.Join(runPath, cacheLeaf)
	for _, file := range image.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := localPath(file.Path)
		if err != nil || filepath.Base(name) != name {
			return errors.New("verified cache contains a non-leaf object")
		}
		source, target := filepath.Join(imageDir, name), filepath.Join(cacheDir, name)
		info, err := root.Lstat(source)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() != file.Size {
			return errors.New("verified cache object is not immutable")
		}
		// The selected, already verified objects are only ever read by pinned
		// GVX (--pull=never). Separate writable cache directories contain all
		// ephemeral backing names; no other generation is visible here. Never
		// fall back to an unaccounted copy or change permissions on the link.
		if err = root.Link(source, target); err != nil {
			return fmt.Errorf("link reviewed cache into private engine view: %w", err)
		}
		linked, err := root.Lstat(target)
		if err != nil {
			return err
		}
		if !os.SameFile(info, linked) || !linked.Mode().IsRegular() {
			return errors.New("verified cache identity changed while staging")
		}
	}
	return nil
}

func readLocal(root *os.Root, name string, limit int64) (string, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return "", errors.New("invalid sandbox recovery marker")
	}
	f, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) {
		return "", errors.Join(err, errors.New("sandbox recovery marker changed"))
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(raw)) > limit {
		return "", errors.New("sandbox recovery marker too large")
	}
	return string(raw), err
}

// Remove only the exact run-owned directories, after positive native scope
// exit. A reboot is proof of closed handles, not of a foreign path's ownership.
func removeRunFiles(root *os.Root, run store.Run, live *instance) error {
	runPath, err := localPath(run.InstancePath)
	if err != nil {
		return err
	}
	if live != nil && !live.runDirOwned {
		if _, err := root.Lstat(runPath); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("run workspace existence is not owned by this activation")
	}
	if err := privateParents(root, runPath, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // Endpoint creation requires a durable record in this directory.
		}
		return err
	}
	workspace, err := root.OpenRoot(runPath)
	if err != nil {
		return err
	}
	dir, recordErr := readLocal(workspace, controlRecord, 512)
	closeErr := workspace.Close()
	if closeErr != nil {
		return closeErr
	}
	if recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
		return recordErr
	}
	if recordErr == nil && dir == "" {
		return errors.New("sandbox recovery endpoint identity is empty")
	}
	if dir != "" {
		expected, err := controlDir(root, run)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || filepath.Base(dir) != filepath.Base(expected) {
			return errors.New("sandbox recovery endpoint identity is invalid")
		}
		if err := process.CheckPrivateDir(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if _, err := os.Lstat(dir); err == nil {
			if live != nil {
				if !live.controlOwned || dir != live.controlDir {
					return errors.New("sandbox endpoint is not owned by this activation")
				}
			} else {
				if err = process.CheckPrivateDir(dir); err != nil {
					return err
				}
				ep, err := os.OpenRoot(dir)
				if err != nil {
					return err
				}
				marker, readErr := readLocal(ep, controlOwner, 256)
				closeErr := ep.Close()
				if readErr != nil || closeErr != nil || marker != controlMarker(run) {
					return errors.Join(readErr, closeErr, errors.New("sandbox endpoint ownership is unconfirmed"))
				}
			}
			if err = os.RemoveAll(dir); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(err, errors.New("sandbox endpoint has not been removed"))
		}
	}
	if err = removeCacheLinks(root, filepath.Join(runPath, cacheLeaf)); err != nil {
		return err
	}
	if err = root.RemoveAll(runPath); err != nil {
		return err
	}
	if _, err = root.Lstat(runPath); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, errors.New("sandbox workspace has not been removed"))
	}
	return nil
}
