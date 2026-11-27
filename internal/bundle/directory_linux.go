//go:build linux

package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func trustedDirectory(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("bundle root must be an absolute clean path")
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		var st unix.Stat_t
		if e := unix.Lstat(current, &st); e != nil {
			return e
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return fmt.Errorf("untrusted bundle directory %s", current)
		}
	}
	return nil
}
func directoryInventory(m Manifest) map[string]bool {
	dirs := map[string]bool{".": true}
	for _, f := range m.Files {
		for p := filepath.Dir(f.Path); p != "."; p = filepath.Dir(p) {
			dirs[p] = true
		}
	}
	return dirs
}
func verifyFile(ctx context.Context, rootFD int, f File, buffer []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	fd, e := unix.Openat2(rootFD, f.Path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(fd), f.Path)
	defer file.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&07777 != f.Mode || st.Size != f.Size {
		return fmt.Errorf("bundle member metadata mismatch: %s", f.Path)
	}
	h := sha256.New()
	n, e := io.CopyBuffer(h, io.LimitReader(file, f.Size+1), buffer)
	if e != nil {
		return e
	}
	if n != f.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != f.Digest {
		return fmt.Errorf("bundle member digest mismatch: %s", f.Path)
	}
	return ctx.Err()
}
func VerifyDirectory(ctx context.Context, root string, m Manifest) (Verified, error) {
	fail := func(e error) (Verified, error) { return Verified{}, e }
	if e := trustedDirectory(root); e != nil {
		return fail(e)
	}
	manifest, e := os.OpenFile(filepath.Join(root, "manifest.json"), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return fail(e)
	}
	var manifestStat unix.Stat_t
	if e = unix.Fstat(int(manifest.Fd()), &manifestStat); e != nil {
		manifest.Close()
		return fail(e)
	}
	if manifestStat.Mode&unix.S_IFMT != unix.S_IFREG || manifestStat.Uid != 0 || manifestStat.Nlink != 1 || manifestStat.Mode&07777 != 0444 || manifestStat.Size > MaxManifestBytes {
		manifest.Close()
		return fail(errors.New("unsafe installed bundle manifest"))
	}
	raw, e := io.ReadAll(io.LimitReader(manifest, MaxManifestBytes+1))
	closeErr := manifest.Close()
	if e != nil {
		return fail(e)
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	actual, e := VerifyManifest(raw)
	if e != nil {
		return fail(e)
	}
	if actual.Digest != m.Digest {
		return fail(errors.New("bundle manifest identity mismatch"))
	}
	m = actual
	fd, e := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return fail(e)
	}
	defer unix.Close(fd)
	files := map[string]File{"manifest.json": {Path: "manifest.json", Size: int64(len(raw)), Mode: 0444}}
	h := sha256.Sum256(raw)
	mf := files["manifest.json"]
	mf.Digest = "sha256:" + hex.EncodeToString(h[:])
	files["manifest.json"] = mf
	for _, f := range m.Files {
		files[f.Path] = f
	}
	dirs := directoryInventory(m)
	buffer := make([]byte, 32<<10)
	e = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		if d.IsDir() {
			if !dirs[rel] {
				return errors.New("unlisted bundle directory")
			}
			var st unix.Stat_t
			if e = unix.Lstat(p, &st); e != nil {
				return e
			}
			if st.Uid != 0 || st.Mode&07777 != 0555 {
				return errors.New("mutable bundle directory")
			}
			return nil
		}
		f, ok := files[rel]
		if !ok {
			return fmt.Errorf("unlisted bundle member %s", rel)
		}
		delete(files, rel)
		return verifyFile(ctx, fd, f, buffer)
	})
	if e != nil {
		return fail(e)
	}
	if len(files) != 0 {
		return fail(errors.New("missing bundle members"))
	}
	return Verified{Root: root, Digest: m.Digest, Manifest: m}, nil
}

// Publish accepts only the exact listed regular members of a bounded gzip tar.
// Destination is a preapproved root-owned directory; digest generations are never
// overwritten. All files and directories are fsynced before atomic publication.
func Publish(ctx context.Context, source Source, destination string) (Verified, error) {
	if os.Geteuid() != 0 {
		return Verified{}, errors.New("bundle publication requires root")
	}
	if e := trustedDirectory(destination); e != nil {
		return Verified{}, e
	}
	raw, e := source.Manifest()
	if e != nil {
		return Verified{}, e
	}
	m, e := VerifyManifest(raw)
	if e != nil {
		return Verified{}, e
	}
	lock, e := os.OpenFile(filepath.Join(destination, ".bundle-publication.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		return Verified{}, e
	}
	defer lock.Close()
	if e = ctx.Err(); e != nil {
		return Verified{}, e
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return Verified{}, e
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	var st unix.Stat_t
	if e = unix.Fstat(int(lock.Fd()), &st); e != nil {
		return Verified{}, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&07777 != 0600 {
		return Verified{}, errors.New("unsafe bundle publication lock")
	}
	final := filepath.Join(destination, strings.TrimPrefix(m.Digest, "sha256:"))
	if _, e = os.Lstat(final); e == nil {
		return VerifyDirectory(ctx, final, m)
	} else if !os.IsNotExist(e) {
		return Verified{}, e
	}
	staging, e := os.MkdirTemp(destination, ".bundle-")
	if e != nil {
		return Verified{}, e
	}
	defer func() {
		if staging != "" {
			filepath.WalkDir(staging, func(p string, d os.DirEntry, e error) error {
				if e == nil && d.IsDir() {
					return os.Chmod(p, 0700)
				}
				return nil
			})
			os.RemoveAll(staging)
		}
	}()
	if e = unpack(ctx, source, staging, m); e != nil {
		return Verified{}, e
	}
	manifest, e := os.OpenFile(filepath.Join(staging, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return Verified{}, e
	}
	_, e = manifest.Write(raw)
	if e == nil {
		e = manifest.Chmod(0444)
	}
	if e == nil {
		e = manifest.Sync()
	}
	ce := manifest.Close()
	if e != nil {
		return Verified{}, e
	}
	if ce != nil {
		return Verified{}, ce
	}
	e = filepath.WalkDir(staging, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if e = os.Chmod(p, 0555); e != nil {
				return e
			}
			f, e := os.Open(p)
			if e != nil {
				return e
			}
			e = f.Sync()
			f.Close()
			return e
		}
		return nil
	})
	if e != nil {
		return Verified{}, e
	}
	if _, e = VerifyDirectory(ctx, staging, m); e != nil {
		return Verified{}, e
	}
	if e = unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE); e != nil {
		return Verified{}, e
	}
	staging = ""
	parent, e := os.Open(destination)
	if e != nil {
		return Verified{}, e
	}
	e = parent.Sync()
	parent.Close()
	if e != nil {
		return Verified{}, e
	}
	return VerifyDirectory(ctx, final, m)
}
