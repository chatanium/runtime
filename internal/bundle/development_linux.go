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

	"golang.org/x/sys/unix"
)

// VerifyDevelopmentWorkerDirectory checks immutable filesystem metadata and
// hashes only. In particular it never parses ELF or executes candidate code.
func VerifyDevelopmentWorkerDirectory(ctx context.Context, root string, expected DevelopmentWorkerManifest, base Verified) (VerifiedDevelopmentWorker, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedDevelopmentWorker{}, err
	}
	if err := trustedDirectory(root); err != nil {
		return VerifiedDevelopmentWorker{}, err
	}
	if base.Digest != base.Manifest.Digest || base.Digest != expected.BaseBundleDigest {
		return VerifiedDevelopmentWorker{}, errors.New("development worker base identity mismatch")
	}
	manifestFile, err := os.OpenFile(filepath.Join(root, DevelopmentWorkerManifestPath), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return VerifiedDevelopmentWorker{}, err
	}
	var stat unix.Stat_t
	if err = unix.Fstat(int(manifestFile.Fd()), &stat); err != nil {
		manifestFile.Close()
		return VerifiedDevelopmentWorker{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&07777 != 0444 || stat.Size > MaxDevelopmentManifestBytes {
		manifestFile.Close()
		return VerifiedDevelopmentWorker{}, errors.New("unsafe development worker manifest file")
	}
	raw, err := io.ReadAll(io.LimitReader(manifestFile, MaxDevelopmentManifestBytes+1))
	closeErr := manifestFile.Close()
	if err != nil {
		return VerifiedDevelopmentWorker{}, err
	}
	if closeErr != nil {
		return VerifiedDevelopmentWorker{}, closeErr
	}
	actual, err := VerifyDevelopmentWorkerManifest(raw, base.Manifest)
	if err != nil {
		return VerifiedDevelopmentWorker{}, err
	}
	if actual.Digest != expected.Digest {
		return VerifiedDevelopmentWorker{}, errors.New("development worker manifest changed")
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return VerifiedDevelopmentWorker{}, err
	}
	defer unix.Close(rootFD)
	files := make(map[string]File, len(actual.Files)+1)
	for _, file := range actual.Files {
		files[file.Path] = file
	}
	hash := sha256.Sum256(raw)
	files[DevelopmentWorkerManifestPath] = File{Path: DevelopmentWorkerManifestPath, Digest: "sha256:" + hex.EncodeToString(hash[:]), Size: int64(len(raw)), Mode: 0444}
	directories := directoryInventory(Manifest{Files: actual.Files})
	buffer := make([]byte, 32<<10)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if !directories[relative] {
				return fmt.Errorf("unlisted development directory %q", relative)
			}
			var stat unix.Stat_t
			if err := unix.Lstat(path, &stat); err != nil {
				return err
			}
			mode := uint32(0555)
			if relative == "." {
				mode = 0550
			}
			if stat.Uid != 0 || stat.Mode&07777 != mode {
				return errors.New("mutable development worker directory")
			}
			return nil
		}
		expected, ok := files[relative]
		if !ok {
			return fmt.Errorf("unlisted development worker member %q", relative)
		}
		if err := verifyFile(ctx, rootFD, expected, buffer); err != nil {
			return err
		}
		delete(files, relative)
		return nil
	})
	if err != nil {
		return VerifiedDevelopmentWorker{}, err
	}
	if len(files) != 0 {
		return VerifiedDevelopmentWorker{}, errors.New("missing development worker inventory members")
	}
	if filepath.Base(root) != "generation" {
		return VerifiedDevelopmentWorker{}, errors.New("development generation path mismatch")
	}
	return VerifiedDevelopmentWorker{Root: root, Digest: actual.Digest, JobID: filepath.Base(filepath.Dir(root)), Manifest: actual}, nil
}
