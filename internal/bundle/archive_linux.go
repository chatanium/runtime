//go:build linux

package bundle

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
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

// unpack receives a verified manifest and an exclusively owned, empty staging
// directory. Publication, ownership and parent trust remain Publish's concern.
func unpack(ctx context.Context, source Source, staging string, manifest Manifest) error {
	for directory := range directoryInventory(manifest) {
		if err := os.MkdirAll(filepath.Join(staging, directory), 0700); err != nil {
			return err
		}
	}
	stream, err := source.Open()
	if err != nil {
		return err
	}
	defer stream.Close()
	buffered := bufio.NewReader(stream)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return err
	}
	defer compressed.Close()
	compressed.Multistream(false)
	archive := tar.NewReader(io.LimitReader(compressed, MaxBundleBytes+int64(len(manifest.Files)+1)*2048+1024))
	remaining := make(map[string]File, len(manifest.Files))
	for _, file := range manifest.Files {
		remaining[file.Path] = file
	}
	buffer := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		expected, ok := remaining[header.Name]
		if !ok || header.Typeflag != tar.TypeReg || header.Size != expected.Size || header.Mode != int64(expected.Mode) || len(header.PAXRecords) != 0 || header.Linkname != "" {
			return fmt.Errorf("invalid archive member %q", header.Name)
		}
		output, err := os.OpenFile(filepath.Join(staging, expected.Path), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return err
		}
		hash := sha256.New()
		count, copyErr := io.CopyBuffer(io.MultiWriter(output, hash), archive, buffer)
		if copyErr == nil && (count != expected.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected.Digest) {
			copyErr = fmt.Errorf("bundle archive digest mismatch: %s", expected.Path)
		}
		if copyErr == nil {
			copyErr = output.Chmod(os.FileMode(expected.Mode))
		}
		if copyErr == nil {
			copyErr = output.Sync()
		}
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		delete(remaining, expected.Path)
	}
	if len(remaining) != 0 {
		return errors.New("incomplete bundle archive")
	}
	// Read through the gzip checksum, allowing only bounded zero tar padding.
	padding, err := io.ReadAll(io.LimitReader(compressed, 10241))
	if err != nil {
		return err
	}
	if len(padding) > 10240 || len(bytes.Trim(padding, "\x00")) != 0 {
		return errors.New("invalid trailing tar payload")
	}
	if _, err := buffered.Peek(1); err != io.EOF {
		return errors.New("trailing or concatenated bundle archive")
	}
	return ctx.Err()
}
