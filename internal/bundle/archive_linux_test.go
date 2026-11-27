//go:build linux

package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type archiveSource []byte

func (s archiveSource) Manifest() ([]byte, error)    { return nil, nil }
func (s archiveSource) Open() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(s)), nil }

func archiveFixture(t *testing.T, manifest Manifest, change func(*tar.Header, []byte) (*tar.Header, []byte), duplicate, missing bool) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	archive := tar.NewWriter(gzipWriter)
	for index, file := range manifest.Files {
		if missing && index == 0 {
			continue
		}
		header := &tar.Header{Name: file.Path, Typeflag: tar.TypeReg, Size: 1, Mode: int64(file.Mode), Format: tar.FormatUSTAR}
		data := []byte("x")
		if index == 0 && change != nil {
			header, data = change(header, data)
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(data); err != nil {
			t.Fatal(err)
		}
		if duplicate && index == 0 {
			if err := archive.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if _, err := archive.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func testArchiveIntegrity(t *testing.T) {
	manifest := bundleFixture(t)
	hash := sha256.Sum256([]byte("x"))
	for index := range manifest.Files {
		manifest.Files[index].Digest = "sha256:" + hex.EncodeToString(hash[:])
	}
	valid := archiveFixture(t, manifest, nil, false, false)
	t.Run("complete-member-hashes-and-modes", func(t *testing.T) {
		root := t.TempDir()
		if err := unpack(context.Background(), archiveSource(valid), root, manifest); err != nil {
			t.Fatal(err)
		}
		for _, file := range manifest.Files {
			data, err := os.ReadFile(filepath.Join(root, file.Path))
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(filepath.Join(root, file.Path))
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "x" || uint32(info.Mode().Perm()) != file.Mode {
				t.Fatal("published bytes/modes differ")
			}
		}
	})
	cases := map[string][]byte{
		"corrupted-member": archiveFixture(t, manifest, func(h *tar.Header, b []byte) (*tar.Header, []byte) { return h, []byte("y") }, false, false),
		"traversal-member": archiveFixture(t, manifest, func(h *tar.Header, b []byte) (*tar.Header, []byte) { h.Name = "../outside"; return h, b }, false, false),
		"symbolic-link": archiveFixture(t, manifest, func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			h.Typeflag = tar.TypeSymlink
			h.Linkname = "/outside"
			h.Size = 0
			return h, nil
		}, false, false),
		"duplicate-member":    archiveFixture(t, manifest, nil, true, false),
		"missing-member":      archiveFixture(t, manifest, nil, false, true),
		"concatenated-stream": append(bytes.Clone(valid), valid...),
		"trailing-data":       append(bytes.Clone(valid), byte(1)),
		"truncated-stream":    valid[:len(valid)-1],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := unpack(context.Background(), archiveSource(data), t.TempDir(), manifest); err == nil {
				t.Fatal("accepted malformed bundle archive")
			}
		})
	}
}
