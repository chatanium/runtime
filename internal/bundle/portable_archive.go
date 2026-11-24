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
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

func portableInventory(m PortableManifest) (map[string]File, map[string]bool) {
	files := make(map[string]File, len(m.Files)+1)
	dirs := map[string]bool{".": true}
	for _, f := range m.Files {
		files[f.Path] = f
		for p := path.Dir(f.Path); p != "." && !dirs[p]; p = path.Dir(p) {
			dirs[p] = true
		}
	}
	return files, dirs
}

func scanPortableArchive(ctx context.Context, source Source, m PortableManifest, destination *os.Root) error {
	stream, err := source.Open()
	if err != nil {
		return err
	}
	defer stream.Close()
	buffered := bufio.NewReader(stream)
	gz, err := gzip.NewReader(buffered)
	if err != nil {
		return err
	}
	defer gz.Close()
	gz.Multistream(false)
	remaining := make(map[string]File, len(m.Files))
	// The verified USTAR members fit exactly one header and the padded
	// content each, followed by two end records. Other gzip bytes are
	// checked separately below.
	bound := int64(1024 + len(m.Files)*512)
	for _, f := range m.Files {
		remaining[f.Path] = f
		bound += (f.Size + 511) &^ 511
	}
	limited := &io.LimitedReader{R: gz, N: bound}
	tr := tar.NewReader(limited)
	buffer := make([]byte, 32<<10)
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		f, ok := remaining[h.Name]
		if !ok || h.Format != tar.FormatUSTAR || h.Typeflag != tar.TypeReg || h.Size != f.Size || h.Mode != int64(f.Mode) || h.Linkname != "" {
			return fmt.Errorf("invalid portable archive member %q", h.Name)
		}
		if err = copyPortableFile(destination, f, tr, buffer); err != nil {
			return err
		}
		delete(remaining, h.Name)
	}
	if len(remaining) != 0 || limited.N != 0 {
		return errors.New("incomplete portable archive or missing end records")
	}
	// Drain through the gzip CRC and reject extra data or gzip members.
	padding, err := io.ReadAll(io.LimitReader(gz, 10241))
	if err != nil {
		return err
	}
	if len(padding) > 10240 || len(bytes.Trim(padding, "\x00")) != 0 {
		return errors.New("invalid portable archive padding")
	}
	if _, err = buffered.Peek(1); err != io.EOF {
		return errors.New("trailing portable archive data")
	}
	return ctx.Err()
}

func copyPortableFile(root *os.Root, f File, src io.Reader, buffer []byte) error {
	hash := sha256.New()
	var dst io.Writer = hash
	var file *os.File
	if root != nil {
		var err error
		file, err = root.OpenFile(filepath.FromSlash(f.Path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		dst = io.MultiWriter(file, hash)
	}
	n, err := io.CopyBuffer(dst, src, buffer)
	if err == nil && (n != f.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != f.Digest) {
		err = fmt.Errorf("portable bundle file digest mismatch: %s", f.Path)
	}
	if file == nil {
		return err
	}
	if err == nil {
		err = file.Chmod(fs.FileMode(f.Mode))
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

// ValidatePortableArchive verifies the full archive without writing or executing
// anything. Builds pass the requested target, including when cross-compiling.
func ValidatePortableArchive(ctx context.Context, source Source, goos, goarch string) (PortableManifest, error) {
	raw, err := source.Manifest()
	if err != nil {
		return PortableManifest{}, err
	}
	m, err := VerifyPortableManifest(raw, goos, goarch)
	if err != nil {
		return PortableManifest{}, err
	}
	if err = scanPortableArchive(ctx, source, m, nil); err != nil {
		return PortableManifest{}, err
	}
	return m, nil
}

func portableManifestFile(raw []byte) File {
	hash := sha256.Sum256(raw)
	return File{Path: "manifest.json", Size: int64(len(raw)), Mode: 0444, Digest: "sha256:" + hex.EncodeToString(hash[:])}
}

// ExtractPortable extracts through the caller-owned handle into an approved,
// private, empty code generation. The caller must only publish on success and
// discard the generation on failure. This never opens a host absolute path.
func ExtractPortable(ctx context.Context, source Source, root *os.Root, goos, goarch string) (PortableManifest, error) {
	raw, err := source.Manifest()
	if err != nil {
		return PortableManifest{}, err
	}
	m, err := VerifyPortableManifest(raw, goos, goarch)
	if err != nil {
		return PortableManifest{}, err
	}
	if err = extractPortable(ctx, source, root, m, raw); err != nil {
		return PortableManifest{}, err
	}
	return m, nil
}

func extractPortable(ctx context.Context, source Source, root *os.Root, m PortableManifest, raw []byte) error {
	if root == nil {
		return errors.New("portable extraction requires a private directory handle")
	}
	info, err := root.Lstat(".")
	if err != nil {
		return err
	}
	if !validPortableDirectory(info) {
		return errors.New("portable destination is not a private directory")
	}
	folder, err := root.Open(".")
	if err != nil {
		return err
	}
	names, err := folder.Readdirnames(1)
	closeErr := folder.Close()
	if len(names) != 0 || err != io.EOF {
		return errors.Join(errors.New("portable destination is not empty"), err, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	_, dirs := portableInventory(m)
	delete(dirs, ".")
	for dir := range dirs {
		if err := ctx.Err(); err != nil {
			return err
		}
		// The root was empty and exclusive; MkdirAll cannot encounter
		// preexisting links and the handle forbids escapes in any case.
		if err = root.MkdirAll(filepath.FromSlash(dir), 0700); err != nil {
			return err
		}
	}
	if err = scanPortableArchive(ctx, source, m, root); err != nil {
		return err
	}
	if err = copyPortableFile(root, portableManifestFile(raw), bytes.NewReader(raw), nil); err != nil {
		return err
	}
	for dir := range dirs {
		if err = syncPortableDirectory(root, filepath.FromSlash(dir)); err != nil {
			return err
		}
	}
	return errors.Join(ctx.Err(), syncPortableDirectory(root, "."))
}

// VerifyPortableDirectory verifies the exact expected generation against the
// embedded manifest, rejecting links or Windows reparse points and extra files.
// A concurrent writer with the install owner's access is outside this boundary.
func VerifyPortableDirectory(ctx context.Context, source Source, root *os.Root, goos, goarch string) (PortableManifest, error) {
	raw, err := source.Manifest()
	if err != nil {
		return PortableManifest{}, err
	}
	m, err := VerifyPortableManifest(raw, goos, goarch)
	if err != nil {
		return PortableManifest{}, err
	}
	if root == nil {
		return PortableManifest{}, errors.New("portable verification requires a private directory handle")
	}
	files, dirs := portableInventory(m)
	files["manifest.json"] = portableManifestFile(raw)
	buffer := make([]byte, 32<<10)
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		local := filepath.FromSlash(name)
		info, err := root.Lstat(local)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if !dirs[name] || !validPortableDirectory(info) {
				return fmt.Errorf("unlisted or unsafe portable directory: %s", name)
			}
			delete(dirs, name)
			return nil
		}
		f, ok := files[name]
		if !ok || !info.Mode().IsRegular() || !validPortableNode(info, fs.FileMode(f.Mode)) || info.Size() != f.Size {
			return fmt.Errorf("unlisted or unsafe portable file: %s", name)
		}
		file, err := root.Open(local)
		if err != nil {
			return err
		}
		actual, err := file.Stat()
		if err == nil && (!os.SameFile(info, actual) || !validPortableFileHandle(file, actual)) {
			err = fmt.Errorf("portable bundle file changed: %s", name)
		}
		if err == nil {
			err = copyPortableFile(nil, f, io.LimitReader(file, f.Size+1), buffer)
		}
		delete(files, name)
		return errors.Join(err, file.Close())
	})
	if err != nil {
		return PortableManifest{}, err
	}
	if len(files) != 0 || len(dirs) != 0 {
		return PortableManifest{}, errors.New("portable code generation is incomplete")
	}
	return m, nil
}

func validPortableDirectory(info fs.FileInfo) bool {
	return info.IsDir() && validPortableNode(info, 0700)
}
