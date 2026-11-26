// Package install owns the portable-v2 installation layout and offline transactions.
package install

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/portable/process"
)

const (
	Format       = "portable-v2"
	manifestName = "installation.json"
	pendingName  = "installation.next"
	ownerLock    = "owner.lock"
	anchorLock   = "management.lock"
	maxDocument  = 16 << 20
)

var ErrLegacy = errors.New("LEGACY_INSTALLATION: use the original Chatanium binary to manage a v1 installation")

// Directory resolves the single portable installation's canonical location.
// It does not create or inspect any installation.
func Directory() (string, error) {
	base, err := dataHome()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(base) || filepath.Clean(base) != base || strings.ContainsAny(base, ",\x00\r\n") {
		return "", errors.New("portable data home must be a canonical absolute path")
	}
	path := filepath.Join(base, "chatanium", "runtime")
	if legacyPath(path) {
		return "", ErrLegacy
	}
	return path, nil
}

func legacyPath(path string) bool {
	path = filepath.ToSlash(filepath.Clean(path))
	for _, root := range []string{"/etc/chatanium", "/var/lib/chatanium", "/usr/local/bin/chatanium"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return strings.HasPrefix(path, "/run/chatanium-")
}

func validateDirectory(path string) error {
	if legacyPath(path) {
		return ErrLegacy
	}
	expected, err := Directory()
	if err != nil {
		return err
	}
	if expected != path {
		return errors.New("installation path does not match the portable runtime directory")
	}
	return nil
}

// walkDirectory never follows a path component. Roots pin the opened directory;
// the stat comparison also prevents accepting a replaced entry during open.
func walkDirectory(path string, create bool) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("expected a canonical absolute path")
	}
	volume := filepath.VolumeName(path) + string(os.PathSeparator)
	root, err := os.OpenRoot(volume)
	if err != nil {
		return nil, err
	}
	for name := range strings.SplitSeq(strings.TrimPrefix(path, volume), string(os.PathSeparator)) {
		if name == "" {
			continue
		}
		next, err := openChild(root, name)
		if create && errors.Is(err, fs.ErrNotExist) {
			if err := process.EnsurePrivateDir(filepath.Join(root.Name(), name)); err != nil {
				root.Close()
				return nil, err
			}
			next, err = openChild(root, name)
		}
		root.Close()
		if err != nil {
			return nil, err
		}
		root = next
	}
	return root, nil
}

func openChild(root *os.Root, name string) (*os.Root, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || !safeEntry(before) {
		return nil, fmt.Errorf("refusing linked or non-directory entry %q", name)
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	after, err := child.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		child.Close()
		return nil, fmt.Errorf("directory %q changed during open", name)
	}
	return child, nil
}

func openRegular(root *os.Root, name string) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || !safeEntry(before) {
		return nil, fmt.Errorf("refusing linked or non-regular entry %q", name)
	}
	file, err := root.OpenFile(name, readFileFlags, 0)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !ownedFile(after) || !os.SameFile(before, after) {
		file.Close()
		return nil, fmt.Errorf("entry %q is not an owned regular file", name)
	}
	if err := checkFileHandle(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// OpenInput opens an explicit canonical operator path without following links.
// The file must not be writable by another account. Secret inputs are private.
func OpenInput(path string, secret bool) (*os.File, error) {
	if legacyPath(path) {
		return nil, ErrLegacy
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Join(filepath.Dir(path), filepath.Base(path)) != path {
		return nil, errors.New("operator input path must be canonical and absolute")
	}
	root, err := walkDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := openRegular(root, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	if secret {
		if err := process.CheckPrivateFileACL(file); err != nil {
			file.Close()
			return nil, err
		}
	}
	return file, nil
}

func ReadInput(path string) ([]byte, error) {
	file, err := OpenInput(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBounded(file)
}

func readBounded(file io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, maxDocument+1))
	if err == nil && len(data) > maxDocument {
		err = errors.New("installation document exceeds its bound")
	}
	return data, err
}

func privateChild(parent *os.Root, name string, create bool) (*os.Root, error) {
	path := filepath.Join(parent.Name(), name)
	if create {
		if err := process.EnsurePrivateDir(path); err != nil {
			return nil, err
		}
	}
	child, err := openChild(parent, name)
	if err != nil {
		return nil, err
	}
	if err := process.CheckPrivateDir(path); err != nil {
		child.Close()
		return nil, err
	}
	return child, nil
}

func anchor(path string, create bool) (*os.Root, error) {
	if err := validateDirectory(path); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	base, err := walkDirectory(filepath.Dir(parent), create)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	return privateChild(base, filepath.Base(parent), create)
}

func readDocument(root *os.Root, name string) ([]byte, error) {
	file, err := openRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBounded(file)
}

func writeNew(root *os.Root, name string, data []byte) error {
	if _, err := root.Lstat(name); err == nil {
		return fs.ErrExist
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// The caller owns the private directory and writer lock. A crash can
	// leave an incomplete temporary file, but never a partial final record.
	temp := ".writing-" + name
	if err := removeOwned(root, temp); err != nil {
		return err
	}
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return errors.Join(err, root.Remove(temp))
	}
	return replaceFile(root, temp, name)
}
