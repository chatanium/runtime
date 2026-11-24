package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/provision"
)

// A Root pins the path and confines name resolution, but does not prevent a
// nested mount or an internal symlink from addressing a different object.
func maintenanceDir(parent *os.Root, name string) (*os.Root, error) {
	if !maintenanceLeaf(name) {
		return nil, fmt.Errorf("invalid maintenance directory leaf %q", name)
	}
	child, err := openChild(parent, name)
	if err != nil {
		return nil, err
	}
	if err := checkMaintenanceDirectory(parent, child); err != nil {
		return nil, errors.Join(err, child.Close())
	}
	return child, nil
}

func maintenanceDirectoryIdentity(parent *os.Root, name string) (string, error) {
	dir := parent
	if name != "." {
		var err error
		dir, err = maintenanceDir(parent, name)
		if err != nil {
			return "", err
		}
		defer dir.Close()
	}
	f, err := dir.Open(".")
	if err != nil {
		return "", err
	}
	id, err := maintenanceHandleIdentity(f)
	return id, errors.Join(err, f.Close())
}

func maintenanceLeaf(name string) bool {
	return fs.ValidPath(name) && name != "." && !strings.ContainsAny(name, "/\\:\x00") && filepath.IsLocal(name) && !strings.HasSuffix(name, ".") && !strings.HasSuffix(name, " ")
}

func maintenanceParent(root *os.Root, name string, create bool) (*os.Root, string, func(), error) {
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if !maintenanceLeaf(part) {
			return nil, "", nil, fmt.Errorf("invalid installation-owned path %q", name)
		}
	}
	current := root
	for _, part := range parts[:len(parts)-1] {
		if create {
			if err := current.Mkdir(part, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
				if current != root {
					current.Close()
				}
				return nil, "", nil, err
			}
		}
		next, err := maintenanceDir(current, part)
		if create && err == nil {
			err = syncDirectory(current)
		}
		if current != root {
			err = errors.Join(err, current.Close())
		}
		if err != nil {
			if next != nil {
				next.Close()
			}
			return nil, "", nil, err
		}
		current = next
	}
	return current, parts[len(parts)-1], func() {
		if current != root {
			current.Close()
		}
	}, nil
}

func maintenanceOpen(root *os.Root, name string) (*os.File, error) {
	parent, leaf, closeParent, err := maintenanceParent(root, name, false)
	if err != nil {
		return nil, err
	}
	defer closeParent()
	f, err := openRegular(parent, leaf)
	if err != nil {
		return nil, err
	}
	if err := checkMaintenanceMount(parent, f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func maintenanceNames(root *os.Root) ([]string, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := dir.Readdirnames(-1)
	return names, errors.Join(err, dir.Close())
}

// Removal is limited to approved generation paths, with every descendant
// vetted before any chmod/unlink. No link (even an in-root link) is accepted.
func maintenanceTree(root *os.Root, name string, remove bool) error {
	if !maintenanceLeaf(name) {
		return fmt.Errorf("invalid maintenance entry %q", name)
	}
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !safeEntry(info) {
		return fmt.Errorf("refusing linked or reparsed maintenance entry %q", name)
	}
	if info.IsDir() {
		child, err := maintenanceDir(root, name)
		if err != nil {
			return err
		}
		if remove && info.Mode().Perm()&0200 == 0 {
			f, e := child.Open(".")
			if e == nil {
				e = errors.Join(f.Chmod(0700), f.Close())
			}
			err = e
		}
		if err == nil {
			names, e := maintenanceNames(child)
			err = e
			for _, sub := range names {
				if err != nil {
					break
				}
				err = maintenanceTree(child, sub, remove)
			}
		}
		if err := errors.Join(err, child.Close()); err != nil {
			return err
		}
	} else {
		f, err := maintenanceOpen(root, name)
		if err != nil {
			return err
		}
		if remove {
			err = allowMaintenanceUnlink(f, info)
		}
		if err := errors.Join(err, f.Close()); err != nil {
			return err
		}
	}
	if !remove {
		return nil
	}
	if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDirectory(root)
}

func removeMaintenancePath(root *os.Root, name string) error {
	parent, leaf, closeParent, err := maintenanceParent(root, name, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer closeParent()
	if err := maintenanceTree(parent, leaf, false); err != nil {
		return err
	}
	return maintenanceTree(parent, leaf, true)
}

// verifyInstalledCode uses the old installation manifest, bound to the ledger,
// not the update executable's newer release lock. No old program is executed.
func (i *Installation) verifyInstalledCode(ctx context.Context, m Manifest) (err error) {
	root, err := maintenanceDir(i.Root, m.CodeDir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	f, err := maintenanceOpen(root, "manifest.json")
	if err != nil {
		return err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, bundle.MaxManifestBytes+1))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return err
	}
	var durable bundle.PortableManifest
	if err := gvxcontract.DecodeStrict(raw, bundle.MaxManifestBytes, 32, &durable); err != nil || !reflect.DeepEqual(durable, m.Bundle) {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		return err
	}
	delete(fields, "digest")
	canonical, err := json.Marshal(fields)
	if err != nil || provision.DomainDigest("chatanium-bundle-portable-v2", canonical) != m.Bundle.Digest {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	inventory := make(map[string]bundle.File, len(durable.Files)+1)
	dirs := make(map[string]bool)
	inventory["manifest.json"] = bundle.File{Path: "manifest.json", Size: int64(len(raw)), Digest: hashBytes(raw), Mode: 0444}
	if len(durable.Files) == 0 || len(durable.Files) > 4096 {
		return store.ErrApprovalMismatch
	}
	for _, f := range durable.Files {
		if _, exists := inventory[f.Path]; exists || f.Size < 0 || f.Size > bundle.MaxBundleBytes || !digestPattern.MatchString(f.Digest) || (f.Mode != 0444 && f.Mode != 0555) {
			return store.ErrApprovalMismatch
		}
		for _, part := range strings.Split(f.Path, "/") {
			if !maintenanceLeaf(part) {
				return store.ErrApprovalMismatch
			}
		}
		inventory[f.Path] = f
		for d := path.Dir(f.Path); d != "." && !dirs[d]; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	var walk func(*os.Root, string) error
	walk = func(current *os.Root, prefix string) error {
		names, err := maintenanceNames(current)
		if err != nil {
			return err
		}
		for _, leaf := range names {
			name := path.Join(prefix, leaf)
			if dirs[name] {
				child, err := maintenanceDir(current, leaf)
				if err != nil {
					return err
				}
				delete(dirs, name)
				if err := errors.Join(walk(child, name), child.Close()); err != nil {
					return err
				}
				continue
			}
			expected, ok := inventory[name]
			if !ok {
				return fmt.Errorf("unexpected entry in installed code: %s", name)
			}
			f, err := maintenanceOpen(current, leaf)
			if err != nil {
				return err
			}
			err = verifyMaintenanceFile(ctx, f, expected.Size, expected.Digest, fs.FileMode(expected.Mode))
			if err := errors.Join(err, f.Close()); err != nil {
				return fmt.Errorf("verify installed code %s: %w", name, err)
			}
			delete(inventory, name)
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		return err
	}
	if len(inventory) != 0 || len(dirs) != 0 {
		return errors.New("installed code does not match its durable manifest")
	}
	return nil
}

type maintenanceReader struct {
	ctx context.Context
	r   io.Reader
}

func (r maintenanceReader) Read(buf []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(buf)
}

func verifyMaintenanceFile(ctx context.Context, f *os.File, size int64, digest string, mode fs.FileMode) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() != size || (mode != 0 && !matchMaintenanceMode(info.Mode(), mode)) {
		return store.ErrApprovalMismatch
	}
	h := sha256.New()
	n, err := io.Copy(h, maintenanceReader{ctx, io.LimitReader(f, size+1)})
	if err != nil {
		return err
	}
	if n != size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
		return store.ErrApprovalMismatch
	}
	return nil
}
