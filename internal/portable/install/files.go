package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/portable/store"
)

func ownedParent(root *os.Root, name string) (*os.Root, string, func(), error) {
	if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\:\x00") {
		return nil, "", nil, fmt.Errorf("invalid installation-relative path %q", name)
	}
	parts := strings.Split(name, "/")
	current := root
	for _, component := range parts[:len(parts)-1] {
		next, err := openChild(current, component)
		if current != root {
			current.Close()
		}
		if err != nil {
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

// removeOwned descends only through pinned, ordinary directory entries. A link
// at the deletion leaf is unlinked, never used to locate another target.
func removeOwned(root *os.Root, name string) error {
	parent, leaf, closeParent, err := ownedParent(root, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer closeParent()
	return deleteEntry(parent, leaf)
}

func deleteEntry(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() && safeEntry(info) {
		child, err := openChild(root, name)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0200 == 0 {
			if err := child.Chmod(".", info.Mode().Perm()|0700); err != nil {
				return errors.Join(err, child.Close())
			}
		}
		f, err := child.Open(".")
		var entries []string
		if err == nil {
			entries, err = f.Readdirnames(-1)
		}
		if f != nil {
			err = errors.Join(err, f.Close())
		}
		for _, entry := range entries {
			if err != nil {
				break
			}
			err = deleteEntry(child, entry)
		}
		if err := errors.Join(err, child.Close()); err != nil {
			return err
		}
	}
	if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDirectory(root)
}

func checkMetadataBudget(i *Installation, addition int64) error {
	limit, err := store.MetadataFileBudget(i.Manifest.MetadataBytes)
	if err != nil {
		return err
	}
	if addition < 0 || addition > limit-reservedUploadBytes-reservedDiscordBytes {
		return store.ErrBudgetExceeded
	}
	changes := addition + reservedUploadBytes + reservedDiscordBytes
	file, err := i.Root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := file.ReadDir(-1)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimPrefix(entry.Name(), ".writing-")
		if name != manifestName && name != pendingName && name != restoreReceiptName && name != backupConfigName && !strings.HasPrefix(name, "draft-") && !strings.HasPrefix(name, "code-") {
			continue
		}
		if strings.HasPrefix(name, "code-") {
			if err := fs.WalkDir(i.Root.FS(), filepath.ToSlash(entry.Name()), func(_ string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				info, err := d.Info()
				if err != nil {
					return err
				}
				if !safeEntry(info) || !info.IsDir() && !info.Mode().IsRegular() {
					return errors.New("invalid entry in portable code directory")
				}
				if info.IsDir() {
					return nil
				}
				if info.Size() > limit-changes {
					return store.ErrBudgetExceeded
				}
				changes += info.Size()
				return nil
			}); err != nil {
				return err
			}
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || !safeEntry(info) {
			return errors.New("invalid portable metadata entry")
		}
		if info.Size() > limit-changes {
			return store.ErrBudgetExceeded
		}
		changes += info.Size()
	}
	if changes > limit {
		return store.ErrBudgetExceeded
	}
	return nil
}
