package discordbackend

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func openOwnershipDirectory(path string) (*os.Root, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() {
		return nil, errors.New("Discord ownership path is not a directory")
	}
	if err := checkOwnershipDirectory(path, before); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, errors.Join(errors.New("Discord ownership directory changed during open"), err)
	}
	return root, nil
}

// SQLite opens the main database plus its own sidecars by path. Reject links
// and foreign files before it can interpret or modify any of these names.
func prepareOwnershipDatabase(root *os.Root, path string, portable bool) error {
	name := filepath.Base(path)
	if filepath.Join(root.Name(), name) != path {
		return errors.New("Discord ownership database is outside its private directory")
	}
	sidecars := []string{"-journal", "-wal", "-shm"}
	var checkDatabase, checkJournal func(*os.File, int64) error
	if portable {
		if err := verifyOwnershipNamespace(root, name); err != nil {
			return err
		}
		sidecars = sidecars[:1]
		checkDatabase = validatePortableOwnershipDatabase
		checkJournal = validatePortableOwnershipJournal
	}
	exists, err := validateOwnershipFile(root, name, checkDatabase)
	if err != nil {
		return err
	}
	for _, suffix := range sidecars {
		sidecar, err := validateOwnershipFile(root, name+suffix, checkJournal)
		if err != nil {
			return err
		}
		if sidecar && !exists {
			return errors.New("Discord ownership database sidecar has no main database")
		}
	}
	if exists {
		return nil
	}
	file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return errors.Join(checkOwnershipFile(file), file.Close())
}

func validateOwnershipFile(root *os.Root, name string, check func(*os.File, int64) error) (_ bool, result error) {
	before, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !before.Mode().IsRegular() {
		return false, errors.New("Discord ownership file is not regular")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|ownershipReadFlags, 0)
	if err != nil {
		return false, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return false, errors.Join(errors.New("Discord ownership file changed during open"), err)
	}
	if err := checkOwnershipFile(file); err != nil {
		return false, err
	}
	if check != nil {
		if err := check(file, after.Size()); err != nil {
			return false, err
		}
	}
	return true, nil
}

func verifyOwnershipNamespace(root *os.Root, database string) (result error) {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, directory.Close()) }()
	entries, err := directory.ReadDir(3)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	for _, entry := range entries {
		if name := entry.Name(); name != database && name != database+"-journal" {
			return errors.New("portable Discord ownership directory contains an unreserved entry")
		}
	}
	return nil
}
