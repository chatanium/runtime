// Package ipcpath names private, per-generation socket directories. There is
// no shared socket name that can address a replacement sandbox.
package ipcpath

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
)

// Directory returns a location only. The creator must create and verify the
// private directory before listening, and remove it after observing exit.
func Directory(installation, lifetime string) (string, error) {
	h := sha256.Sum256([]byte(filepath.Clean(installation) + "\x00" + lifetime))
	name := "ct-" + hex.EncodeToString(h[:12])
	dir := filepath.Join(installation, name)
	// Reserve space for go-plugin's private child directory and endpoint.
	short := func(d string) bool { return len(filepath.Join(d, "plugin-dir4294967295", "s")) < 100 }
	if !short(dir) {
		base, err := FallbackBase()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, name)
		if !short(dir) {
			return "", errors.New("native user profile is too long for the private AF_UNIX endpoint")
		}
	}
	return dir, nil
}
