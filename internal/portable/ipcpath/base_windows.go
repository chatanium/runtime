package ipcpath

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// FallbackBase ignores ambient TMP and TEMP. Use the account's native profile,
// with its durable short-name alias when available for AF_UNIX compatibility.
func FallbackBase() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_Profile, 0)
	if err != nil {
		return "", err
	}
	p, err := windows.UTF16PtrFromString(base)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	if n, e := windows.GetShortPathName(p, &buf[0], uint32(len(buf))); e == nil && n > 0 && n < uint32(len(buf)) {
		base = windows.UTF16ToString(buf[:n])
	}
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return "", errors.New("Windows socket fallback is not an absolute profile directory")
	}
	return base, nil
}
