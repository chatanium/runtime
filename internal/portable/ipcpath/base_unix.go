//go:build !windows

package ipcpath

import (
	"errors"
	"os"
	"runtime"
)

// FallbackBase is read-only and independent of TMPDIR; crash recovery and
// a second invocation by the owner must resolve exactly the approved location.
func FallbackBase() (string, error) {
	base := "/tmp"
	switch runtime.GOOS {
	case "linux":
	case "darwin":
		base = "/private/tmp"
	default:
		return "", errors.New("unsupported portable socket platform")
	}
	st, err := os.Lstat(base)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0 {
		return "", errors.New("unsafe system socket fallback directory")
	}
	return base, nil
}
