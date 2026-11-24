//go:build linux || (darwin && arm64)

package upload

import (
	"os"
	"testing"
)

func makeSpoolPublic(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}
