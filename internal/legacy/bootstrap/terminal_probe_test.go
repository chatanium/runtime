//go:build linux

package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
)

// These are surviving, complete source-bound publication fixtures, not an
// alternative named-body publication implementation. No management root, gate,
// service, account, or privileged operation is involved.
func terminalProbeFixture(t *testing.T) (*os.File, host.TerminalProbeRecord) {
	t.Helper()
	directory := t.TempDir()
	root, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	record := host.TerminalProbeRecord{}
	for slot := range record.Paths {
		record.Paths[slot] = filepath.Join(directory, []string{"probe-0", "probe-1"}[slot])
		record.Payloads[slot] = []byte([]string{`{"slot":0,"source":"original"}`, `{"slot":1,"source":"original"}`}[slot])
		file, err := os.OpenFile(record.Paths[slot], os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(record.Payloads[slot]); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Sync(); err != nil {
			file.Close()
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err = unix.Fstat(int(file.Fd()), &stat); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		record.Files[slot] = host.TerminalNativeIdentity{Path: record.Paths[slot], Kind: "file", Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid, Mode: stat.Mode & 07777, Links: uint64(stat.Nlink)}
	}
	if err = root.Sync(); err != nil {
		t.Fatal(err)
	}
	return root, record
}

func terminalProbeFixtureExchange(t *testing.T, root *os.File, record host.TerminalProbeRecord) {
	t.Helper()
	if err := unix.Renameat2(int(root.Fd()), filepath.Base(record.Paths[0]), int(root.Fd()), filepath.Base(record.Paths[1]), unix.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalProbeCapabilityExchangeAndDurableCleanup(t *testing.T) {
	root, record := terminalProbeFixture(t)
	if err := terminalProbeExchange(root, record, [2]int{0, 1}); err != nil {
		t.Fatal(err)
	}
	if err := terminalProbeRequireLayout(root, record, [2]int{1, 0}); err != nil {
		t.Fatal(err)
	}
	if err := terminalProbeRemove(root, record); err != nil {
		t.Fatal(err)
	}
	if err := terminalProbeRequireLayout(root, record, [2]int{-1, -1}); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalProbeRecoveryDoesNotExchangeSwappedLayoutBackward(t *testing.T) {
	root, record := terminalProbeFixture(t)
	terminalProbeFixtureExchange(t, root, record)
	// Model interruption immediately after exchange, before its directory fsync.
	if err := terminalProbeExchange(root, record, [2]int{1, 0}); err != nil {
		t.Fatal(err)
	}
	if err := terminalProbeRequireLayout(root, record, [2]int{1, 0}); err != nil {
		t.Fatal("recovery exchanged an already-forward layout backward:", err)
	}
	if err := terminalProbeRemove(root, record); err != nil {
		t.Fatal(err)
	}
	if err := terminalProbeRequireLayout(root, record, [2]int{-1, -1}); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalProbeInterruptedCleanupRemovesOnlyExactSurvivor(t *testing.T) {
	root, record := terminalProbeFixture(t)
	terminalProbeFixtureExchange(t, root, record)
	if err := unix.Unlinkat(int(root.Fd()), filepath.Base(record.Paths[0]), 0); err != nil {
		t.Fatal(err)
	}
	// The remaining native identity still comes from the original source intent;
	// a missing peer must not prevent safe bounded cleanup or imply exchange proof.
	if err := terminalProbeRemove(root, record); err != nil {
		t.Fatal(err)
	}
	if err := terminalProbeRequireLayout(root, record, [2]int{-1, -1}); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalProbeMismatchPreservesEverySurvivor(t *testing.T) {
	for _, mismatch := range []string{"body", "native", "symlink"} {
		t.Run(mismatch, func(t *testing.T) {
			root, record := terminalProbeFixture(t)
			path := record.Paths[1]
			switch mismatch {
			case "body":
				if err := os.WriteFile(path, []byte("malformed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "native":
				// Keep the old native inode alive to rule out inode-number reuse.
				if err := os.Rename(path, filepath.Join(filepath.Dir(path), "unrelated-held-object")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, record.Payloads[1], 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(record.Paths[0], path); err != nil {
					t.Fatal(err)
				}
			}
			if err := terminalProbeRemove(root, record); err == nil {
				t.Fatal("cleanup accepted an unrelated or malformed probe object")
			}
			for _, name := range record.Paths {
				if _, err := os.Lstat(name); err != nil {
					t.Fatal("failed-closed cleanup removed a surviving object:", err)
				}
			}
			raw, err := os.ReadFile(record.Paths[0])
			if err != nil || !bytes.Equal(raw, record.Payloads[0]) {
				t.Fatal("failed-closed cleanup changed the proven peer", err)
			}
		})
	}
}

func TestTerminalProbeNoReplaceCollisionPreservesBothObjects(t *testing.T) {
	root, record := terminalProbeFixture(t)
	if err := terminalProbeNoReplace(root, record, [2]int{0, 1}); err != nil {
		t.Fatal(err)
	}
	if err := terminalProbeRequireLayout(root, record, [2]int{0, 1}); err != nil {
		t.Fatal(err)
	}
}
