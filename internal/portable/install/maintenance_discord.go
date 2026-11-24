package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

const discordOwnershipPath = "app/discord/" + discordOwnershipLeaf

// The worker owns this DELETE-mode ledger, not the supervisor SQLite handle.
// Recovery has already proved that no worker can access it. Refuse a hot or
// unexpected sidecar: copying a main file alone must not discard transactions.
func (i *Installation) inspectDiscordBackup(ctx context.Context) (_ backupMember, resultErr error) {
	if err := checkPurgeNamespace(i.Root, "app/discord", func(name string) bool { return name == discordOwnershipLeaf }); err != nil {
		return backupMember{}, fmt.Errorf("%w: Discord ownership database must be closed and journal-free: %w", store.ErrCleanupPending, err)
	}
	f, err := maintenanceOpen(i.Root, discordOwnershipPath)
	if errors.Is(err, fs.ErrNotExist) {
		return backupMember{}, nil
	}
	if err != nil {
		return backupMember{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	if err := process.CheckPrivateFileACL(f); err != nil {
		return backupMember{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return backupMember{}, err
	}
	size := info.Size()
	const pageBytes = 4096
	if size < 0 || size > reservedDiscordBytes || size%pageBytes != 0 {
		return backupMember{}, store.ErrBudgetExceeded
	}
	// A securely pre-created empty file has no pages to commit yet.
	if size > 0 {
		var header [20]byte
		if _, err := f.ReadAt(header[:], 0); err != nil {
			return backupMember{}, err
		}
		if string(header[:16]) != "SQLite format 3\x00" || header[16] != 16 || header[17] != 0 || header[18] != 1 || header[19] != 1 {
			return backupMember{}, errors.New("Discord ownership database is not cold portable SQLite")
		}
	}
	h := sha256.New()
	n, err := io.Copy(h, maintenanceReader{ctx, io.LimitReader(f, size+1)})
	if err != nil || n != size {
		return backupMember{}, errors.Join(store.ErrApprovalMismatch, err)
	}
	return backupMember{Path: discordOwnershipPath, Size: size, Digest: "sha256:" + hex.EncodeToString(h.Sum(nil))}, nil
}
