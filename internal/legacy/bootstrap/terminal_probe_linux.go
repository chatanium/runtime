//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
)

const terminalProbePayloadMax = 8192

// The source WAL binds these complete bytes and both anonymous native identities
// before either approved name is exposed. The bodies grant no cleanup authority.
type terminalProbePayload struct {
	Version        uint32                         `json:"version"`
	InstallationID RuntimeInstallationID          `json:"installation_id"`
	TransactionID  string                         `json:"transaction_id"`
	ApprovalDigest string                         `json:"approval_digest"`
	Attempt        uint64                         `json:"attempt"`
	Slot           int                            `json:"slot"`
	Files          [2]host.TerminalNativeIdentity `json:"files"`
}

func terminalProbeApprovedPlan(ctx context.Context, store interface {
	ActiveTerminalPublicationProbe(context.Context) (host.TerminalProbeRecord, error)
}, id RuntimeInstallationID) (PurgeApproval, bool, error) {
	var approval PurgeApproval
	record, err := store.ActiveTerminalPublicationProbe(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return approval, false, nil
	}
	if err != nil {
		return approval, false, err
	}
	if err = gvxcontract.DecodeStrict(record.ApprovedPlan, terminalReceiptMax, 32, &approval); err != nil {
		return approval, true, err
	}
	if err = terminalProbeApproval(record, approval); err != nil {
		return approval, true, err
	}
	if approval.InstallationID != id {
		return approval, true, errors.New("active terminal probe belongs to another installation")
	}
	return approval, true, nil
}

func terminalProbeApproval(record host.TerminalProbeRecord, approval PurgeApproval) error {
	sum, err := PurgePlanDigest(approval)
	if err != nil || sum != approval.PlanDigest || !validID(approval.PlanID) {
		return errors.New("terminal probe approval digest differs")
	}
	raw, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	if record.Version != 1 || record.InstallationID != string(approval.InstallationID) || record.TransactionID != approval.PlanID || record.ApprovalDigest != approval.PlanDigest || !bytes.Equal(record.ApprovedPlan, raw) || record.Attempt == 0 || record.Incarnation == "" {
		return errors.New("terminal probe differs from the original approved plan")
	}
	if record.Paths != approval.PublicationProbePaths {
		return errors.New("terminal probe paths differ from approval")
	}
	for slot := range record.Files {
		file := record.Files[slot]
		if file.Path != record.Paths[slot] || file.Absent || file.Kind != "file" || file.Inode == 0 || file.Mode != 0600 || file.Links != 1 || len(record.Payloads[slot]) == 0 || len(record.Payloads[slot]) > terminalProbePayloadMax {
			return errors.New("terminal probe source identity is invalid")
		}
	}
	if record.Files[0].Device == record.Files[1].Device && record.Files[0].Inode == record.Files[1].Inode {
		return errors.New("terminal probe requires two distinct native objects")
	}
	return nil
}

// terminalProbeLayout returns the source slot occupying each approved name, or
// -1 for absence. It never interprets a name alone as ownership evidence.
func terminalProbeLayout(root *os.File, record host.TerminalProbeRecord) ([2]int, error) {
	layout := [2]int{-1, -1}
	for nameSlot, path := range record.Paths {
		fd, err := unix.Openat(int(root.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return layout, err
		}
		file := os.NewFile(uintptr(fd), "terminal-probe-readback")
		var stat unix.Stat_t
		err = unix.Fstat(fd, &stat)
		if err == nil && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size <= 0 || stat.Size > terminalProbePayloadMax) {
			err = errors.New("terminal probe name contains an unsafe or oversized object")
		}
		var raw []byte
		if err == nil {
			raw, err = io.ReadAll(io.LimitReader(file, terminalProbePayloadMax+1))
		}
		err = errors.Join(err, file.Close())
		if err != nil {
			return layout, err
		}
		actual := terminalNativeIdentity{Kind: "file", Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid, Mode: stat.Mode & 07777, Links: uint64(stat.Nlink)}
		for sourceSlot, expected := range record.Files {
			if terminalPublicationMatches(terminalNativeIdentity(expected), actual) && bytes.Equal(record.Payloads[sourceSlot], raw) {
				layout[nameSlot] = sourceSlot
				break
			}
		}
		if layout[nameSlot] == -1 {
			return layout, errors.New("terminal probe name contains an unrelated or changed object")
		}
	}
	if layout[0] >= 0 && layout[0] == layout[1] {
		return layout, errors.New("terminal probe native object occupies both approved names")
	}
	return layout, nil
}

func terminalProbeRequireLayout(root *os.File, record host.TerminalProbeRecord, expected [2]int) error {
	actual, err := terminalProbeLayout(root, record)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("terminal probe layout changed during capability proof")
	}
	return nil
}

// Missing names are allowed only as interrupted cleanup/publication, never as
// proof of exchange. Inspect both names before unlinking either, preserving all
// objects on a malformed or mismatched layout.
func terminalProbeRemove(root *os.File, record host.TerminalProbeRecord) error {
	layout, err := terminalProbeLayout(root, record)
	if err != nil {
		return err
	}
	for slot, source := range layout {
		if source < 0 {
			continue
		}
		if err = terminalProbeRequireLayout(root, record, layout); err != nil {
			return err
		}
		if err = unix.Unlinkat(int(root.Fd()), filepath.Base(record.Paths[slot]), 0); err != nil {
			return err
		}
		if err = root.Sync(); err != nil {
			return err
		}
		layout[slot] = -1
	}
	if err = root.Sync(); err != nil {
		return err
	}
	return terminalProbeRequireLayout(root, record, [2]int{-1, -1})
}

func terminalProbeNoReplace(root *os.File, record host.TerminalProbeRecord, layout [2]int) error {
	if err := terminalProbeRequireLayout(root, record, layout); err != nil {
		return err
	}
	name := filepath.Base(record.Paths[0])
	// linkat never replaces an occupied destination. The initial publication
	// exercises AT_EMPTY_PATH on the anonymous inode; this collision also works
	// when recovering a source-bound inode after its anonymous FD was lost.
	if err := unix.Linkat(int(root.Fd()), name, int(root.Fd()), name, 0); !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("terminal probe NOREPLACE collision was not preserved: %w", errors.Join(err, errors.New("expected EEXIST")))
	}
	return terminalProbeRequireLayout(root, record, layout)
}

func terminalProbeExchange(root *os.File, record host.TerminalProbeRecord, layout [2]int) error {
	if layout != [2]int{0, 1} && layout != [2]int{1, 0} {
		return errors.New("terminal capability proof requires both complete probe objects")
	}
	if err := terminalProbeNoReplace(root, record, layout); err != nil {
		return err
	}
	if err := root.Sync(); err != nil {
		return err
	}
	if err := terminalProbeRequireLayout(root, record, layout); err != nil {
		return err
	}
	if layout == [2]int{0, 1} {
		if err := unix.Renameat2(int(root.Fd()), filepath.Base(record.Paths[0]), int(root.Fd()), filepath.Base(record.Paths[1]), unix.RENAME_EXCHANGE); err != nil {
			return err
		}
	}
	// The swapped layout proves an interrupted exchange already happened. Never
	// exchange it backward merely to repeat the syscall after a restart.
	if err := root.Sync(); err != nil {
		return err
	}
	return terminalProbeRequireLayout(root, record, [2]int{1, 0})
}

func terminalCapabilityPreflight(ctx context.Context, guard *host.ManagementGuard, store *host.Store, approval PurgeApproval) (host.TerminalCapability, error) {
	var capability host.TerminalCapability
	if guard == nil || guard.Mode() != host.ManagementExclusive {
		return capability, host.ErrManagementGuardRequired
	}
	if err := ctx.Err(); err != nil {
		return capability, err
	}
	if approval.TerminalReceiptPath != terminalReceiptPath(approval.InstallationID) || approval.PublicationProbePaths != [2]string{filepath.Join(terminalRoot, terminalStageName(approval.InstallationID, approval.PlanID, 0)), filepath.Join(terminalRoot, terminalStageName(approval.InstallationID, approval.PlanID, 1))} {
		return capability, errors.New("terminal capability paths are not the approved fixed names")
	}
	raw, err := json.Marshal(approval)
	if err != nil {
		return capability, err
	}
	sum, err := PurgePlanDigest(approval)
	if err != nil || sum != approval.PlanDigest || !validID(approval.PlanID) {
		return capability, errors.New("terminal capability approval digest differs")
	}
	fd, err := guard.RootFD()
	if err != nil {
		return capability, err
	}
	fd, err = unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return capability, err
	}
	root := os.NewFile(uintptr(fd), "borrowed-terminal-probe-root")
	defer root.Close()

	record, err := store.ActiveTerminalPublicationProbe(ctx)
	expectedAttempt := uint64(0)
	if err == nil {
		if err = terminalProbeApproval(record, approval); err != nil {
			return capability, err
		}
		if err = store.ValidateTerminalPublicationProbe(ctx, guard, record); err != nil {
			return capability, err
		}
		layout, readErr := terminalProbeLayout(root, record)
		if readErr != nil {
			return capability, readErr
		}
		if record.Complete {
			if layout != [2]int{-1, -1} {
				return capability, errors.New("completed terminal probe reappeared")
			}
			if err = root.Sync(); err != nil {
				return capability, err
			}
			return store.CompleteTerminalPublicationProbe(ctx, guard, record, host.TerminalProbeEvidence{CreatedAnonymous: true, LinkedNoReplace: true, NoReplaceRejected: true, Exchanged: true, Synced: true, Absent: true})
		}
		if record.Exchanged || layout == [2]int{0, 1} || layout == [2]int{1, 0} {
			if record.Exchanged {
				if layout[0] == 0 || layout[1] == 1 {
					return capability, errors.New("durably exchanged terminal probe moved backward")
				}
			} else {
				if err = terminalProbeExchange(root, record, layout); err != nil {
					return capability, errors.Join(err, terminalProbeRemove(root, record))
				}
				record, err = store.RecordTerminalPublicationProbeExchange(ctx, guard, record, host.TerminalProbeEvidence{CreatedAnonymous: true, LinkedNoReplace: true, NoReplaceRejected: true, Exchanged: true, Synced: true})
				if err != nil {
					return capability, err
				}
			}
			if err = terminalProbeRemove(root, record); err != nil {
				return capability, err
			}
			return store.CompleteTerminalPublicationProbe(ctx, guard, record, host.TerminalProbeEvidence{CreatedAnonymous: true, LinkedNoReplace: true, NoReplaceRejected: true, Exchanged: true, Synced: true, Absent: true})
		}
		// A partial publication cannot establish all capabilities.
		// Retire only exact survivors, then atomically bind a fresh attempt to
		// the same original approval. Never mint a new or narrowed plan.
		if err = terminalProbeRemove(root, record); err != nil {
			return capability, err
		}
		expectedAttempt = record.Attempt
	} else if !errors.Is(err, sql.ErrNoRows) {
		return capability, err
	}
	if expectedAttempt == ^uint64(0) {
		return capability, errors.New("terminal probe attempt overflow")
	}
	var files [2]*os.File
	var native [2]host.TerminalNativeIdentity
	for slot := range files {
		var identity terminalNativeIdentity
		files[slot], identity, err = terminalAnonymous(root)
		if err != nil {
			return capability, err
		}
		defer files[slot].Close()
		identity.Path = approval.PublicationProbePaths[slot]
		native[slot] = host.TerminalNativeIdentity(identity)
	}
	var payloads [2][]byte
	for slot := range files {
		payloads[slot], err = json.Marshal(terminalProbePayload{Version: 1, InstallationID: approval.InstallationID, TransactionID: approval.PlanID, ApprovalDigest: approval.PlanDigest, Attempt: expectedAttempt + 1, Slot: slot, Files: native})
		if err != nil {
			return capability, err
		}
		if len(payloads[slot]) > terminalProbePayloadMax {
			return capability, errors.New("terminal probe payload exceeds bound")
		}
		if err = terminalWriteAnonymous(files[slot], payloads[slot]); err != nil {
			return capability, err
		}
	}
	record, err = store.BindTerminalPublicationProbe(ctx, guard, raw, approval.PlanID, files, payloads, expectedAttempt)
	if err != nil {
		return capability, err
	}
	for slot, file := range files {
		if err = terminalLink(root, file, filepath.Base(record.Paths[slot])); err != nil {
			return capability, errors.Join(err, terminalProbeRemove(root, record))
		}
		if err = root.Sync(); err != nil {
			return capability, errors.Join(err, terminalProbeRemove(root, record))
		}
		layout := [2]int{0, -1}
		if slot == 1 {
			layout[1] = 1
		}
		if err = terminalProbeRequireLayout(root, record, layout); err != nil {
			return capability, errors.Join(err, terminalProbeRemove(root, record))
		}
	}
	if err = terminalProbeExchange(root, record, [2]int{0, 1}); err != nil {
		return capability, errors.Join(err, terminalProbeRemove(root, record))
	}
	record, err = store.RecordTerminalPublicationProbeExchange(ctx, guard, record, host.TerminalProbeEvidence{CreatedAnonymous: true, LinkedNoReplace: true, NoReplaceRejected: true, Exchanged: true, Synced: true})
	if err != nil {
		return capability, err
	}
	if err = terminalProbeRemove(root, record); err != nil {
		return capability, err
	}
	return store.CompleteTerminalPublicationProbe(ctx, guard, record, host.TerminalProbeEvidence{CreatedAnonymous: true, LinkedNoReplace: true, NoReplaceRejected: true, Exchanged: true, Synced: true, Absent: true})
}
