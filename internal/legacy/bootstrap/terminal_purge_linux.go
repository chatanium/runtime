//go:build linux

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const terminalRoot = "/var/lib/chatanium"
const terminalReceiptVersion uint32 = 1
const terminalReceiptMax = 32 << 20
const terminalTargetMax = 1024
const terminalPending uint8 = 0
const terminalRemoving uint8 = 1
const terminalComplete uint8 = 2

type terminalNativeIdentity host.TerminalNativeIdentity
type terminalTarget struct {
	Native terminalNativeIdentity `json:"native"`
	State  uint8                  `json:"state"`
}
type terminalAbsenceGuard struct {
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	Name      string `json:"name,omitempty"`
	UID       uint32 `json:"uid,omitempty"`
	GID       uint32 `json:"gid,omitempty"`
	GroupOnly bool   `json:"group_only,omitempty"`
}
type terminalSource struct {
	Control  terminalNativeIdentity `json:"control"`
	Database terminalNativeIdentity `json:"database"`
	Witness  terminalNativeIdentity `json:"witness"`
}
type terminalReceipt struct {
	Version             uint32                  `json:"version"`
	InstallationID      RuntimeInstallationID   `json:"installation_id"`
	Incarnation         string                  `json:"incarnation"`
	TransactionID       string                  `json:"transaction_id"`
	Approval            PurgeApproval           `json:"approval"`
	Source              terminalSource          `json:"source"`
	Targets             []terminalTarget        `json:"targets"`
	Guards              []terminalAbsenceGuard  `json:"guards"`
	Authority           host.TerminalPurgeSeal  `json:"authority"`
	SealDigest          string                  `json:"seal_digest"`
	Revision            uint64                  `json:"revision"`
	Publication         terminalNativeIdentity  `json:"publication"`
	PreviousPublication *terminalNativeIdentity `json:"previous_publication,omitempty"`
}

func terminalReceiptPath(id RuntimeInstallationID) string {
	return filepath.Join(terminalRoot, ".purge-terminal-"+string(id)+".json")
}
func terminalStageName(id RuntimeInstallationID, transaction string, revision uint64) string {
	return fmt.Sprintf(".purge-terminal-%s-%s-%d.next", id, transaction, revision)
}
func terminalObserve(path string) (terminalNativeIdentity, error) {
	native := terminalNativeIdentity{Path: path}
	var st unix.Stat_t
	if e := unix.Lstat(path, &st); os.IsNotExist(e) {
		native.Absent = true
		return native, nil
	} else if e != nil {
		return native, e
	}
	native.Device = uint64(st.Dev)
	native.Inode = st.Ino
	native.UID = st.Uid
	native.GID = st.Gid
	native.Mode = st.Mode & 07777
	native.Links = uint64(st.Nlink)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		native.Kind = "file"
	case unix.S_IFDIR:
		native.Kind = "directory"
	case unix.S_IFSOCK:
		native.Kind = "socket"
	default:
		return native, errors.New("terminal target has an unsupported native type")
	}
	return native, nil
}
func terminalMatch(expected terminalNativeIdentity) error {
	actual, e := terminalObserve(expected.Path)
	if e != nil {
		return e
	}
	if expected.Absent {
		if !actual.Absent {
			return errors.New("terminal absence guard reappeared")
		}
		return nil
	}
	if actual.Absent {
		return os.ErrNotExist
	}
	if actual.Kind != expected.Kind || actual.Device != expected.Device || actual.Inode != expected.Inode || actual.UID != expected.UID || actual.GID != expected.GID || actual.Mode != expected.Mode || actual.Links != expected.Links {
		return errors.New("terminal target native identity changed")
	}
	if expected.Digest != "" {
		fd, e := unix.Open(expected.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		file := os.NewFile(uintptr(fd), expected.Path)
		actualDigest, e := streamDigest(file)
		file.Close()
		if e != nil {
			return e
		}
		if actualDigest != expected.Digest {
			return errors.New("terminal target content identity changed")
		}
	}
	return nil
}
func terminalAccountAbsent(guard terminalAbsenceGuard) error {
	if e := validateTerminalAccountGuard(guard); e != nil {
		return e
	}
	if !guard.GroupOnly {
		if _, e := user.Lookup(guard.Name); e == nil {
			return errors.New("terminal account name reappeared")
		} else if !unknownUser(e) {
			return e
		}
		if _, e := user.LookupId(strconv.FormatUint(uint64(guard.UID), 10)); e == nil {
			return errors.New("terminal UID reused")
		} else {
			var unknown user.UnknownUserIdError
			if !errors.As(e, &unknown) {
				return e
			}
		}
	}
	if _, e := user.LookupGroup(guard.Name); e == nil {
		return errors.New("terminal group name reappeared")
	} else if !unknownGroup(e) {
		return e
	}
	if guard.GID != 0 {
		if _, e := user.LookupGroupId(strconv.FormatUint(uint64(guard.GID), 10)); e == nil {
			return errors.New("terminal GID reused")
		} else {
			var unknown user.UnknownGroupIdError
			if !errors.As(e, &unknown) {
				return e
			}
		}
	}
	return nil
}
func terminalCheckAbsence(receipt terminalReceipt) error {
	for _, guard := range receipt.Guards {
		if guard.Kind == "account" {
			if e := terminalAccountAbsent(guard); e != nil {
				return e
			}
		} else {
			if _, e := os.Lstat(guard.Path); e == nil {
				return errors.New("completed selected terminal guard reappeared")
			} else if !os.IsNotExist(e) {
				return e
			}
		}
	}
	for _, target := range receipt.Targets {
		if target.State == terminalComplete || target.Native.Absent {
			if _, e := os.Lstat(target.Native.Path); e == nil {
				return errors.New("completed terminal target reappeared")
			} else if !os.IsNotExist(e) {
				return e
			}
		}
	}
	return nil
}
func terminalImmutableDigest(receipt terminalReceipt) (string, error) {
	targets := make([]terminalNativeIdentity, len(receipt.Targets))
	for index, target := range receipt.Targets {
		targets[index] = target.Native
	}
	return digest("chatanium-terminal-purge-seal-v1", struct {
		Version                    uint32
		InstallationID             RuntimeInstallationID
		Incarnation, TransactionID string
		Approval                   PurgeApproval
		Source                     terminalSource
		Targets                    []terminalNativeIdentity
		Guards                     []terminalAbsenceGuard
		Authority                  host.TerminalPurgeSeal
	}{receipt.Version, receipt.InstallationID, receipt.Incarnation, receipt.TransactionID, receipt.Approval, receipt.Source, targets, receipt.Guards, receipt.Authority})
}
func (c *terminalNativeContext) validateReceipt(receipt terminalReceipt) error {
	if e := c.validate(); e != nil {
		return e
	}
	id := c.installationID
	if receipt.Version != terminalReceiptVersion || receipt.InstallationID != id || receipt.Approval.InstallationID != id || !validID(string(id)) || !validID(receipt.TransactionID) || !validID(receipt.Incarnation) || len(receipt.Targets) == 0 || len(receipt.Targets) > terminalTargetMax || len(receipt.Guards) > 8192 {
		return errors.New("invalid bounded terminal receipt")
	}
	approved, e := PurgePlanDigest(receipt.Approval)
	if e != nil || approved != receipt.Approval.PlanDigest {
		return errors.New("terminal receipt approval digest mismatch")
	}
	seal, e := terminalImmutableDigest(receipt)
	if e != nil || seal != receipt.SealDigest {
		return errors.New("terminal receipt immutable seal mismatch")
	}
	if e = c.validateAuthority(receipt); e != nil {
		return e
	}
	seen := map[string]bool{}
	var phases uint64
	unfinished := false
	for _, target := range receipt.Targets {
		path := target.Native.Path
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == c.rootPath || seen[path] || target.State > terminalComplete {
			return errors.New("invalid terminal target")
		}
		seen[path] = true
		if target.Native.Kind != "file" && target.Native.Kind != "directory" && target.Native.Kind != "socket" && !target.Native.Absent {
			return errors.New("invalid terminal native object kind")
		}
		if isAncestor(path, c.receiptPath) || path == c.receiptPath || path == filepath.Join(c.rootPath, ".management.lock") {
			return errors.New("terminal authority overlaps selected deletion")
		}
		if unfinished && target.State != terminalPending {
			return errors.New("terminal progress is not a completed prefix")
		}
		unfinished = unfinished || target.State != terminalComplete
		phases += uint64(target.State)
	}
	if receipt.Revision != 2+phases {
		return errors.New("terminal publication revision differs from exact progress")
	}
	return nil
}
func terminalAnonymous(root *os.File) (*os.File, terminalNativeIdentity, error) {
	fd, e := unix.Openat(int(root.Fd()), ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, terminalNativeIdentity{}, e
	}
	file := os.NewFile(uintptr(fd), "anonymous-terminal-publication")
	fail := func(e error) (*os.File, terminalNativeIdentity, error) {
		file.Close()
		return nil, terminalNativeIdentity{}, e
	}
	if e = file.Chmod(0600); e != nil {
		return fail(e)
	}
	if os.Geteuid() == 0 {
		if e = file.Chown(0, 0); e != nil {
			return fail(e)
		}
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return fail(e)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 0 {
		return fail(errors.New("anonymous publication is not an unlinked regular inode"))
	}
	return file, terminalNativeIdentity{Kind: "file", Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: 0600, Links: 1}, nil
}
func terminalWriteAnonymous(file *os.File, raw []byte) error {
	if len(raw) == 0 || len(raw) > terminalReceiptMax {
		return errors.New("terminal publication exceeds bound")
	}
	if _, e := file.Write(raw); e != nil {
		return e
	}
	return file.Sync()
}
func terminalLink(root, file *os.File, name string) error {
	if filepath.Base(name) != name || name == "." || name == "" {
		return errors.New("invalid terminal publication basename")
	}
	return host.LinkAnonymous(file, int(root.Fd()), name)
}
func (c *terminalNativeContext) read(name string) (terminalReceipt, terminalNativeIdentity, error) {
	root := c.root
	if e := c.validate(); e != nil {
		return terminalReceipt{}, terminalNativeIdentity{}, e
	}
	var receipt terminalReceipt
	fd, e := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return receipt, terminalNativeIdentity{}, e
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return receipt, terminalNativeIdentity{}, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != c.ownerUID || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Size <= 0 || st.Size > terminalReceiptMax {
		return receipt, terminalNativeIdentity{}, errors.New("unsafe terminal receipt inode")
	}
	raw, e := io.ReadAll(io.LimitReader(file, terminalReceiptMax+1))
	if e != nil {
		return receipt, terminalNativeIdentity{}, e
	}
	if e = gvxcontract.DecodeStrict(raw, terminalReceiptMax, 32, &receipt); e != nil {
		return receipt, terminalNativeIdentity{}, e
	}
	if e = c.validateReceipt(receipt); e != nil {
		return receipt, terminalNativeIdentity{}, e
	}
	native := terminalNativeIdentity{Path: filepath.Join(c.rootPath, name), Kind: "file", Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: 0600, Links: 1}
	if !terminalPublicationMatches(receipt.Publication, native) {
		return receipt, native, errors.New("terminal receipt publication provenance changed")
	}
	return receipt, native, nil
}
func terminalPublicationMatches(a, b terminalNativeIdentity) bool {
	return a.Kind == b.Kind && a.Device == b.Device && a.Inode == b.Inode && a.UID == b.UID && a.GID == b.GID && a.Mode == b.Mode && a.Links == b.Links
}
func terminalNext(previous, next terminalReceipt) error {
	if previous.SealDigest != next.SealDigest || previous.InstallationID != next.InstallationID || previous.Incarnation != next.Incarnation || previous.TransactionID != next.TransactionID || next.Revision != previous.Revision+1 || len(previous.Targets) != len(next.Targets) || next.PreviousPublication == nil || !terminalPublicationMatches(*next.PreviousPublication, previous.Publication) {
		return errors.New("terminal receipt progress is not the exact next transaction")
	}
	changed := 0
	for index := range previous.Targets {
		a, b := previous.Targets[index], next.Targets[index]
		if a.Native != b.Native {
			return errors.New("terminal progress changed native authority")
		}
		if a.State != b.State {
			changed++
			if a.State == terminalComplete || b.State != a.State+1 {
				return errors.New("terminal completion moved backward or skipped")
			}
		}
	}
	if changed != 1 {
		return errors.New("terminal progress must advance exactly one target phase")
	}
	return nil
}
func (c *terminalNativeContext) persistProgress(previous terminalReceipt, next terminalReceipt) (terminalReceipt, error) {
	if e := c.validateReceipt(previous); e != nil {
		return previous, e
	}
	root := c.root
	file, native, e := terminalAnonymous(root)
	if e != nil {
		return previous, e
	}
	defer file.Close()
	native.Path = c.receiptPath
	next.Publication = native
	prior := previous.Publication
	next.PreviousPublication = &prior
	if e = terminalNext(previous, next); e != nil {
		return previous, e
	}
	raw, e := json.Marshal(next)
	if e != nil {
		return previous, e
	}
	if e = terminalWriteAnonymous(file, raw); e != nil {
		return previous, e
	}
	stage := terminalStageName(next.InstallationID, next.TransactionID, next.Revision)
	if e = terminalLink(root, file, stage); e != nil {
		return previous, e
	}
	if e = root.Sync(); e != nil {
		return previous, e
	}
	canonical := filepath.Base(c.receiptPath)
	if e = unix.Renameat2(int(root.Fd()), stage, int(root.Fd()), canonical, unix.RENAME_EXCHANGE); e != nil {
		return previous, e
	}
	if e = root.Sync(); e != nil {
		return previous, e
	}
	old, _, e := c.read(stage)
	if e != nil {
		return previous, e
	}
	if old.Revision != previous.Revision || old.SealDigest != previous.SealDigest || !terminalPublicationMatches(old.Publication, previous.Publication) {
		return previous, errors.New("exchanged prior terminal receipt changed")
	}
	if e = unix.Unlinkat(int(root.Fd()), stage, 0); e != nil {
		return previous, e
	}
	if e = root.Sync(); e != nil {
		return previous, e
	}
	return next, nil
}
func terminalDeleteTarget(target terminalTarget) error {
	e := terminalMatch(target.Native)
	if target.Native.Absent {
		if e != nil {
			return e
		}
		return terminalSyncAbsentParent(target.Native.Path)
	}
	if os.IsNotExist(e) {
		return terminalSyncAbsentParent(target.Native.Path)
	}
	if e != nil {
		return e
	}
	if target.Native.Kind == "directory" {
		entries, e := os.ReadDir(target.Native.Path)
		if e != nil {
			return e
		}
		if len(entries) != 0 {
			return errors.New("terminal directory contains unknown or surviving children")
		}
	}
	if e = os.Remove(target.Native.Path); e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(target.Native.Path))
}

func terminalSyncAbsentParent(path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		e := syncDirectory(parent)
		if e == nil {
			return nil
		}
		if !os.IsNotExist(e) || parent == "/" {
			return e
		}
	}
}
func (c *terminalNativeContext) resumeFiles(ctx context.Context, receipt terminalReceipt) (terminalReceipt, error) {
	if e := c.validateReceipt(receipt); e != nil {
		return receipt, e
	}
	for index := range receipt.Targets {
		if e := ctx.Err(); e != nil {
			return receipt, e
		}
		if e := terminalCheckAbsence(receipt); e != nil {
			return receipt, e
		}
		if receipt.Targets[index].State == terminalComplete {
			continue
		}
		if receipt.Targets[index].State == terminalPending {
			next := receipt
			next.Targets = append([]terminalTarget(nil), receipt.Targets...)
			next.Revision++
			next.Targets[index].State = terminalRemoving
			var e error
			receipt, e = c.persistProgress(receipt, next)
			if e != nil {
				return receipt, e
			}
		}
		target := receipt.Targets[index]
		if target.Native.Kind == "directory" {
			for _, child := range receipt.Targets {
				if !child.Native.Absent && child.Native.Kind == "directory" && child.State == terminalComplete && filepath.Dir(child.Native.Path) == target.Native.Path {
					if target.Native.Links == 0 {
						return receipt, errors.New("terminal directory link count underflow")
					}
					target.Native.Links--
				}
			}
		}
		if e := terminalDeleteTarget(target); e != nil {
			return receipt, e
		}
		next := receipt
		next.Targets = append([]terminalTarget(nil), receipt.Targets...)
		next.Revision++
		next.Targets[index].State = terminalComplete
		var e error
		receipt, e = c.persistProgress(receipt, next)
		if e != nil {
			return receipt, e
		}
	}
	if e := terminalCheckAbsence(receipt); e != nil {
		return receipt, e
	}
	return receipt, nil
}

// A linked next publication and an exchanged old publication are the only
// recoverable staging layouts. No unrelated transaction is ever adopted.
func (c *terminalNativeContext) settleStage(current terminalReceipt) (terminalReceipt, error) {
	if e := c.validateReceipt(current); e != nil {
		return current, e
	}
	root := c.root
	fd, e := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if e != nil {
		return current, e
	}
	directory := os.NewFile(uintptr(fd), "terminal-stage-directory")
	defer directory.Close()
	prefix := ".purge-terminal-" + string(current.InstallationID) + "-"
	stage := ""
	for count := 0; ; {
		entries, e := directory.ReadDir(64)
		for _, entry := range entries {
			count++
			if count > 1<<20 {
				return current, errors.New("terminal authority directory exceeds bounded scan")
			}
			if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".next") {
				if stage != "" {
					return current, errors.New("multiple terminal stage files require retained evidence")
				}
				stage = entry.Name()
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return current, e
		}
	}
	if stage == "" {
		return current, nil
	}
	candidate, _, e := c.read(stage)
	if e != nil {
		return current, e
	}
	oldStage := terminalStageName(current.InstallationID, current.TransactionID, current.Revision)
	newStage := terminalStageName(current.InstallationID, current.TransactionID, current.Revision+1)
	if stage == oldStage {
		if e = terminalNext(candidate, current); e != nil {
			return current, e
		}
	} else if stage == newStage {
		if e = terminalNext(current, candidate); e != nil {
			return current, e
		}
		canonical := filepath.Base(c.receiptPath)
		if e = unix.Renameat2(int(root.Fd()), stage, int(root.Fd()), canonical, unix.RENAME_EXCHANGE); e != nil {
			return current, e
		}
		if e = root.Sync(); e != nil {
			return current, e
		}
		current = candidate
	} else {
		return current, errors.New("unrecognized terminal staging revision retained")
	}
	old, _, e := c.read(stage)
	if e != nil {
		return current, e
	}
	if e = terminalNext(old, current); e != nil {
		return current, e
	}
	if e = root.Sync(); e != nil {
		return current, e
	}
	if e = unix.Unlinkat(int(root.Fd()), stage, 0); e != nil {
		return current, e
	}
	if e = root.Sync(); e != nil {
		return current, e
	}
	return current, nil
}

func terminalRejectStaging(root *os.File, id RuntimeInstallationID) error {
	fd, e := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if e != nil {
		return e
	}
	directory := os.NewFile(uintptr(fd), "terminal-prepublication-directory")
	defer directory.Close()
	prefix := ".purge-terminal-" + string(id) + "-"
	for count := 0; ; {
		entries, e := directory.ReadDir(64)
		for _, entry := range entries {
			count++
			if count > 1<<20 {
				return errors.New("terminal authority directory exceeds bounded scan")
			}
			if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".next") {
				return errors.New("named terminal staging authority must settle before a new anonymous publication")
			}
		}
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
	}
}
