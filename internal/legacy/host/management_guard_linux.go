//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

const ManagementRoot = "/var/lib/chatanium"
const ManagementMarker = "chatanium-management-v1\n"

type ManagementLockMode uint8

const (
	ManagementShared    ManagementLockMode = 1
	ManagementExclusive ManagementLockMode = 2
)

var ErrManagementGuardRequired = errors.New("live management acquisition guard required")
var ErrManagementGuardAbsent = errors.New("management acquisition guard absent from context")
var ErrTerminalPurge = errors.New("installation is irreversibly fenced for terminal purge")

type ManagementGuard struct {
	mu        sync.Mutex
	root      string
	directory *os.File
	lock      *os.File
	mode      ManagementLockMode
	uid       uint32
	closed    bool
}
type managementGuardContextKey struct{}

func WithManagementGuard(ctx context.Context, g *ManagementGuard) context.Context {
	return context.WithValue(ctx, managementGuardContextKey{}, g)
}
func ManagementGuardFromContext(ctx context.Context) (*ManagementGuard, error) {
	value := ctx.Value(managementGuardContextKey{})
	if value == nil {
		return nil, ErrManagementGuardAbsent
	}
	g, ok := value.(*ManagementGuard)
	if !ok || g == nil || !g.Live() {
		return nil, ErrManagementGuardRequired
	}
	return g, nil
}
func (g *ManagementGuard) Mode() ManagementLockMode {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return 0
	}
	return g.mode
}
func (g *ManagementGuard) Live() bool { return g != nil && g.Mode() != 0 }
func (g *ManagementGuard) RootFD() (int, error) {
	if g == nil {
		return -1, ErrManagementGuardRequired
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.directory == nil || g.lock == nil {
		return -1, ErrManagementGuardRequired
	}
	return int(g.directory.Fd()), nil
}
func (g *ManagementGuard) Close() error {
	if g == nil {
		return ErrManagementGuardRequired
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	return errors.Join(unix.Flock(int(g.lock.Fd()), unix.LOCK_UN), g.lock.Close(), g.directory.Close())
}
func (g *ManagementGuard) require(exclusive bool) error {
	if g == nil {
		return ErrManagementGuardRequired
	}
	mode := g.Mode()
	if mode == 0 || exclusive && mode != ManagementExclusive {
		return ErrManagementGuardRequired
	}
	return nil
}
func nativeManagementIdentity(path string, stat unix.Stat_t) TerminalNativeIdentity {
	kind := "file"
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		kind = "directory"
	case unix.S_IFSOCK:
		kind = "socket"
	}
	return TerminalNativeIdentity{Path: path, Kind: kind, Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid, Mode: stat.Mode & 07777, Links: uint64(stat.Nlink)}
}
func observeManagementAnchorAt(root string, uid uint32) (ManagementAnchorObservation, error) {
	observation := ManagementAnchorObservation{Root: TerminalNativeIdentity{Path: root, Kind: "directory", Absent: true}, Lock: TerminalNativeIdentity{Path: filepath.Join(root, ".management.lock"), Kind: "file", Absent: true}, Marker: ManagementMarker}
	var stat unix.Stat_t
	err := unix.Lstat(root, &stat)
	if errors.Is(err, unix.ENOENT) {
		return observation, nil
	}
	if err != nil {
		return observation, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || stat.Mode&0022 != 0 {
		return observation, errors.New("management root is not protected owned infrastructure")
	}
	observation.Root = nativeManagementIdentity(root, stat)
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return observation, err
	}
	defer unix.Close(fd)
	lockFD, err := unix.Openat(fd, ".management.lock", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return observation, nil
	}
	if err != nil {
		return observation, err
	}
	file := os.NewFile(uintptr(lockFD), "management-marker")
	defer file.Close()
	if err = unix.Fstat(lockFD, &stat); err != nil {
		return observation, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || stat.Gid != uid || stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size != int64(len(ManagementMarker)) {
		return observation, errors.New("management marker native identity is unsafe")
	}
	marker, err := io.ReadAll(io.LimitReader(file, int64(len(ManagementMarker))+1))
	if err != nil {
		return observation, err
	}
	if string(marker) != ManagementMarker {
		return observation, errors.New("unrecognized management marker")
	}
	observation.Lock = nativeManagementIdentity(filepath.Join(root, ".management.lock"), stat)
	return observation, nil
}
func ObserveManagementAnchor(ctx context.Context) (ManagementAnchorObservation, error) {
	if err := ctx.Err(); err != nil {
		return ManagementAnchorObservation{}, err
	}
	parent, err := trustedDirectory(filepath.Dir(ManagementRoot))
	if err != nil {
		return ManagementAnchorObservation{}, err
	}
	parent.Close()
	return observeManagementAnchorAt(ManagementRoot, 0)
}
func EnsureManagementAnchor(ctx context.Context, approved ManagementAnchorObservation) (ManagementAnchorObservation, error) {
	return ensureManagementAnchorAt(ctx, ManagementRoot, 0, approved)
}
func ensureManagementAnchorAt(ctx context.Context, root string, uid uint32, approved ManagementAnchorObservation) (ManagementAnchorObservation, error) {
	if err := ctx.Err(); err != nil {
		return ManagementAnchorObservation{}, err
	}
	if approved.Marker != ManagementMarker || approved.Root.Path != root || approved.Lock.Path != filepath.Join(root, ".management.lock") {
		return ManagementAnchorObservation{}, invalid("management anchor approval is not the fixed source-derived location")
	}
	current, err := observeManagementAnchorAt(root, uid)
	if err != nil {
		return current, err
	}
	if !managementAnchorMatches(current, approved) {
		return current, errors.New("management anchor observation changed after approval")
	}
	if !current.Lock.Absent {
		return current, nil
	}
	if current.Root.Absent {
		if err = os.Mkdir(root, 0755); err != nil {
			return current, err
		}
		parent, err := os.Open(filepath.Dir(root))
		if err != nil {
			return current, err
		}
		err = errors.Join(parent.Sync(), parent.Close())
		if err != nil {
			return current, err
		}
	}
	directoryFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return current, err
	}
	directory := os.NewFile(uintptr(directoryFD), "management-root")
	defer directory.Close()
	fd, err := unix.Openat(directoryFD, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return current, err
	}
	file := os.NewFile(uintptr(fd), "anonymous-management-marker")
	defer file.Close()
	if _, err = file.WriteString(ManagementMarker); err != nil {
		return current, err
	}
	if err = file.Sync(); err != nil {
		return current, err
	}
	if err = LinkAnonymous(file, directoryFD, ".management.lock"); err != nil {
		return current, err
	}
	if err = directory.Sync(); err != nil {
		return current, err
	}
	return observeManagementAnchorAt(root, uid)
}
func AcquireManagementGuard(ctx context.Context, mode ManagementLockMode) (*ManagementGuard, error) {
	parent, err := trustedDirectory(filepath.Dir(ManagementRoot))
	if err != nil {
		return nil, err
	}
	parent.Close()
	return acquireManagementGuardAt(ctx, ManagementRoot, 0, mode)
}
func acquireManagementGuardAt(ctx context.Context, root string, uid uint32, mode ManagementLockMode) (*ManagementGuard, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if mode != ManagementShared && mode != ManagementExclusive {
		return nil, invalid("unknown management lock mode")
	}
	observation, err := observeManagementAnchorAt(root, uid)
	if err != nil {
		return nil, err
	}
	if observation.Root.Absent || observation.Lock.Absent {
		return nil, errors.New("approved management anchor initialization required")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(rootFD), "guarded-management-root")
	fd, err := unix.Openat(rootFD, ".management.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		directory.Close()
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "stable-management-lock")
	fail := func(err error) (*ManagementGuard, error) { lock.Close(); directory.Close(); return nil, err }
	operation := unix.LOCK_SH
	if mode == ManagementExclusive {
		operation = unix.LOCK_EX
	}
	for {
		err = unix.Flock(fd, operation|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fail(err)
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return fail(err)
	}
	if nativeManagementIdentity(observation.Lock.Path, stat) != observation.Lock {
		return fail(errors.New("management lock inode changed during acquisition"))
	}
	current, err := observeManagementAnchorAt(root, uid)
	if err != nil {
		return fail(err)
	}
	if !managementAnchorMatches(current, observation) {
		return fail(errors.New("management anchor replaced during acquisition"))
	}
	return &ManagementGuard{root: root, directory: directory, lock: lock, mode: mode, uid: uid}, nil
}
func (g *ManagementGuard) receiptPath(id string) (string, error) {
	if err := g.require(false); err != nil {
		return "", err
	}
	if !safeID(id) {
		return "", invalid("invalid terminal installation ID")
	}
	return filepath.Join(g.root, ".purge-terminal-"+id+".json"), nil
}
func (g *ManagementGuard) checkNoReceipt(id string) error {
	path, err := g.receiptPath(id)
	if err != nil {
		return err
	}
	rootFD, err := g.RootFD()
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	err = unix.Fstatat(rootFD, filepath.Base(path), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return ErrTerminalPurge
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}
func (g *ManagementGuard) stagePath(id, txn string, step uint64) (string, error) {
	if err := g.require(true); err != nil {
		return "", err
	}
	if !safeID(id) || !terminalKeyID(txn) {
		return "", invalid("invalid terminal stage identity")
	}
	return filepath.Join(g.root, fmt.Sprintf(".purge-terminal-%s-%s-%d.next", id, txn, step)), nil
}

func managementAnchorMatches(a, b ManagementAnchorObservation) bool {
	a.Root.Links = 0
	b.Root.Links = 0
	return a == b
}
func (s *Store) checkSourceAdmission(ctx context.Context, terminal bool) error {
	if s.closed || s.gate == nil {
		return ErrManagementGuardRequired
	}
	control, err := terminalObserve(s.dir, false)
	if err != nil {
		return err
	}
	expected := s.sourceControl
	expected.Links = control.Links
	if !terminalIdentityMatches(expected, control, false) {
		return errors.New("Store control incarnation changed")
	}
	database, err := terminalObserve(filepath.Join(s.dir, "supervisor.sqlite"), false)
	if err != nil {
		return err
	}
	if !terminalIdentityMatches(s.sourceDatabase, database, false) {
		return errors.New("Store database native incarnation changed")
	}
	var stat unix.Stat_t
	err = unix.Lstat(filepath.Join(s.gate.root, ".purge-terminal-"+s.productID+".json"), &stat)
	if err == nil {
		return ErrTerminalPurge
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	var incarnation string
	if err = s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='incarnation'").Scan(&incarnation); err != nil {
		return err
	}
	if !safeID(incarnation) || s.incarnation != "" && incarnation != s.incarnation {
		return errors.New("Store installation incarnation changed")
	}
	var fence string
	err = s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='terminal_fence'").Scan(&fence)
	if err == nil && !terminal {
		return ErrTerminalPurge
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if terminal && err != nil {
		return err
	}
	if !terminal && s.gate.Mode() != ManagementExclusive {
		var active string
		err = s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='terminal_probe_active'").Scan(&active)
		if err == nil {
			return ErrTerminalPurge
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return nil
}
func (s *Store) ManagementAnchor(ctx context.Context) (ManagementAnchorObservation, error) {
	var result ManagementAnchorObservation
	err := terminalReadRecord(ctx, s, "management_anchor", &result)
	return result, err
}
func (r *MetadataReader) ManagementAnchor(ctx context.Context) (ManagementAnchorObservation, error) {
	return r.store.ManagementAnchor(ctx)
}

func recordManagementAnchorTx(ctx context.Context, tx *sql.Tx, g *ManagementGuard, plan *ManagementPlanRecord) error {
	if err := g.require(false); err != nil {
		return err
	}
	anchor, err := observeManagementAnchorAt(g.root, g.uid)
	if err != nil {
		return err
	}
	var approved ManagementAnchorObservation
	if plan != nil {
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(plan.Plan, &fields); err != nil {
			return err
		}
		if err = json.Unmarshal(fields["management_anchor"], &approved); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(anchor)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES('management_anchor',?)", raw); err != nil {
		return err
	}
	for index, native := range []TerminalNativeIdentity{anchor.Root, anchor.Lock} {
		created := false
		if plan != nil {
			if index == 0 {
				created = approved.Root.Absent
			} else {
				created = approved.Lock.Absent
			}
		}
		properties := ProvisionProperties{Path: native.Path, UID: native.UID, GID: native.GID, Mode: native.Mode, Dev: native.Device, Ino: native.Inode, ReadOnly: true, ProductCreated: created}
		if index == 1 {
			properties.Digest = provision.Digest([]byte(ManagementMarker))
		}
		encoded, err := json.Marshal(properties)
		if err != nil {
			return err
		}
		record := ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: newID(), Kind: "management-anchor", Identity: native.Path, ExistedBefore: !created, ProductCreated: created, Desired: encoded}, Observed: ObjectObservation{Identity: native.Path, Attributes: encoded}, State: "OBSERVED", CleanupState: "PENDING"}
		body, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO provisioning_ledger VALUES(?,?,?,?)", record.ID, record.Kind, record.Identity, body); err != nil {
			return err
		}
	}
	return nil
}

// LinkAnonymous publishes a held O_TMPFILE inode without replacing a name.
// The procfs descriptor link avoids AT_EMPTY_PATH's CAP_DAC_READ_SEARCH
// requirement without exposing a pathname before the complete body is ready.
func LinkAnonymous(file *os.File, directoryFD int, name string) error {
	if file == nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name || len(name) > 255 {
		return invalid("anonymous publication requires a held file and one destination name")
	}
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	var native, directory unix.Stat_t
	if err = unix.Fstat(fd, &native); err != nil {
		return err
	}
	if err = unix.Fstat(directoryFD, &directory); err != nil {
		return err
	}
	if flags&unix.O_TMPFILE != unix.O_TMPFILE || flags&unix.O_EXCL != 0 || native.Mode&unix.S_IFMT != unix.S_IFREG || native.Mode&07777 != 0600 || native.Uid != uint32(os.Geteuid()) || native.Nlink > 1 || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != uint32(os.Geteuid()) || directory.Mode&0022 != 0 {
		return errors.New("anonymous publication native file or directory protection is invalid")
	}
	source := fmt.Sprintf("/proc/self/fd/%d", fd)
	var descriptor unix.Stat_t
	if err = unix.Stat(source, &descriptor); err != nil {
		return err
	}
	if descriptor.Dev != native.Dev || descriptor.Ino != native.Ino || descriptor.Mode != native.Mode || descriptor.Uid != native.Uid || descriptor.Gid != native.Gid {
		return errors.New("anonymous proc descriptor does not identify the held inode")
	}
	err = unix.Linkat(unix.AT_FDCWD, source, directoryFD, name, unix.AT_SYMLINK_FOLLOW)
	runtime.KeepAlive(file)
	return err
}
