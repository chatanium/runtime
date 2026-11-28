//go:build linux

package host

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

type storageMount struct {
	device, root, target, kind, source, options string
	readOnly                                    bool
}

func storageMounts() ([]storageMount, error) {
	return readStorageMounts("/proc/self/mountinfo")
}

func readStorageMounts(path string) ([]storageMount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var result []storageMount
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 1<<20)
	unescape := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		sep := -1
		for i, v := range fields {
			if v == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(fields) < sep+4 {
			return nil, errors.New("malformed mount inventory")
		}
		result = append(result, storageMount{device: fields[2], root: unescape.Replace(fields[3]), target: unescape.Replace(fields[4]), kind: fields[sep+1], source: unescape.Replace(fields[sep+2]), options: fields[5] + "," + fields[sep+3], readOnly: strings.Contains(","+fields[5]+",", ",ro,") && !strings.Contains(","+fields[5]+",", ",rw,")})
	}
	return result, scan.Err()
}
func requireNoMounts(root string) error {
	mounts, err := storageMounts()
	if err != nil {
		return err
	}
	for _, m := range mounts {
		if m.target == root || strings.HasPrefix(m.target, root+"/") {
			return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("owned storage still has mounted references"))
		}
	}
	return nil
}
func backingFile(m InstallationManifest) (*os.File, error) {
	p := m.Paths.BackingFile
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return nil, invalid("noncanonical backing file")
	}
	parent, err := trustedDirectory(filepath.Dir(p))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(p), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Dev != m.Backing.Dev || st.Ino != m.Backing.Ino || st.Size != m.Backing.SizeBytes) {
		err = errors.New("owned regular backing identity changed")
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func readXFSIdentity(f *os.File) (string, error) {
	var header [64]byte
	if _, err := f.ReadAt(header[:], 0); err != nil {
		return "", err
	}
	if string(header[:4]) != "XFSB" {
		return "", errors.New("backing does not contain XFS")
	}
	h := hex.EncodeToString(header[32:48])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
func loopStatus(path string) ([232]byte, error) {
	var status [232]byte
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return status, err
	}
	defer unix.Close(fd)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.LOOP_GET_STATUS64, uintptr(unsafe.Pointer(&status[0])))
	if errno != 0 {
		return status, errno
	}
	return status, nil
}
func verifyLoop(path string, m InstallationManifest) error {
	if !strings.HasPrefix(path, "/dev/loop") {
		return errors.New("owned mount is not a loop device")
	}
	if _, err := strconv.ParseUint(strings.TrimPrefix(path, "/dev/loop"), 10, 32); err != nil {
		return err
	}
	status, err := loopStatus(path)
	if err != nil {
		return err
	}
	if binary.NativeEndian.Uint64(status[0:8]) != m.Backing.Dev || binary.NativeEndian.Uint64(status[8:16]) != m.Backing.Ino || binary.NativeEndian.Uint64(status[24:32]) != 0 || binary.NativeEndian.Uint64(status[32:40]) != 0 {
		return errors.New("loop backing identity or geometry mismatch")
	}
	return nil
}
func (s *Storage) verifyBacking() error { return VerifyBacking(s.installation) }
func VerifyBacking(m InstallationManifest) error {
	f, err := backingFile(m)
	if err != nil {
		return err
	}
	defer f.Close()
	uuid, err := readXFSIdentity(f)
	if err != nil {
		return err
	}
	if uuid != m.Backing.XFSUUID || uuid == "00000000-0000-0000-0000-000000000000" {
		return errors.New("backing XFS UUID mismatch")
	}
	mounts, err := storageMounts()
	if err != nil {
		return err
	}
	count := 0
	for _, mount := range mounts {
		if mount.target != m.Paths.StorageRoot {
			continue
		}
		count++
		options := "," + mount.options + ","
		if mount.kind != "xfs" || mount.root != "/" || !strings.Contains(options, ",rw,") || (!strings.Contains(options, ",prjquota,") && !strings.Contains(options, ",pquota,")) || !strings.Contains(options, ",nodev,") || !strings.Contains(options, ",nosuid,") {
			return errors.New("owned XFS mount options mismatch")
		}
		if err = verifyLoop(mount.source, m); err != nil {
			return err
		}
	}
	if count != 1 {
		return errors.New("owned backing requires one unambiguous XFS mount")
	}
	return nil
}
func provisionObject(ctx context.Context, store *Store, kind, identity string, p ProvisionProperties) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	id := newID()
	err = store.BeginProvision(ctx, ProvisionIntent{ID: id, Kind: kind, Identity: identity, ProductCreated: true, Desired: raw})
	return id, err
}
func observeStorage(ctx context.Context, store *Store, id, identity string, p ProvisionProperties) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return store.ObserveProvision(ctx, id, ObjectObservation{Identity: identity, Attributes: raw})
}

func validateBackingBudget(m InstallationManifest) error {
	if err := ValidateAppAllowance(m.Budget, 0, 0); err != nil {
		return err
	}
	bytes, inodes := int64(0), int64(0)
	for _, part := range []struct{ bytes, inodes int64 }{
		{m.Budget.DataBytes, m.Budget.DataInodes},
		{m.Budget.SourceBytes, m.Budget.SourceInodes},
		{m.Budget.CacheBytes, m.Budget.CacheInodes},
		{m.Budget.PreparationBytes, m.Budget.PreparationInodes},
		{m.Budget.MetadataHeadroomBytes, m.Budget.MetadataHeadroomInodes},
	} {
		if part.bytes <= 0 || part.inodes <= 0 || bytes > math.MaxInt64-part.bytes || inodes > math.MaxInt64-part.inodes {
			return invalid("finite nonoverflowing storage pools and metadata headroom required")
		}
		bytes += part.bytes
		inodes += part.inodes
	}
	if m.Backing.SizeBytes < bytes || m.Backing.SizeBytes%4096 != 0 {
		return invalid("owned backing cannot cover all approved storage pools and headroom")
	}
	return nil
}

// CreateBacking never formats a pre-existing file, including an interrupted one.
// Interrupted work is inspected through the provisioning ledger by maintenance.
func CreateBacking(ctx context.Context, m InstallationManifest, store *Store, d *Systemd) (BackingIdentity, error) {
	var identity BackingIdentity
	if store == nil || d == nil {
		return identity, invalid("live storage owner required")
	}
	if err := validateBackingBudget(m); err != nil {
		return identity, err
	}
	if err := store.requireLease(); err != nil {
		return identity, err
	}
	if err := ctx.Err(); err != nil {
		return identity, err
	}
	if _, err := os.Lstat(m.Paths.BackingFile); err == nil {
		records, err := store.PendingProvisions(ctx)
		if err != nil {
			return identity, err
		}
		for _, record := range records {
			if record.Kind != "backing" || record.Identity != m.Paths.BackingFile || !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || record.FirstFailure == string(FailureBackingExists) {
				continue
			}
			var observed ProvisionProperties
			if err = json.Unmarshal(record.Observed.Attributes, &observed); err != nil {
				return identity, err
			}
			if observed.UUID == "" || observed.SizeBytes != m.Backing.SizeBytes {
				continue
			}
			expected := m
			expected.Backing = BackingIdentity{Dev: observed.Dev, Ino: observed.Ino, SizeBytes: observed.SizeBytes, XFSUUID: observed.UUID}
			f, err := backingFile(expected)
			if err != nil {
				return identity, err
			}
			uuid, err := readXFSIdentity(f)
			f.Close()
			if err != nil {
				return identity, err
			}
			if uuid != observed.UUID {
				return identity, errors.New("recorded completed backing UUID changed")
			}
			return expected.Backing, nil
		}
		return identity, errors.New("known backing has no completed durable format observation; recovery required")
	} else if !errors.Is(err, os.ErrNotExist) {
		return identity, err
	}
	parent, err := trustedDirectory(filepath.Dir(m.Paths.BackingFile))
	if err != nil {
		return identity, err
	}
	defer parent.Close()
	id, err := provisionObject(ctx, store, "backing", m.Paths.BackingFile, ProvisionProperties{Path: m.Paths.BackingFile, SizeBytes: m.Backing.SizeBytes, Mode: 0600, ProductCreated: true})
	if err != nil {
		return identity, err
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(m.Paths.BackingFile), unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return identity, errors.Join(err, store.RecordProvisionFailure(ctx, id, FailureBackingExists))
		}
		return identity, err
	}
	file := os.NewFile(uintptr(fd), m.Paths.BackingFile)
	defer file.Close()
	var created unix.Stat_t
	if err = unix.Fstat(fd, &created); err != nil {
		return identity, err
	}
	if err = file.Sync(); err != nil {
		return identity, err
	}
	if err = parent.Sync(); err != nil {
		return identity, err
	}
	if err = observeStorage(ctx, store, id, m.Paths.BackingFile, ProvisionProperties{Path: m.Paths.BackingFile, Dev: created.Dev, Ino: created.Ino, SizeBytes: created.Size, Mode: 0600, ProductCreated: true}); err != nil {
		return identity, err
	}
	if err = unix.Fallocate(fd, 0, 0, m.Backing.SizeBytes); err != nil {
		return identity, err
	}
	if err = file.Sync(); err != nil {
		return identity, err
	}
	if err = parent.Sync(); err != nil {
		return identity, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return identity, err
	}
	identity = BackingIdentity{Dev: st.Dev, Ino: st.Ino, SizeBytes: st.Size}
	if err = observeStorage(ctx, store, id, m.Paths.BackingFile, ProvisionProperties{Path: m.Paths.BackingFile, Dev: st.Dev, Ino: st.Ino, SizeBytes: st.Size, Mode: 0600, ProductCreated: true}); err != nil {
		return identity, err
	}
	// No force flag: mkfs must reject a recognizable pre-existing filesystem.
	_, err = d.RunHelper(ctx, d.Owner(), bundle.MkfsXFS, []string{"-q", "-K", "-m", "crc=1,reflink=1", "-L", "chatanium", "-d", "file=1,size=" + strconv.FormatInt(m.Backing.SizeBytes, 10), m.Paths.BackingFile}, nil, 64<<10)
	if err != nil {
		return identity, err
	}
	// Image formatting must not turn the approved physical reservation sparse.
	// Reassert it after the helper, and verify that it did not replace the inode.
	if err = unix.Fallocate(fd, 0, 0, m.Backing.SizeBytes); err != nil {
		return identity, err
	}
	var after unix.Stat_t
	if err = unix.Fstat(fd, &after); err != nil {
		return identity, err
	}
	var current unix.Stat_t
	if err = unix.Lstat(m.Paths.BackingFile, &current); err != nil {
		return identity, err
	}
	if after.Dev != st.Dev || after.Ino != st.Ino || current.Dev != st.Dev || current.Ino != st.Ino || after.Size != m.Backing.SizeBytes {
		return identity, errors.New("format helper changed owned backing identity or size")
	}
	if err = file.Sync(); err != nil {
		return identity, err
	}
	identity.XFSUUID, err = readXFSIdentity(file)
	if err != nil {
		return identity, err
	}
	err = observeStorage(ctx, store, id, m.Paths.BackingFile, ProvisionProperties{Path: m.Paths.BackingFile, Dev: st.Dev, Ino: st.Ino, SizeBytes: st.Size, UUID: identity.XFSUUID, Mode: 0600, ProductCreated: true})
	return identity, err
}

func recordedLoop(ctx context.Context, m InstallationManifest, store *Store) (string, string, error) {
	records, err := store.PendingProvisions(ctx)
	if err != nil {
		return "", "", err
	}
	intent := ""
	for _, record := range records {
		if record.Kind != "loop" || record.Identity != m.Paths.BackingFile || !record.ProductCreated || record.ExistedBefore {
			continue
		}
		var desired ProvisionProperties
		if err = json.Unmarshal(record.Desired, &desired); err != nil {
			return "", "", err
		}
		if desired.Dev == m.Backing.Dev && desired.Ino == m.Backing.Ino && desired.UUID == m.Backing.XFSUUID {
			intent = record.ID
		}
	}
	devices, err := os.ReadDir("/sys/block")
	if err != nil {
		return "", "", err
	}
	found := ""
	for _, device := range devices {
		if !strings.HasPrefix(device.Name(), "loop") {
			continue
		}
		path := filepath.Join("/dev", device.Name())
		status, err := loopStatus(path)
		if errors.Is(err, unix.ENXIO) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		if binary.NativeEndian.Uint64(status[0:8]) != m.Backing.Dev || binary.NativeEndian.Uint64(status[8:16]) != m.Backing.Ino {
			continue
		}
		if intent == "" || found != "" {
			return "", "", errors.New("unrecorded or duplicate backing loop attachment")
		}
		if err = verifyLoop(path, m); err != nil {
			return "", "", err
		}
		found = path
	}
	return found, intent, nil
}

func prepareStorageParents(ctx context.Context, m InstallationManifest, store *Store) error {
	for _, name := range []string{"persistent", "instances", "images", "prepared", "preparation"} {
		path := filepath.Join(m.Paths.StorageRoot, name)
		if _, err := os.Lstat(path); err == nil {
			f, err := trustedDirectory(path)
			if err != nil {
				return err
			}
			f.Close()
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if m.State != "PROVISIONING" {
			return errors.New("known storage parent is missing; recovery required")
		}
		intent, err := provisionObject(ctx, store, "directory", path, ProvisionProperties{Path: path, Mode: 0700, ProductCreated: true})
		if err != nil {
			return err
		}
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
		var st unix.Stat_t
		if err = unix.Lstat(path, &st); err != nil {
			return err
		}
		if err = observeStorage(ctx, store, intent, path, ProvisionProperties{Path: path, Dev: st.Dev, Ino: st.Ino, Mode: 0700, ProductCreated: true}); err != nil {
			return err
		}
	}
	return nil
}

func AttachBacking(ctx context.Context, m InstallationManifest, store *Store, d *Systemd) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || d == nil {
		return errors.New("owned backing requires live store and owner")
	}
	if err := store.requireLease(); err != nil {
		return err
	}
	file, err := backingFile(m)
	if err != nil {
		return err
	}
	defer file.Close()
	uuid, err := readXFSIdentity(file)
	if err != nil {
		return err
	}
	if uuid != m.Backing.XFSUUID {
		return errors.New("known XFS backing UUID mismatch")
	}
	mounts, err := storageMounts()
	if err != nil {
		return err
	}
	for _, mount := range mounts {
		if mount.target == m.Paths.StorageRoot {
			if err = VerifyBacking(m); err != nil {
				return err
			}
			return prepareStorageParents(ctx, m, store)
		}
	}
	root, err := trustedDirectory(m.Paths.StorageRoot)
	if err != nil {
		return err
	}
	entries, err := root.ReadDir(1)
	root.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) != 0 {
		return errors.New("backing mount target is not empty")
	}
	loopPath, loopIntent, err := recordedLoop(ctx, m, store)
	if err != nil {
		return err
	}
	if loopPath == "" {
		loopIntent, err = provisionObject(ctx, store, "loop", m.Paths.BackingFile, ProvisionProperties{Path: m.Paths.BackingFile, Dev: m.Backing.Dev, Ino: m.Backing.Ino, UUID: m.Backing.XFSUUID})
		if err != nil {
			return err
		}
		control, err := unix.Open("/dev/loop-control", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		number, err := unix.IoctlRetInt(control, unix.LOOP_CTL_GET_FREE)
		unix.Close(control)
		if err != nil {
			return err
		}
		loopPath = fmt.Sprintf("/dev/loop%d", number)
		fd, err := unix.Open(loopPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.LOOP_SET_FD, file.Fd()); errno != 0 {
			return errno
		}
	}
	if err = verifyLoop(loopPath, m); err != nil {
		return err
	}
	if err = observeStorage(ctx, store, loopIntent, m.Paths.BackingFile, ProvisionProperties{Path: loopPath, Source: m.Paths.BackingFile, Dev: m.Backing.Dev, Ino: m.Backing.Ino, UUID: m.Backing.XFSUUID}); err != nil {
		return err
	}
	mountIntent, err := provisionObject(ctx, store, "mount", m.Paths.StorageRoot, ProvisionProperties{Source: loopPath, Target: m.Paths.StorageRoot, UUID: m.Backing.XFSUUID})
	if err != nil {
		return err
	}
	if err = unix.Mount(loopPath, m.Paths.StorageRoot, "xfs", unix.MS_NODEV|unix.MS_NOSUID, "prjquota"); err != nil {
		return err
	}
	if err = VerifyBacking(m); err != nil {
		return err
	}
	if err = observeStorage(ctx, store, mountIntent, m.Paths.StorageRoot, ProvisionProperties{Source: loopPath, Target: m.Paths.StorageRoot, UUID: m.Backing.XFSUUID}); err != nil {
		return err
	}
	return prepareStorageParents(ctx, m, store)
}

func DetachBacking(ctx context.Context, m InstallationManifest, store *Store, d *Systemd, e CleanupEvidence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateStorageWriters(e); err != nil {
		return err
	}
	if store == nil || d == nil {
		return sharedhost.ErrCleanupIncomplete
	}
	if err := store.requireLease(); err != nil {
		return err
	}
	file, err := backingFile(m)
	if err != nil {
		return err
	}
	uuid, err := readXFSIdentity(file)
	file.Close()
	if err != nil {
		return err
	}
	if uuid != m.Backing.XFSUUID {
		return errors.New("known backing UUID mismatch during detach")
	}
	mounts, err := storageMounts()
	if err != nil {
		return err
	}
	loopPath := ""
	mounted := false
	for _, mount := range mounts {
		if strings.HasPrefix(mount.target, m.Paths.StorageRoot+"/") {
			return sharedhost.ErrCleanupIncomplete
		}
		if mount.target == m.Paths.StorageRoot {
			loopPath = mount.source
			mounted = true
		}
	}
	if mounted {
		if err = VerifyBacking(m); err != nil {
			return err
		}
		root, err := openDirectory(m.Paths.StorageRoot)
		if err != nil {
			return err
		}
		err = unix.Syncfs(int(root.Fd()))
		root.Close()
		if err != nil {
			return err
		}
		if err = unix.Unmount(m.Paths.StorageRoot, 0); err != nil {
			return err
		}
	} else {
		loopPath, _, err = recordedLoop(ctx, m, store)
		if err != nil {
			return err
		}
	}
	if err = requireNoMounts(m.Paths.StorageRoot); err != nil {
		return err
	}
	if loopPath != "" {
		if err = verifyLoop(loopPath, m); err != nil {
			return err
		}
		fd, err := unix.Open(loopPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.LOOP_CLR_FD, 0)
		unix.Close(fd)
		if errno != 0 {
			return errno
		}
		_, err = loopStatus(loopPath)
		if !errors.Is(err, unix.ENXIO) {
			return errors.Join(sharedhost.ErrCleanupIncomplete, err)
		}
	}
	detached, err := VerifyDetached(ctx, m)
	if err != nil {
		return err
	}
	if e.BootID != detached.BootID {
		return errors.New("upstream detach evidence belongs to another boot")
	}
	e.MountsAbsent = detached.MountsAbsent
	e.OpenReferencesAbsent = e.OpenReferencesAbsent && detached.OpenReferencesAbsent
	records, err := store.PendingProvisions(ctx)
	if err != nil {
		return err
	}
	// Settle only this backing's loop/mount intents after both kernel objects
	// and their open references are proven absent. Keep the retained file owned.
	for _, kind := range []string{"mount", "loop"} {
		for _, record := range records {
			if record.Kind != kind || !record.ProductCreated || record.ExistedBefore {
				continue
			}
			var desired ProvisionProperties
			if err = json.Unmarshal(record.Desired, &desired); err != nil {
				return err
			}
			if kind == "loop" {
				if record.Identity != m.Paths.BackingFile || desired.Path != m.Paths.BackingFile || desired.Dev != m.Backing.Dev || desired.Ino != m.Backing.Ino || desired.UUID != m.Backing.XFSUUID {
					continue
				}
			} else {
				if record.Identity != m.Paths.StorageRoot || desired.Target != m.Paths.StorageRoot || desired.UUID != m.Backing.XFSUUID {
					continue
				}
				if loopPath != "" && desired.Source != loopPath {
					continue
				}
				if !strings.HasPrefix(desired.Source, "/dev/loop") {
					continue
				}
				if _, err = strconv.ParseUint(strings.TrimPrefix(desired.Source, "/dev/loop"), 10, 32); err != nil {
					return err
				}
			}
			if err = store.CompleteProvisionCleanup(ctx, record.ID, e); err != nil {
				return err
			}
		}
	}
	return nil
}

// VerifyDetached is passive. It does not treat a successful unmount request as
// proof: every loop device and process descriptor/mapping is checked again.
func VerifyDetached(ctx context.Context, m InstallationManifest) (CleanupEvidence, error) {
	return verifyDetached(ctx, m, true)
}

func verifyDetached(ctx context.Context, m InstallationManifest, formatted bool) (CleanupEvidence, error) {
	var e CleanupEvidence
	if err := ctx.Err(); err != nil {
		return e, err
	}
	if !formatted && m.Backing.Dev == 0 && m.Backing.Ino == 0 {
		if _, err := os.Lstat(m.Paths.BackingFile); !errors.Is(err, os.ErrNotExist) {
			return e, errors.New("unrecorded backing path is occupied")
		}
	} else {
		file, err := backingFile(m)
		if err != nil {
			return e, err
		}
		if formatted {
			uuid, err := readXFSIdentity(file)
			file.Close()
			if err != nil {
				return e, err
			}
			if uuid != m.Backing.XFSUUID {
				return e, errors.New("detached backing UUID changed")
			}
		} else {
			file.Close()
		}
	}
	return verifyDetachedReferences(ctx, m)
}

func verifyDetachedReferences(ctx context.Context, m InstallationManifest) (CleanupEvidence, error) {
	var e CleanupEvidence
	if err := ctx.Err(); err != nil {
		return e, err
	}
	if err := requireNoMounts(m.Paths.StorageRoot); err != nil {
		return e, err
	}
	devices, err := os.ReadDir("/sys/block")
	if err != nil {
		return e, err
	}
	for _, entry := range devices {
		if !strings.HasPrefix(entry.Name(), "loop") {
			continue
		}
		status, err := loopStatus(filepath.Join("/dev", entry.Name()))
		if errors.Is(err, unix.ENXIO) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return e, err
		}
		if binary.NativeEndian.Uint64(status[0:8]) == m.Backing.Dev && binary.NativeEndian.Uint64(status[8:16]) == m.Backing.Ino {
			return e, errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("owned backing remains loop-attached"))
		}
	}
	if err = storageReferencesAbsent(ctx, m); err != nil {
		return e, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return e, err
	}
	e.BootID = strings.TrimSpace(string(boot))
	e.MountsAbsent = true
	e.OpenReferencesAbsent = true
	// Unit/job/transport and temporary-quota evidence comes from the owner,
	// never from an unmounted persistent filesystem.
	return e, nil
}

func storageReferencesAbsent(ctx context.Context, m InstallationManifest) error {
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, process := range processes {
		if _, err = strconv.ParseUint(process.Name(), 10, 32); err != nil {
			continue
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		base := filepath.Join("/proc", process.Name())
		descriptors, err := os.ReadDir(filepath.Join(base, "fd"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, descriptor := range descriptors {
			path := filepath.Join(base, "fd", descriptor.Name())
			var st unix.Stat_t
			if err = unix.Stat(path, &st); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			if st.Dev == m.Backing.Dev && st.Ino == m.Backing.Ino {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("backing has an open descriptor"))
			}
			target, err := os.Readlink(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			target = strings.TrimSuffix(target, " (deleted)")
			if target == m.Paths.BackingFile || target == m.Paths.StorageRoot || strings.HasPrefix(target, m.Paths.StorageRoot+"/") {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("storage has an open descriptor"))
			}
		}
		maps, err := os.ReadFile(filepath.Join(base, "maps"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(maps), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if len(fields) < 5 {
				return errors.New("malformed process mapping inventory")
			}
			device := strings.Split(fields[3], ":")
			if len(device) != 2 {
				return errors.New("malformed mapped device identity")
			}
			major, err := strconv.ParseUint(device[0], 16, 32)
			if err != nil {
				return err
			}
			minor, err := strconv.ParseUint(device[1], 16, 32)
			if err != nil {
				return err
			}
			inode, err := strconv.ParseUint(fields[4], 10, 64)
			if err != nil {
				return err
			}
			if uint32(major) == unix.Major(m.Backing.Dev) && uint32(minor) == unix.Minor(m.Backing.Dev) && inode == m.Backing.Ino && inode != 0 {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("backing has an active mapped inode reference"))
			}
			if len(fields) < 6 {
				continue
			}
			path := strings.TrimSuffix(strings.Join(fields[5:], " "), " (deleted)")
			if path == m.Paths.BackingFile || path == m.Paths.StorageRoot || strings.HasPrefix(path, m.Paths.StorageRoot+"/") {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("storage has an active mapped reference"))
			}
		}
	}
	return nil
}

func (s *Storage) PrepareImageSpace(ctx context.Context, jobID string, l provision.PrepareLimits) (ImageSpace, error) {
	return s.prepareImageSpace(ctx, jobID, l, nil)
}

func (s *Storage) PrepareCacheSpace(ctx context.Context, jobID string, source ImageSpace, l provision.PrepareLimits) (ImageSpace, error) {
	return s.prepareImageSpace(ctx, jobID, l, &source)
}
func (s *Storage) prepareImageSpace(ctx context.Context, jobID string, l provision.PrepareLimits, source *ImageSpace) (ImageSpace, error) {
	var space ImageSpace
	if err := ctx.Err(); err != nil {
		return space, err
	}
	if !safeID(jobID) || l.InputBytes <= 0 || l.InputBytes > math.MaxInt64/2 || l.OutputBytes <= 0 || l.ExpandedBytes <= 0 || l.Inodes < 2 || l.ExpandedBytes > math.MaxInt64-l.OutputBytes {
		return space, invalid("finite image preparation peak required")
	}
	if err := s.requireAdmission(); err != nil {
		return space, err
	}
	if s.config.Preparer.UID == 0 || s.config.Preparer.GID == 0 || s.config.Preparer.UID != s.installation.Identities.Preparer.UID || s.config.Preparer.GID != s.installation.Identities.Preparer.GID {
		return space, errors.New("preparation requires the approved non-root native identity")
	}
	if err := s.verifyBacking(); err != nil {
		return space, err
	}
	space = ImageSpace{JobID: jobID, Source: filepath.Join(s.config.StorageRoot, "images", jobID), Cache: filepath.Join(s.config.StorageRoot, "prepared", jobID), Work: filepath.Join(s.config.StorageRoot, "preparation", jobID)}
	if source != nil {
		if err := s.store.RequirePreparationWriterDomain(ctx, *source); err != nil {
			return space, err
		}
		sourceJob := filepath.Base(source.Source)
		if !safeID(sourceJob) || sourceJob == jobID || source.Source != filepath.Join(s.config.StorageRoot, "images", sourceJob) {
			return space, errors.New("reused source has unexpected native path or reused job identity")
		}
		project, exists, err := s.store.StorageProject(ctx, sourceJob+":source")
		if err != nil {
			return space, err
		}
		if !exists || project == 0 || project != source.SourceProject {
			return space, errors.New("reused source lacks exact durable project")
		}
		if err = s.quota.project(source.Source, project, false); err != nil {
			return space, err
		}
		f, err := openDirectory(source.Source)
		if err != nil {
			return space, err
		}
		var st unix.Stat_t
		err = unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if err != nil {
			return space, err
		}
		if st.Uid != 0 || st.Mode&07777 != 0550 {
			return space, errors.New("reused source is not immutable root-owned storage")
		}
		generation, err := s.store.StorageGeneration(ctx, sourceJob+":source")
		if err != nil {
			return space, err
		}
		space.Source = source.Source
		space.SourceProject = project
		space.SourceGenerationID = generation
		space.ReusedSource = true
	}
	space.ProvisionID = newID()
	desired, err := json.Marshal(ProvisionProperties{Name: "image-space", ImageSpace: &space, PrepareLimits: &l})
	if err != nil {
		return space, err
	}
	if err = s.store.BeginProvision(ctx, ProvisionIntent{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + jobID, ProductCreated: true, Desired: desired}); err != nil {
		return space, err
	}
	if space.ReusedSource {
		if err = s.store.RetainGeneration(ctx, "preparation", space.SourceGenerationID, jobID); err != nil {
			return space, err
		}
	}
	for _, r := range []struct {
		kind, path string
		bytes      int64
		project    *uint32
	}{{"source", space.Source, 2 * l.InputBytes, &space.SourceProject}, {"cache", space.Cache, l.OutputBytes, &space.CacheProject}, {"preparation", space.Work, l.ExpandedBytes + l.OutputBytes, &space.WorkProject}} {
		if space.ReusedSource && r.kind == "source" {
			continue
		}
		// XFS ceilings must be exactly representable; do not round approval upward.
		project, err := s.store.ReserveStorage(ctx, jobID+":"+r.kind, r.kind, r.bytes, l.Inodes)
		if err != nil {
			return space, err
		}
		*r.project = project
		if r.kind == "preparation" {
			if err = s.store.BindStorageGeneration(ctx, jobID+":preparation", "image-preparation:"+jobID); err != nil {
				return space, err
			}
		}
		if err = observeStorage(ctx, s.store, space.ProvisionID, "image-space:"+jobID, ProvisionProperties{Name: "image-space", ImageSpace: &space}); err != nil {
			return space, err
		}
		if err = s.quota.unused(project); err != nil {
			return space, err
		}
		if err = s.quota.limit(project, r.bytes, l.Inodes); err != nil {
			return space, err
		}
		uid, gid := s.config.Preparer.UID, s.config.Preparer.GID
		if r.kind == "cache" {
			uid, gid = 0, 0
		}
		if err = s.prepareImageDirectory(ctx, r.path, uid, gid, project); err != nil {
			return space, err
		}
		if r.kind == "cache" {
			if err = s.prepareImageDirectory(ctx, filepath.Join(r.path, "generation"), s.config.Preparer.UID, s.config.Preparer.GID, project); err != nil {
				return space, err
			}
		}
	}
	return space, nil
}

// The cache's root-owned envelope is private before its writable child exists.
// Recording that creation intent, rather than inferring it from a later chmod,
// distinguishes a confined generation from retained legacy storage.
func (s *Storage) prepareImageDirectory(ctx context.Context, path string, uid, gid, project uint32) error {
	properties := ProvisionProperties{Path: path, Parent: filepath.Dir(path), Mode: 0700, UID: uid, GID: gid, ProductCreated: true}
	intent, err := provisionObject(ctx, s.store, "directory", path, properties)
	if err != nil {
		return err
	}
	if err = os.Mkdir(path, 0700); err != nil {
		return err
	}
	f, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Dev != s.quota.device {
		return errors.New("preparation directory was not born on owned storage as root")
	}
	properties.Dev, properties.Ino = st.Dev, st.Ino
	initial := properties
	initial.UID, initial.GID, initial.Mode = st.Uid, st.Gid, st.Mode&07777
	if err = observeStorage(ctx, s.store, intent, path, initial); err != nil {
		return err
	}
	if err = s.quota.project(path, project, true); err != nil {
		return err
	}
	if err = unix.Fchown(int(f.Fd()), int(uid), int(gid)); err != nil {
		return err
	}
	if err = unix.Fchmod(int(f.Fd()), 0700); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Dev != properties.Dev || st.Ino != properties.Ino || st.Uid != uid || st.Gid != gid || st.Mode&07777 != 0700 {
		return errors.New("preparation directory changed during creation")
	}
	return observeStorage(ctx, s.store, intent, path, properties)
}

// PreparationLayout describes only a private, not-yet-published writer domain.
// B rechecks these native identities at every pre-exec gate transition.
func (s *Storage) PreparationLayout(ctx context.Context, space ImageSpace) (PreparationStorageView, error) {
	var view PreparationStorageView
	if err := ctx.Err(); err != nil {
		return view, err
	}
	if err := s.requireAdmission(); err != nil {
		return view, err
	}
	if !safeID(space.JobID) || !safeID(space.ProvisionID) || space.Committed || space.Cache != filepath.Join(s.config.StorageRoot, "prepared", space.JobID) || space.Work != filepath.Join(s.config.StorageRoot, "preparation", space.JobID) {
		return view, errors.New("preparation layout is not a fresh controller-owned space")
	}
	sourceJob := filepath.Base(space.Source)
	if !safeID(sourceJob) || space.Source != filepath.Join(s.config.StorageRoot, "images", sourceJob) || !space.ReusedSource && sourceJob != space.JobID {
		return view, errors.New("preparation layout source has unknown ownership")
	}
	if s.config.Preparer.UID == 0 || s.config.Preparer.GID == 0 || s.config.Preparer.UID != s.installation.Identities.Preparer.UID || s.config.Preparer.GID != s.installation.Identities.Preparer.GID {
		return view, errors.New("preparation layout has an unapproved native identity")
	}
	record, err := s.store.Provision(ctx, space.ProvisionID)
	if err != nil {
		return view, err
	}
	var properties ProvisionProperties
	if record.Kind != "image" || record.Identity != "image-space:"+space.JobID || !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
		return view, errors.New("preparation layout lacks its live storage intent")
	}
	if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &properties); err != nil {
		return view, err
	}
	if properties.ImageSpace == nil || *properties.ImageSpace != space {
		return view, errors.New("preparation layout differs from its durable storage identity")
	}
	for _, claim := range []struct {
		id      string
		project uint32
	}{{sourceJob + ":source", space.SourceProject}, {space.JobID + ":cache", space.CacheProject}, {space.JobID + ":preparation", space.WorkProject}} {
		if err := s.store.CheckStorageReservation(ctx, claim.id, claim.project); err != nil {
			return view, err
		}
	}
	if err = s.verifyBacking(); err != nil {
		return view, err
	}
	root, err := trustedDirectory(s.config.StorageRoot)
	if err != nil {
		return view, err
	}
	defer root.Close()
	view = PreparationStorageView{Version: gvxcontract.PreparationWriterDomainVersion, JobID: space.JobID, ProvisionID: space.ProvisionID}
	for _, item := range []struct {
		pool, name, role string
		project          uint32
		out              *PreparationStorageRoot
	}{
		{"images", sourceJob, "source", space.SourceProject, &view.Source},
		{"prepared", space.JobID, "cache", space.CacheProject, &view.Cache},
		{"preparation", space.JobID, "work", space.WorkProject, &view.Work},
	} {
		poolPath := filepath.Join(s.config.StorageRoot, item.pool)
		poolIdentity, pool, err := s.preparationRootAt(root, item.pool, poolPath, item.role+"-pool", 0, false)
		if err != nil {
			return PreparationStorageView{}, err
		}
		if err = s.ownedPreparationPool(ctx, poolIdentity.HostPath, poolIdentity.Dev, poolIdentity.Ino); err != nil {
			pool.Close()
			return PreparationStorageView{}, err
		}
		barrier, dataParent := poolIdentity, pool
		if item.role == "cache" {
			if poolIdentity.UID != 0 || poolIdentity.GID != s.config.RuntimeGID || poolIdentity.Mode != 0710 {
				pool.Close()
				return PreparationStorageView{}, errors.New("prepared traversal pool changed native permissions")
			}
			envelopePath := filepath.Join(poolPath, item.name)
			barrier, dataParent, err = s.preparationRootAt(pool, item.name, envelopePath, "cache-barrier", item.project, true)
			pool.Close()
			if err != nil {
				return PreparationStorageView{}, err
			}
			if err = s.ownedPreparationDirectory(ctx, barrier, 0, 0); err != nil {
				dataParent.Close()
				return PreparationStorageView{}, err
			}
		}
		if err = validatePreparationBarrier(barrier); err != nil {
			dataParent.Close()
			return PreparationStorageView{}, err
		}
		barrier.RootID = item.role + "-barrier"
		name := item.name
		if item.role == "cache" {
			name = "generation"
		}
		path := filepath.Join(barrier.HostPath, name)
		data, f, err := s.preparationRootAt(dataParent, name, path, item.role, item.project, true)
		dataParent.Close()
		if err != nil {
			return PreparationStorageView{}, err
		}
		f.Close()
		if err = s.ownedPreparationDirectory(ctx, data, s.config.Preparer.UID, s.config.Preparer.GID); err != nil {
			return PreparationStorageView{}, err
		}
		readOnly, err := preparationDataReadOnly(data, s.config.Preparer.UID, s.config.Preparer.GID, item.role == "source")
		if err != nil {
			return PreparationStorageView{}, err
		}
		*item.out = PreparationStorageRoot{Barrier: barrier, Data: data, ReadOnly: readOnly}
	}
	if space.ReusedSource && !view.Source.ReadOnly {
		return PreparationStorageView{}, errors.New("reused source is not sealed")
	}
	return view, nil
}

func validatePreparationBarrier(root NativeRootIdentity) error {
	if root.UID != 0 || root.GID != 0 || root.Mode != 0700 {
		return errors.New("preparation writer barrier is not private root-owned storage")
	}
	return nil
}

func preparationDataReadOnly(root NativeRootIdentity, uid, gid uint32, allowReadOnly bool) (bool, error) {
	if uid == 0 || gid == 0 {
		return false, errors.New("preparation requires a non-root native writer")
	}
	if root.UID == uid && root.GID == gid && root.Mode == 0700 {
		return false, nil
	}
	if allowReadOnly && root.UID == 0 && root.GID == gid && root.Mode == 0550 {
		return true, nil
	}
	return false, errors.New("preparation data has unexpected native access")
}

func (s *Storage) preparationRootAt(parent *os.File, name, path, role string, project uint32, inherit bool) (NativeRootIdentity, *os.File, error) {
	var root NativeRootIdentity
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return root, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil {
		var attributes fsxattr
		err = ioctlXattr(f, 0x801c581f, &attributes)
		if err == nil && (st.Dev != s.quota.device || attributes.ProjectID != project || attributes.Flags&(0x1|0x100) != 0 || inherit && attributes.Flags&0x200 == 0) {
			err = errors.New("preparation storage changed native filesystem, project or inheritance")
		}
	}
	if err != nil {
		f.Close()
		return root, nil, err
	}
	root = NativeRootIdentity{RootID: role, HostPath: path, Dev: st.Dev, Ino: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, Project: project}
	return root, f, nil
}

func (s *Storage) ownedPreparationPool(ctx context.Context, path string, dev, ino uint64) error {
	records, err := s.store.ObjectProvisions(ctx, "directory", path)
	if err != nil {
		return err
	}
	for _, record := range records {
		if !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
			continue
		}
		var desired, observed ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return err
		}
		if desired.Path != path || desired.UID != 0 || desired.GID != 0 || desired.Mode != 0700 {
			continue
		}
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return err
		}
		if observed.Path != path || observed.Dev != dev || observed.Ino != ino {
			return errors.New("preparation pool differs from its original native identity")
		}
		return nil
	}
	return errors.New("preparation pool lacks its original owned native identity")
}

func (s *Storage) ownedPreparationDirectory(ctx context.Context, root NativeRootIdentity, uid, gid uint32) error {
	records, err := s.store.ObjectProvisions(ctx, "directory", root.HostPath)
	if err != nil {
		return err
	}
	for _, record := range records {
		if !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
			continue
		}
		var desired, observed ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return err
		}
		if desired.Path != root.HostPath || desired.Parent != filepath.Dir(root.HostPath) || desired.Mode != 0700 || desired.UID != uid || desired.GID != gid {
			continue
		}
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return err
		}
		if observed.Path != root.HostPath || observed.Dev != root.Dev || observed.Ino != root.Ino {
			return errors.New("preparation directory differs from its creation identity")
		}
		return nil
	}
	return errors.New("preparation directory lacks its exact private-birth intent")
}

func validateStorageWriters(e CleanupEvidence) error {
	if e.BootID == "" || !e.JobsAbsent || !e.ProcessesAbsent || !e.TransportsClosed || !e.OpenReferencesAbsent {
		return sharedhost.ErrCleanupIncomplete
	}
	return nil
}
func (s *Storage) releaseImagePart(ctx context.Context, space ImageSpace, kind, path string, project uint32, e CleanupEvidence) error {
	if !safeID(space.JobID) {
		return invalid("invalid preparation claim")
	}
	if err := validateStorageWriters(e); err != nil {
		return err
	}
	if err := s.verifyBacking(); err != nil {
		return err
	}
	parent := ""
	switch kind {
	case "source":
		parent = "images"
	case "cache":
		parent = "prepared"
	case "preparation":
		parent = "preparation"
	default:
		return invalid("unknown image space kind")
	}
	if path != filepath.Join(s.config.StorageRoot, parent, space.JobID) {
		return errors.New("preparation path ownership mismatch")
	}
	actual, exists, err := s.store.StorageProject(ctx, space.JobID+":"+kind)
	if err != nil {
		return err
	}
	if !exists {
		if project != 0 {
			return errors.New("preparation project has no durable claim")
		}
		if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("unclaimed image-space path is occupied")
	}
	if project != 0 && project != actual {
		return errors.New("preparation project differs from durable claim")
	}
	project = actual
	if err := s.store.CheckStorageRelease(ctx, space.JobID+":"+kind); err != nil {
		return err
	}
	if err := requireNoMounts(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err = s.verifyCleanupRoot(ctx, path, project); err != nil {
			return err
		}
		if kind == "cache" {
			if err = s.verifyCacheGenerationCleanup(ctx, path, project); err != nil {
				return err
			}
		}
		if err = os.RemoveAll(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.quota.reclaimed(ctx, project); err != nil {
		return err
	}
	e.MountsAbsent = true
	e.QuotaReclaimed = true
	if kind == "cache" {
		if err := s.completeStorageDirectory(ctx, filepath.Join(path, "generation"), e); err != nil {
			return err
		}
	}
	if err := s.completeStorageDirectory(ctx, path, e); err != nil {
		return err
	}
	return s.store.ReleaseStorage(ctx, space.JobID+":"+kind, e)
}

func (s *Storage) ReleaseImageSpaceEvidence(ctx context.Context, space ImageSpace, e CleanupEvidence) (CleanupEvidence, error) {
	var err error
	e, err = s.releasePreparationReferences(ctx, space, e)
	if err != nil {
		return e, err
	}
	for _, r := range []struct {
		kind, path string
		project    uint32
	}{
		{"source", space.Source, space.SourceProject}, {"cache", space.Cache, space.CacheProject}, {"preparation", space.Work, space.WorkProject},
	} {
		if space.ReusedSource && r.kind == "source" {
			continue
		}
		if err = s.releaseImagePart(ctx, space, r.kind, r.path, r.project, e); err != nil {
			return e, err
		}
	}
	details, err := s.imageSpaceReclaimDetails(ctx, space, e.Details)
	if err != nil {
		return e, err
	}
	e.Details = details
	e.QuotaReclaimed = true
	if err = s.store.CompleteProvisionCleanup(ctx, space.ProvisionID, e); err != nil {
		return e, err
	}
	return e, nil
}

// CommitImageSpace retains source/cache reservations for their entire published
// generation lifetime. Only the bounded transient peak workspace is reclaimed.
func (s *Storage) CommitImageSpace(ctx context.Context, space ImageSpace, e CleanupEvidence) error {
	if err := s.store.RequirePreparationWriterDomain(ctx, space); err != nil {
		return err
	}
	if err := s.verifyImageCacheEnvelope(ctx, space, false); err != nil {
		return err
	}
	if err := s.verifyImmutableImageRoot(ctx, space.Source, space.SourceProject); err != nil {
		return err
	}
	if err := s.verifyImmutableImageRoot(ctx, filepath.Join(space.Cache, "generation"), space.CacheProject); err != nil {
		return err
	}
	verified, err := s.releasePreparationReferences(ctx, space, e)
	if err != nil {
		return err
	}
	e = verified
	if err := s.releaseImagePart(ctx, space, "preparation", space.Work, space.WorkProject, e); err != nil {
		return err
	}
	if err := s.exposeImageCache(ctx, space); err != nil {
		return err
	}
	space.Committed = true
	return observeStorage(ctx, s.store, space.ProvisionID, "image-space:"+space.JobID, ProvisionProperties{Name: "image-space", ImageSpace: &space})
}

func (s *Storage) openImageCacheEnvelope(ctx context.Context, space ImageSpace) (NativeRootIdentity, *os.File, error) {
	var root NativeRootIdentity
	if !safeID(space.JobID) || !safeID(space.ProvisionID) || space.CacheProject == 0 || space.Cache != filepath.Join(s.config.StorageRoot, "prepared", space.JobID) {
		return root, nil, errors.New("cache envelope has unknown controller ownership")
	}
	parent, err := trustedDirectory(filepath.Dir(space.Cache))
	if err != nil {
		return root, nil, err
	}
	defer parent.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(parent.Fd()), &st); err != nil {
		return root, nil, err
	}
	if st.Dev != s.quota.device || st.Gid != s.config.RuntimeGID || st.Mode&07777 != 0710 {
		return root, nil, errors.New("cache traversal parent changed native identity")
	}
	if err = s.ownedPreparationPool(ctx, filepath.Dir(space.Cache), st.Dev, st.Ino); err != nil {
		return root, nil, err
	}
	root, f, err := s.preparationRootAt(parent, space.JobID, space.Cache, "cache-barrier", space.CacheProject, true)
	if err != nil {
		return root, nil, err
	}
	if err = s.ownedPreparationDirectory(ctx, root, 0, 0); err != nil {
		f.Close()
		return root, nil, err
	}
	entries, err := f.ReadDir(2)
	if err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return root, nil, err
	}
	if len(entries) != 1 || entries[0].Name() != "generation" {
		f.Close()
		return root, nil, errors.New("cache envelope contains an unexpected generation layout")
	}
	generation, data, err := s.preparationRootAt(f, "generation", filepath.Join(space.Cache, "generation"), "cache", space.CacheProject, true)
	if err != nil {
		f.Close()
		return root, nil, err
	}
	data.Close()
	if err = s.ownedPreparationDirectory(ctx, generation, s.config.Preparer.UID, s.config.Preparer.GID); err != nil {
		f.Close()
		return root, nil, err
	}
	if generation.UID != 0 || generation.Mode != 0550 || generation.GID != s.config.Sandbox.GID && generation.GID != s.config.RuntimeGID {
		f.Close()
		return root, nil, errors.New("cache generation root has not been sealed for its native reader")
	}
	return root, f, nil
}

func (s *Storage) cacheExposureIntent(ctx context.Context, space ImageSpace, root NativeRootIdentity) (string, bool, error) {
	records, err := s.store.ObjectProvisions(ctx, "directory", space.Cache)
	if err != nil {
		return "", false, err
	}
	id, observed := "", false
	for _, record := range records {
		if !record.ProductCreated || record.ExistedBefore || record.CleanupState == "COMPLETE" {
			continue
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return "", false, err
		}
		if desired.Name != "image-cache-exposure" {
			continue
		}
		if id != "" || desired.Path != space.Cache || desired.Parent != filepath.Dir(space.Cache) || desired.Source != space.ProvisionID || desired.Dev != root.Dev || desired.Ino != root.Ino || desired.UID != 0 || desired.GID != s.config.RuntimeGID || desired.Mode != 0710 {
			return "", false, errors.New("cache exposure differs from its exact native storage intent")
		}
		switch record.State {
		case "INTENT":
		case "OBSERVED":
			var actual ProvisionProperties
			if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &actual); err != nil {
				return "", false, err
			}
			if actual.Name != desired.Name || actual.Path != desired.Path || actual.Parent != desired.Parent || actual.Source != desired.Source || actual.Dev != desired.Dev || actual.Ino != desired.Ino || actual.UID != desired.UID || actual.GID != desired.GID || actual.Mode != desired.Mode {
				return "", false, errors.New("cache exposure observation differs from its publication intent")
			}
			observed = true
		default:
			return "", false, errors.New("cache exposure has unknown journal state")
		}
		id = record.ID
	}
	return id, observed, nil
}

func validateCacheExposure(root NativeRootIdentity, runtimeGID uint32, intent, observed bool) error {
	if root.UID != 0 || runtimeGID == 0 || observed && !intent {
		return errors.New("cache envelope has invalid native exposure authority")
	}
	if !intent {
		return validatePreparationBarrier(root)
	}
	if observed {
		if root.GID == runtimeGID && root.Mode == 0710 {
			return nil
		}
	} else if root.Mode == 0700 && (root.GID == 0 || root.GID == runtimeGID) || root.Mode == 0710 && root.GID == runtimeGID {
		return nil
	}
	return errors.New("cache envelope changed outside its journaled exposure")
}

func (s *Storage) verifyImageCacheEnvelope(ctx context.Context, space ImageSpace, exposed bool) error {
	root, f, err := s.openImageCacheEnvelope(ctx, space)
	if err != nil {
		return err
	}
	f.Close()
	id, observed, err := s.cacheExposureIntent(ctx, space, root)
	if err != nil {
		return err
	}
	if exposed && (id == "" || !observed) {
		return errors.New("committed cache lacks its completed native exposure observation")
	}
	return validateCacheExposure(root, s.config.RuntimeGID, id != "", observed)
}

// Called only after the confined writers have settled, both retained trees are
// immutable, and Work has actually been removed and its project usage is zero.
func (s *Storage) exposeImageCache(ctx context.Context, space ImageSpace) error {
	root, f, err := s.openImageCacheEnvelope(ctx, space)
	if err != nil {
		return err
	}
	defer f.Close()
	id, observed, err := s.cacheExposureIntent(ctx, space, root)
	if err != nil {
		return err
	}
	if err = validateCacheExposure(root, s.config.RuntimeGID, id != "", observed); err != nil {
		return err
	}
	if observed {
		return nil
	}
	properties := ProvisionProperties{Name: "image-cache-exposure", Path: space.Cache, Parent: filepath.Dir(space.Cache), Source: space.ProvisionID, Dev: root.Dev, Ino: root.Ino, UID: 0, GID: s.config.RuntimeGID, Mode: 0710, ProductCreated: true}
	if id == "" {
		id, err = provisionObject(ctx, s.store, "directory", space.Cache, properties)
		if err != nil {
			return err
		}
	}
	if err = unix.Fchown(int(f.Fd()), 0, int(s.config.RuntimeGID)); err != nil {
		return err
	}
	if err = unix.Fchmod(int(f.Fd()), 0710); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Dev != root.Dev || st.Ino != root.Ino || st.Uid != 0 || st.Gid != s.config.RuntimeGID || st.Mode&07777 != 0710 {
		return errors.New("cache envelope changed during native publication")
	}
	if err = s.quota.project(space.Cache, space.CacheProject, false); err != nil {
		return err
	}
	return observeStorage(ctx, s.store, id, space.Cache, properties)
}

func (s *Storage) verifyCacheGenerationCleanup(ctx context.Context, path string, project uint32) error {
	records, err := s.store.ObjectProvisions(ctx, "directory", path)
	if err != nil {
		return err
	}
	privateBirth := false
	for _, record := range records {
		if !record.ProductCreated || record.ExistedBefore || record.CleanupState == "COMPLETE" {
			continue
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return err
		}
		if desired.Path == path && desired.Parent == filepath.Dir(path) && desired.UID == 0 && desired.GID == 0 && desired.Mode == 0700 {
			privateBirth = true
		}
	}
	// Legacy disposal keeps its historical outer identity and actual project
	// reclaim guards. It must not be admitted as a current writer domain.
	if !privateBirth {
		return nil
	}
	generation := filepath.Join(path, "generation")
	if _, err = os.Lstat(generation); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return s.verifyCleanupRoot(ctx, generation, project)
}

func (s *Storage) ReclaimEvidence(ctx context.Context) (CleanupEvidence, error) {
	var e CleanupEvidence
	if err := s.verifyBacking(); err != nil {
		return e, err
	}
	projects, err := s.store.TemporaryStorageProjects(ctx)
	if err != nil {
		return e, err
	}
	for _, project := range projects {
		if err = s.quota.reclaimed(ctx, project); err != nil {
			return e, err
		}
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return e, err
	}
	e.BootID = strings.TrimSpace(string(boot))
	e.QuotaReclaimed = true
	return e, nil
}

func (s *Storage) CreateEndpoint(ctx context.Context, l sharedhost.Lease) (EndpointIdentity, *os.File, *os.File, error) {
	if err := s.requireAdmission(); err != nil {
		return EndpointIdentity{}, nil, nil, err
	}
	var identity EndpointIdentity
	if err := s.Verify(ctx, l); err != nil {
		return identity, nil, nil, err
	}
	directory, err := openDirectory(l.IPCPath)
	if err != nil {
		return identity, nil, nil, err
	}
	defer directory.Close()
	var ds unix.Stat_t
	if err = unix.Fstat(int(directory.Fd()), &ds); err != nil {
		return identity, nil, nil, err
	}
	if ds.Uid != 0 || ds.Gid != s.config.RuntimeGID || ds.Mode&07777 != 0710 {
		return identity, nil, nil, errors.New("native endpoint directory policy mismatch")
	}
	path := filepath.Join(l.IPCPath, "primary.sock")
	if len(path) >= 108 {
		return identity, nil, nil, invalid("native endpoint exceeds Unix path limit")
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return identity, nil, nil, err
	}
	listener := os.NewFile(uintptr(fd), "native-primary-listener")
	fail := func(e error) (EndpointIdentity, *os.File, *os.File, error) {
		listener.Close()
		return EndpointIdentity{}, nil, nil, e
	}
	if err = unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return fail(err)
	}
	if err = unix.Fchownat(int(directory.Fd()), "primary.sock", int(s.config.RuntimeUID), int(s.config.RuntimeGID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fail(err)
	}
	if err = unix.Fchmodat(int(directory.Fd()), "primary.sock", 0600, 0); err != nil {
		return fail(err)
	}
	if err = unix.Listen(fd, 1); err != nil {
		return fail(err)
	}
	pinFD, err := unix.Openat2(int(directory.Fd()), "primary.sock", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return fail(err)
	}
	pin := os.NewFile(uintptr(pinFD), "native-primary-path")
	var st unix.Stat_t
	if err = unix.Fstat(pinFD, &st); err != nil {
		pin.Close()
		return fail(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != s.config.RuntimeUID || st.Gid != s.config.RuntimeGID || st.Mode&07777 != 0600 || st.Dev != s.quota.device {
		pin.Close()
		return fail(errors.New("native listener pathname inode policy mismatch"))
	}
	identity = EndpointIdentity{Directory: l.IPCPath, Path: path, DirectoryDev: ds.Dev, DirectoryIno: ds.Ino, SocketDev: st.Dev, SocketIno: st.Ino, UID: st.Uid, GID: st.Gid, Mode: 0600}
	if err = s.store.RecordEndpoint(ctx, l.Ownership, identity); err != nil {
		pin.Close()
		return fail(err)
	}
	return identity, listener, pin, nil
}

func (s *Storage) verifyCleanupRoot(ctx context.Context, path string, project uint32) error {
	f, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Dev != s.quota.device {
		return errors.New("cleanup root changed native filesystem")
	}
	records, err := s.store.PendingProvisions(ctx)
	if err != nil {
		return err
	}
	proven := false
	var partialMode, partialGID uint32
	for _, record := range records {
		if record.Kind != "directory" || record.Identity != path || !record.ProductCreated || record.ExistedBefore {
			continue
		}
		var desired, observed ProvisionProperties
		if err = json.Unmarshal(record.Desired, &desired); err != nil {
			return err
		}
		if desired.Path != path || desired.Mode != 0700 && desired.Mode != 0710 {
			continue
		}
		partialMode = desired.Mode
		partialGID = desired.GID
		if record.State == "OBSERVED" {
			if err = json.Unmarshal(record.Observed.Attributes, &observed); err != nil {
				return err
			}
			if observed.Dev != st.Dev || observed.Ino != st.Ino {
				return errors.New("scratch cleanup inode differs from ledger")
			}
		}
		proven = true
		break
	}
	if !proven {
		return errors.New("scratch cleanup lacks directory creation intent")
	}
	var x fsxattr
	if err = ioctlXattr(f, 0x801c581f, &x); err != nil {
		return err
	}
	if x.Flags&(0x1|0x100) != 0 {
		return errors.New("cleanup root has realtime allocation")
	}
	if x.ProjectID == project && x.Flags&0x200 != 0 {
		return nil
	}
	if st.Uid != 0 || st.Gid != 0 && st.Gid != partialGID || st.Mode&07777 != partialMode && st.Mode&07777 != partialMode&0700 {
		return errors.New("unassigned partial root has foreign native identity")
	}
	if x.ProjectID != 0 {
		return errors.New("partial scratch root has foreign project")
	}
	entries, err := f.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) != 0 {
		return errors.New("unassigned partial scratch root contains data")
	}
	return nil
}

func (s *Storage) completeStorageDirectory(ctx context.Context, path string, e CleanupEvidence) error {
	records, err := s.store.PendingProvisions(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Kind == "directory" && record.Identity == path && record.ProductCreated && !record.ExistedBefore {
			if err = s.store.CompleteProvisionCleanup(ctx, record.ID, e); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Storage) prepareWorkerTraversal(ctx context.Context) error {
	for _, path := range []string{s.config.StorageRoot, filepath.Join(s.config.StorageRoot, "instances"), filepath.Join(s.config.StorageRoot, "prepared")} {
		f, err := trustedDirectory(path)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err = unix.Fstat(int(f.Fd()), &st); err != nil {
			f.Close()
			return err
		}
		if st.Dev != s.quota.device {
			f.Close()
			return errors.New("worker traversal root changed filesystem")
		}
		properties := ProvisionProperties{Path: path, UID: 0, GID: s.config.RuntimeGID, Mode: 0710, Dev: st.Dev, Ino: st.Ino, ProductCreated: true}
		if path == s.config.StorageRoot {
			properties.Volume = &s.installation.Backing
		}
		ready := st.Gid == s.config.RuntimeGID && st.Mode&07777 == 0710
		if ready && properties.Volume != nil {
			records, err := s.store.ObjectProvisions(ctx, "directory", path)
			if err != nil {
				f.Close()
				return err
			}
			ready = false
			for _, record := range records {
				if record.State != "OBSERVED" || !record.ProductCreated || record.ExistedBefore {
					continue
				}
				var observed ProvisionProperties
				if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
					f.Close()
					return err
				}
				if observed.Volume != nil && *observed.Volume == s.installation.Backing && observed.Dev == st.Dev && observed.Ino == st.Ino && observed.GID == s.config.RuntimeGID && observed.Mode == 0710 {
					ready = true
					break
				}
			}
		}
		if ready {
			f.Close()
			continue
		}
		intent, err := provisionObject(ctx, s.store, "directory", path, properties)
		if err != nil {
			f.Close()
			return err
		}
		err = unix.Fchown(int(f.Fd()), 0, int(s.config.RuntimeGID))
		if err == nil {
			err = unix.Fchmod(int(f.Fd()), 0710)
		}
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
		if err = observeStorage(ctx, s.store, intent, path, properties); err != nil {
			return err
		}
	}
	return nil
}

func (s *Storage) releasePreparationReferences(ctx context.Context, space ImageSpace, e CleanupEvidence) (CleanupEvidence, error) {
	e, err := s.VerifyImageSpaceDetached(ctx, space, e)
	if err != nil {
		return e, err
	}
	if err = s.store.ReleaseGeneration(ctx, "preparation", "image-preparation:"+space.JobID, space.JobID, e); err != nil {
		return e, err
	}
	if space.ReusedSource {
		if space.SourceGenerationID == "" {
			return e, errors.New("reused source lacks immutable generation binding")
		}
		if err = s.store.ReleaseGeneration(ctx, "preparation", space.SourceGenerationID, space.JobID, e); err != nil {
			return e, err
		}
	}
	return e, nil
}

// VerifyProvisioningDetached proves safe disposal of an interrupted, never-used
// backing without mounting it or guessing whether a partial format completed.
func VerifyProvisioningDetached(ctx context.Context, m InstallationManifest, store *Store) (BackingIdentity, CleanupEvidence, error) {
	var empty BackingIdentity
	var evidence CleanupEvidence
	if store == nil || m.ActiveRevision != "" || m.State != "PROVISIONING" && m.State != "RECOVERY_REQUIRED" {
		return empty, evidence, errors.New("incomplete backing cleanup requires a never-active installation")
	}
	if err := store.CheckNoStorageAllocations(ctx); err != nil {
		return empty, evidence, err
	}
	records, err := store.PendingProvisions(ctx)
	if err != nil {
		return empty, evidence, err
	}
	recordID := ""
	approvedSize := m.Backing.SizeBytes
	for _, record := range records {
		if record.Kind != "backing" || record.Identity != m.Paths.BackingFile || !record.ProductCreated || record.ExistedBefore || record.FirstFailure == string(FailureBackingExists) {
			continue
		}
		var desired, observed ProvisionProperties
		if err = json.Unmarshal(record.Desired, &desired); err != nil {
			return empty, evidence, err
		}
		if desired.Path != m.Paths.BackingFile || desired.SizeBytes != approvedSize || record.State != "OBSERVED" {
			continue
		}
		recordID = record.ID
		if record.State == "OBSERVED" {
			if err = json.Unmarshal(record.Observed.Attributes, &observed); err != nil {
				return empty, evidence, err
			}
			if observed.Dev != 0 && observed.Ino != 0 {
				m.Backing = BackingIdentity{Dev: observed.Dev, Ino: observed.Ino, SizeBytes: observed.SizeBytes, XFSUUID: observed.UUID}
			}
		}
		break
	}
	if m.Backing.Dev == 0 && m.Backing.Ino == 0 {
		var st unix.Stat_t
		if err = unix.Lstat(m.Paths.BackingFile, &st); err == nil {
			return empty, evidence, errors.New("unobserved backing inode ownership is uncertain; creation intent and native mode cannot authorize removal")
		} else if !errors.Is(err, os.ErrNotExist) {
			return empty, evidence, err
		} else {
			for _, record := range records {
				if record.Kind == "loop" && record.Identity == m.Paths.BackingFile {
					return empty, evidence, errors.New("absent unobserved backing has a loop creation intent")
				}
			}
		}
	}
	if m.Backing.Dev != 0 && m.Backing.Ino != 0 && m.Backing.XFSUUID == "" {
		var st unix.Stat_t
		if err = unix.Lstat(m.Paths.BackingFile, &st); err != nil {
			return empty, evidence, err
		}
		if recordID == "" || st.Dev != m.Backing.Dev || st.Ino != m.Backing.Ino || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Size < 0 || st.Size > approvedSize {
			return empty, evidence, errors.New("partial backing differs from its observed creation inode or approved size")
		}
		m.Backing.SizeBytes = st.Size
		f, err := backingFile(m)
		if err != nil {
			return empty, evidence, err
		}
		f.Close()
		if err = observeStorage(ctx, store, recordID, m.Paths.BackingFile, ProvisionProperties{Path: m.Paths.BackingFile, Dev: st.Dev, Ino: st.Ino, SizeBytes: st.Size, Mode: 0600, ProductCreated: true}); err != nil {
			return empty, evidence, err
		}
	}
	evidence, err = verifyDetached(ctx, m, false)
	if err != nil {
		return empty, evidence, err
	}
	evidence.QuotaReclaimed = true
	identity := m.Backing
	if identity.Dev == 0 && identity.Ino == 0 {
		identity = BackingIdentity{}
	}
	return identity, evidence, nil
}

// VerifyRemovedBacking is restricted to resuming an explicitly approved purge
// after unlink. It never relaxes the normal known-backing existence check.
func VerifyRemovedBacking(ctx context.Context, m InstallationManifest, store *Store) (CleanupEvidence, error) {
	var evidence CleanupEvidence
	if store == nil {
		return evidence, errors.New("removed backing verification requires live store")
	}
	if err := store.AssertRemovable(ctx); err != nil {
		return evidence, err
	}
	if _, err := store.TemporaryStorageProjects(ctx); err != nil {
		return evidence, err
	}
	records, err := store.ObjectProvisions(ctx, "backing", m.Paths.BackingFile)
	if err != nil {
		return evidence, err
	}
	expected := m
	proven := false
	for _, removal := range records {
		if removal.Kind != "backing" || removal.Identity != m.Paths.BackingFile || !removal.ExistedBefore || removal.ProductCreated {
			continue
		}
		var intent ProvisionProperties
		if err = json.Unmarshal(removal.Desired, &intent); err != nil {
			return evidence, err
		}
		if intent.Source != "remove" || !safeID(intent.Revision) || intent.Path != m.Paths.BackingFile {
			continue
		}
		original, err := store.Provision(ctx, intent.Revision)
		if err != nil {
			return evidence, err
		}
		if original.Kind != "backing" || original.Identity != m.Paths.BackingFile || !original.ProductCreated || original.ExistedBefore || original.State != "OBSERVED" {
			return evidence, errors.New("backing removal does not reference an observed owned original")
		}
		var observed ProvisionProperties
		if err = json.Unmarshal(original.Observed.Attributes, &observed); err != nil {
			return evidence, err
		}
		if observed.Path != m.Paths.BackingFile || observed.Dev == 0 || observed.Ino == 0 || intent.Dev != observed.Dev || intent.Ino != observed.Ino || intent.SizeBytes != observed.SizeBytes || intent.UUID != observed.UUID {
			return evidence, errors.New("backing removal snapshot differs from original identity")
		}
		identity := BackingIdentity{Dev: observed.Dev, Ino: observed.Ino, SizeBytes: observed.SizeBytes, XFSUUID: observed.UUID}
		if m.Backing.Dev != 0 || m.Backing.Ino != 0 {
			if identity != m.Backing {
				return evidence, errors.New("removed backing identity differs from installed manifest")
			}
		} else if m.ActiveRevision != "" || identity.SizeBytes < 0 || identity.SizeBytes > m.Backing.SizeBytes {
			return evidence, errors.New("removed incomplete backing exceeds approved creation intent")
		}
		if identity.XFSUUID == "" {
			if err = store.CheckNoStorageAllocations(ctx); err != nil {
				return evidence, err
			}
		}
		expected.Backing = identity
		proven = true
		break
	}
	if !proven {
		return evidence, errors.New("missing backing has no matching durable explicit removal lineage")
	}
	parent, err := trustedDirectory(filepath.Dir(m.Paths.BackingFile))
	if err != nil {
		return evidence, err
	}
	var stat unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), filepath.Base(m.Paths.BackingFile), &stat, unix.AT_SYMLINK_NOFOLLOW)
	parent.Close()
	if !errors.Is(err, unix.ENOENT) {
		if err != nil {
			return evidence, err
		}
		return evidence, errors.New("removed backing pathname is occupied")
	}
	evidence, err = verifyDetachedReferences(ctx, expected)
	if err != nil {
		return evidence, err
	}
	// No file, loop, mount, mapping or open descriptor can retain the deleted
	// volume. Temporary claims were already durably reclaimed before unlink.
	evidence.QuotaReclaimed = true
	return evidence, nil
}

// VerifyImageSpaceDetached cannot upgrade unknown private-namespace evidence.
// The helper owner must first prove namespace absence (or a durable never-submit
// history); this method independently checks native data and mount references.
func (s *Storage) VerifyImageSpaceDetached(ctx context.Context, space ImageSpace, e CleanupEvidence) (CleanupEvidence, error) {
	e.QuotaReclaimed = false
	if !safeID(space.JobID) || !safeID(space.ProvisionID) || space.Cache != filepath.Join(s.config.StorageRoot, "prepared", space.JobID) || space.Work != filepath.Join(s.config.StorageRoot, "preparation", space.JobID) {
		return e, errors.New("image space is not controller-owned")
	}
	sourceJob := filepath.Base(space.Source)
	if !safeID(sourceJob) || space.Source != filepath.Join(s.config.StorageRoot, "images", sourceJob) || !space.ReusedSource && sourceJob != space.JobID {
		return e, errors.New("image source is not controller-owned")
	}
	if err := validateScopedCleanup(e, true, false); err != nil {
		return e, err
	}
	helperDetails := e.Details
	var prior ImageSpaceReclaimDetails
	if len(helperDetails) != 0 && gvxcontract.DecodeStrict(helperDetails, durableJSONMax, 16, &prior) == nil && prior.Version == 1 {
		if prior.JobID != space.JobID || prior.ProvisionID != space.ProvisionID || prior.Source != space.Source || prior.Cache != space.Cache || prior.Work != space.Work || prior.ReusedSource != space.ReusedSource {
			return e, errors.New("replayed cleanup evidence belongs to a different image space")
		}
		helperDetails = prior.HelperDetails
	}
	var never PreparationNoSubmissionDetails
	if len(helperDetails) != 0 && gvxcontract.DecodeStrict(helperDetails, 64<<10, 8, &never) == nil && never.NoHelperSubmission {
		if never.JobID != space.JobID || never.ProvisionID != space.ProvisionID || len(e.Units) != 0 {
			return e, errors.New("never-submitted proof has different image-space binding")
		}
		history, err := s.store.PreparationUnitProvisions(ctx, space.JobID)
		if err != nil {
			return e, err
		}
		if len(history) != 0 {
			return e, errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("image task has helper submission history"))
		}
	}
	if err := s.verifyBacking(); err != nil {
		return e, err
	}
	var projects []uint32
	for _, part := range []struct {
		id       string
		expected uint32
	}{{sourceJob + ":source", space.SourceProject}, {space.JobID + ":cache", space.CacheProject}, {space.JobID + ":preparation", space.WorkProject}} {
		project, exists, err := s.store.StorageProject(ctx, part.id)
		if err != nil {
			return e, err
		}
		if !exists {
			if part.expected != 0 {
				return e, errors.New("image project lacks durable reservation")
			}
			continue
		}
		if project == 0 || part.expected != 0 && project != part.expected {
			return e, errors.New("image project differs from durable reservation")
		}
		projects = append(projects, project)
	}
	if err := s.imageSpaceReferencesAbsent(ctx, space, projects, false); err != nil {
		return e, err
	}
	return e, nil
}

func (s *Storage) imageSpaceReferencesAbsent(ctx context.Context, space ImageSpace, projects []uint32, writersOnly bool) error {
	roots := []string{space.Source, space.Cache, space.Work}
	var relative []string
	for _, root := range roots {
		path, err := filepath.Rel(s.config.StorageRoot, root)
		if err != nil {
			return err
		}
		relative = append(relative, "/"+filepath.ToSlash(path))
	}
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	seen := make(map[[2]uint64]bool)
	for _, process := range processes {
		pid, parseErr := strconv.ParseUint(process.Name(), 10, 32)
		if parseErr != nil || pid == 0 {
			continue
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		base := filepath.Join("/proc", process.Name())
		nsPath := filepath.Join(base, "ns/mnt")
		var before unix.Stat_t
		if err = unix.Stat(nsPath, &before); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		key := [2]uint64{before.Dev, before.Ino}
		if !seen[key] {
			mounts, err := readStorageMounts(filepath.Join(base, "mountinfo"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			for _, mount := range mounts {
				device := strings.Split(mount.device, ":")
				if len(device) != 2 {
					return errors.New("malformed mounted device identity")
				}
				major, err := strconv.ParseUint(device[0], 10, 32)
				if err != nil {
					return err
				}
				minor, err := strconv.ParseUint(device[1], 10, 32)
				if err != nil {
					return err
				}
				if uint32(major) != unix.Major(s.quota.device) || uint32(minor) != unix.Minor(s.quota.device) {
					continue
				}
				for _, root := range relative {
					if mount.root == root || strings.HasPrefix(mount.root, root+"/") {
						if !writersOnly || !mount.readOnly {
							return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("image project subtree retains an unauthorized native mount"))
						}
					}
				}
			}
			var after unix.Stat_t
			if err = unix.Stat(nsPath, &after); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			if after.Dev != before.Dev || after.Ino != before.Ino {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("mount namespace changed during image cleanup observation"))
			}
			seen[key] = true
		}
		if err = s.inspectProcessDescriptors(ctx, base, int(pid), projects, writersOnly); err != nil {
			return err
		}
		maps, err := os.Open(filepath.Join(base, "maps"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		scan := bufio.NewScanner(maps)
		scan.Buffer(make([]byte, 4096), 1<<20)
		var shared []nativeMappingIdentity
		for scan.Scan() {
			if err = ctx.Err(); err != nil {
				maps.Close()
				return err
			}
			mapping, e := parseNativeMappingHeader(scan.Text())
			if e != nil {
				maps.Close()
				return e
			}
			if mapping.Major != unix.Major(s.quota.device) || mapping.Minor != unix.Minor(s.quota.device) || mapping.Inode == 0 {
				continue
			}
			if writersOnly && mapping.Permissions[3] == 'p' {
				continue
			}
			matched, e := s.mappedProjectReferenceMatches(filepath.Join(base, "map_files", mapping.Range), projects, mapping)
			if e != nil {
				maps.Close()
				return e
			}
			if !matched {
				continue
			}
			if !writersOnly {
				maps.Close()
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("image project retains a mapped inode"))
			}
			shared = append(shared, mapping)
		}
		err = scan.Err()
		maps.Close()
		if err != nil {
			return err
		}
		if len(shared) != 0 {
			if err = verifySharedMappingsReadOnly(ctx, filepath.Join(base, "smaps"), shared); err != nil {
				return err
			}
		}
	}
	return nil
}

// inspectProcessDescriptors binds each candidate's identity, project and access
// mode to one held open-file description. It is not an atomic all-process scan;
// the caller's independent unit/writer/namespace quiescence fence is required.
func (s *Storage) inspectProcessDescriptors(ctx context.Context, base string, pid int, projects []uint32, writersOnly bool) error {
	dir, err := os.Open(filepath.Join(base, "fd"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(sharedhost.ErrCleanupIncomplete, err)
	}
	defer dir.Close()
	pidfd := -1
	defer func() {
		if pidfd >= 0 {
			unix.Close(pidfd)
		}
	}()
	for {
		entries, readErr := dir.ReadDir(1)
		for _, entry := range entries {
			if err = ctx.Err(); err != nil {
				return errors.Join(sharedhost.ErrCleanupIncomplete, err)
			}
			target, err := strconv.ParseUint(entry.Name(), 10, 31)
			if err != nil {
				return errors.Join(sharedhost.ErrCleanupIncomplete, err)
			}
			var observed unix.Stat_t
			if err = unix.Stat(filepath.Join(base, "fd", entry.Name()), &observed); err != nil {
				return errors.Join(sharedhost.ErrCleanupIncomplete, err)
			}
			if observed.Dev != s.quota.device || observed.Mode&unix.S_IFMT != unix.S_IFREG && observed.Mode&unix.S_IFMT != unix.S_IFDIR {
				continue
			}
			if pid != os.Getpid() && pidfd < 0 {
				pidfd, err = unix.PidfdOpen(pid, 0)
				if err != nil {
					return errors.Join(sharedhost.ErrCleanupIncomplete, err)
				}
			}
			held, err := captureProcessDescriptor(pid, pidfd, int(target))
			if err != nil {
				return err
			}
			err = s.checkCapturedProjectDescriptor(held, observed, projects, writersOnly)
			err = errors.Join(err, held.Close())
			if err != nil {
				return errors.Join(sharedhost.ErrCleanupIncomplete, err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return errors.Join(sharedhost.ErrCleanupIncomplete, readErr)
		}
	}
}

func (s *Storage) checkCapturedProjectDescriptor(held *os.File, observed unix.Stat_t, projects []uint32, writersOnly bool) error {
	var current unix.Stat_t
	if err := unix.Fstat(int(held.Fd()), &current); err != nil {
		return err
	}
	if current.Dev != observed.Dev || current.Ino != observed.Ino || current.Mode&unix.S_IFMT != observed.Mode&unix.S_IFMT {
		return errors.New("descriptor identity changed before held capture")
	}
	flags, writable, err := capturedDescriptorAccess(held)
	if err != nil {
		return err
	}
	// O_PATH itself cannot write or mmap the inode. Do not reopen it to ask
	// unsupported ioctls and accidentally classify a different description.
	// This exemption is only for the fenced, immutable writer-only proof.
	if writersOnly && flags&unix.O_PATH != 0 {
		if writable {
			return errors.New("O_PATH capture has unknown writable access")
		}
		return nil
	}
	var attributes fsxattr
	if err := ioctlXattr(held, 0x801c581f, &attributes); err != nil {
		return err
	}
	for _, project := range projects {
		if attributes.ProjectID != project {
			continue
		}
		if writersOnly && !writable {
			return nil
		}
		return errors.New("image project retains an unauthorized held descriptor")
	}
	return nil
}

func captureProcessDescriptor(pid, pidfd, target int) (*os.File, error) {
	if pid <= 0 || target < 0 {
		return nil, errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("invalid native descriptor capture identity"))
	}
	var fd int
	var err error
	if pid == os.Getpid() {
		fd, err = unix.FcntlInt(uintptr(target), unix.F_DUPFD_CLOEXEC, 0)
	} else {
		if pidfd < 0 {
			return nil, errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("foreign descriptor requires a pinned pidfd"))
		}
		fd, err = unix.PidfdGetfd(pidfd, target, 0)
	}
	if err != nil {
		return nil, errors.Join(sharedhost.ErrCleanupIncomplete, err)
	}
	return os.NewFile(uintptr(fd), "held-native-open-description"), nil
}

// mappedProjectReferenceMatches observes an inode pinned by an exact VMA.
// It never supplies file-description flags for the descriptor scan.
func (s *Storage) mappedProjectReferenceMatches(path string, projects []uint32, mapping nativeMappingIdentity) (bool, error) {
	var expected unix.Stat_t
	if err := unix.Stat(path, &expected); err != nil {
		return false, errors.Join(sharedhost.ErrCleanupIncomplete, err)
	}
	if unix.Major(expected.Dev) != mapping.Major || unix.Minor(expected.Dev) != mapping.Minor || expected.Ino != mapping.Inode {
		return false, errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("mapped inode differs from exact mapping header"))
	}
	if expected.Dev != s.quota.device || expected.Mode&unix.S_IFMT != unix.S_IFREG && expected.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return false, errors.Join(sharedhost.ErrCleanupIncomplete, err)
	}
	f := os.NewFile(uintptr(fd), "image-reference-observation")
	defer f.Close()
	var current unix.Stat_t
	if err = unix.Fstat(fd, &current); err != nil {
		return false, err
	}
	if current.Dev != expected.Dev || current.Ino != expected.Ino {
		return false, errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("native reference changed during observation"))
	}
	var attributes fsxattr
	if err = ioctlXattr(f, 0x801c581f, &attributes); err != nil {
		return false, err
	}
	for _, project := range projects {
		if attributes.ProjectID == project {
			return true, nil
		}
	}
	return false, nil
}

func (s *Storage) RecoverUnsubmittedImageSpaces(ctx context.Context) error {
	records, err := s.store.PendingProvisions(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Kind != "image" || !strings.HasPrefix(record.Identity, "image-space:") || !record.ProductCreated || record.ExistedBefore {
			continue
		}
		var properties ProvisionProperties
		raw := record.Desired
		if record.State == "OBSERVED" {
			raw = record.Observed.Attributes
		}
		if err = gvxcontract.DecodeStrict(raw, 64<<10, 16, &properties); err != nil {
			return err
		}
		if properties.Name != "image-space" || properties.ImageSpace == nil {
			return errors.New("invalid image-space recovery record")
		}
		space := *properties.ImageSpace
		if space.ProvisionID != record.ID || record.Identity != "image-space:"+space.JobID {
			return errors.New("image-space recovery binding mismatch")
		}
		if space.Committed {
			continue
		}
		history, err := s.store.PreparationUnitProvisions(ctx, space.JobID)
		if err != nil {
			return err
		}
		if len(history) != 0 {
			continue
		}
		boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return err
		}
		details, err := json.Marshal(PreparationNoSubmissionDetails{JobID: space.JobID, ProvisionID: space.ProvisionID, NoHelperSubmission: true})
		if err != nil {
			return err
		}
		proof := CleanupEvidence{BootID: strings.TrimSpace(string(boot)), JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, OpenReferencesAbsent: true, MountsAbsent: true, Details: details}
		if _, err = s.ReleaseImageSpaceEvidence(ctx, space, proof); err != nil {
			return err
		}
	}
	return nil
}

type ImageSpaceClaimReclaim struct {
	ClaimID           string `json:"claim_id"`
	Project           uint32 `json:"project"`
	QuotaPresent      bool   `json:"quota_present"`
	Blocks512         uint64 `json:"blocks_512"`
	Inodes            uint64 `json:"inodes"`
	RealtimeBlocks512 uint64 `json:"realtime_blocks_512"`
}

type ImageSpaceReclaimDetails struct {
	Version       uint32                   `json:"version"`
	JobID         string                   `json:"job_id"`
	ProvisionID   string                   `json:"provision_id"`
	Source        string                   `json:"source"`
	Cache         string                   `json:"cache"`
	Work          string                   `json:"work"`
	ReusedSource  bool                     `json:"reused_source"`
	Claims        []ImageSpaceClaimReclaim `json:"claims"`
	HelperDetails []byte                   `json:"helper_details"`
}

func (s *Storage) imageSpaceReclaimDetails(ctx context.Context, space ImageSpace, helperDetails []byte) ([]byte, error) {
	var previous ImageSpaceReclaimDetails
	if len(helperDetails) != 0 && gvxcontract.DecodeStrict(helperDetails, durableJSONMax, 16, &previous) == nil && previous.Version == 1 {
		if previous.JobID != space.JobID || previous.ProvisionID != space.ProvisionID {
			return nil, errors.New("previous cleanup evidence belongs to a different image space")
		}
		helperDetails = previous.HelperDetails
	}
	details := ImageSpaceReclaimDetails{Version: 1, JobID: space.JobID, ProvisionID: space.ProvisionID, Source: space.Source, Cache: space.Cache, Work: space.Work, ReusedSource: space.ReusedSource, HelperDetails: helperDetails}
	for _, kind := range []string{"source", "cache", "preparation"} {
		if space.ReusedSource && kind == "source" {
			continue
		}
		id := space.JobID + ":" + kind
		project, exists, err := s.store.StorageProject(ctx, id)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		quota, err := s.quota.get(project)
		present := err == nil
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return nil, err
		}
		if quota.Blocks != 0 || quota.Inodes != 0 || quota.RTBlocks != 0 {
			return nil, errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("released image claim retains actual quota usage"))
		}
		details.Claims = append(details.Claims, ImageSpaceClaimReclaim{ClaimID: id, Project: project, QuotaPresent: present, Blocks512: quota.Blocks, Inodes: quota.Inodes, RealtimeBlocks512: quota.RTBlocks})
	}
	return json.Marshal(details)
}

func capturedDescriptorAccess(held *os.File) (int, bool, error) {
	flags, err := unix.FcntlInt(held.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return 0, false, err
	}
	mode := flags & unix.O_ACCMODE
	if mode != unix.O_RDONLY && mode != unix.O_WRONLY && mode != unix.O_RDWR {
		return 0, false, errors.New("unknown held descriptor access mode")
	}
	return flags, mode == unix.O_WRONLY || mode == unix.O_RDWR, nil
}

type CommittedImageSpaceDetails struct {
	Version            uint32                 `json:"version"`
	Purpose            string                 `json:"purpose"`
	JobID              string                 `json:"job_id"`
	ProvisionID        string                 `json:"provision_id"`
	Source             string                 `json:"source"`
	Cache              string                 `json:"cache"`
	SourceProject      uint32                 `json:"source_project"`
	CacheProject       uint32                 `json:"cache_project"`
	SourceGenerationID string                 `json:"source_generation_id"`
	CacheGenerationID  string                 `json:"cache_generation_id"`
	RetainedReadOnly   bool                   `json:"retained_read_only"`
	Work               ImageSpaceClaimReclaim `json:"work"`
	HelperDetails      []byte                 `json:"helper_details"`
}

// VerifyCommittedImageSpace retires only a settled helper's outer unit record.
// It supplements the image manager's exact generation/integrity validation,
// permits immutable retained readers, and is not an all-data cleanup proof.
func (s *Storage) VerifyCommittedImageSpace(ctx context.Context, space ImageSpace, e CleanupEvidence) (CleanupEvidence, error) {
	e.QuotaReclaimed = false
	if err := validateScopedCleanup(e, true, false); err != nil {
		return e, err
	}
	if !safeID(space.JobID) || !safeID(space.ProvisionID) || space.Cache != filepath.Join(s.config.StorageRoot, "prepared", space.JobID) || space.Work != filepath.Join(s.config.StorageRoot, "preparation", space.JobID) {
		return e, errors.New("committed image space is not controller-owned")
	}
	sourceJob := filepath.Base(space.Source)
	if !safeID(sourceJob) || space.Source != filepath.Join(s.config.StorageRoot, "images", sourceJob) || !space.ReusedSource && sourceJob != space.JobID {
		return e, errors.New("committed source path has unknown ownership")
	}
	record, err := s.store.Provision(ctx, space.ProvisionID)
	if err != nil {
		return e, err
	}
	if record.Kind != "image" || record.Identity != "image-space:"+space.JobID || !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
		return e, errors.New("image space has no live committed storage record")
	}
	var properties ProvisionProperties
	if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &properties); err != nil {
		return e, err
	}
	expected := space
	expected.Committed = true
	if properties.Name != "image-space" || properties.ImageSpace == nil || *properties.ImageSpace != expected {
		return e, errors.New("image space differs from durable committed identity")
	}
	if err = s.store.RequirePreparationWriterDomain(ctx, space); err != nil {
		return e, err
	}
	if err = s.verifyImageCacheEnvelope(ctx, space, true); err != nil {
		return e, err
	}
	if err = s.verifyBacking(); err != nil {
		return e, err
	}
	for _, claim := range []struct {
		id      string
		project uint32
	}{{sourceJob + ":source", space.SourceProject}, {space.JobID + ":cache", space.CacheProject}, {space.JobID + ":preparation", space.WorkProject}} {
		project, exists, err := s.store.StorageProject(ctx, claim.id)
		if err != nil {
			return e, err
		}
		if !exists || project == 0 || project != claim.project {
			return e, errors.New("committed storage project binding changed")
		}
	}
	sourceGeneration, err := s.store.StorageGeneration(ctx, sourceJob+":source")
	if err != nil {
		return e, err
	}
	cacheGeneration, err := s.store.StorageGeneration(ctx, space.JobID+":cache")
	if err != nil {
		return e, err
	}
	if space.ReusedSource && sourceGeneration != space.SourceGenerationID {
		return e, errors.New("retained source generation changed")
	}
	if _, err = os.Lstat(space.Work); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return e, err
		}
		return e, errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("committed preparation workspace still exists"))
	}
	if err = s.quota.reclaimed(ctx, space.WorkProject); err != nil {
		return e, err
	}
	work, err := s.quota.get(space.WorkProject)
	present := err == nil
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return e, err
	}
	if work.Blocks != 0 || work.Inodes != 0 || work.RTBlocks != 0 {
		return e, sharedhost.ErrCleanupIncomplete
	}
	if err = s.verifyImmutableImageRoot(ctx, space.Source, space.SourceProject); err != nil {
		return e, err
	}
	if err = s.verifyImmutableImageRoot(ctx, filepath.Join(space.Cache, "generation"), space.CacheProject); err != nil {
		return e, err
	}
	if err = s.imageSpaceReferencesAbsent(ctx, space, []uint32{space.SourceProject, space.CacheProject, space.WorkProject}, true); err != nil {
		return e, err
	}
	details := CommittedImageSpaceDetails{Version: 1, Purpose: "committed-helper-retirement-retaining-readers", JobID: space.JobID, ProvisionID: space.ProvisionID, Source: space.Source, Cache: space.Cache, SourceProject: space.SourceProject, CacheProject: space.CacheProject, SourceGenerationID: sourceGeneration, CacheGenerationID: cacheGeneration, RetainedReadOnly: true, Work: ImageSpaceClaimReclaim{ClaimID: space.JobID + ":preparation", Project: space.WorkProject, QuotaPresent: present, Blocks512: work.Blocks, Inodes: work.Inodes, RealtimeBlocks512: work.RTBlocks}, HelperDetails: e.Details}
	e.Details, err = json.Marshal(details)
	// Keep the generic quota bit false: retained source/cache are not reclaimed.
	// Only Work's actual zero readback is established in the typed details.
	return e, err
}

func (s *Storage) verifyImmutableImageRoot(ctx context.Context, path string, project uint32) error {
	f, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	records, err := s.store.ObjectProvisions(ctx, "directory", path)
	if err != nil {
		return err
	}
	bound := false
	for _, record := range records {
		if !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
			continue
		}
		var observed ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return err
		}
		if observed.Path == path && observed.Dev == st.Dev && observed.Ino == st.Ino {
			bound = true
			break
		}
	}
	if !bound {
		return errors.New("immutable image root differs from owned native inode")
	}
	return s.verifyImmutableImageNode(ctx, f, project)
}

func (s *Storage) verifyImmutableImageNode(ctx context.Context, f *os.File, project uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	kind := st.Mode & unix.S_IFMT
	if st.Dev != s.quota.device || st.Uid != 0 || st.Mode&0222 != 0 || kind != unix.S_IFDIR && kind != unix.S_IFREG {
		return errors.New("committed image has writable, foreign or unsupported native object")
	}
	var attributes fsxattr
	if err := ioctlXattr(f, 0x801c581f, &attributes); err != nil {
		return err
	}
	if attributes.ProjectID != project || attributes.Flags&(0x1|0x100) != 0 || kind == unix.S_IFDIR && attributes.Flags&0x200 == 0 {
		return errors.New("committed image project identity or inheritance changed")
	}
	if kind == unix.S_IFREG {
		return nil
	}
	for {
		entries, err := f.ReadDir(1)
		for _, entry := range entries {
			var child unix.Stat_t
			if e := unix.Fstatat(int(f.Fd()), entry.Name(), &child, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return e
			}
			if child.Mode&unix.S_IFMT != unix.S_IFREG && child.Mode&unix.S_IFMT != unix.S_IFDIR {
				return errors.New("committed image contains a non-file native object")
			}
			fd, e := unix.Openat2(int(f.Fd()), entry.Name(), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS})
			if e != nil {
				return e
			}
			next := os.NewFile(uintptr(fd), "immutable-image-observation")
			e = s.verifyImmutableImageNode(ctx, next, project)
			e = errors.Join(e, next.Close())
			if e != nil {
				return e
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

type nativeMappingIdentity struct {
	Range, Permissions string
	Start, End, Offset uint64
	Major, Minor       uint32
	Inode              uint64
}

func parseNativeMappingHeader(line string) (nativeMappingIdentity, error) {
	var result nativeMappingIdentity
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return result, errors.New("malformed native mapping header")
	}
	address := strings.Split(fields[0], "-")
	if len(address) != 2 {
		return result, errors.New("malformed native mapping range")
	}
	start, err := strconv.ParseUint(address[0], 16, 64)
	if err != nil {
		return result, err
	}
	end, err := strconv.ParseUint(address[1], 16, 64)
	if err != nil || end <= start {
		return result, errors.New("invalid native mapping range")
	}
	p := fields[1]
	if len(p) != 4 || p[0] != 'r' && p[0] != '-' || p[1] != 'w' && p[1] != '-' || p[2] != 'x' && p[2] != '-' || p[3] != 'p' && p[3] != 's' {
		return result, errors.New("malformed native mapping permissions")
	}
	offset, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return result, err
	}
	device := strings.Split(fields[3], ":")
	if len(device) != 2 {
		return result, errors.New("malformed native mapping device")
	}
	major, err := strconv.ParseUint(device[0], 16, 32)
	if err != nil {
		return result, err
	}
	minor, err := strconv.ParseUint(device[1], 16, 32)
	if err != nil {
		return result, err
	}
	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return result, err
	}
	return nativeMappingIdentity{Range: fields[0], Permissions: p, Start: start, End: end, Offset: offset, Major: uint32(major), Minor: uint32(minor), Inode: inode}, nil
}

var errSharedMappingWritable = errors.New("retained shared mapping can write the immutable image")

func verifySharedMappingsReadOnly(ctx context.Context, path string, expected []nativeMappingIdentity) error {
	if len(expected) == 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.Join(sharedhost.ErrCleanupIncomplete, err)
	}
	defer f.Close()
	type observation struct{ header, flags bool }
	observed := make([]observation, len(expected))
	indexes := make(map[string]int, len(expected))
	for i, mapping := range expected {
		if len(mapping.Permissions) != 4 || mapping.Permissions[3] != 's' || mapping.Inode == 0 {
			return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("shared mapping proof has invalid native identity"))
		}
		if _, exists := indexes[mapping.Range]; exists {
			return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("ambiguous shared mapping inventory"))
		}
		indexes[mapping.Range] = i
	}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 1<<20)
	current := -1
	for scan.Scan() {
		if err = ctx.Err(); err != nil {
			return errors.Join(sharedhost.ErrCleanupIncomplete, err)
		}
		fields := strings.Fields(scan.Text())
		if len(fields) == 0 {
			continue
		}
		if strings.Contains(fields[0], "-") {
			if current >= 0 && !observed[current].flags {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("shared mapping lacks VmFlags"))
			}
			header, e := parseNativeMappingHeader(scan.Text())
			if e != nil {
				return errors.Join(sharedhost.ErrCleanupIncomplete, e)
			}
			current = -1
			if index, found := indexes[header.Range]; found {
				if observed[index].header || header != expected[index] {
					return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("smaps header differs from exact shared mapping identity"))
				}
				observed[index].header = true
				current = index
			}
			continue
		}
		if current < 0 || fields[0] != "VmFlags:" {
			continue
		}
		if observed[current].flags || len(fields) < 2 {
			return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("shared mapping has ambiguous or empty VmFlags"))
		}
		rd, wr, ex, ms, mw := false, false, false, false, false
		for i, flag := range fields[1:] {
			if len(flag) != 2 || flag[0] < 'a' || flag[0] > 'z' || flag[1] < 'a' || flag[1] > 'z' {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("malformed shared mapping VmFlags"))
			}
			for _, prior := range fields[1 : i+1] {
				if flag == prior {
					return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("duplicate shared mapping capability"))
				}
			}
			switch flag {
			case "rd":
				rd = true
			case "wr":
				wr = true
			case "ex":
				ex = true
			case "ms":
				ms = true
			case "mw":
				mw = true
			}
		}
		permissions := expected[current].Permissions
		if rd != (permissions[0] == 'r') || wr != (permissions[1] == 'w') || ex != (permissions[2] == 'x') || !ms {
			return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("shared mapping capabilities disagree with native header"))
		}
		if wr || mw {
			return errors.Join(sharedhost.ErrCleanupIncomplete, errSharedMappingWritable)
		}
		observed[current].flags = true
	}
	if err = scan.Err(); err != nil {
		return errors.Join(sharedhost.ErrCleanupIncomplete, err)
	}
	for _, entry := range observed {
		if !entry.header || !entry.flags {
			return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("exact shared mapping VmFlags are unavailable"))
		}
	}
	return nil
}
