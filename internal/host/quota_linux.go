//go:build linux

package host

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These layouts and commands are the Linux UAPI in linux/dqblk_xfs.h and
// linux/fs.h, not xfs_quota output parsing. XFS accounts 512-byte basic blocks.
type diskQuota struct {
	Version                                    int8
	Flags                                      int8
	FieldMask                                  uint16
	ID                                         uint32
	BlockHard, BlockSoft, InodeHard, InodeSoft uint64
	Blocks, Inodes                             uint64
	ITimer, BTimer                             int32
	IWarns, BWarns                             uint16
	TimerHigh                                  [4]int8
	RTBlockHard, RTBlockSoft, RTBlocks         uint64
	RTTimer                                    int32
	RTWarns                                    uint16
	Pad3                                       int16
	Pad4                                       [8]byte
}
type fsxattr struct {
	Flags, ExtSize, Nextents, ProjectID, CowExtSize uint32
	Pad                                             [8]byte
}
type quotaFS struct {
	root   *os.File
	device uint64
	// Immutable after constructor preflight, before this object is published.
	blockBytes int64
}

func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, invalid("host directory must be canonical absolute path")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
func trustedDirectory(path string) (*os.File, error) {
	// Every ancestor must be trusted too: a root-owned child below a writable
	// home/tmp directory could otherwise be renamed after this check.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		ancestor, err := openDirectory(parent)
		if err != nil {
			return nil, err
		}
		var st unix.Stat_t
		err = unix.Fstat(int(ancestor.Fd()), &st)
		ancestor.Close()
		if err != nil {
			return nil, err
		}
		if st.Uid != 0 || st.Mode&0022 != 0 {
			return nil, errors.New("host directory ancestor is not root-owned and immutable to untrusted users")
		}
		if parent == "/" {
			break
		}
	}
	f, err := openDirectory(path)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Uid != 0 || st.Mode&0022 != 0 {
		f.Close()
		return nil, fmt.Errorf("host root directory must be root-owned and not group/other writable")
	}
	return f, nil
}
func newQuotaFS(storage, ipc string) (*quotaFS, error) {
	root, err := trustedDirectory(storage)
	if err != nil {
		return nil, prerequisite(err)
	}
	other, err := trustedDirectory(ipc)
	if err != nil {
		root.Close()
		return nil, prerequisite(err)
	}
	defer other.Close()
	var a, b unix.Stat_t
	var fs unix.Statfs_t
	if err = unix.Fstat(int(root.Fd()), &a); err == nil {
		err = unix.Fstat(int(other.Fd()), &b)
	}
	if err == nil {
		err = unix.Fstatfs(int(root.Fd()), &fs)
	}
	if err != nil {
		root.Close()
		return nil, prerequisite(err)
	}
	if a.Dev != b.Dev || fs.Type != unix.XFS_SUPER_MAGIC {
		root.Close()
		return nil, prerequisite(errors.New("storage and IPC require one XFS filesystem"))
	}
	q := &quotaFS{root: root, device: a.Dev}
	if err = q.preflight(); err != nil {
		root.Close()
		return nil, prerequisite(err)
	}
	return q, nil
}
func (q *quotaFS) command(op uint32, id uint32, p unsafe.Pointer) error {
	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL_FD, q.root.Fd(), uintptr(((uint32('X')<<8|op)<<8)|2), uintptr(id), uintptr(p), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func (q *quotaFS) preflight() error {
	// qstatv v1 is 160 bytes; flags occupy bytes 2-3 in the UAPI.
	var stat [160]byte
	stat[0] = 1
	if err := q.command(8, 0, unsafe.Pointer(&stat[0])); err != nil {
		return err
	}
	flags := uint16(stat[2]) | uint16(stat[3])<<8
	if flags&0x30 != 0x30 {
		return errors.New("XFS project accounting AND enforcement required")
	}
	// XFS_IOC_FSGEOMETRY_V1, stable Linux xfs_fs.h UAPI (112-byte ABI).
	// XFS realtime quotas have a separate accounting pool. Reject realtime
	// filesystems rather than silently permit a second byte budget.
	var geometry [112]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, q.root.Fd(), 0x80705864, uintptr(unsafe.Pointer(&geometry[0])))
	if errno != 0 {
		return errno
	}
	if binary.NativeEndian.Uint64(geometry[40:48]) != 0 {
		return errors.New("managed XFS filesystem must not have a realtime allocation device")
	}
	blockBytes := int64(binary.NativeEndian.Uint32(geometry[0:4]))
	if blockBytes < 512 || blockBytes%512 != 0 {
		return errors.New("XFS data block size is not an integral quota basic-block multiple")
	}
	if q.blockBytes == 0 {
		q.blockBytes = blockBytes
	} else if q.blockBytes != blockBytes {
		return errors.New("managed XFS data block geometry changed")
	}
	return nil
}
func (q *quotaFS) get(id uint32) (diskQuota, error) {
	d := diskQuota{Version: 1, Flags: 2, ID: id}
	err := q.command(3, id, unsafe.Pointer(&d))
	return d, err
}
func (q *quotaFS) unused(id uint32) error {
	d, err := q.get(id)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if d.Blocks != 0 || d.Inodes != 0 || d.RTBlocks != 0 || d.BlockHard != 0 || d.BlockSoft != 0 || d.InodeHard != 0 || d.InodeSoft != 0 || d.RTBlockHard != 0 || d.RTBlockSoft != 0 {
		return errors.New("allocated project ID collides with existing filesystem quota")
	}
	return nil
}
func (q *quotaFS) limit(id uint32, bytes, inodes int64) error {
	expected, err := q.projectLimits(id, bytes, inodes)
	if err != nil {
		return err
	}
	d, err := q.get(id)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if d.Blocks > uint64(bytes/512) || d.Inodes > uint64(inodes) || d.RTBlocks != 0 {
		return errors.New("retained data exceeds proposed project limit")
	}
	if err = q.command(4, id, unsafe.Pointer(&expected)); err != nil {
		return err
	}
	return q.verifyLimit(id, bytes, inodes)
}

// XFS reports quota limits in 512-byte basic blocks, but rounds limits to its
// filesystem data-block granularity. Never let that rounding enlarge an
// approved ordinary byte ceiling. A one-filesystem-block realtime guard is
// finite and exact; preflight has already rejected any realtime allocation
// device, so it does not create a second usable storage budget.
func (q *quotaFS) projectLimits(id uint32, bytes, inodes int64) (diskQuota, error) {
	if q.blockBytes < 512 || q.blockBytes%512 != 0 {
		return diskQuota{}, prerequisite(errors.New("validated XFS data-block geometry is required"))
	}
	if id == 0 || bytes <= 0 || bytes%q.blockBytes != 0 || inodes <= 0 {
		return diskQuota{}, invalid(fmt.Sprintf("positive project byte limit must be divisible by XFS data block size %d and inode limit must be positive", q.blockBytes))
	}
	rtGuard := uint64(q.blockBytes / 512)
	blocks := uint64(bytes / 512)
	return diskQuota{
		Version: 1, Flags: 2, FieldMask: 0x3f, ID: id,
		BlockHard: blocks, BlockSoft: blocks,
		InodeHard: uint64(inodes), InodeSoft: uint64(inodes),
		RTBlockHard: rtGuard, RTBlockSoft: rtGuard,
	}, nil
}
func ioctlXattr(f *os.File, cmd uintptr, x *fsxattr) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), cmd, uintptr(unsafe.Pointer(x)))
	if e != 0 {
		return e
	}
	return nil
}
func (q *quotaFS) project(path string, id uint32, create bool) error {
	f, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Dev != q.device {
		return errors.New("project directory changed filesystem")
	}
	var x fsxattr
	if err = ioctlXattr(f, 0x801c581f, &x); err != nil {
		return err
	}
	if x.Flags&(0x1|0x100) != 0 {
		return errors.New("realtime allocation/inheritance is not supported by this storage policy")
	}
	if create {
		if x.ProjectID != 0 && x.ProjectID != id {
			return errors.New("directory belongs to another project")
		}
		x.ProjectID = id
		x.Flags |= 0x200
		if err = ioctlXattr(f, 0x401c5820, &x); err != nil {
			return err
		}
		if err = ioctlXattr(f, 0x801c581f, &x); err != nil {
			return err
		}
	}
	if x.ProjectID != id || x.Flags&0x200 == 0 {
		return errors.New("project inheritance missing")
	}
	return nil
}

// A local observation cadence, not a lifecycle deadline or operator resource limit.
const quotaReclaimPollInterval = 10 * time.Millisecond

func (q *quotaFS) reclaimed(ctx context.Context, id uint32) error {
	if err := ctx.Err(); err != nil {
		return cleanupStep(FailureCleanupQuotaReferences, errors.Join(ErrCleanupIncomplete, err))
	}
	// A successful path unlink is insufficient: open references retain quota.
	// Flush writes once; subsequent iterations only observe reclamation.
	if err := unix.Syncfs(int(q.root.Fd())); err != nil {
		return cleanupStep(FailureCleanupSync, err)
	}
	// Syncfs alone can leave deferred XFS inode inactivation pending:
	// https://github.com/torvalds/linux/commit/01e8f379a4895a9a173391408db4fb49ec91e148
	// A statfs barrier may only expedite that work. Wait for exact zero usage,
	// never for barrier success alone, within the original cleanup context.
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return cleanupStep(FailureCleanupQuotaReferences, errors.Join(ErrCleanupIncomplete, err))
		}
		var filesystem unix.Statfs_t
		if err := unix.Fstatfs(int(q.root.Fd()), &filesystem); err != nil {
			return cleanupStep(FailureCleanupBarrier, err)
		}
		if err := ctx.Err(); err != nil {
			return cleanupStep(FailureCleanupQuotaReferences, errors.Join(ErrCleanupIncomplete, err))
		}
		d, err := q.get(id)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return cleanupStep(FailureCleanupQuotaRead, err)
		}
		if err := ctx.Err(); err != nil {
			return cleanupStep(FailureCleanupQuotaReferences, errors.Join(ErrCleanupIncomplete, err))
		}
		if errors.Is(err, unix.ENOENT) || (d.Blocks == 0 && d.Inodes == 0 && d.RTBlocks == 0) {
			return nil
		}
		// No timer allocation on the ordinary zero-usage fast path.
		if timer == nil {
			timer = time.NewTimer(quotaReclaimPollInterval)
		} else {
			timer.Reset(quotaReclaimPollInterval)
		}
		select {
		case <-ctx.Done():
			return cleanupStep(FailureCleanupQuotaReferences, errors.Join(ErrCleanupIncomplete, ctx.Err()))
		case <-timer.C:
		}
	}
}
func (q *quotaFS) verifyLimit(id uint32, bytes, inodes int64) error {
	expected, err := q.projectLimits(id, bytes, inodes)
	if err != nil {
		return err
	}
	d, err := q.get(id)
	if err != nil {
		return err
	}
	if d.BlockHard != expected.BlockHard || d.BlockSoft != expected.BlockSoft ||
		d.InodeHard != expected.InodeHard || d.InodeSoft != expected.InodeSoft ||
		d.RTBlockHard != expected.RTBlockHard || d.RTBlockSoft != expected.RTBlockSoft || d.RTBlocks != 0 {
		return errors.New("project hard quota enforcement changed")
	}
	return nil
}
