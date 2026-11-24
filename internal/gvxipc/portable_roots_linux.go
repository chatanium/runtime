//go:build linux

package gvxipc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

type guestMountDir struct {
	file    *os.File
	stat    unix.Stat_t
	fs      unix.Statfs_t
	mountID uint64
}

func describeGuestMountDir(f *os.File) (d guestMountDir, err error) {
	d.file = f
	fd := int(f.Fd())
	if err = unix.Fstat(fd, &d.stat); err != nil {
		return d, err
	}
	if d.stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return d, errors.New("mount pin is not a directory")
	}
	if err = unix.Fstatfs(fd, &d.fs); err != nil {
		return d, err
	}
	var st unix.Statx_t
	if err = unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st); err != nil {
		return d, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 || st.Mnt_id == 0 {
		return d, errors.New("missing mount identity for directory pin")
	}
	d.mountID = st.Mnt_id
	return d, nil
}

func guestDirAttrs(d *guestMountDir) gvxcontract.RootAttrs {
	return gvxcontract.RootAttrs{UID: d.stat.Uid, GID: d.stat.Gid, Mode: d.stat.Mode & 07777}
}

// The procfs magic link resolves from the pinned FD even after the original
// pathname is covered. Check its identity before passing it to mount(2).
func guestMountFDPath(d *guestMountDir) (string, error) {
	path := "/proc/self/fd/" + strconv.FormatUint(uint64(d.file.Fd()), 10)
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", err
	}
	if st.Dev != d.stat.Dev || st.Ino != d.stat.Ino || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", errors.New("procfs FD link does not resolve to pinned directory")
	}
	return path, nil
}

type expectedGuestMount struct {
	name, fsType string
	mountID, dev uint64
	readOnly     bool
	secure       bool // nodev, nosuid and noexec are mandatory for /dev/shm
}

func (d *guestMountDir) mountAt(name, fsType string) expectedGuestMount {
	return expectedGuestMount{name: name, fsType: fsType, mountID: d.mountID, dev: uint64(d.stat.Dev)}
}

func verifyGuestMounts(proc *os.File, expected ...expectedGuestMount) error {
	// proc is pinned. Its numeric, kernel-owned process directory avoids
	// resolving any symlink supplied by the image when opening mountinfo.
	pid, err := unix.Openat(int(proc.Fd()), strconv.Itoa(os.Getpid()), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(pid)
	fd, err := unix.Openat(pid, "mountinfo", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "guest-mountinfo")
	defer f.Close()
	bounded := &io.LimitedReader{R: f, N: 64 << 10}
	scan := bufio.NewScanner(bounded)
	scan.Buffer(make([]byte, 4096), 16<<10)
	seen := make([]bool, len(expected))
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 10 {
			return errors.New("invalid guest mount record")
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return err
		}
		location := fields[4]
		for _, root := range [...]string{gvxcontract.PortablePersistentPath, gvxcontract.PortableScratchPath, gvxcontract.PortableTmpPath, gvxcontract.PortableShmPath} {
			if strings.HasPrefix(location, root) && len(location) > len(root) && location[len(root)] == '/' {
				return fmt.Errorf("guest mount below %s", root)
			}
		}
		for i, want := range expected {
			if id != want.mountID {
				continue
			}
			// A private mount has no propagation tags. Requiring the
			// separator immediately after the options also rejects slave,
			// shared and unbindable mounts.
			if seen[i] || location != want.name || fields[6] != "-" || (want.fsType != "" && fields[7] != want.fsType) {
				return fmt.Errorf("unexpected or nonprivate guest mount at %s", want.name)
			}
			if fields[2] != strconv.FormatUint(uint64(unix.Major(want.dev)), 10)+":"+strconv.FormatUint(uint64(unix.Minor(want.dev)), 10) {
				return fmt.Errorf("mount device mismatch at %s", want.name)
			}
			options := fields[5]
			if want.readOnly != hasMountOption(options, "ro") || want.readOnly == hasMountOption(options, "rw") {
				return fmt.Errorf("wrong readonly state for guest mount at %s", want.name)
			}
			if want.secure && (!hasMountOption(options, "nodev") || !hasMountOption(options, "nosuid") || !hasMountOption(options, "noexec")) {
				return fmt.Errorf("unsafe guest shared-memory mount at %s", want.name)
			}
			seen[i] = true
		}
	}
	if err = scan.Err(); err != nil {
		return err
	}
	if bounded.N == 0 {
		return errors.New("guest mount evidence exceeds bounds")
	}
	for i, ok := range seen {
		if !ok {
			return fmt.Errorf("missing mount evidence at %s", expected[i].name)
		}
	}
	return nil
}

func hasMountOption(options, option string) bool {
	for opt := range strings.SplitSeq(options, ",") {
		if opt == option {
			return true
		}
	}
	return false
}

func portableShmSpec(approved, page int64, uid, gid uint32) (int64, gvxcontract.RootAttrs, uintptr, error) {
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
	if page <= 0 || approved < 0 || approved%page != 0 {
		return 0, gvxcontract.RootAttrs{}, 0, errors.New("approved /dev/shm limit is not a guest page multiple")
	}
	if approved == 0 {
		// size=0 means unlimited for a tmpfs. Hide the engine's default
		// tmpfs under an inaccessible read-only mount with no usable space.
		return page, gvxcontract.RootAttrs{}, flags | unix.MS_RDONLY, nil
	}
	return approved, gvxcontract.RootAttrs{UID: uid, GID: gid, Mode: 0700}, flags, nil
}

func initializePortableRoots(v gvxcontract.BridgeInit, p gvxcontract.RootInitPayload, final *[3]guestMountDir) (result gvxcontract.RootInitResult, pins []*os.File, err error) {
	ruid, euid, suid := unix.Getresuid()
	rgid, egid, sgid := unix.Getresgid()
	if os.Getpid() != 1 || ruid != 0 || euid != 0 || suid != 0 || rgid != 0 || egid != 0 || sgid != 0 {
		return result, nil, errors.New("portable bridge must be the guest init at UID:GID 0:0")
	}
	var caps [2]unix.CapUserData
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err = unix.Capget(&hdr, &caps[0]); err != nil {
		return result, nil, err
	}
	if caps[0].Effective&(1<<unix.CAP_SYS_ADMIN) == 0 {
		return result, nil, errors.New("trusted guest init lacks CAP_SYS_ADMIN")
	}
	page := int64(os.Getpagesize())
	shmSize, shmAttrs, shmFlags, err := portableShmSpec(p.PortableLimits.ShmBytes, page, v.UID, v.GID)
	if err != nil {
		return result, nil, err
	}

	files := make([]*os.File, 0, 12)
	defer func() {
		if err != nil {
			err = errors.Join(err, closeRootFDs(files))
		}
	}()
	pin := func(name string) (guestMountDir, error) {
		f, e := openDirectory(name)
		if e != nil {
			return guestMountDir{}, fmt.Errorf("pin guest directory %s: %w", name, e)
		}
		files = append(files, f)
		d, e := describeGuestMountDir(f)
		if e != nil {
			return guestMountDir{}, fmt.Errorf("inspect guest directory %s: %w", name, e)
		}
		return d, nil
	}
	root, err := pin("/")
	if err != nil {
		return result, nil, err
	}
	proc, err := pin("/proc")
	if err != nil {
		return result, nil, err
	}
	persistent, err := pin(gvxcontract.PortablePersistentPath)
	if err != nil {
		return result, nil, err
	}
	scratch, err := pin(gvxcontract.PortableScratchPath)
	if err != nil {
		return result, nil, err
	}
	tmp, err := pin(gvxcontract.PortableTmpPath)
	if err != nil {
		return result, nil, err
	}
	shm, err := pin(gvxcontract.PortableShmPath)
	if err != nil {
		return result, nil, err
	}
	if proc.fs.Type != unix.PROC_SUPER_MAGIC || persistent.fs.Type != unix.EXT4_SUPER_MAGIC || scratch.fs.Type != unix.EXT4_SUPER_MAGIC || shm.fs.Type != unix.TMPFS_MAGIC ||
		persistent.stat.Dev == scratch.stat.Dev || tmp.mountID != root.mountID || guestDirAttrs(&scratch) != (gvxcontract.RootAttrs{Mode: 0755}) {
		return result, nil, errors.New("unexpected portable guest filesystem layout")
	}
	rootMount := root.mountAt("/", "")
	rootMount.readOnly = true
	procMount := proc.mountAt("/proc", "proc")
	dataMount := persistent.mountAt(gvxcontract.PortablePersistentPath, "ext4")
	if err = verifyGuestMounts(proc.file, rootMount, procMount, dataMount,
		scratch.mountAt(gvxcontract.PortableScratchPath, "ext4"), shm.mountAt(gvxcontract.PortableShmPath, "tmpfs")); err != nil {
		return result, nil, err
	}
	if _, err = initializeRoot(persistent.file, p.Roots[0], nil); err != nil {
		return result, nil, fmt.Errorf("persistent root: %w", err)
	}

	makeScratchChild := func(name string, entry gvxcontract.RootInitEntry) (guestMountDir, error) {
		parent := int(scratch.file.Fd())
		if e := unix.Mkdirat(parent, name, entry.Pre.Mode); e != nil {
			return guestMountDir{}, e
		}
		fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if e != nil {
			return guestMountDir{}, e
		}
		f := os.NewFile(uintptr(fd), name)
		files = append(files, f)
		d, e := describeGuestMountDir(f)
		if e != nil {
			return guestMountDir{}, e
		}
		if d.stat.Dev != scratch.stat.Dev || d.stat.Ino == scratch.stat.Ino || d.mountID != scratch.mountID || guestDirAttrs(&d) != entry.Pre {
			return guestMountDir{}, errors.New("scratch child is not a fresh directory on the pinned ext4lite mount")
		}
		if _, e = initializeRoot(f, entry, unix.Fsync); e != nil {
			return guestMountDir{}, e
		}
		return d, nil
	}
	tmpSource, err := makeScratchChild("tmp", p.Roots[2])
	if err != nil {
		return result, nil, fmt.Errorf("create scratch tmp: %w", err)
	}
	workSource, err := makeScratchChild("work", p.Roots[1])
	if err != nil {
		return result, nil, fmt.Errorf("create scratch work: %w", err)
	}
	if workSource.stat.Ino == tmpSource.stat.Ino {
		return result, nil, errors.New("scratch work and tmp alias the same inode")
	}
	if err = unix.Fsync(int(scratch.file.Fd())); err != nil {
		return result, nil, fmt.Errorf("sync scratch directory: %w", err)
	}

	bind := func(source, target *guestMountDir, mountpoint string) error {
		from, e := guestMountFDPath(source)
		if e != nil {
			return e
		}
		to, e := guestMountFDPath(target)
		if e != nil {
			return e
		}
		if e = unix.Mount(from, to, "", unix.MS_BIND, ""); e != nil {
			return fmt.Errorf("bind guest %s: %w", mountpoint, e)
		}
		return nil
	}
	// Mount work over the scratch volume only after tmp is accessible; the
	// parent and both sources stay pinned even after the first bind.
	if err = bind(&tmpSource, &tmp, gvxcontract.PortableTmpPath); err != nil {
		return result, nil, err
	}
	if err = bind(&workSource, &scratch, gvxcontract.PortableScratchPath); err != nil {
		return result, nil, err
	}
	shmTarget, err := guestMountFDPath(&shm)
	if err != nil {
		return result, nil, err
	}
	options := fmt.Sprintf("size=%d,mode=%04o,uid=%d,gid=%d", shmSize, shmAttrs.Mode, shmAttrs.UID, shmAttrs.GID)
	if err = unix.Mount("tmpfs", shmTarget, "tmpfs", shmFlags, options); err != nil {
		return result, nil, fmt.Errorf("constrain guest /dev/shm: %w", err)
	}

	shmFinal, err := pin(gvxcontract.PortableShmPath)
	if err != nil {
		return result, nil, err
	}
	if shmFinal.mountID == shm.mountID || shmFinal.fs.Type != unix.TMPFS_MAGIC || guestDirAttrs(&shmFinal) != shmAttrs ||
		int64(shmFinal.fs.Bsize) != page || int64(shmFinal.fs.Frsize) != page || shmFinal.fs.Blocks != uint64(shmSize/page) {
		return result, nil, errors.New("guest /dev/shm size, identity or mode readback mismatch")
	}
	result = gvxcontract.RootInitResult{Digest: v.Roots.Digest, Nonce: p.Nonce, Results: make([]gvxcontract.RootStepResult, 0, len(p.Roots))}
	shmMount := shmFinal.mountAt(gvxcontract.PortableShmPath, "tmpfs")
	shmMount.readOnly = shmFlags&unix.MS_RDONLY != 0
	shmMount.secure = true
	mounts := [6]expectedGuestMount{rootMount, procMount, shmMount}
	sources := [...]*guestMountDir{&persistent, &workSource, &tmpSource}
	for i, entry := range p.Roots {
		d, e := pin(entry.Mountpoint)
		if e != nil {
			return gvxcontract.RootInitResult{}, nil, e
		}
		src := sources[i]
		attrs := guestDirAttrs(&d)
		if d.stat.Dev != src.stat.Dev || d.stat.Ino != src.stat.Ino || attrs != entry.Target ||
			(i == 0 && d.mountID != src.mountID) || (i != 0 && d.mountID == src.mountID) {
			return gvxcontract.RootInitResult{}, nil, fmt.Errorf("portable %s root identity or mode readback mismatch", entry.RootID)
		}
		final[i] = d
		mounts[3+i] = d.mountAt(entry.Mountpoint, "ext4")
		result.Results = append(result.Results, gvxcontract.RootStepResult{RootID: entry.RootID, Step: 2, Observed: attrs})
	}
	if err = verifyGuestMounts(proc.file, mounts[:]...); err != nil {
		return gvxcontract.RootInitResult{}, nil, err
	}
	// The host may promote a new image to retained immediately on READY.
	// Flush ext4lite's journal and backing file before making that promise.
	if err = unix.Syncfs(int(final[0].file.Fd())); err != nil {
		return gvxcontract.RootInitResult{}, nil, fmt.Errorf("sync persistent guest filesystem: %w", err)
	}
	return result, files, nil
}

// verifyPortableRootAccess walks the original paths as the module's identity,
// rather than inheriting the root bridge's ability to traverse their parents.
func verifyPortableRootAccess(entries []gvxcontract.RootInitEntry, final *[3]guestMountDir) error {
	for i, entry := range entries {
		f, err := openDirectoryWithFlags(entry.Mountpoint, unix.O_PATH)
		if err != nil {
			return fmt.Errorf("open %s as module: %w", entry.Mountpoint, err)
		}
		d, err := describeGuestMountDir(f)
		if err == nil {
			if d.stat.Dev != final[i].stat.Dev || d.stat.Ino != final[i].stat.Ino ||
				d.mountID != final[i].mountID || guestDirAttrs(&d) != entry.Target ||
				d.fs.Flags&unix.ST_RDONLY != 0 {
				err = errors.New("initialized root identity, mode or writability changed")
			} else {
				// Do not alter persistent data to prove access. Check write
				// and search on the exact FD with effective credentials.
				err = unix.Faccessat2(int(f.Fd()), "", unix.W_OK|unix.X_OK, unix.AT_EMPTY_PATH|unix.AT_EACCESS)
			}
		}
		if err = errors.Join(err, f.Close()); err != nil {
			return fmt.Errorf("check %s as module: %w", entry.Mountpoint, err)
		}
	}
	return nil
}

func closeRootFDs(files []*os.File) error {
	var err error
	for _, f := range files {
		if e := f.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}
	return err
}
