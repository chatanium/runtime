//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
)

type DevelopmentLockInfo struct {
	Version uint32 `json:"version"`
	Path    string `json:"path"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Mode    uint32 `json:"mode"`
}

func InspectDevelopmentLock(ctx context.Context, id RuntimeInstallationID) (DevelopmentLockInfo, error) {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return DevelopmentLockInfo{}, e
	}
	defer metadata.Close()
	return inspectDevelopmentLock(ctx, metadata)
}
func inspectDevelopmentLock(ctx context.Context, metadata *host.MetadataReader) (DevelopmentLockInfo, error) {
	var info DevelopmentLockInfo
	m, e := metadata.Installation(ctx)
	if e != nil {
		return info, e
	}
	path := filepath.Join(m.Paths.Installation, "dev-watch.lock")
	if e = trustedPath(path, false); e != nil {
		return info, e
	}
	var st unix.Stat_t
	if e = unix.Lstat(path, &st); e != nil {
		return info, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size != 0 || st.Uid != 0 || st.Gid != m.Identities.App.GID || st.Mode&07777 != 0440 {
		return info, errors.New("development coordination lock native properties differ")
	}
	records, e := metadata.ObjectProvisions(ctx, "config", path)
	if e != nil {
		return info, e
	}
	found := false
	for _, record := range records {
		if record.State != "OBSERVED" || record.CleanupState == "COMPLETE" || !record.ProductCreated || record.ExistedBefore {
			continue
		}
		var p host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return info, e
		}
		if p.Path == path && p.Dev == uint64(st.Dev) && p.Ino == st.Ino && p.Mode == 0440 && p.UID == 0 && p.GID == st.Gid && p.SizeBytes == 0 {
			if found {
				return info, errors.New("ambiguous development lock receipt")
			}
			found = true
		}
	}
	if !found {
		return info, errors.New("development coordination lock has no exact observed owned receipt")
	}
	return DevelopmentLockInfo{Version: 1, Path: path, Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: 0440}, nil
}
func lockDevelopmentForPurge(ctx context.Context, id RuntimeInstallationID) (*os.File, error) {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return nil, e
	}
	defer metadata.Close()
	m, e := metadata.Installation(ctx)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(m.Paths.Installation, "dev-watch.lock")
	if _, e = os.Lstat(path); os.IsNotExist(e) {
		return nil, nil
	} else if e != nil {
		return nil, e
	}
	info, e := inspectDevelopmentLock(ctx, metadata)
	if e != nil {
		return nil, e
	}
	fd, e := unix.Open(info.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(fd), info.Path)
	fail := func(e error) (*os.File, error) { file.Close(); return nil, e }
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fail(errors.Join(errors.New("active development coordination prevents purge"), e))
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return fail(e)
	}
	if uint64(st.Dev) != info.Device || st.Ino != info.Inode {
		return fail(errors.New("development lock changed during purge fencing"))
	}
	var canonical unix.Stat_t
	if e = unix.Lstat(info.Path, &canonical); e != nil {
		return fail(e)
	}
	if canonical.Dev != st.Dev || canonical.Ino != st.Ino {
		return fail(errors.New("development lock canonical identity changed"))
	}
	processes, e := os.ReadDir("/proc")
	if e != nil {
		return fail(e)
	}
	for _, process := range processes {
		if _, e = strconv.Atoi(process.Name()); e != nil {
			continue
		}
		directory := filepath.Join("/proc", process.Name(), "fd")
		entries, e := os.ReadDir(directory)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return fail(e)
		}
		for _, entry := range entries {
			if process.Name() == strconv.Itoa(os.Getpid()) && entry.Name() == strconv.Itoa(fd) {
				continue
			}
			var other unix.Stat_t
			e = unix.Stat(filepath.Join(directory, entry.Name()), &other)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return fail(e)
			}
			if other.Dev == st.Dev && other.Ino == st.Ino {
				return fail(errors.New("development coordination lock has an outstanding descriptor or waiter"))
			}
		}
	}
	return file, nil
}
