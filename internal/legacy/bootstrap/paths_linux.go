//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func provisionDirectories(ctx context.Context, s *host.Store, p ApprovedInitPlan) error {
	var paths []string
	for _, object := range p.Objects {
		if object.Kind == "directory" && object.Action == "create" {
			paths = append(paths, object.Identity)
		}
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) < len(paths[j]) })
	for _, path := range paths {
		if record, e := ownedRecord(ctx, s, "directory", path); e == nil {
			if deferCreate, err := oldBootDirectoryMissing(ctx, s, host.InstallationManifest{Paths: p.Paths}, path); err != nil {
				return err
			} else if deferCreate {
				continue
			}
			if e = matchRecord(record); e != nil {
				return e
			}
			m, e := s.Installation(ctx)
			if e != nil {
				return e
			}
			if e = recordBootDirectory(ctx, s, m, path, record.ID); e != nil {
				return e
			}
			continue
		}
		mode, gid := uint32(0700), uint32(0)
		switch path {
		case p.Paths.EngineRoot:
			mode = 0755
		case p.Paths.StorageRoot, p.Paths.RunRoot, filepath.Join(p.Paths.RunRoot, "instances"):
			mode = 0710
			gid = p.Identities.App.GID
		}
		if e := trustedPath(path, true); e != nil {
			return e
		}
		if _, e := os.Lstat(path); e == nil {
			return errors.New("existing directory is not product-owned")
		} else if !os.IsNotExist(e) {
			return e
		}
		desired := host.ProvisionProperties{Path: path, Mode: mode, GID: gid, ProductCreated: true}
		id, e := initIntent(ctx, s, "directory", path, desired, false)
		if e != nil {
			return e
		}
		if e = os.Mkdir(path, os.FileMode(mode)); e != nil {
			return e
		}
		if e = os.Chown(path, 0, int(gid)); e != nil {
			return e
		}
		if e = os.Chmod(path, os.FileMode(mode)); e != nil {
			return e
		}
		if e = observePath(ctx, s, id, path, desired); e != nil {
			return e
		}
		m, e := s.Installation(ctx)
		if e != nil {
			return e
		}
		if e = recordBootDirectory(ctx, s, m, path, id); e != nil {
			return e
		}
	}
	for _, path := range []string{p.Paths.EngineRoot, p.Paths.StorageRoot, p.Paths.RunRoot} {
		if deferred, e := oldBootDirectoryMissing(ctx, s, host.InstallationManifest{Paths: p.Paths}, path); e != nil {
			return e
		} else if deferred {
			continue
		}
		if e := validateTraversal(path, p.Identities.App); e != nil {
			return e
		}
	}
	return nil
}
func validateTraversal(path string, identity host.NumericIdentity) error {
	for p := path; p != "/"; p = filepath.Dir(p) {
		var st unix.Stat_t
		if e := unix.Lstat(p, &st); e != nil {
			return e
		}
		mode := st.Mode
		if mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("runtime path ancestor is not directory")
		}
		can := mode&0001 != 0 || st.Gid == identity.GID && mode&0010 != 0 || st.Uid == identity.UID && mode&0100 != 0
		if !can {
			return errors.New("approved runtime identity cannot traverse protected ancestor")
		}
	}
	return nil
}
func validateAccountShell(name string) error {
	raw, e := os.ReadFile("/etc/passwd")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == name {
			if fields[5] != "/nonexistent" || fields[6] != "/usr/sbin/nologin" {
				return errors.New("dedicated account must have no login or home")
			}
			return nil
		}
	}
	return errors.New("dedicated account is not a static local identity")
}
func validateUnsharedGroup(name, gid string) error {
	raw, e := os.ReadFile("/etc/group")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 4 && fields[0] == name && fields[2] == gid {
			for _, member := range strings.Split(fields[3], ",") {
				if member != "" && member != name {
					return errors.New("product group has foreign members")
				}
			}
			return nil
		}
	}
	return errors.New("dedicated group is not static local identity")
}
