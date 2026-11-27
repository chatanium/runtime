//go:build linux

package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

// These objects are host infrastructure, not exclusive installation property.
// The approved initializer journals shared-network-anchor before calling the
// mutation helper. Per-installation purge must preserve all three paths.
type NetworkAnchorObject struct {
	Path       string              `json:"path"`
	Exists     bool                `json:"exists"`
	Properties ProvisionProperties `json:"properties"`
}

func networkAnchorPaths() []string {
	return []string{filepath.Dir(NetworkIPAMRoot), NetworkIPAMRoot, NetworkIPAMLockPath}
}
func networkAnchorMode(path string) (uint32, bool) {
	switch path {
	case filepath.Dir(NetworkIPAMRoot):
		return 0755, true
	case NetworkIPAMRoot:
		return 0700, true
	case NetworkIPAMLockPath:
		return 0600, false
	}
	return 0, false
}
func networkAnchorParent(path string) error {
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		current = filepath.Join(current, part)
		var st unix.Stat_t
		if err := unix.Lstat(current, &st); err != nil {
			if errors.Is(err, unix.ENOENT) && (current == filepath.Dir(NetworkIPAMRoot) || current == NetworkIPAMRoot) {
				return nil
			}
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return errors.New("shared network anchor has an untrusted ancestor")
		}
	}
	return nil
}
func inspectNetworkAnchor(ctx context.Context, path string) (NetworkAnchorObject, error) {
	if err := ctx.Err(); err != nil {
		return NetworkAnchorObject{}, err
	}
	mode, directory := networkAnchorMode(path)
	if mode == 0 {
		return NetworkAnchorObject{}, errors.New("unknown shared network anchor path")
	}
	if err := networkAnchorParent(path); err != nil {
		return NetworkAnchorObject{}, err
	}
	p := ProvisionProperties{Path: path, Parent: filepath.Dir(path), UID: 0, GID: 0, Mode: mode}
	if !directory {
		p.Digest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(NetworkIPAMMarker)))
	}
	object := NetworkAnchorObject{Path: path, Properties: p}
	var st unix.Stat_t
	err := unix.Lstat(path, &st)
	if errors.Is(err, unix.ENOENT) {
		return object, nil
	}
	if err != nil {
		return object, err
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 || st.Mode&07000 != 0 {
		return object, errors.New("shared network anchor ownership/mode is untrusted")
	}
	if directory {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || path == NetworkIPAMRoot && st.Mode&0777 != 0700 {
			return object, errors.New("shared network anchor is not the protected directory")
		}
	} else {
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Size != int64(len(NetworkIPAMMarker)) {
			return object, errors.New("shared network lock has unsupported shape")
		}
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return object, e
		}
		f := os.NewFile(uintptr(fd), path)
		var observed unix.Stat_t
		e = unix.Fstat(fd, &observed)
		if e != nil || observed.Ino != st.Ino || observed.Dev != st.Dev {
			f.Close()
			return object, errors.New("shared network lock identity changed during inspection")
		}
		var marker [len(NetworkIPAMMarker)]byte
		_, e = f.ReadAt(marker[:], 0)
		e = errors.Join(e, f.Close())
		if e != nil {
			return object, e
		}
		if string(marker[:]) != NetworkIPAMMarker {
			return object, errors.New("shared network lock marker is not supported")
		}
	}
	object.Exists = true
	object.Properties.Mode = st.Mode & 0777
	object.Properties.Dev = uint64(st.Dev)
	object.Properties.Ino = st.Ino
	return object, nil
}
func InspectNetworkAnchors(ctx context.Context) ([]NetworkAnchorObject, error) {
	var out []NetworkAnchorObject
	for _, path := range networkAnchorPaths() {
		object, err := inspectNetworkAnchor(ctx, path)
		if err != nil {
			return nil, err
		}
		out = append(out, object)
	}
	return out, nil
}

// ProvisionNetworkAnchor accepts only a fixed object and its exact approved
// inspection. It never overwrites an existing inode, repairs ownership, or
// recreates missing READY state. The initializer is responsible for rejecting
// such recovery before dispatch and for journaling this submission first.
func ProvisionNetworkAnchor(ctx context.Context, expected NetworkAnchorObject) (ObjectObservation, error) {
	if os.Geteuid() != 0 {
		return ObjectObservation{}, errors.New("shared network anchor provisioning requires root")
	}
	actual, err := inspectNetworkAnchor(ctx, expected.Path)
	if err != nil {
		return ObjectObservation{}, err
	}
	if !networkAnchorEqual(actual, expected) {
		return ObjectObservation{}, errors.New("shared network anchor differs from approved inspection")
	}
	if !actual.Exists {
		mode, directory := networkAnchorMode(expected.Path)
		if directory {
			if err = os.Mkdir(expected.Path, os.FileMode(mode)); err != nil {
				return ObjectObservation{}, err
			}
			fd, e := unix.Open(expected.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if e != nil {
				return ObjectObservation{}, e
			}
			e = unix.Fchown(fd, 0, 0)
			if e == nil {
				e = unix.Fchmod(fd, mode)
			}
			if e == nil {
				e = unix.Fsync(fd)
			}
			e = errors.Join(e, unix.Close(fd))
			if e != nil {
				return ObjectObservation{}, e
			}
		} else {
			// Publish a complete marker with link(O_EXCL semantics), never truncate or
			// replace a lock inode: existing waiters must remain on the same flock.
			f, e := os.CreateTemp(NetworkIPAMRoot, ".anchor-")
			if e != nil {
				return ObjectObservation{}, e
			}
			temporary := f.Name()
			defer os.Remove(temporary)
			if e = f.Chmod(0600); e == nil {
				_, e = f.WriteString(NetworkIPAMMarker)
			}
			if e == nil {
				e = f.Sync()
			}
			e = errors.Join(e, f.Close())
			if e != nil {
				return ObjectObservation{}, e
			}
			if e = unix.Linkat(unix.AT_FDCWD, temporary, unix.AT_FDCWD, expected.Path, 0); e != nil {
				return ObjectObservation{}, e
			}
		}
		parent, e := os.Open(filepath.Dir(expected.Path))
		if e != nil {
			return ObjectObservation{}, e
		}
		if e = errors.Join(parent.Sync(), parent.Close()); e != nil {
			return ObjectObservation{}, e
		}
		actual, err = inspectNetworkAnchor(ctx, expected.Path)
		if err != nil {
			return ObjectObservation{}, err
		}
		if !actual.Exists {
			return ObjectObservation{}, errors.New("created shared network anchor absent on readback")
		}
	}
	actual.Properties.ProductCreated = !expected.Exists
	raw, err := json.Marshal(actual.Properties)
	if err != nil {
		return ObjectObservation{}, err
	}
	return ObjectObservation{Identity: expected.Path, Attributes: raw}, nil
}
func networkAnchorEqual(actual, expected NetworkAnchorObject) bool {
	if actual.Path != expected.Path || actual.Exists != expected.Exists {
		return false
	}
	actual.Properties.ProductCreated = false
	expected.Properties.ProductCreated = false
	return reflect.DeepEqual(actual.Properties, expected.Properties)
}
