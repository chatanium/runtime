//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

const NetworkIPAMRoot = "/var/lib/chatanium/network-ipam"
const NetworkIPAMLockPath = NetworkIPAMRoot + "/lock"
const NetworkIPAMMarker = "chatanium-gvx-network-ipam:1\n"

type networkAllocation struct {
	Owner               sharedhost.Ownership         `json:"owner"`
	BootID              string            `json:"boot_id"`
	HostInventoryDigest string            `json:"host_inventory_digest"`
	Flows               map[string]string `json:"flows"`
	Record              NetworkRecord     `json:"record"`
	// Exact bounded observations, not merely a deterministic object name, are
	// retained across an owner crash. The prefix remains claimed until CLEANED.
	Rules              map[string]string `json:"rules"`
	Topology           map[string]string `json:"topology"`
	namespacePin       *os.File
	namespacePublished bool
}

func networkTrustedDirectory(path string) error {
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		current = filepath.Join(current, part)
		var st unix.Stat_t
		if err := unix.Lstat(current, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 || (current == path && st.Mode&07777 != 0700) {
			return errors.New("network allocation path is not protected root-owned storage")
		}
		if current == path && st.Gid != 0 {
			return errors.New("network allocation anchor group is not root")
		}
	}
	return nil
}
func networkLock(ctx context.Context) (*os.File, error) {
	if err := networkTrustedDirectory(NetworkIPAMRoot); err != nil {
		return nil, err
	}
	fd, err := unix.Open(NetworkIPAMLockPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "network-ipam-lock")
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Size != int64(len(NetworkIPAMMarker)) {
		f.Close()
		return nil, errors.New("invalid network allocation lock")
	}
	var marker [len(NetworkIPAMMarker)]byte
	if _, err = f.ReadAt(marker[:], 0); err != nil || string(marker[:]) != NetworkIPAMMarker {
		f.Close()
		return nil, errors.New("missing or unsupported shared network allocator format")
	}
	if err = ctx.Err(); err != nil {
		f.Close()
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
		return f, nil
	}
	if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
		f.Close()
		return nil, err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
		if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
	}
}
func networkUnlock(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }
func networkAllocationPath(a *networkAllocation) string {
	return filepath.Join(NetworkIPAMRoot, networkToken(a.Owner.RuntimeInstallationID, a.Record.Generation)+".json")
}
func networkSave(a *networkAllocation) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("network observation exceeds durable bound")
	}
	f, err := os.CreateTemp(NetworkIPAMRoot, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(name, networkAllocationPath(a)); err != nil {
		return err
	}
	return networkSyncDirectory()
}
func networkSyncDirectory() error {
	f, e := os.Open(NetworkIPAMRoot)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}
func networkAllocations() ([]*networkAllocation, error) {
	entries, err := os.ReadDir(NetworkIPAMRoot)
	if err != nil {
		return nil, err
	}
	if len(entries) > 65538 {
		return nil, errors.New("network allocation inventory exceeds bound")
	}
	var out []*networkAllocation
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		p := filepath.Join(NetworkIPAMRoot, entry.Name())
		fd, e := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return nil, e
		}
		f := os.NewFile(uintptr(fd), p)
		var st unix.Stat_t
		e = unix.Fstat(fd, &st)
		if e != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Size > 1<<20 {
			f.Close()
			return nil, fmt.Errorf("untrusted network allocation %s", p)
		}
		raw, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
		closeErr := f.Close()
		if e = errors.Join(e, closeErr); e != nil {
			return nil, e
		}
		var a networkAllocation
		if e = gvxcontract.DecodeStrict(raw, 1<<20, 24, &a); e != nil {
			return nil, e
		}
		if networkAllocationPath(&a) != p || a.Record.Generation == "" || a.Owner.RuntimeInstallationID == "" {
			return nil, errors.New("network allocation identity mismatch")
		}
		if a.Rules == nil {
			a.Rules = make(map[string]string)
		}
		if a.Topology == nil {
			a.Topology = make(map[string]string)
		}
		if a.Flows == nil {
			a.Flows = make(map[string]string)
		}
		out = append(out, &a)
	}
	return out, nil
}
