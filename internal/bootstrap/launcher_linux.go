//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
	"os"
)

func verifyInstalledLauncher(ctx context.Context, s *ownedSession) error {
	var record host.ProvisionRecord
	records, e := s.store.ObjectProvisions(ctx, "config", s.manifest.Paths.Launcher)
	if e != nil {
		return e
	}
	for _, candidate := range records {
		if candidate.State != "OBSERVED" || candidate.CleanupState == "COMPLETE" || !(candidate.ProductCreated && !candidate.ExistedBefore || candidate.ExistedBefore && !candidate.ProductCreated) {
			continue
		}
		if matchRecord(candidate) == nil {
			if record.ID != "" {
				return errors.New("ambiguous installed launcher observations")
			}
			record = candidate
		}
	}
	if record.ID == "" {
		return errors.New("installed launcher has no verified owned or explicitly borrowed observation")
	}
	if e = matchRecord(record); e != nil {
		return e
	}
	var p host.ProvisionProperties
	if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return e
	}
	executable, e := os.Open("/proc/self/exe")
	if e != nil {
		return e
	}
	defer executable.Close()
	var st unix.Stat_t
	if e = unix.Fstat(int(executable.Fd()), &st); e != nil {
		return e
	}
	if p.Dev == 0 || p.Ino == 0 || uint64(st.Dev) != p.Dev || st.Ino != p.Ino || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0022 != 0 || st.Mode&0111 == 0 || p.Digest == "" {
		return errors.New("development operations require the actual installed launcher")
	}
	if _, e = installedBundle(ctx, s.manifest); e != nil {
		return e
	}
	return nil
}
