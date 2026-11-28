//go:build linux

package bootstrap

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"time"
)

func (s *ownedSession) openObservationOutput() error {
	source := int(os.Stdout.Fd())
	flags, e := unix.FcntlInt(uintptr(source), unix.F_GETFL, 0)
	if e != nil {
		return e
	}
	fd, e := unix.FcntlInt(uintptr(source), unix.F_DUPFD_CLOEXEC, 3)
	if e != nil {
		return e
	}
	if e = unix.SetNonblock(fd, true); e != nil {
		unix.Close(fd)
		return e
	}
	s.observationOutput = os.NewFile(uintptr(fd), "chatanium-observations")
	s.observationSource = source
	s.observationFlags = flags
	return nil
}
func (s *ownedSession) forwardObservation(raw []byte) error {
	s.mu.Lock()
	output := s.observationOutput
	closing := s.closing
	s.mu.Unlock()
	if closing || output == nil {
		return nil
	}
	if e := output.SetWriteDeadline(time.Now().Add(time.Duration(s.config.Limits.HostOperationDeadline))); e != nil && !errors.Is(e, os.ErrNoDeadline) {
		return e
	}
	_, e := output.Write(raw)
	if e == nil {
		_, e = output.WriteString("\n")
	}
	if e != nil {
		s.mu.Lock()
		closing = s.closing
		s.mu.Unlock()
		if closing {
			return nil
		}
	}
	return e
}
func (s *ownedSession) closeObservationOutput() error {
	s.mu.Lock()
	output := s.observationOutput
	s.observationOutput = nil
	source, flags := s.observationSource, s.observationFlags
	s.mu.Unlock()
	if output == nil {
		return nil
	}
	e := output.Close()
	_, restore := unix.FcntlInt(uintptr(source), unix.F_SETFL, flags)
	return errors.Join(e, restore)
}
