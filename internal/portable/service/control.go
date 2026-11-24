package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
	modruntime "github.com/thirdscam/chatanium/internal/runtime"
)

type stopServer struct {
	listener net.Listener
	request  chan struct{}
	finish   chan struct{}
	once     sync.Once
	workers  sync.WaitGroup
	result   string
}

func listenStop(path string) (*stopServer, error) {
	ln, err := process.Listen(path)
	if err != nil {
		return nil, err
	}
	s := &stopServer{listener: ln, request: make(chan struct{}), finish: make(chan struct{})}
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// One fixed verb; a local client can occupy the reader only briefly.
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var command [5]byte
			_, err = io.ReadFull(conn, command[:])
			if err != nil || string(command[:]) != "STOP\n" {
				conn.Close()
				continue
			}
			s.once.Do(func() { close(s.request) })
			// All later callers have already durably recorded the same intent;
			// the listener backlog suffices while this caller awaits proof.
			<-s.finish
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, s.result)
			conn.Close()
		}
	}()
	return s, nil
}

func (s *stopServer) close(clean bool) {
	s.result = "PENDING\n"
	if clean {
		s.result = "STOPPED\n"
	}
	close(s.finish)
	s.workers.Wait()
}

// Stop fences admissions in SQLite before contacting the owner. A missing
// socket is not proof that a cleanup-pending child has gone away.
func Stop(ctx context.Context, dir string) error {
	i, err := install.Open(dir)
	if err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		cfg, err := modruntime.DecodeConfig(i.Manifest.Config)
		if err != nil {
			i.Close()
			return err
		}
		// A stuck local owner is not a reason to hang an operator forever.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.Defaults.DrainDeadline)+3*(time.Duration(cfg.Limits.TerminationDeadline)+time.Duration(cfg.Limits.HostOperationDeadline)))
		defer cancel()
	}
	defer i.Close()
	db, err := i.Store(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	record, err := db.Installation(ctx)
	if err != nil {
		return err
	}
	if record.Desired != store.DesiredStopped {
		if err = db.RequestStop(ctx, record.EpochID); err != nil {
			return err
		}
	}
	idle := func() error {
		current, err := db.Installation(ctx)
		if err != nil {
			return err
		}
		if current.WorkerPending || current.EpochID != "" && (current.Desired != store.DesiredStopped || current.EpochID != record.EpochID) {
			return errors.New("CLEANUP_PENDING: foreground owner has not confirmed exit")
		}
		runs, err := db.Runs(ctx)
		if err != nil {
			return err
		}
		if len(runs) != 0 {
			return errors.New("CLEANUP_PENDING: outstanding sandbox resources")
		}
		return nil
	}
	if record.EpochID == "" || record.Desired == store.DesiredStopped && !record.WorkerPending {
		return idle()
	}
	leaf, err := ipcpath.Directory(i.Path, record.EpochID)
	if err != nil {
		return err
	}
	path := filepath.Join(leaf, "stop")
	conn, err := process.Dial(ctx, path)
	if err != nil {
		if e := idle(); e == nil {
			return nil
		}
		return fmt.Errorf("CLEANUP_PENDING: contact foreground owner: %w", err)
	}
	defer conn.Close()
	u := context.AfterFunc(ctx, func() { conn.Close() })
	defer u()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if _, err = io.WriteString(conn, "STOP\n"); err != nil {
		return err
	}
	var reply [8]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		if idle() == nil {
			return nil
		}
		return fmt.Errorf("CLEANUP_PENDING: awaiting foreground owner: %w", err)
	}
	if string(reply[:]) != "STOPPED\n" {
		return errors.New("CLEANUP_PENDING: foreground owner could not confirm cleanup")
	}
	return nil
}
