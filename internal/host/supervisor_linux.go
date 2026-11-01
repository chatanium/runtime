//go:build linux

package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type runtimeEpoch struct {
	pid   int32
	pidfd *os.File
	dead  bool
}
type Supervisor struct {
	config      SupervisorConfig
	platform    Platform
	journal     *journal
	storage     *storage
	listener    *net.UnixListener
	lockfile    *os.File
	mu          sync.Mutex
	epochs      map[string]*runtimeEpoch
	locks       map[string]*sync.Mutex
	connections chan struct{}
	workers     sync.WaitGroup
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func NewSupervisor(ctx context.Context, c SupervisorConfig, p Platform) (*Supervisor, error) {
	if os.Geteuid() != 0 {
		return nil, prerequisite(errors.New("supervisor requires host root"))
	}
	if p == nil || c.RuntimeUID == 0 || c.RuntimeGID == 0 || c.MaxMessageBytes <= 0 || c.OperationTimeout <= 0 || c.ReconcileInterval <= 0 || c.MaxConnections <= 0 {
		return nil, invalid("supervisor requires explicit finite settings and nonroot runtime identity")
	}
	if filepath.Dir(c.SocketPath) != c.ManagementDirectory {
		return nil, invalid("supervisor socket must be directly inside management directory")
	}
	management, err := trustedDirectory(c.ManagementDirectory)
	if err != nil {
		return nil, prerequisite(err)
	}
	defer management.Close()
	// Root owns the directory; runtime can traverse but cannot replace socket/db.
	if err = unix.Fchown(int(management.Fd()), 0, int(c.RuntimeGID)); err != nil {
		return nil, err
	}
	if err = unix.Fchmod(int(management.Fd()), 0710); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(c.ManagementDirectory, "supervisor.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, prerequisite(err)
	}
	cleanupLock := true
	defer func() {
		if cleanupLock {
			lock.Close()
		}
	}()
	// P3's private spool is a sibling of supervisor metadata, never a module
	// mount. Only this fixed child is writable by the authenticated runtime.
	if err = prepareRuntimeDirectory(management, "uploads", c.RuntimeUID, c.RuntimeGID); err != nil {
		return nil, err
	}
	if err = p.Preflight(ctx); err != nil {
		return nil, prerequisite(err)
	}
	store, err := newStorage(c)
	if err != nil {
		return nil, err
	}
	j, err := openJournal(ctx, c.ManagementDirectory)
	if err != nil {
		store.quota.root.Close()
		return nil, err
	}
	store.journal = j
	if err = p.BindCreateJournal(j); err != nil {
		j.db.Close()
		store.quota.root.Close()
		return nil, err
	}
	s := &Supervisor{config: c, platform: p, journal: j, storage: store, lockfile: lock, epochs: make(map[string]*runtimeEpoch), locks: make(map[string]*sync.Mutex), connections: make(chan struct{}, c.MaxConnections)}
	// Never adopt an old runtime's authority. Unresolved submissions remain
	// exclusively reserved and reconciled while unrelated epochs may register.
	if err = s.reconcile(ctx, true); err != nil && !unresolvedCleanupOnly(err) {
		j.db.Close()
		store.quota.root.Close()
		return nil, err
	}
	if st, e := os.Lstat(c.SocketPath); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			j.db.Close()
			store.quota.root.Close()
			return nil, invalid("control socket path occupied by non-socket")
		}
		if e = os.Remove(c.SocketPath); e != nil {
			j.db.Close()
			store.quota.root.Close()
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		j.db.Close()
		store.quota.root.Close()
		return nil, e
	}
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: c.SocketPath, Net: "unixpacket"})
	if err != nil {
		j.db.Close()
		store.quota.root.Close()
		return nil, err
	}
	s.listener = l
	if err = os.Chown(c.SocketPath, 0, int(c.RuntimeGID)); err == nil {
		err = os.Chmod(c.SocketPath, 0660)
	}
	if err != nil {
		l.Close()
		j.db.Close()
		store.quota.root.Close()
		return nil, err
	}
	cleanupLock = false
	return s, nil
}
func (s *Supervisor) instanceLock(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.locks[id]
	if m == nil {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	return m
}
func (s *Supervisor) Serve(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			s.listener.Close()
		case <-done:
		}
	}()
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		ticker := time.NewTicker(s.config.ReconcileInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				op, cancel := operationContext(context.Background(), s.config.OperationTimeout)
				_ = s.reconcile(op, false)
				cancel()
			}
		}
	}()
	for {
		c, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case s.connections <- struct{}{}:
			s.workers.Add(1)
			go func() { defer s.workers.Done(); defer func() { <-s.connections }(); s.handle(c) }()
		default:
			c.Close()
		}
	}
}
func (s *Supervisor) handle(c *net.UnixConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(s.config.OperationTimeout))
	cred, err := peerIdentity(c)
	if err != nil || cred.Uid != s.config.RuntimeUID || cred.Gid != s.config.RuntimeGID {
		return
	}
	data, files, err := receivePacket(c, s.config.MaxMessageBytes)
	if err != nil {
		return
	}
	defer closeFiles(files)
	var req controlRequest
	resp := controlResponse{Version: controlVersion}
	if err = strictJSON(data, &req); err == nil {
		err = validateRequest(req)
	}
	if err != nil {
		resp.Error = controlError(err)
		_ = sendPacket(c, s.config.MaxMessageBytes, resp, nil)
		return
	}
	ctx, cancel := operationContext(context.Background(), s.config.OperationTimeout)
	defer cancel()
	var resultFiles []*os.File
	if req.Operation == "register" {
		if len(files) != 1 {
			err = invalid("registration requires one runtime self-pidfd")
		} else if err = pidfdPeer(files[0], cred); err == nil {
			dup, e := unix.FcntlInt(files[0].Fd(), unix.F_DUPFD_CLOEXEC, 0)
			if e != nil {
				err = e
			} else {
				f := os.NewFile(uintptr(dup), "runtime-pidfd")
				boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
				if e != nil {
					f.Close()
					err = e
				} else {
					// start identity is kernel fdinfo + boot identity, retained for diagnostics;
					// liveness always uses the held pidfd, never a PID-number probe.
					info, e := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", f.Fd()))
					if e != nil {
						f.Close()
						err = e
					} else {
						s.mu.Lock()
						for _, epoch := range s.epochs {
							if epoch.pid == cred.Pid && !epoch.dead {
								err = errors.New("runtime already has an epoch")
								break
							}
						}
						id := newID()
						if err == nil {
							err = s.journal.epoch(ctx, id, strings.TrimSpace(string(boot)), int(cred.Pid), string(info))
						}
						if err == nil {
							s.epochs[id] = &runtimeEpoch{pid: cred.Pid, pidfd: f}
							resp.EpochID = id
						} else {
							f.Close()
						}
						s.mu.Unlock()
					}
				}
			}
		}
	} else {
		if len(files) != 0 {
			err = invalid("unexpected control descriptors")
		} else if err = s.authenticate(req.EpochID, cred); err == nil {
			resultFiles, err = s.dispatch(ctx, req, &resp)
		}
	}
	defer closeFiles(resultFiles)
	if err != nil {
		resp.Error = controlError(err)
	}
	// A lost reply does not roll back creation. Durable claims remain owned.
	_ = sendPacket(c, s.config.MaxMessageBytes, resp, resultFiles)
}
func (s *Supervisor) authenticate(id string, cred *unix.Ucred) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.epochs[id]
	if e == nil || e.dead || e.pid != cred.Pid {
		return failure("UNAUTHENTICATED_INSTANCE", errors.New("runtime epoch is not bound to Unix peer"))
	}
	fds := []unix.PollFd{{Fd: int32(e.pidfd.Fd()), Events: unix.POLLIN}}
	_, err := unix.Poll(fds, 0)
	if err != nil {
		return err
	}
	if fds[0].Revents != 0 {
		e.dead = true
		return failure("UNAUTHENTICATED_INSTANCE", errors.New("runtime exited"))
	}
	return nil
}
func (s *Supervisor) dispatch(ctx context.Context, r controlRequest, out *controlResponse) ([]*os.File, error) {
	if r.Operation == "image_manifest" {
		bound, err := manifestPacketLimit(s.config.MaxMessageBytes)
		if err != nil {
			return nil, err
		}
		declaration, err := s.platform.ImageManifest(ctx, r.ImageDigest, int64(bound))
		if err != nil {
			return nil, err
		}
		if len(declaration) == 0 || len(declaration) > bound || !json.Valid(declaration) {
			return nil, invalid("image manifest declaration is missing, oversized or invalid JSON")
		}
		out.Manifest = declaration
		return nil, nil
	}
	if r.Operation == "acquire" {
		lock := s.instanceLock(r.Spec.InstanceID)
		lock.Lock()
		defer lock.Unlock()
		// Hold the per-instance lock before publishing intent: an epoch reaper
		// cannot complete cleanup and then race a late allocation.
		s.mu.Lock()
		epoch := s.epochs[r.EpochID]
		if epoch == nil || epoch.dead {
			s.mu.Unlock()
			return nil, errors.New("runtime epoch has been revoked")
		}
		l, err := s.journal.allocate(ctx, r.EpochID, *r.Spec, s.config)
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if err = s.storage.provision(ctx, l); err != nil {
			_ = s.journal.state(ctx, l.Spec.InstanceID, "FAILED", "HOST_PREREQUISITE_FAILED")
			cleanCtx, cancel := operationContext(context.Background(), s.config.OperationTimeout)
			defer cancel()
			return nil, errors.Join(prerequisite(err), s.cleanup(cleanCtx, l))
		}
		for _, kind := range []string{"scratch", "ipc", "persistent", "logs"} {
			if err = s.journal.claim(ctx, l.Spec.InstanceID, kind, "ALLOCATED"); err != nil {
				return nil, err
			}
		}
		if err = s.journal.state(ctx, l.Spec.InstanceID, "ALLOCATED", ""); err != nil {
			return nil, err
		}
		out.Lease = &l
		return nil, nil
	}
	if r.Operation == "reconcile" {
		return nil, reconciliationError(s.reconcile(ctx, false))
	}
	lock := s.instanceLock(r.InstanceID)
	// Wait must not hold the instance lock: termination is what unblocks Wait.
	if r.Operation != "wait" {
		lock.Lock()
		defer lock.Unlock()
	}
	l, state, err := s.journal.lease(ctx, r.EpochID, r.InstanceID)
	if errors.Is(err, errInstanceAbsent) && (r.Operation == "terminate" || r.Operation == "release") {
		return nil, s.journal.retireAbsent(ctx, r.EpochID, r.InstanceID)
	}
	if err != nil {
		return nil, err
	}
	switch r.Operation {
	case "create":
		if state != "ALLOCATED" {
			return nil, invalid("container creation is not in ALLOCATED state")
		}
		if err = s.storage.socketDirectory(l, r.SocketDirectory); err != nil {
			return nil, err
		}
		if err = s.journal.state(ctx, r.InstanceID, "CREATING", ""); err != nil {
			return nil, err
		}
		if l.Spec.InitialEgress == EgressPublicInternet {
			if err = s.journal.claim(ctx, r.InstanceID, "network", "TOPOLOGY_INTENT"); err != nil {
				return nil, s.abort(l, "JOURNAL_WRITE_FAILED", err)
			}
		}
		container, e := s.platform.Create(ctx, l.Spec, l, r.Bootstrap, r.SocketDirectory)
		if e != nil {
			return nil, s.abort(l, "CONTAINER_CREATE_FAILED", e)
		}
		if container == nil || container.ID == "" || container.Stdout == nil || container.Stderr == nil {
			if container != nil {
				closeFiles([]*os.File{container.Stdout, container.Stderr})
			}
			return nil, s.abort(l, "CONTAINER_CREATE_FAILED", errors.New("platform returned incomplete container ownership"))
		}
		if err = s.journal.container(ctx, l, container.ID); err != nil {
			closeFiles([]*os.File{container.Stdout, container.Stderr})
			return nil, s.abort(l, "JOURNAL_WRITE_FAILED", err)
		}
		out.ContainerID = container.ID
		return []*os.File{container.Stdout, container.Stderr}, nil
	case "start":
		if state != "CREATED" {
			return nil, invalid("container is not in CREATED state")
		}
		if err = s.journal.state(ctx, r.InstanceID, "STARTING", ""); err != nil {
			return nil, err
		}
		if err = s.platform.Start(ctx, l.Ownership); err != nil {
			return nil, s.abort(l, "CONTAINER_START_FAILED", err)
		}
		return nil, s.journal.state(ctx, r.InstanceID, "STARTED", "")
	case "wait":
		observation, cancel := context.WithTimeout(ctx, s.config.OperationTimeout/2)
		defer cancel()
		exit, e := s.platform.Wait(observation, l.Ownership)
		if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
			return nil, &Error{Reason: "WAIT_PENDING", Message: "container has not exited within observation window"}
		}
		if e != nil {
			return nil, e
		}
		out.Exit = &exit
		return nil, nil
	case "terminate":
		return nil, s.platform.Terminate(ctx, l.Ownership)
	case "egress":
		if state != "STARTED" && !(state == "CREATED" && r.Egress == EgressNone) {
			return nil, invalid("egress opening requires a started instance; prestart permits closure only")
		}
		if r.Egress == EgressPublicInternet && l.Spec.InitialEgress != EgressPublicInternet {
			return nil, invalid("public egress cannot add an endpoint to an initially NONE instance")
		}
		if err = s.journal.claim(ctx, r.InstanceID, "network", "POLICY_INTENT"); err != nil {
			return nil, err
		}
		if err = s.platform.SetEgress(ctx, l.Ownership, r.Egress); err != nil {
			return nil, err
		}
		return nil, s.journal.claim(ctx, r.InstanceID, "network", "ALLOCATED")
	case "capture":
		if state != "STARTED" {
			return nil, invalid("socket capture requires started container")
		}
		f, e := s.storage.capture(l, r.SocketName)
		if e != nil {
			return nil, e
		}
		return []*os.File{f}, nil
	case "release":
		return nil, s.cleanup(ctx, l)
	}
	return nil, invalid("invalid operation")
}
func (s *Supervisor) cleanup(ctx context.Context, l Lease) error {
	// Platform cleanup must prove the container dead/removed before its mounts
	// can be unlinked. A timeout/unknown outcome retains every storage claim.
	err := cleanupStep(FailureCleanupPlatform, s.platform.Reconcile(ctx, l.Ownership))
	if err == nil {
		err = cleanupStep(FailureCleanupCreateGuard, s.journal.unresolvedCreates(ctx, l.Spec.InstanceID))
	}
	if err == nil {
		err = s.storage.cleanup(ctx, l)
	}
	physicalFailure := err != nil
	if err == nil {
		err = cleanupStep(FailureCleanupJournal, s.journal.cleanup(ctx, l.Spec.InstanceID, true, nil))
	}
	if err == nil {
		return nil
	}
	// Preserve the finite first-step evidence even if the caller's cleanup
	// context has expired. This records no raw child/error text and never
	// authorizes release; a failed COMPLETE transaction retains ownership.
	recordCtx, cancel := operationContext(context.Background(), s.config.OperationTimeout)
	defer cancel()
	recordFailure := s.journal.recordCleanupFailure(recordCtx, l.Ownership, err)
	var recordStatus error
	if physicalFailure {
		recordStatus = s.journal.cleanup(recordCtx, l.Spec.InstanceID, false, err)
	}
	return errors.Join(ErrCleanupIncomplete, err, recordFailure, recordStatus)
}
func (s *Supervisor) abort(l Lease, reason string, cause error) error {
	cleanup, cancel := operationContext(context.Background(), s.config.OperationTimeout)
	defer cancel()
	record := s.journal.state(cleanup, l.Spec.InstanceID, "FAILED", reason)
	return errors.Join(cause, record, s.cleanup(cleanup, l))
}
func (s *Supervisor) reconcile(ctx context.Context, all bool) error {
	// Loss of enforcement is terminal authority loss, not a warning. Revoke
	// every epoch and clean it; do not silently run with weaker isolation.
	enforcement := errors.Join(s.storage.quota.preflight(), s.platform.Preflight(ctx))
	if enforcement != nil {
		all = true
	}
	s.mu.Lock()
	dead := make(map[string]bool)
	for id, e := range s.epochs {
		fds := []unix.PollFd{{Fd: int32(e.pidfd.Fd()), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 0)
		if enforcement != nil || err != nil || fds[0].Revents != 0 {
			e.dead = true
		}
		if e.dead {
			dead[id] = true
		}
	}
	s.mu.Unlock()
	leases, err := s.journal.pending(ctx, "")
	if err != nil {
		return err
	}
	var errs []error
	if enforcement != nil {
		errs = append(errs, enforcement)
	}
	for _, l := range leases {
		s.mu.Lock()
		_, known := s.epochs[l.Ownership.EpochID]
		s.mu.Unlock()
		if e := s.reconcileLease(ctx, l, all || !known || dead[l.Ownership.EpochID]); e != nil {
			errs = append(errs, e)
		}
	}
	s.mu.Lock()
	for id, e := range s.epochs {
		if e.dead {
			if _, err = s.journal.db.ExecContext(ctx, "UPDATE runtime_epochs SET state='DEAD' WHERE id=?", id); err != nil {
				errs = append(errs, err)
			}
			e.pidfd.Close()
			delete(s.epochs, id)
		}
	}
	s.mu.Unlock()
	if all {
		if _, err = s.journal.db.ExecContext(ctx, "UPDATE runtime_epochs SET state='REVOKED' WHERE state='LIVE'"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// pending() is a snapshot taken before acquiring the instance lock. A normal
// Release may complete while this reaper waits. Re-read cleanup under the same
// lock as Release before inspecting paths that successful cleanup deleted.
func (s *Supervisor) reconcileLease(ctx context.Context, l Lease, orphan bool) error {
	lock := s.instanceLock(l.Spec.InstanceID)
	lock.Lock()
	defer lock.Unlock()
	var cleanup string
	if err := s.journal.db.QueryRowContext(ctx, "SELECT cleanup FROM instances WHERE id=? AND epoch=?", l.Spec.InstanceID, l.Ownership.EpochID).Scan(&cleanup); err != nil {
		return err
	}
	if cleanup == "COMPLETE" {
		return nil
	}
	var failure error
	if !orphan {
		unresolvedErr := s.journal.unresolvedCreates(ctx, l.Spec.InstanceID)
		if unresolvedErr != nil && !errors.Is(unresolvedErr, ErrCreateUnresolved) {
			return unresolvedErr
		}
		if unresolvedErr == nil {
			if verifyErr := s.storage.verify(l); verifyErr == nil {
				return nil
			} else {
				failure = errors.Join(prerequisite(verifyErr), s.journal.state(ctx, l.Spec.InstanceID, "FAILED", "HOST_PREREQUISITE_FAILED"))
			}
		}
	}
	return errors.Join(failure, s.cleanup(ctx, l))
}
func (s *Supervisor) Close() error {
	_ = s.listener.Close()
	s.workers.Wait()
	ctx, cancel := operationContext(context.Background(), s.config.OperationTimeout)
	defer cancel()
	err := s.reconcile(ctx, true)
	s.mu.Lock()
	for _, e := range s.epochs {
		e.pidfd.Close()
	}
	s.epochs = map[string]*runtimeEpoch{}
	s.mu.Unlock()
	return errors.Join(err, s.journal.db.Close(), s.storage.quota.root.Close(), s.lockfile.Close())
}

// EpochPID is intentionally absent from the protocol: clients cannot nominate
// another process or pass a short-lived sudo launcher as their lifetime owner.
