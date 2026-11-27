//go:build linux

package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
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
	journal     *Store
	lease       *InstallationLease
	listener    *net.UnixListener
	mu          sync.Mutex
	epochs      map[string]*runtimeEpoch
	locks       map[string]*sync.Mutex
	epochID     string
	draining    bool
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
func NewSupervisor(ctx context.Context, c SupervisorConfig, p Platform, store *Store, lease *InstallationLease) (*Supervisor, error) {
	if os.Geteuid() != 0 {
		return nil, prerequisite(errors.New("supervisor requires host root"))
	}
	if p == nil || store == nil || lease == nil || lease.store != store || lease.closed || lease.owner.Name == "" || c.RuntimeInstallationID != store.productID || c.RuntimeUID == 0 || c.RuntimeGID == 0 || c.MaxMessageBytes <= 0 || c.OperationTimeout <= 0 || c.ReconcileInterval <= 0 || c.MaxConnections <= 0 {
		return nil, invalid("live bound installation lease and finite settings required")
	}
	if filepath.Dir(c.SocketPath) != c.ManagementDirectory || store.dir != c.ManagementDirectory {
		return nil, invalid("control socket must be in installation control anchor")
	}
	installed, err := store.Installation(ctx)
	if err != nil {
		return nil, err
	}
	if c.RuntimeUID != installed.Identities.App.UID || c.RuntimeGID != installed.Identities.App.GID || c.App != installed.Identities.App || c.Sandbox != installed.Identities.Sandbox || c.Preparer != installed.Identities.Preparer || c.StorageRoot != installed.Paths.StorageRoot {
		return nil, invalid("supervisor identities/paths differ from installed approval")
	}
	if err := store.requireLease(); err != nil {
		return nil, err
	}
	if err := p.BindCreateJournal(store); err != nil {
		return nil, err
	}
	if err := p.Preflight(ctx); err != nil {
		return nil, prerequisite(err)
	}
	s := &Supervisor{config: c, platform: p, journal: store, lease: lease, epochID: newID(), epochs: make(map[string]*runtimeEpoch), locks: make(map[string]*sync.Mutex), connections: make(chan struct{}, c.MaxConnections)}
	if err := s.reconcile(ctx, true); err != nil && !unresolvedCleanupOnly(err) {
		return nil, err
	}
	if st, err := os.Lstat(c.SocketPath); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, invalid("control socket occupied by non-socket")
		}
		if err = os.Remove(c.SocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: c.SocketPath, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	s.listener = listener
	if err = os.Chown(c.SocketPath, 0, int(c.RuntimeGID)); err == nil {
		err = os.Chmod(c.SocketPath, 0660)
	}
	if err != nil {
		listener.Close()
		return nil, err
	}
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
	if err = decodeControlRequest(data, &req); err == nil {
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
		s.mu.Lock()
		worker := s.config.Worker
		draining := s.draining
		s.mu.Unlock()
		if len(files) != 1 || draining || !validUnit(worker) || int(cred.Pid) != worker.MainPID {
			err = invalid("registration requires one runtime self-pidfd")
		} else if err = s.verifyWorkerAdmission(ctx, worker); err == nil {
			err = pidfdPeer(files[0], cred)
			if err != nil {
				resp.Error = controlError(err)
				_ = sendPacket(c, s.config.MaxMessageBytes, resp, nil)
				return
			}
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
					// Persist the kernel-verified worker invocation, never a restorable
					// descriptor number. Liveness uses the held pidfd exclusively.
					info, e := json.Marshal(worker)
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
						id := s.epochID
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
	sendErr := sendPacket(c, s.config.MaxMessageBytes, resp, resultFiles)
	if req.Operation == "create" && resp.Error == nil {
		recordCtx, recordCancel := operationContext(context.Background(), s.config.OperationTimeout)
		_ = s.journal.endpointTransfer(recordCtx, req.InstanceID, sendErr == nil)
		recordCancel()
	}
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
		if r.Spec.Resources.ControlMessageMaxBytes > int64(s.config.MaxMessageBytes) {
			return nil, invalid("instance control bound exceeds complete runtime packet bound")
		}
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
		// Native preparation belongs to the platform Create transaction. Acquire
		// commits claims only and cannot dispatch a service.
		if err = s.journal.state(ctx, l.Spec.InstanceID, "PREPARING", ""); err != nil {
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
		if state != "PREPARING" {
			return nil, invalid("stage creation is not in PREPARING state")
		}
		if err = s.journal.state(ctx, r.InstanceID, "PREPARING", ""); err != nil {
			return nil, err
		}
		if l.Spec.InitialEgress == EgressPublicInternet {
			if err = s.journal.claim(ctx, r.InstanceID, "network", "TOPOLOGY_INTENT"); err != nil {
				return nil, s.abort(l, "JOURNAL_WRITE_FAILED", err)
			}
		}
		process, e := s.platform.Create(ctx, l.Spec, l, r.Bootstrap)
		if e != nil {
			return nil, s.abort(l, "STAGE_CREATE_FAILED", e)
		}
		var transferred []*os.File
		if process != nil {
			transferred = []*os.File{process.Stdin, process.Stdout, process.Stderr, process.Listener, process.Endpoint}
		}
		if process == nil || !validUnit(process.Unit) {
			closeFiles(transferred)
			return nil, s.abort(l, "STAGE_CREATE_FAILED", errors.New("incomplete stage ownership"))
		}
		if err = ValidateCreateResponse(process, s.config.MaxMessageBytes); err == nil {
			err = validateStageDescriptors(process)
		}
		if err != nil {
			closeFiles(transferred)
			return nil, s.abort(l, "STAGE_CREATE_FAILED", err)
		}
		record, e := s.journal.Unit(ctx, l.Ownership)
		if e != nil || record.Unit != process.Unit {
			closeFiles(transferred)
			return nil, s.abort(l, "JOURNAL_WRITE_FAILED", errors.Join(e, errors.New("platform did not atomically record observed unit")))
		}
		if record.MountNamespace == nil || record.MountNamespace.Device == 0 || record.MountNamespace.Inode == 0 || record.MountNamespaceDisposition != NamespacePrivate {
			closeFiles(transferred)
			return nil, s.abort(l, "NATIVE_NAMESPACE_IDENTITY_MISSING", errors.New("stage admission requires captured private native mount namespace"))
		}
		out.Unit = &process.Unit
		out.Init = &process.Init
		out.EndpointIdentity = &process.EndpointIdentity
		return transferred, nil
	case "start":
		if state != "CREATED" {
			return nil, invalid("stage is not in CREATED state")
		}
		if err = s.journal.state(ctx, r.InstanceID, "STARTING", ""); err != nil {
			return nil, err
		}
		if err = s.platform.Start(ctx, l.Ownership); err != nil {
			return nil, s.abort(l, "STAGE_START_FAILED", err)
		}
		return nil, nil
	case "wait":
		observation, cancel := context.WithTimeout(ctx, s.config.OperationTimeout/2)
		defer cancel()
		exit, e := s.platform.Wait(observation, l.Ownership)
		if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
			return nil, &Error{Reason: "WAIT_PENDING", Message: "unit has not exited within observation window"}
		}
		if e != nil {
			return nil, e
		}
		out.Exit = &exit
		return nil, nil
	case "terminate":
		return nil, s.platform.Terminate(ctx, l.Ownership)
	case "egress":
		if state != "STARTING" && state != "READY" && !(state == "CREATED" && r.Egress == EgressNone) {
			return nil, invalid("egress opening requires a started instance; prestart permits closure only")
		}
		if r.Egress == EgressPublicInternet && l.Spec.InitialEgress != EgressPublicInternet {
			return nil, invalid("public egress cannot add an endpoint to an initially NONE instance")
		}
		roots, rootErr := s.journal.RootIntent(ctx, l.Ownership)
		confirmed := rootErr == nil && roots.Confirmed
		if r.Egress == EgressPublicInternet && !confirmed {
			return nil, invalid("public egress requires durable root confirmation")
		}
		if err = s.journal.claim(ctx, r.InstanceID, "network", "POLICY_INTENT"); err != nil {
			return nil, err
		}
		if err = s.platform.SetEgress(ctx, l.Ownership, r.Egress); err != nil {
			return nil, s.abort(l, "EGRESS_ENFORCEMENT_FAILED", err)
		}
		if err = s.journal.claim(ctx, r.InstanceID, "network", "ALLOCATED"); err != nil {
			return nil, err
		}
		if state == "STARTING" && confirmed {
			return nil, s.journal.state(ctx, r.InstanceID, "READY", "")
		}
		return nil, nil
	case "confirm_guest_storage":
		if state != "STARTING" {
			return nil, invalid("root confirmation requires starting bridge")
		}
		if err = s.platform.ConfirmGuestStorage(ctx, l.Ownership, *r.RootInitResult); err != nil {
			return nil, s.abort(l, "ROOT_INITIALIZATION_FAILED", err)
		}
		return nil, nil
	case "release":
		return nil, s.cleanup(ctx, l)
	}
	return nil, invalid("invalid operation")
}
func (s *Supervisor) cleanup(ctx context.Context, l Lease) error {
	if err := s.journal.state(ctx, l.Spec.InstanceID, "STOPPING", ""); err != nil {
		return err
	}
	// Platform applies terminal recording, AddRef release, transport absence,
	// native detach and actual quota reclamation before returning success.
	err := cleanupStep(FailureCleanupPlatform, s.platform.Reconcile(ctx, l.Ownership))
	if err == nil {
		err = cleanupStep(FailureCleanupCreateGuard, s.journal.unresolvedCreates(ctx, l.Spec.InstanceID))
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
	record := s.journal.state(cleanup, l.Spec.InstanceID, "CLEANUP_PENDING", reason)
	return errors.Join(cause, record, s.cleanup(cleanup, l))
}
func (s *Supervisor) reconcile(ctx context.Context, all bool) error {
	if err := s.journal.requireLease(); err != nil {
		return err
	}
	// Loss of enforcement is terminal authority loss, not a warning. Revoke
	// every epoch and clean it; do not silently run with weaker isolation.
	enforcement := s.platform.Preflight(ctx)
	if enforcement != nil {
		all = true
	}
	s.mu.Lock()
	dead := make(map[string]bool)
	for id, e := range s.epochs {
		fds := []unix.PollFd{{Fd: int32(e.pidfd.Fd()), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 0)
		if all || enforcement != nil || err != nil || fds[0].Revents != 0 {
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
			if verifyErr := s.platform.Preflight(ctx); verifyErr == nil {
				return nil
			} else {
				failure = errors.Join(prerequisite(verifyErr), s.journal.state(ctx, l.Spec.InstanceID, "CLEANUP_PENDING", "HOST_PREREQUISITE_FAILED"))
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
	return err
}

// EpochPID is intentionally absent from the protocol: clients cannot nominate
// another process or pass a short-lived sudo launcher as their lifetime owner.

func (s *Supervisor) EpochID() string { return s.epochID }
func (s *Supervisor) BindWorker(ctx context.Context, u UnitIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.verifyWorkerAdmission(ctx, u); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config.Worker.Name != "" && s.config.Worker != u {
		return errors.New("worker invocation cannot be replaced in one supervisor")
	}
	s.config.Worker = u
	return nil
}
func (s *Supervisor) Drain(ctx context.Context) error {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
	return s.reconcile(ctx, true)
}
func (s *Supervisor) verifyWorkerAdmission(ctx context.Context, u UnitIdentity) error {
	if !validUnit(u) {
		return errors.New("incomplete observed worker invocation")
	}
	records, err := s.journal.UnitProvisions(ctx, u.Name)
	if err != nil {
		return err
	}
	var captured *NamespaceIdentity
	for _, record := range records {
		if record.State != "OBSERVED" {
			continue
		}
		var properties ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &properties); err != nil {
			return err
		}
		if properties.Unit == nil || *properties.Unit != u {
			continue
		}
		if properties.Exit != nil || properties.Absence != nil || properties.CgroupEmpty {
			return errors.New("worker invocation already has terminal or absence evidence")
		}
		if properties.MountNamespace == nil {
			continue
		}
		if properties.MountNamespaceDisposition != NamespacePrivate || properties.MountNamespace.Device == 0 || properties.MountNamespace.Inode == 0 {
			return errors.New("worker lacks a captured private mount namespace")
		}
		if captured != nil && *captured != *properties.MountNamespace {
			return errors.New("conflicting worker native mount namespace identities")
		}
		captured = properties.MountNamespace
	}
	if captured == nil {
		return errors.New("worker admission requires durable native private namespace capture")
	}
	return verifyWorkerProcess(u)
}

func verifyWorkerProcess(u UnitIdentity) error {
	if !validUnit(u) {
		return errors.New("incomplete observed worker invocation")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(boot)) != u.BootID {
		return errors.New("worker belongs to another boot")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", u.MainPID))
	if err != nil {
		return err
	}
	close := strings.LastIndexByte(string(raw), ')')
	if close < 0 {
		return errors.New("invalid worker stat")
	}
	fields := strings.Fields(string(raw[close+1:]))
	if len(fields) < 20 {
		return errors.New("short worker stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start != u.StartTime {
		return errors.New("worker PID start identity mismatch")
	}
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", u.MainPID))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(cgroup)) != "0::"+u.CgroupPath {
		return errors.New("worker cgroup differs from observed invocation")
	}
	exe, err := os.Open(fmt.Sprintf("/proc/%d/exe", u.MainPID))
	if err != nil {
		return err
	}
	defer exe.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(exe, 1<<30))
	if err != nil {
		return err
	}
	if n == 1<<30 || "sha256:"+hex.EncodeToString(h.Sum(nil)) != u.ExecutableDigest {
		return errors.New("worker executable digest mismatch")
	}
	return nil
}
