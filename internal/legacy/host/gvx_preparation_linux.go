//go:build linux

package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxstage"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

// preparationContext is created only by the closed, root-owned preparation API.
// It cannot be supplied through the worker or module command protocols.
type preparationContext struct {
	storage *Storage
	space   ImageSpace
	layout  PreparationStorageView
}

func (d *Systemd) StartPreparation(ctx context.Context, s OwnedService, files StandardFiles, storage *Storage, space ImageSpace) (UnitObservation, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil || storage == nil || storage.store != store || storage.systemd != d || storage.cleanupOnly || (s.Program != bundle.Preparer && s.Program != bundle.Rungv) {
		return UnitObservation{}, &notSubmitted{errors.New("preparation requires the same admission storage, store and fixed purpose")}
	}
	view, err := storage.PreparationLayout(ctx, space)
	if err != nil {
		return UnitObservation{}, &notSubmitted{err}
	}
	s.preparationContext = &preparationContext{storage: storage, space: space, layout: view}
	if err = d.verifyPreparationLayout(ctx, s); err != nil {
		return UnitObservation{}, &notSubmitted{err}
	}
	for _, f := range []*os.File{files.Stdin, files.Stdout, files.Stderr} {
		var st unix.Stat_t
		if f == nil {
			return UnitObservation{}, &notSubmitted{errors.New("preparation requires three root-controlled pipes")}
		}
		if err = unix.Fstat(int(f.Fd()), &st); err != nil {
			return UnitObservation{}, &notSubmitted{err}
		}
		if st.Mode&unix.S_IFMT != unix.S_IFIFO || st.Uid != 0 {
			return UnitObservation{}, &notSubmitted{errors.New("preparation stdio is not a root-owned pipe")}
		}
	}
	return d.StartOwned(ctx, s, files)
}

func (d *Systemd) verifyPreparationLayout(ctx context.Context, s OwnedService) error {
	p := s.preparationContext
	if p == nil || p.storage == nil || p.storage.store != d.store || p.storage.systemd != d {
		return errors.New("preparation has no trusted storage context")
	}
	view, err := p.storage.PreparationLayout(ctx, p.space)
	if err != nil {
		return err
	}
	if view != p.layout || view.Version != gvxcontract.PreparationWriterDomainVersion || view.JobID != p.space.JobID || view.ProvisionID != p.space.ProvisionID {
		return errors.New("preparation storage birth layout changed")
	}
	if s.WorkingDirectory != "/chatanium/work" || s.RootDirectory != "" || s.NetworkNamespacePath != "" || len(s.Mounts) != 4 {
		return errors.New("preparation exceeds its fixed private aliases")
	}
	expected := map[string]OwnedMount{
		"/chatanium/source": {Source: view.Source.Data.HostPath, Target: "/chatanium/source", ReadOnly: s.Program == bundle.Rungv || p.space.ReusedSource},
		"/chatanium/cache":  {Source: view.Cache.Data.HostPath, Target: "/chatanium/cache"},
		"/chatanium/work":   {Source: view.Work.Data.HostPath, Target: "/chatanium/work"},
		"/chatanium/base":   {Source: d.bundle.Root, Target: "/chatanium/base", ReadOnly: true},
	}
	if view.Cache.Data.HostPath != filepath.Join(p.space.Cache, "generation") || view.Source.Data.HostPath != p.space.Source || view.Work.Data.HostPath != p.space.Work {
		return errors.New("preparation data paths differ from the owned image space")
	}
	for _, mount := range s.Mounts {
		want, ok := expected[mount.Target]
		if !ok || mount != want {
			return errors.New("preparation mount is not an exact approved data leaf")
		}
		delete(expected, mount.Target)
	}
	return nil
}

func preparationDigest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func preparationLaunchFingerprint(s OwnedService) *PreparationWriterLaunch {
	if s.preparation == nil {
		return nil
	}
	return &s.preparation.launch
}

func (d *Systemd) preparationWriterObservation(ctx context.Context, id string) (*PreparationWriterRecord, error) {
	writer, err := d.store.PreparationWriter(ctx, id)
	if err != nil {
		return nil, err
	}
	return &writer, nil
}

func (d *Systemd) preparationLaunch(s OwnedService, p *preparationGate) PreparationWriterLaunch {
	return PreparationWriterLaunch{
		Version:         gvxcontract.PreparationWriterDomainVersion,
		ProtocolVersion: gvxcontract.PreparationWriterProtocolVersion,
		FilterVersion:   gvxcontract.PreparationWriterFilterVersion,
		InstallationID:  d.store.productID, JobID: s.preparationContext.space.JobID,
		ProvisionID: s.preparationContext.space.ProvisionID,
		UnitName:    s.Name, Generation: s.Generation, BootID: d.boot, Purpose: p.config.Purpose,
		BundleDigest: d.bundle.Digest, StageDigest: p.stageDigest, TargetDigest: p.config.ExecutableDigest,
		StagePath: p.stagePath, TargetPath: p.config.Executable,
		ArgumentDigest: preparationDigest(struct {
			Argv, Env []string
			Workdir   string
			Limits    sharedhost.ResourceLimits
			Offline   bool
		}{p.config.Argv, p.config.Env, p.config.Workdir, s.Limits, s.OfflinePreparation}),
		DeclarationDigest: preparationDigest(p.config), PreparerUID: s.Identity.UID, PreparerGID: s.Identity.GID,
		Layout: s.preparationContext.layout,
	}
}

// acceptPeer owns the existing stream and controller-opened pidfd. Message
// validation stays separate for preparation v2 and the unchanged module v1 gate.
func (g *stageGate) acceptPeer(ctx context.Context, u sharedhost.UnitIdentity, s OwnedService) error {
	deadline, err := gvxstage.Deadline(g.config)
	if err != nil {
		return err
	}
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	g.mu.Lock()
	listener := g.listener
	g.mu.Unlock()
	if listener == nil {
		return net.ErrClosed
	}
	if err = listener.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = g.close() })
	defer stop()
	conn, err := listener.AcceptUnix()
	if err != nil {
		return err
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		conn.Close()
		return net.ErrClosed
	}
	g.conn = conn
	g.mu.Unlock()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if int(cred.Pid) != u.MainPID || cred.Uid != s.Identity.UID || cred.Gid != s.Identity.GID {
		return errors.New("stage peer credentials mismatch")
	}
	pidfd, err := unix.PidfdOpen(u.MainPID, 0)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		unix.Close(pidfd)
		return net.ErrClosed
	}
	g.pidfd = pidfd
	return nil
}

func (p *preparationGate) message(kind string) gvxstage.PreparationMessage {
	return gvxstage.PreparationMessage{Version: gvxcontract.PreparationWriterProtocolVersion, Type: kind,
		EpochID: p.config.RuntimeInstallationID, InstanceID: p.config.Generation, Generation: p.config.Generation,
		WriterDomainVersion: gvxcontract.PreparationWriterDomainVersion, FilterVersion: gvxcontract.PreparationWriterFilterVersion}
}

func (p *preparationGate) admit(ctx context.Context, d *Systemd, r *systemdReference) error {
	if p.launch.FilterVersion != gvxcontract.PreparationWriterFilterVersion || p.config.FilterVersion != p.launch.FilterVersion {
		return errors.New("preparation launch and native gate filter versions differ")
	}
	d.mu.Lock()
	u, s := r.unit, r.service
	d.mu.Unlock()
	if err := p.gate.acceptPeer(ctx, u, s); err != nil {
		return err
	}
	p.gate.mu.Lock()
	conn := p.gate.conn
	if p.gate.closed || conn == nil || p.gate.pidfd < 0 {
		p.gate.mu.Unlock()
		return net.ErrClosed
	}
	// Pin our native observation against cancellation closing/reusing the gate's
	// descriptor number. This is a controller duplicate, never a stage transfer.
	pidfd, err := unix.FcntlInt(uintptr(p.gate.pidfd), unix.F_DUPFD_CLOEXEC, 0)
	p.gate.mu.Unlock()
	if err != nil {
		return err
	}
	defer unix.Close(pidfd)
	stop := context.AfterFunc(ctx, func() { _ = p.gate.close() })
	defer stop()
	ready, err := gvxstage.ReadPreparationMessage(conn)
	if err != nil {
		return err
	}
	if !gvxstage.MatchesPreparation(ready, p.config) || ready.Type != gvxstage.PreparationReady {
		return errors.New("preparation registration binding mismatch")
	}
	if err = d.verifyPreparationProcess(ctx, u, s); err != nil {
		return err
	}
	birth, err := observePreparationBirth(u, s, pidfd)
	if err != nil {
		return err
	}
	d.mu.Lock()
	mountNamespace := r.observation.MountNamespace
	d.mu.Unlock()
	if mountNamespace == nil || *mountNamespace != birth.MountNamespace {
		return errors.New("preparation birth differs from the durably observed mount namespace")
	}
	writer := PreparationWriterRecord{Launch: p.launch, Birth: &birth}
	if err = d.recordPreparationWriter(ctx, r, writer); err != nil {
		return err
	}
	if _, err = gvxstage.Deadline(p.config.Binding()); err != nil {
		return err
	}
	if err = gvxstage.WritePreparationMessage(conn, p.message(gvxstage.PreparationArm)); err != nil {
		return err
	}
	filtered, err := gvxstage.ReadPreparationMessage(conn)
	if err != nil {
		return err
	}
	if !gvxstage.MatchesPreparation(filtered, p.config) || filtered.Type != gvxstage.PreparationFilterReady {
		return errors.New("preparation filter acknowledgment mismatch")
	}
	if err = d.verifyPreparationProcess(ctx, u, s); err != nil {
		return err
	}
	after, err := observePreparationBirth(u, s, pidfd)
	if err != nil {
		return err
	}
	if !samePreparationBirth(birth, after) {
		return errors.New("preparation native birth changed during filter installation")
	}
	if err = validatePreparationFilterTransition(birth.Tasks, after.Tasks); err != nil {
		return err
	}
	writer.Evidence = &PreparationWriterEvidence{Version: gvxcontract.PreparationWriterDomainVersion,
		ProtocolVersion: gvxcontract.PreparationWriterProtocolVersion, FilterVersion: gvxcontract.PreparationWriterFilterVersion,
		FilterDigest: gvxstage.PreparationFilterDigest(), AuditArch: unix.AUDIT_ARCH_X86_64,
		RejectX32: true, TSYNC: true, FilterReady: true, Tasks: after.Tasks}
	writer.StartIntent = true
	// Full evidence and START intent share the one atomic journal transition.
	if err = d.recordPreparationWriter(ctx, r, writer); err != nil {
		return err
	}
	if _, err = gvxstage.Deadline(p.config.Binding()); err != nil {
		return err
	}
	if err = verifyPreparationPIDFD(u, pidfd); err != nil {
		return err
	}
	p.gate.mu.Lock()
	if p.gate.closed || p.gate.started || p.gate.conn != conn {
		p.gate.mu.Unlock()
		return net.ErrClosed
	}
	p.gate.started = true
	p.gate.conn = nil
	p.gate.mu.Unlock()
	err = gvxstage.WritePreparationMessage(conn, p.message(gvxstage.PreparationStart))
	return errors.Join(err, conn.Close())
}

func (d *Systemd) verifyPreparationProcess(ctx context.Context, u sharedhost.UnitIdentity, s OwnedService) error {
	observed, err := d.Observe(ctx, u)
	if err != nil {
		return err
	}
	if observed.Unit != u || observed.Exit != nil {
		return errors.New("preparation invocation changed before gate release")
	}
	if err = d.verifyPreparationLayout(ctx, s); err != nil {
		return err
	}
	return verifyServiceProcess(u, s, d)
}

func verifyPreparationPIDFD(u sharedhost.UnitIdentity, fd int) error {
	if fd < 0 {
		return errors.New("preparation has no controller-held pidfd")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	if err != nil {
		return err
	}
	if n != 0 || poll[0].Revents != 0 {
		return errors.New("preparation pidfd is no longer live")
	}
	start, err := processStart(u.MainPID)
	if err != nil {
		return err
	}
	if start != u.StartTime {
		return errors.New("preparation PID was reused")
	}
	return nil
}

func boundedPreparationRead(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(raw)) > max {
		err = errors.New("native preparation metadata exceeds its bound")
	}
	return raw, err
}

func parsePreparationIDMap(raw []byte, id uint32) ([2]PreparationIDMap, error) {
	var result [2]PreparationIDMap
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if id == 0 || len(lines) != 2 {
		return result, errors.New("preparation namespace must map only root and its exact role")
	}
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return result, errors.New("invalid preparation namespace map")
		}
		values := [3]uint32{}
		for n, field := range fields {
			value, err := strconv.ParseUint(field, 10, 32)
			if err != nil {
				return result, err
			}
			values[n] = uint32(value)
		}
		result[i] = PreparationIDMap{Inside: values[0], Outside: values[1], Length: values[2]}
	}
	want := [2]PreparationIDMap{{Inside: 0, Outside: 0, Length: 1}, {Inside: id, Outside: id, Length: 1}}
	if result != want {
		return result, errors.New("preparation namespace contains extra or aliased identities")
	}
	return result, nil
}

func nativeNamespace(fd int) (NamespaceIdentity, error) {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	return NamespaceIdentity{Device: st.Dev, Inode: st.Ino}, err
}

func validatePreparationUserNamespace(child, parent, host NamespaceIdentity, typ, owner uint32) error {
	if child.Device == 0 || child.Inode == 0 || parent.Device == 0 || parent.Inode == 0 || host.Device == 0 || host.Inode == 0 || typ != unix.CLONE_NEWUSER || owner != 0 || child == host || parent != host {
		return errors.New("preparation user namespace is not a root-owned direct child of PID1")
	}
	return nil
}

func observePreparationBirth(u sharedhost.UnitIdentity, s OwnedService, pidfd int) (PreparationWriterBirth, error) {
	b := PreparationWriterBirth{Version: gvxcontract.PreparationWriterDomainVersion, Unit: u,
		PeerPID: u.MainPID, PeerUID: s.Identity.UID, PeerGID: s.Identity.GID}
	if err := verifyPreparationPIDFD(u, pidfd); err != nil {
		return b, err
	}
	var pidStat unix.Stat_t
	if err := unix.Fstat(pidfd, &pidStat); err != nil {
		return b, err
	}
	b.PIDFDDevice, b.PIDFDInode = pidStat.Dev, pidStat.Ino
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/user", u.MainPID), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return b, err
	}
	defer unix.Close(fd)
	b.UserNamespace, err = nativeNamespace(fd)
	if err != nil {
		return b, err
	}
	typ, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil {
		return b, err
	}
	b.UserNamespaceType = uint32(typ)
	var owner uint32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.NS_GET_OWNER_UID, uintptr(unsafe.Pointer(&owner)))
	if errno != 0 {
		return b, errno
	}
	b.UserNamespaceOwnerUID = owner
	parentFD, err := unix.IoctlRetInt(fd, unix.NS_GET_PARENT)
	if err != nil {
		return b, err
	}
	defer unix.Close(parentFD)
	unix.CloseOnExec(parentFD)
	b.ParentUserNamespace, err = nativeNamespace(parentFD)
	if err != nil {
		return b, err
	}
	hostFD, err := unix.Open("/proc/1/ns/user", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return b, err
	}
	defer unix.Close(hostFD)
	b.HostUserNamespace, err = nativeNamespace(hostFD)
	if err != nil {
		return b, err
	}
	if err = validatePreparationUserNamespace(b.UserNamespace, b.ParentUserNamespace, b.HostUserNamespace, b.UserNamespaceType, owner); err != nil {
		return b, err
	}
	for _, mapping := range []struct {
		name   string
		id     uint32
		result *[2]PreparationIDMap
	}{{"uid_map", s.Identity.UID, &b.UIDMap}, {"gid_map", s.Identity.GID, &b.GIDMap}} {
		raw, err := boundedPreparationRead(fmt.Sprintf("/proc/%d/%s", u.MainPID, mapping.name), 4096)
		if err != nil {
			return b, err
		}
		*mapping.result, err = parsePreparationIDMap(raw, mapping.id)
		if err != nil {
			return b, err
		}
	}
	groups, err := boundedPreparationRead(fmt.Sprintf("/proc/%d/setgroups", u.MainPID), 32)
	if err != nil {
		return b, err
	}
	if strings.TrimSpace(string(groups)) != "deny" {
		return b, errors.New("preparation namespace permits setgroups")
	}
	b.SetgroupsDenied = true
	mnt, disposition, err := captureMountNamespace(u, u.MainPID, false)
	if err != nil {
		return b, err
	}
	if disposition != NamespacePrivate {
		return b, errors.New("preparation has no private mount namespace")
	}
	b.MountNamespace = *mnt
	b.Tasks, err = observePreparationTasks(u, s, b.UserNamespace)
	if err != nil {
		return b, err
	}
	return b, verifyPreparationPIDFD(u, pidfd)
}

func observePreparationTasks(u sharedhost.UnitIdentity, s OwnedService, ns NamespaceIdentity) (PreparationTaskSnapshot, error) {
	var result PreparationTaskSnapshot
	directory := fmt.Sprintf("/proc/%d/task", u.MainPID)
	tasks, err := os.ReadDir(directory)
	if err != nil {
		return result, err
	}
	if len(tasks) == 0 || uint64(len(tasks)) > uint64(s.Limits.Pids) || uint64(len(tasks)) > math.MaxUint32 {
		return result, errors.New("preparation task inventory exceeds its native admitted limit")
	}
	hash := sha256.New()
	for i, task := range tasks {
		tid, err := strconv.Atoi(task.Name())
		if err != nil || tid <= 0 {
			return result, errors.New("invalid native preparation task")
		}
		base := filepath.Join(directory, task.Name())
		raw, err := boundedPreparationRead(filepath.Join(base, "status"), 1<<20)
		if err != nil {
			return result, err
		}
		snapshot, err := parsePreparationTask(raw, s.Identity)
		if err != nil {
			return result, err
		}
		var actual unix.Stat_t
		if err = unix.Stat(filepath.Join(base, "ns/user"), &actual); err != nil {
			return result, err
		}
		if actual.Dev != ns.Device || actual.Ino != ns.Inode {
			return result, errors.New("preparation task escaped its root-owned user namespace")
		}
		cg, err := boundedPreparationRead(filepath.Join(base, "cgroup"), 4096)
		if err != nil {
			return result, err
		}
		if strings.TrimSpace(string(cg)) != "0::"+u.CgroupPath {
			return result, errors.New("preparation task escaped its owned cgroup")
		}
		if i == 0 {
			result = snapshot
		} else if snapshot != result {
			return result, errors.New("preparation threads have inconsistent authority or filter state")
		}
		// Length delimit every complete native status; never truncate tasks to fit
		// the bounded durable representation.
		fmt.Fprintf(hash, "%d:%d:", tid, len(raw))
		hash.Write(raw)
		fmt.Fprintf(hash, ":%d:%d:%d:", ns.Device, ns.Inode, len(cg))
		hash.Write(cg)
	}
	after, err := os.ReadDir(directory)
	if err != nil {
		return result, err
	}
	if len(tasks) != len(after) {
		return result, errors.New("preparation task inventory changed during observation")
	}
	for i := range tasks {
		if tasks[i].Name() != after[i].Name() {
			return result, errors.New("preparation task identities changed during observation")
		}
	}
	result.ThreadCount = uint32(len(tasks))
	result.SnapshotDigest = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

func parsePreparationTask(raw []byte, identity NumericIdentity) (PreparationTaskSnapshot, error) {
	var result PreparationTaskSnapshot
	fields := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			fields[k] = strings.Fields(v)
		}
	}
	for _, kind := range []struct {
		key    string
		id     uint32
		values *[4]uint32
	}{{"Uid", identity.UID, &result.UIDs}, {"Gid", identity.GID, &result.GIDs}} {
		if len(fields[kind.key]) != 4 || kind.id == 0 {
			return result, errors.New("missing native preparation credentials")
		}
		for i, text := range fields[kind.key] {
			value, err := strconv.ParseUint(text, 10, 32)
			if err != nil || uint32(value) != kind.id {
				return result, errors.New("preparation task credentials differ from its dedicated role")
			}
			kind.values[i] = uint32(value)
		}
	}
	groups, ok := fields["Groups"]
	if !ok {
		return result, errors.New("missing native supplementary group evidence")
	}
	for _, group := range groups {
		value, err := strconv.ParseUint(group, 10, 32)
		if err != nil || uint32(value) != identity.GID {
			return result, errors.New("preparation task has extra supplementary authority")
		}
	}
	if uint64(len(groups)) > math.MaxUint32 {
		return result, errors.New("invalid native supplementary group count")
	}
	result.SupplementaryGroupCount = uint32(len(groups))
	// The compressed uniform group value is the natively verified primary GID;
	// the separate actual count preserves an empty supplementary vector.
	result.SupplementaryGID = result.GIDs[0]
	for i, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		values := fields[key]
		if len(values) != 1 {
			return result, errors.New("missing native preparation capability set")
		}
		value, err := strconv.ParseUint(values[0], 16, 64)
		if err != nil || value != 0 {
			return result, errors.New("preparation task retains capabilities")
		}
		result.Capabilities[i] = value
	}
	if strings.Join(fields["NoNewPrivs"], "") != "1" {
		return result, errors.New("preparation task lacks no-new-privileges")
	}
	result.NoNewPrivileges = true
	for _, kind := range []struct {
		key   string
		value *uint32
	}{{"Seccomp", &result.SeccompMode}, {"Seccomp_filters", &result.SeccompFilters}} {
		values := fields[kind.key]
		if len(values) != 1 {
			return result, errors.New("missing native preparation seccomp readback")
		}
		value, err := strconv.ParseUint(values[0], 10, 32)
		if err != nil {
			return result, err
		}
		*kind.value = uint32(value)
	}
	if result.SeccompMode > 2 || (result.SeccompMode == 0) != (result.SeccompFilters == 0) {
		return result, errors.New("inconsistent native preparation seccomp state")
	}
	return result, nil
}

func samePreparationBirth(a, b PreparationWriterBirth) bool {
	// Runtime thread creation is allowed; uniform authority is independently
	// validated for every observed thread in each snapshot.
	a.Tasks, b.Tasks = PreparationTaskSnapshot{}, PreparationTaskSnapshot{}
	return a == b
}

func validatePreparationFilterTransition(before, after PreparationTaskSnapshot) error {
	if before.SeccompFilters == math.MaxUint32 || after.SeccompMode != 2 || after.SeccompFilters != before.SeccompFilters+1 {
		return errors.New("preparation did not install exactly one TSYNC filter")
	}
	before.ThreadCount, after.ThreadCount = 0, 0
	before.SnapshotDigest, after.SnapshotDigest = "", ""
	before.SeccompMode, after.SeccompMode = 0, 0
	before.SeccompFilters, after.SeccompFilters = 0, 0
	if before != after {
		return errors.New("preparation authority changed during filter installation")
	}
	return nil
}

func (d *Systemd) helperProperties(ctx context.Context, r *systemdReference) (ProvisionProperties, bool, error) {
	var properties ProvisionProperties
	records, err := d.store.UnitProvisions(ctx, r.unit.Name)
	if err != nil {
		return properties, false, err
	}
	for _, record := range records {
		if record.ID != r.intent {
			continue
		}
		raw := record.Observed.Attributes
		if len(raw) == 0 {
			raw = record.Desired
		}
		if err = gvxcontract.DecodeStrict(raw, 64<<10, 16, &properties); err != nil {
			return properties, false, err
		}
		return properties, record.CleanupState == "COMPLETE", nil
	}
	return properties, false, errors.New("native helper dispatch record is missing")
}

func (d *Systemd) recordPreparationWriter(ctx context.Context, r *systemdReference, writer PreparationWriterRecord) error {
	r.recordMu.Lock()
	defer r.recordMu.Unlock()
	p, complete, err := d.helperProperties(ctx, r)
	if err != nil {
		return err
	}
	if complete {
		return errors.New("completed preparation cannot acquire new gate evidence")
	}
	d.mu.Lock()
	u, job, observation := r.unit, r.job, r.observation
	d.mu.Unlock()
	p.Name, p.Unit, p.JobPath = u.Name, &u, string(job)
	p.MountNamespace, p.MountNamespaceDisposition = observation.MountNamespace, observation.MountNamespaceDisposition
	p.Writer = &writer
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err = d.store.ObserveProvision(ctx, r.intent, ObjectObservation{Identity: u.Name, Attributes: raw}); err != nil {
		return err
	}
	d.mu.Lock()
	r.observation.Writer = &writer
	d.mu.Unlock()
	return nil
}

func (d *Systemd) fencePreparation(ctx context.Context, r *systemdReference) (*PreparationWriterRecord, error) {
	if r.service.Program != bundle.Preparer && r.service.Program != bundle.Rungv {
		return nil, nil
	}
	if r.intent == "" || r.rejection != "" {
		return nil, nil
	}
	writer, err := d.store.PreparationWriter(ctx, r.intent)
	if err != nil {
		legacy, historyErr := d.completedLegacyPreparation(ctx, r)
		if historyErr != nil {
			return nil, errors.Join(err, historyErr)
		}
		if legacy {
			return nil, nil
		}
		return nil, err
	}
	if writer.Birth == nil || writer.Birth.Unit != r.unit {
		return nil, errors.New("preparation cleanup lacks exact observed current-protocol birth")
	}
	if !writer.StartIntent {
		if !writer.StartForbidden {
			if err = d.store.ForbidPreparationWriterStart(ctx, r.intent, *writer.Birth); err != nil {
				return nil, err
			}
		}
		writer.StartForbidden = true
	} else if writer.Evidence == nil || writer.StartForbidden || writer.Evidence.FilterDigest != gvxstage.PreparationFilterDigest() {
		return nil, errors.New("preparation START has no exact current confinement evidence")
	}
	return &writer, nil
}

func (d *Systemd) persistPreparationSettlement(ctx context.Context, r *systemdReference, proof *CleanupEvidence) error {
	writer, err := d.fencePreparation(ctx, r)
	if err != nil {
		return err
	}
	if writer == nil {
		return nil
	}
	if r.unit.BootID == d.boot {
		if err = privateNamespaceReferencesAbsent(ctx, &writer.Birth.UserNamespace, "user"); err != nil {
			return err
		}
	}
	proof.Details, err = json.Marshal(UnitAbsenceDetails{UnitAbsent: true, CgroupEmpty: true, TransportPipes: r.pipes,
		WriterUserNamespace: &writer.Birth.UserNamespace, WriterUserNamespaceAbsent: true})
	if err != nil {
		return err
	}
	r.recordMu.Lock()
	defer r.recordMu.Unlock()
	p, complete, err := d.helperProperties(ctx, r)
	if err != nil {
		return err
	}
	if complete {
		if p.Absence == nil || p.Unit == nil || *p.Unit != r.unit {
			return errors.New("completed preparation has no immutable native settlement")
		}
		if err = validateUnitAbsenceEvidence(r.unit, r.pipes, p.MountNamespace, p.MountNamespaceDisposition, *p.Absence); err != nil {
			return err
		}
		var details UnitAbsenceDetails
		if err = gvxcontract.DecodeStrict(p.Absence.Details, 64<<10, 8, &details); err != nil {
			return err
		}
		if details.WriterUserNamespace == nil || *details.WriterUserNamespace != writer.Birth.UserNamespace || !details.WriterUserNamespaceAbsent {
			return errors.New("completed preparation lacks exact user namespace settlement")
		}
		return nil
	}
	p.Absence, p.CgroupEmpty, p.Writer = proof, true, writer
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err = d.store.ObserveProvision(ctx, r.intent, ObjectObservation{Identity: r.unit.Name, Attributes: raw}); err != nil {
		return err
	}
	d.mu.Lock()
	r.observation.Absence, r.observation.CgroupEmpty, r.observation.Writer = proof, true, writer
	d.mu.Unlock()
	return nil
}

func privateNamespaceReferencesAbsent(ctx context.Context, identity *NamespaceIdentity, kind string) error {
	if identity == nil || identity.Device == 0 || identity.Inode == 0 || (kind != "mnt" && kind != "user") {
		return errors.New("missing exact private namespace identity")
	}
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, process := range processes {
		pid, parseErr := strconv.Atoi(process.Name())
		if parseErr != nil {
			continue
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		before, err := processStart(pid)
		if err != nil {
			return errors.Join(sharedhost.ErrCleanupIncomplete, err)
		}
		base := filepath.Join("/proc", process.Name())
		tasks, err := os.ReadDir(filepath.Join(base, "task"))
		if err != nil {
			return errors.Join(sharedhost.ErrCleanupIncomplete, err)
		}
		for _, task := range tasks {
			var ns unix.Stat_t
			if err = unix.Stat(filepath.Join(base, "task", task.Name(), "ns", kind), &ns); err != nil {
				return errors.Join(sharedhost.ErrCleanupIncomplete, err)
			}
			if ns.Dev == identity.Device && ns.Ino == identity.Inode {
				return errors.New("owned private namespace still has a task reference")
			}
		}
		directory, err := os.Open(filepath.Join(base, "fd"))
		if err != nil {
			return errors.Join(sharedhost.ErrCleanupIncomplete, err)
		}
		fds, err := directory.ReadDir(-1)
		if err != nil {
			directory.Close()
			return errors.Join(sharedhost.ErrCleanupIncomplete, err)
		}
		target := kind + ":[" + strconv.FormatUint(identity.Inode, 10) + "]"
		var fdErr error
		for _, fd := range fds {
			path := filepath.Join(base, "fd", fd.Name())
			link, err := os.Readlink(path)
			if err != nil {
				fdErr = errors.Join(sharedhost.ErrCleanupIncomplete, err)
				break
			}
			if link == target {
				var ns unix.Stat_t
				if err = unix.Stat(path, &ns); err != nil {
					fdErr = errors.Join(sharedhost.ErrCleanupIncomplete, err)
					break
				}
				if ns.Dev == identity.Device && ns.Ino == identity.Inode {
					fdErr = errors.New("owned private namespace still has an FD reference")
					break
				}
			}
		}
		closeErr := directory.Close()
		if fdErr != nil || closeErr != nil {
			return errors.Join(fdErr, closeErr)
		}
		after, err := processStart(pid)
		if err != nil || before != after {
			return errors.Join(sharedhost.ErrCleanupIncomplete, err)
		}
	}
	return nil
}

// Recovery never reopens a historical descriptor number or resumes a gate.
// A fresh pidfd is scoped by the unchanged native invocation and process start.
func verifyRecoveredPreparation(u sharedhost.UnitIdentity, service OwnedService, writer PreparationWriterRecord) error {
	if writer.Birth == nil || writer.Birth.Unit != u {
		return errors.New("preparation recovery lacks its exact native birth")
	}
	fd, err := unix.PidfdOpen(u.MainPID, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	now, err := observePreparationBirth(u, service, fd)
	if err != nil {
		return err
	}
	before := *writer.Birth
	before.PIDFDDevice, before.PIDFDInode = now.PIDFDDevice, now.PIDFDInode
	if !samePreparationBirth(before, now) {
		return errors.New("preparation namespace or credentials changed during recovery")
	}
	minimum := writer.Birth.Tasks.SeccompFilters
	if writer.StartIntent {
		if writer.Evidence == nil || writer.Evidence.FilterDigest != gvxstage.PreparationFilterDigest() {
			return errors.New("preparation recovery has no approved filter evidence")
		}
		minimum = writer.Evidence.Tasks.SeccompFilters
		if now.Tasks.SeccompMode != 2 {
			return errors.New("preparation recovery lost seccomp confinement")
		}
	}
	if now.Tasks.SeccompFilters < minimum {
		return errors.New("preparation recovery lost its admitted filter chain")
	}
	return nil
}

// This exception only replays immutable COMPLETE native history for disposal.
// It grants neither a current writer-domain receipt nor target-start authority.
func (d *Systemd) completedLegacyPreparation(ctx context.Context, r *systemdReference) (bool, error) {
	if r.service.Program != bundle.Preparer && r.service.Program != bundle.Rungv {
		return false, nil
	}
	if r.intent != "systemd-"+r.unit.Generation || r.unit.Name != "chatanium-image-"+string(r.service.Program)+"-"+r.unit.Generation+".service" || !validUnit(r.unit) {
		return false, errors.New("legacy disposal has no exact historical helper identity")
	}
	records, err := d.store.UnitProvisions(ctx, r.unit.Name)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if record.ID != r.intent {
			continue
		}
		if record.Kind != "unit" || record.Identity != r.unit.Name || record.State != "OBSERVED" || record.CleanupState != "COMPLETE" || !record.ProductCreated || record.ExistedBefore {
			return false, errors.New("legacy preparation disposal requires immutable COMPLETE native history")
		}
		var desired, observed ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return false, err
		}
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return false, err
		}
		if desired.Source != string(r.service.Program) || desired.Unit == nil || observed.Unit == nil || *observed.Unit != r.unit || desired.Limits == nil || *desired.Limits != r.service.Limits || desired.Ownership == nil || desired.Ownership.RuntimeInstallationID != d.store.productID {
			return false, errors.New("legacy disposal lineage differs from its fixed historical native intent")
		}
		if desired.Unit.Name != r.unit.Name || desired.Unit.Generation != r.unit.Generation || desired.Unit.BootID != r.unit.BootID || desired.Unit.ExecutableDigest != r.unit.ExecutableDigest || desired.Unit.ResourceFingerprint != r.unit.ResourceFingerprint || observed.Rejection != "" || observed.Exit == nil && observed.Absence == nil {
			return false, errors.New("legacy disposal has no saved native artifact/outcome identity")
		}
		if observed.MountNamespace == nil || observed.MountNamespaceDisposition != NamespacePrivate || observed.MountNamespace.Device == 0 || observed.MountNamespace.Inode == 0 {
			return false, errors.New("legacy disposal lacks its saved private mount namespace")
		}
		if err = validateRetiredPreparationWriter(desired, observed, r.unit); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, errors.New("legacy native preparation history is missing")
}

func (d *Systemd) retirePreparationGate(ctx context.Context, r *systemdReference) error {
	manifest, err := d.store.Installation(ctx)
	if err != nil {
		return err
	}
	if !safeID(r.unit.Generation) {
		return errors.New("invalid settled preparation generation")
	}
	if err = os.RemoveAll(filepath.Join(manifest.Paths.RunRoot, "stages", r.unit.Generation)); err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.refs, r.unit.Name)
	delete(d.jobs, r.job)
	d.mu.Unlock()
	return nil
}

// Unsupported filter-v1 receipts are immutable disposal history, not current
// confinement. Validate their closed shape without relabeling any version or
// digest, and never use them for START, readiness, or namespace-absence claims.
func validateRetiredPreparationWriter(desired, observed ProvisionProperties, unit sharedhost.UnitIdentity) error {
	if desired.Writer == nil && observed.Writer == nil {
		return nil
	}
	if desired.Writer == nil || observed.Writer == nil {
		return errors.New("legacy writer receipt has an incomplete prefix")
	}
	intent, writer := desired.Writer, observed.Writer
	if intent.Birth != nil || intent.Evidence != nil || intent.StartIntent || intent.StartForbidden || intent.Launch != writer.Launch {
		return errors.New("legacy writer receipt differs from its original launch")
	}
	if observed.Unit == nil || *observed.Unit != unit {
		return errors.New("retired writer receipt differs from the saved native unit")
	}
	// A owns the exact historical v1 instruction digest and strict original
	// native-settlement shape. Never substitute the current digest/version.
	return validateUnsupportedPreparationWriterV1(observed)
}
