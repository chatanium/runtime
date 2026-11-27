//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxstage"
	"golang.org/x/sys/unix"
)

type stageGate struct {
	mu              sync.Mutex
	config          gvxstage.Config
	directory       string
	listener        *net.UnixListener
	conn            *net.UnixConn
	pidfd           int
	started, closed bool
}

func createStageGate(base string, c gvxstage.Config, gid uint32) (*stageGate, string, error) {
	c.GatePath = filepath.Join(base, "stages", c.Generation, "gate.sock")
	if err := gvxstage.Validate(c); err != nil {
		return nil, "", err
	}
	return createBoundStageGate(base, c, gid, c)
}

func createBoundStageGate(base string, c gvxstage.Config, gid uint32, document any) (*stageGate, string, error) {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base || !safeID(c.Generation) || gid == 0 {
		return nil, "", errors.New("invalid protected stage directory")
	}
	baseFD, e := unix.Openat2(unix.AT_FDCWD, base, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, "", e
	}
	defer unix.Close(baseFD)
	var st unix.Stat_t
	if e = unix.Fstat(baseFD, &st); e != nil {
		return nil, "", e
	}
	if st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, "", errors.New("unprotected stage base")
	}
	if e = unix.Mkdirat(baseFD, "stages", 0755); e != nil && !errors.Is(e, unix.EEXIST) {
		return nil, "", e
	}
	parentFD, e := unix.Openat(baseFD, "stages", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, "", e
	}
	defer unix.Close(parentFD)
	if e = unix.Fstat(parentFD, &st); e != nil {
		return nil, "", e
	}
	if st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, "", errors.New("unprotected stage parent")
	}
	if e = unix.Mkdirat(parentFD, c.Generation, 0750); e != nil {
		return nil, "", e
	}
	directory := filepath.Join(base, "stages", c.Generation)
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(directory)
		}
	}()
	if e = unix.Fchownat(parentFD, c.Generation, 0, int(gid), unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return nil, "", e
	}
	if e = os.Chmod(directory, 0750); e != nil {
		return nil, "", e
	}
	c.GatePath = filepath.Join(directory, "gate.sock")
	raw, e := json.Marshal(document)
	if e != nil {
		return nil, "", e
	}
	if len(raw) > gvxstage.MaxConfigBytes {
		return nil, "", errors.New("stage config exceeds bound")
	}
	path := filepath.Join(directory, "stage.json")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0640)
	if e != nil {
		return nil, "", e
	}
	if _, e = f.Write(raw); e == nil {
		e = f.Chown(0, int(gid))
	}
	if e == nil {
		e = f.Chmod(0440)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return nil, "", e
	}
	if closeErr != nil {
		return nil, "", closeErr
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: c.GatePath, Net: "unix"})
	if e != nil {
		return nil, "", e
	}
	listener.SetUnlinkOnClose(false)
	if e = os.Chown(c.GatePath, 0, int(gid)); e != nil {
		listener.Close()
		return nil, "", e
	}
	if e = os.Chmod(c.GatePath, 0660); e != nil {
		listener.Close()
		return nil, "", e
	}
	complete = true
	return &stageGate{config: c, directory: directory, listener: listener, pidfd: -1}, path, nil
}
func (g *stageGate) authenticate(ctx context.Context, d *Systemd, u UnitIdentity, s OwnedService) error {
	if e := g.acceptPeer(ctx, u, s); e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() { _ = g.close() })
	defer stop()
	g.mu.Lock()
	conn := g.conn
	g.mu.Unlock()
	m, e := gvxstage.ReadMessage(conn)
	if e != nil {
		return e
	}
	if !gvxstage.Matches(m, g.config) || m.Type != "READY" {
		return errors.New("stage READY binding mismatch")
	}
	observed, e := d.Observe(ctx, u)
	if e != nil {
		return e
	}
	if observed.Unit != u || observed.Exit != nil {
		return errors.New("stage invocation changed before gate")
	}
	if e = verifyServiceProcess(u, s, d); e != nil {
		return e
	}
	return nil
}
func verifyServiceProcess(u UnitIdentity, s OwnedService, d *Systemd) error {
	start, e := processStart(u.MainPID)
	if e != nil {
		return e
	}
	if start != u.StartTime {
		return errors.New("stage PID was reused")
	}
	_, _, _, digest, e := d.program(s.Program)
	if e != nil {
		return e
	}
	if s.preparation != nil {
		digest = s.preparation.stageDigest
	}
	if s.development != nil {
		digest = s.development.ExecutableDigest
	}
	actualDigest, e := hashFile(fmt.Sprintf("/proc/%d/exe", u.MainPID))
	if e != nil {
		return e
	}
	if actualDigest != digest {
		return errors.New("stage executable differs from verified program")
	}
	if e = verifyCgroups(u.MainPID, s.Limits); e != nil {
		return e
	}
	ns := fmt.Sprintf("/proc/%d/ns/net", u.MainPID)
	var actual, want unix.Stat_t
	if e = unix.Stat(ns, &actual); e != nil {
		return e
	}
	if s.NetworkNamespacePath != "" {
		if e = unix.Stat(s.NetworkNamespacePath, &want); e != nil {
			return e
		}
		if actual.Dev != want.Dev || actual.Ino != want.Ino {
			return errors.New("stage network namespace mismatch")
		}
	} else {
		if e = unix.Stat("/proc/1/ns/net", &want); e != nil {
			return e
		}
		shared := actual.Dev == want.Dev && actual.Ino == want.Ino
		if s.OfflinePreparation == shared {
			return errors.New("preparation network namespace differs from fixed purpose")
		}
	}
	var mounts, self unix.Stat_t
	if e = unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", u.MainPID), &mounts); e != nil {
		return e
	}
	if e = unix.Stat("/proc/self/ns/mnt", &self); e != nil {
		return e
	}
	if mounts.Ino == self.Ino && mounts.Dev == self.Dev {
		return errors.New("stage mount namespace is not private")
	}
	if s.RootDirectory != "" {
		var native, root unix.Stat_t
		if e = unix.Stat(s.RootDirectory, &native); e != nil {
			return e
		}
		if e = unix.Stat(fmt.Sprintf("/proc/%d/root", u.MainPID), &root); e != nil {
			return e
		}
		if native.Dev != root.Dev || native.Ino != root.Ino {
			return errors.New("stage root directory differs from owned view")
		}
		var control unix.Statfs_t
		if e = unix.Statfs(fmt.Sprintf("/proc/%d/root/sys/fs/cgroup", u.MainPID), &control); e != nil {
			return e
		}
		if control.Flags&unix.ST_RDONLY == 0 {
			return errors.New("stage cgroup filesystem remains writable")
		}
	}
	if e = verifyTaskAuthority(u, s); e != nil {
		return e
	}
	for _, m := range s.Mounts {
		path := fmt.Sprintf("/proc/%d/root%s", u.MainPID, m.Target)
		var src, dst unix.Stat_t
		if e = unix.Stat(m.Source, &src); e != nil {
			return e
		}
		if e = unix.Stat(path, &dst); e != nil {
			return e
		}
		if src.Dev != dst.Dev || src.Ino != dst.Ino {
			return errors.New("stage bind mount identity mismatch")
		}
		if m.ReadOnly {
			var fs unix.Statfs_t
			if e = unix.Statfs(path, &fs); e != nil {
				return e
			}
			if fs.Flags&unix.ST_RDONLY == 0 {
				return errors.New("stage readonly bind is writable")
			}
		}
	}
	return nil
}
func (g *stageGate) start() error {
	g.mu.Lock()
	if g.started || g.closed || g.conn == nil {
		g.mu.Unlock()
		return errors.New("stage gate already released or unconnected")
	}
	if _, e := gvxstage.Deadline(g.config); e != nil {
		g.mu.Unlock()
		return e
	}
	g.started = true
	conn := g.conn
	g.conn = nil
	g.mu.Unlock()
	e := gvxstage.WriteMessage(conn, gvxstage.Message{Version: 1, Type: "START", EpochID: g.config.EpochID, InstanceID: g.config.InstanceID, Generation: g.config.Generation})
	closeErr := conn.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func (g *stageGate) close() error {
	g.mu.Lock()
	g.closed = true
	conn, listener, pidfd := g.conn, g.listener, g.pidfd
	g.conn = nil
	g.listener = nil
	g.pidfd = -1
	g.mu.Unlock()
	var all []error
	if conn != nil {
		all = append(all, conn.Close())
	}
	if listener != nil {
		all = append(all, listener.Close())
	}
	if pidfd >= 0 {
		all = append(all, unix.Close(pidfd))
	}
	return errors.Join(all...)
}
func stageEnvironment(tmp string) []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "TMPDIR=" + tmp, "LANG=C", "LC_ALL=C"}
}
func remainingStartup(l Lease) (time.Duration, error) {
	now, e := gvxstage.BootNS()
	if e != nil {
		return 0, e
	}
	remaining := time.Duration(l.StartupDeadlineBootNS - now)
	if remaining <= 0 || remaining > time.Hour {
		return 0, errors.New("invalid shared startup budget")
	}
	return remaining, nil
}
func verifyTaskAuthority(u UnitIdentity, s OwnedService) error {
	tasks, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", u.MainPID))
	if e != nil {
		return e
	}
	if len(tasks) == 0 {
		return errors.New("service has no observed tasks")
	}
	for _, task := range tasks {
		path := fmt.Sprintf("/proc/%d/task/%s/status", u.MainPID, task.Name())
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		fields := map[string][]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok {
				fields[k] = strings.Fields(v)
			}
		}
		for _, k := range []string{"Uid", "Gid"} {
			values := fields[k]
			if len(values) != 4 {
				return errors.New("missing task credentials")
			}
			id := s.Identity.UID
			if k == "Gid" {
				id = s.Identity.GID
			}
			for _, v := range values {
				if v != strconv.FormatUint(uint64(id), 10) {
					return errors.New("task credentials differ from dedicated identity")
				}
			}
		}
		for _, v := range fields["Groups"] {
			if v != strconv.FormatUint(uint64(s.Identity.GID), 10) {
				return errors.New("task has supplementary authority")
			}
		}
		for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			values := fields[k]
			if len(values) != 1 {
				return errors.New("missing task capability evidence")
			}
			bits, e := strconv.ParseUint(values[0], 16, 64)
			if e != nil || bits != 0 {
				return errors.New("nonzero nonroot service capabilities")
			}
		}
		if strings.Join(fields["NoNewPrivs"], "") != "1" {
			return errors.New("service lacks no-new-privileges")
		}
		cg, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/cgroup", u.MainPID, task.Name()))
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(cg)) != "0::"+u.CgroupPath {
			return errors.New("task escaped owned cgroup")
		}
	}
	return nil
}

type preparationGate struct {
	gate        *stageGate
	config      gvxstage.PreparationConfig
	stagePath   string
	stageDigest string
	launch      PreparationWriterLaunch
}

func (d *Systemd) newPreparationGate(ctx context.Context, s OwnedService) (*preparationGate, error) {
	if s.Program != bundle.Preparer && s.Program != bundle.Rungv {
		return nil, errors.New("only fixed preparation programs may use the helper gate")
	}
	if s.Identity.UID == 0 || s.Identity.GID == 0 {
		return nil, errors.New("preparation gate requires the installed nonroot preparer")
	}
	if s.preparationContext == nil {
		return nil, errors.New("preparation gate has no owned storage context")
	}
	target, _, _, digest, e := d.program(s.Program)
	if e != nil {
		return nil, e
	}
	if target.Interpreter != "" {
		return nil, errors.New("preparation executable must be the verified static program")
	}
	stage, _, _, stageDigest, e := d.program(bundle.Stage)
	if e != nil {
		return nil, e
	}
	if stage.Interpreter != "" {
		return nil, errors.New("preparation gate must be static")
	}
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return nil, errors.New("preparation gate requires bound store")
	}
	manifest, e := store.Installation(ctx)
	if e != nil {
		return nil, e
	}
	duration := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		duration = time.Until(deadline)
	}
	if duration <= 0 || duration > time.Hour {
		return nil, errors.New("invalid preparation gate deadline")
	}
	now, e := gvxstage.BootNS()
	if e != nil {
		return nil, e
	}
	executable := filepath.Join("/chatanium/base", target.Path)
	argv := []string{executable}
	if len(s.Argv) > 0 {
		argv = append(argv, s.Argv[1:]...)
	}
	purpose := gvxstage.PreparationPurpose
	if s.Program == bundle.Rungv {
		purpose = gvxstage.LoadPurpose
	}
	config := gvxstage.PreparationConfig{Version: gvxcontract.PreparationWriterProtocolVersion, WriterDomainVersion: gvxcontract.PreparationWriterDomainVersion, FilterVersion: gvxcontract.PreparationWriterFilterVersion, Purpose: purpose, RuntimeInstallationID: store.productID, Generation: s.Generation, GatePath: "/chatanium/gate/gate.sock", Executable: executable, ExecutableDigest: digest, Workdir: s.WorkingDirectory, Argv: argv, Env: append(d.programEnvironment(target), s.Env...), DeadlineBootNS: now + int64(duration)}
	if e = gvxstage.ValidatePreparation(config); e != nil {
		return nil, e
	}
	gate, _, e := createBoundStageGate(manifest.Paths.RunRoot, config.Binding(), s.Identity.GID, config)
	if e != nil {
		return nil, e
	}
	p := &preparationGate{gate: gate, config: config, stagePath: filepath.Join("/chatanium/base", stage.Path), stageDigest: stageDigest}
	p.launch = d.preparationLaunch(s, p)
	return p, nil
}

func (d *Systemd) preparationConfig(ctx context.Context, generation string) (gvxstage.PreparationConfig, error) {
	var result gvxstage.PreparationConfig
	if !safeID(generation) {
		return result, errors.New("invalid preparation generation")
	}
	manifest, e := d.store.Installation(ctx)
	if e != nil {
		return result, e
	}
	return gvxstage.ReadPreparationDeclaration(filepath.Join(manifest.Paths.RunRoot, "stages", generation, "stage.json"))
}

func (d *Systemd) recoverPreparationUnit(ctx context.Context, name, generation string, program bundle.ProgramID, limits ResourceLimits, description string, props map[string]dbus.Variant) (UnitObservation, error) {
	config, e := d.preparationConfig(ctx, generation)
	if e != nil {
		return UnitObservation{}, e
	}
	target, _, _, targetDigest, e := d.program(program)
	if e != nil {
		return UnitObservation{}, e
	}
	stage, _, _, stageDigest, e := d.program(bundle.Stage)
	if e != nil {
		return UnitObservation{}, e
	}
	purpose := gvxstage.PreparationPurpose
	if program == bundle.Rungv {
		purpose = gvxstage.LoadPurpose
	}
	if target.Interpreter != "" || stage.Interpreter != "" || config.RuntimeInstallationID != d.store.productID || config.Generation != generation || config.Purpose != purpose || config.Executable != filepath.Join("/chatanium/base", target.Path) || config.ExecutableDigest != targetDigest {
		return UnitObservation{}, errors.New("preparation recovery target binding changed")
	}
	privateUsers, e := variant[bool](props, "PrivateUsers")
	if e != nil || !privateUsers {
		return UnitObservation{}, errors.New("preparation lost mandatory private users")
	}
	writer, e := d.store.PreparationWriter(ctx, "systemd-"+generation)
	if e != nil {
		return UnitObservation{}, e
	}
	if writer.Launch.InstallationID != d.store.productID || writer.Launch.UnitName != name || writer.Launch.Generation != generation || writer.Launch.BootID != d.boot || writer.Launch.BundleDigest != d.bundle.Digest || writer.Launch.Purpose != purpose || writer.Launch.StageDigest != stageDigest || writer.Launch.TargetDigest != targetDigest || writer.Launch.TargetPath != config.Executable || writer.Launch.FilterVersion != config.FilterVersion || writer.Launch.FilterVersion != gvxcontract.PreparationWriterFilterVersion || writer.Launch.DeclarationDigest != preparationDigest(config) {
		return UnitObservation{}, errors.New("preparation recovery lacks its exact immutable launch")
	}
	var commands []systemdExecObservation
	exec, ok := props["ExecStart"]
	if !ok {
		return UnitObservation{}, errors.New("preparation ExecStart missing")
	}
	if e = dbus.Store([]interface{}{exec.Value()}, &commands); e != nil || len(commands) != 1 {
		return UnitObservation{}, errors.New("preparation ExecStart type changed")
	}
	stagePath := filepath.Join("/chatanium/base", stage.Path)
	command := commands[0]
	if command.Path != stagePath || command.IgnoreFailure || len(command.Args) != 3 || command.Args[0] != stagePath || command.Args[1] != "--prepare" || command.Args[2] != "/chatanium/gate/stage.json" {
		return UnitObservation{}, errors.New("preparation gate command changed")
	}
	env, e := variant[[]string](props, "Environment")
	if e != nil {
		return UnitObservation{}, e
	}
	if !sameGateStrings(env, config.Env) {
		return UnitObservation{}, errors.New("preparation environment changed")
	}
	baseEnv := d.programEnvironment(target)
	if len(env) < len(baseEnv) || !sameGateStrings(env[:len(baseEnv)], baseEnv) {
		return UnitObservation{}, errors.New("preparation closure environment changed")
	}
	offline, e := variant[bool](props, "PrivateNetwork")
	if e != nil {
		return UnitObservation{}, e
	}
	cwd, e := variant[string](props, "WorkingDirectory")
	if e != nil || cwd != config.Workdir {
		return UnitObservation{}, errors.New("preparation working directory changed")
	}
	manifest, e := d.store.Installation(ctx)
	if e != nil {
		return UnitObservation{}, e
	}
	gate := &preparationGate{config: config, stagePath: stagePath, stageDigest: stageDigest, launch: writer.Launch, gate: &stageGate{directory: filepath.Join(manifest.Paths.RunRoot, "stages", generation), pidfd: -1, closed: true}}
	service := OwnedService{Name: name, Generation: generation, Program: program, Argv: append([]string{""}, config.Argv[1:]...), Env: env[len(baseEnv):], Limits: limits, WorkingDirectory: config.Workdir, Identity: manifest.Identities.Preparer, OfflinePreparation: offline, preparation: gate}
	if writer.Launch.PreparerUID != service.Identity.UID || writer.Launch.PreparerGID != service.Identity.GID || writer.Launch.StagePath != stagePath {
		return UnitObservation{}, errors.New("preparation recovery role or stage path changed")
	}
	if description != serviceDescription(service, d.bundle.Digest) {
		return UnitObservation{}, errors.New("preparation launch fingerprint changed")
	}
	base := UnitIdentity{Name: name, Generation: generation, BootID: d.boot, ExecutableDigest: stageDigest, ResourceFingerprint: launchFingerprint(service, d.bundle.Digest)}
	records, e := d.store.UnitProvisions(ctx, name)
	if e != nil {
		return UnitObservation{}, e
	}
	intent := ""
	var pipes []string
	for _, record := range records {
		if !strings.HasPrefix(record.ID, "systemd-") {
			continue
		}
		var desired ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return UnitObservation{}, e
		}
		if desired.Unit != nil && desired.Unit.Generation == generation && desired.Source == string(program) && desired.Unit.ResourceFingerprint == base.ResourceFingerprint && desired.Unit.ExecutableDigest == stageDigest {
			intent = record.ID
			pipes = desired.TransportPipes
			if desired.Ownership != nil {
				service.Ownership = *desired.Ownership
			}
			break
		}
	}
	if intent == "" {
		return UnitObservation{}, ErrCreateUnresolved
	}
	observed, e := d.Observe(ctx, base)
	if e != nil {
		return observed, e
	}
	observed.Writer = &writer
	if writer.Birth != nil && writer.Birth.Unit != observed.Unit {
		return observed, errors.New("preparation recovery invocation differs from recorded birth")
	}
	if observed.Exit == nil {
		actual, e := hashFile(fmt.Sprintf("/proc/%d/exe", observed.Unit.MainPID))
		if e != nil {
			return observed, e
		}
		if actual != stageDigest && actual != targetDigest {
			return observed, errors.New("preparation executable left the authenticated transition")
		}
		if e = verifyCgroups(observed.Unit.MainPID, limits); e != nil {
			return observed, e
		}
	}
	if writer.Birth != nil && !writer.StartIntent && !writer.StartForbidden {
		if e = d.store.ForbidPreparationWriterStart(ctx, intent, *writer.Birth); e != nil {
			return observed, e
		}
		writer.StartForbidden = true
	}
	if observed.Exit == nil && writer.Birth != nil {
		if e = verifyRecoveredPreparation(observed.Unit, service, writer); e != nil {
			return observed, e
		}
	}
	d.mu.Lock()
	held := d.refs[name]
	d.mu.Unlock()
	if held == nil {
		if e = d.manager.CallWithContext(ctx, systemdInterface+".Manager.RefUnit", 0, name).Err; e != nil {
			return observed, e
		}
		held = &systemdReference{unit: observed.Unit, service: service, observation: observed, terminal: observed.Exit, acquired: true, intent: intent, pipes: pipes}
		d.mu.Lock()
		d.refs[name] = held
		d.mu.Unlock()
	} else {
		if held.unit.InvocationID != "" && held.unit != observed.Unit {
			return observed, errors.New("preparation invocation replacement forbidden")
		}
		d.mu.Lock()
		held.unit = observed.Unit
		held.observation = observed
		held.service = service
		held.intent = intent
		held.pipes = pipes
		d.mu.Unlock()
	}
	return observed, nil
}

func sameGateStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
