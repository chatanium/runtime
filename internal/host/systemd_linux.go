//go:build linux

package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

const systemdInterface = "org.freedesktop.systemd1"
const cpuPeriodUSec uint64 = 100000

type StandardFiles struct{ Stdin, Stdout, Stderr *os.File }
type OwnedMount struct {
	Source, Target string
	ReadOnly       bool
}
type OwnedService struct {
	Owner                                                 UnitIdentity
	Ownership                                             Ownership
	Name, Generation                                      string
	Program                                               bundle.ProgramID
	Argv, Env                                             []string
	Identity                                              NumericIdentity
	Limits                                                ResourceLimits
	WorkingDirectory, NetworkNamespacePath, RootDirectory string
	OfflinePreparation                                    bool
	Mounts                                                []OwnedMount
	TimeoutStop                                           time.Duration
	development                                           *developmentInvocation
	preparation                                           *preparationGate
	preparationContext                                    *preparationContext
}
type systemdProperty struct {
	Name  string
	Value dbus.Variant
}
type systemdAux struct {
	Name       string
	Properties []systemdProperty
}
type systemdExec struct {
	Path          string
	Args          []string
	IgnoreFailure bool
}
type systemdBind struct {
	Source, Target string
	IgnoreMissing  bool
	Flags          uint64
}
type systemdTemporaryFS struct{ Path, Options string }
type systemdJob struct {
	ID       uint32
	Unit     string
	Type     string
	State    string
	Path     dbus.ObjectPath
	UnitPath dbus.ObjectPath
}
type systemdUnit struct {
	Name, Description, LoadState, ActiveState, SubState, Following string
	Path                                                           dbus.ObjectPath
	JobID                                                          uint32
	JobType                                                        string
	JobPath                                                        dbus.ObjectPath
}
type systemdJobResult struct{ Unit, Result string }
type systemdReference struct {
	releaseMu                                               sync.Mutex
	recordMu                                                sync.Mutex
	unit                                                    UnitIdentity
	service                                                 OwnedService
	observation                                             UnitObservation
	job                                                     dbus.ObjectPath
	acquired, released, recorded, connectionLost, oomKilled bool
	terminal                                                *ProcessExit
	done                                                    chan struct{}
	terminalErr                                             error
	intent                                                  string
	pipes                                                   []string
	rejection                                               string
}
type Systemd struct {
	conn                    atomic.Pointer[dbus.Conn]
	manager                 systemdManager
	reconnect               sync.Mutex
	admissionClosed, closed atomic.Bool
	bundle                  bundle.Verified
	boot                    string
	mu                      sync.Mutex
	owner                   UnitIdentity
	store                   *Store
	refs                    map[string]*systemdReference
	jobs                    map[dbus.ObjectPath]systemdJobResult
	signals                 chan *dbus.Signal
	changed                 chan struct{}
}

func NewSystemd(ctx context.Context, verified bundle.Verified) (*Systemd, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("systemd authority requires root")
	}
	verified, err := bundle.VerifyDirectory(ctx, verified.Root, verified.Manifest)
	if err != nil {
		return nil, err
	}
	conn, err := dbus.Dial("unix:path=/run/systemd/private")
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Systemd, error) { conn.Close(); return nil, e }
	if err = conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
		return fail(err)
	}
	if !conn.SupportsUnixFDs() {
		return fail(errors.New("systemd connection did not negotiate Unix FD passing"))
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fail(err)
	}
	d := &Systemd{bundle: verified, boot: strings.TrimSpace(string(boot)), refs: make(map[string]*systemdReference), jobs: make(map[dbus.ObjectPath]systemdJobResult), signals: make(chan *dbus.Signal, 128), changed: make(chan struct{}, 1)}
	d.conn.Store(conn)
	d.manager = systemdManager{d}
	conn.Signal(d.signals)
	if err = d.manager.CallWithContext(ctx, systemdInterface+".Manager.Subscribe", 0).Err; err != nil {
		return fail(err)
	}
	go d.signalLoop()
	return d, nil
}
func (d *Systemd) Close() error { d.closed.Store(true); return d.conn.Load().Close() }
func (d *Systemd) BindStore(s *Store) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s == nil || d.store != nil && d.store != s {
		return errors.New("systemd store rebinding forbidden")
	}
	d.store = s
	return nil
}
func (d *Systemd) Owner() UnitIdentity { d.mu.Lock(); defer d.mu.Unlock(); return d.owner }
func (d *Systemd) connected() error {
	if !d.conn.Load().Connected() {
		d.admissionClosed.Store(true)
		return errors.New("systemd disconnected; admission closed")
	}
	return nil
}
func property(name string, value any) systemdProperty {
	return systemdProperty{name, dbus.MakeVariant(value)}
}
func finiteLimits(r ResourceLimits) (uint64, error) {
	if r.NanoCPUs <= 0 || r.NanoCPUs%1000 != 0 || r.MemoryBytes <= 0 || r.MemoryBytes%int64(os.Getpagesize()) != 0 || r.Pids <= 0 || r.Pids == math.MaxInt64 {
		return 0, errors.New("finite exactly representable CPU/memory/task limits required")
	}
	if r.NanoCPUs > math.MaxInt64/int64(cpuPeriodUSec) || r.NanoCPUs*int64(cpuPeriodUSec)%1000000000 != 0 || r.NanoCPUs*int64(cpuPeriodUSec)/1000000000 < 1000 {
		return 0, errors.New("CPU quota cannot be represented without upward rounding")
	}
	return uint64(r.NanoCPUs / 1000), nil
}
func cleanAbsolute(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\n\r")
}
func unitName(s string) bool {
	if len(s) > 240 || (!strings.HasSuffix(s, ".service") && !strings.HasSuffix(s, ".scope")) {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-", c)) {
			return false
		}
	}
	return true
}
func randomGeneration() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func resourceFingerprint(r ResourceLimits) string {
	raw, _ := json.Marshal(r)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (d *Systemd) program(id bundle.ProgramID) (bundle.Program, string, []string, string, error) {
	p, e := d.bundle.Program(id)
	if e != nil {
		return p, "", nil, "", e
	}
	path := filepath.Join(d.bundle.Root, p.Path)
	exe := path
	prefix := []string{path}
	target := p.Path
	if p.Interpreter != "" {
		target = p.Interpreter
		exe = filepath.Join(d.bundle.Root, p.Interpreter)
		prefix = []string{exe, "--inhibit-cache"}
		if len(p.LibraryDirectories) > 0 {
			dirs := make([]string, len(p.LibraryDirectories))
			for i, v := range p.LibraryDirectories {
				dirs[i] = filepath.Join(d.bundle.Root, v)
			}
			prefix = append(prefix, "--library-path", strings.Join(dirs, ":"))
		}
		prefix = append(prefix, path)
	}
	var digest string
	for _, f := range d.bundle.Manifest.Files {
		if f.Path == target {
			digest = f.Digest
			break
		}
	}
	if digest == "" {
		return p, "", nil, "", errors.New("actual executable not in verified inventory")
	}
	return p, exe, prefix, digest, nil
}

// purposePolicy is trusted host-only policy, never a capability field in RPC.
func purposePolicy(s OwnedService) (uint64, error) {
	if len(s.Argv) > 512 {
		return 0, errors.New("too many helper arguments")
	}
	total := 0
	for _, a := range s.Argv {
		total += len(a)
		if strings.ContainsRune(a, 0) {
			return 0, errors.New("NUL argument")
		}
	}
	if total > 128<<10 {
		return 0, errors.New("helper arguments too large")
	}
	switch s.Program {
	case bundle.Worker, bundle.Stage, bundle.Preparer:
		if s.Identity.UID == 0 || s.Identity.GID == 0 {
			return 0, errors.New("nonroot role requires dedicated identity")
		}
		return 0, nil
	case bundle.Rungv:
		if s.Identity.UID == 0 || s.Identity.GID == 0 || len(s.Argv) < 2 || s.Argv[1] != "load" {
			return 0, errors.New("only nonroot bounded rungv load service is allowed")
		}
		return 0, nil
	case bundle.IP, bundle.IPTables, bundle.IP6Tables, bundle.Conntrack:
		if s.RootDirectory != "" || len(s.Mounts) != 0 || s.OfflinePreparation {
			return 0, errors.New("network helper cannot create a private mount view")
		}
		if s.Identity.UID != 0 {
			return 0, errors.New("network helper must be root")
		}
		if s.Program == bundle.IP {
			for _, arg := range s.Argv[1:] {
				if arg == "netns" || arg == "exec" || arg == "-n" || arg == "-netns" || arg == "--netns" || strings.HasPrefix(arg, "-netns=") || strings.HasPrefix(arg, "--netns=") {
					return 0, errors.New("network namespace ownership is native, not an ip subcommand")
				}
			}
		}
		return uint64(1)<<unix.CAP_NET_ADMIN | uint64(1)<<unix.CAP_NET_RAW, nil
	case bundle.MkfsXFS:
		if s.Identity.UID != 0 || len(s.Argv) < 8 {
			return 0, errors.New("invalid format helper")
		}
		for _, a := range s.Argv[1:] {
			if a == "-f" || strings.HasPrefix(a, "/dev/") {
				return 0, errors.New("format overwrite or block device forbidden")
			}
		}
		return uint64(1)<<unix.CAP_SYS_ADMIN | uint64(1)<<unix.CAP_DAC_OVERRIDE, nil
	case bundle.XFSQuota:
		return 0, errors.New("quota helper is not used; quota authority uses quotactl_fd")
	case bundle.ProgramID("useradd"), bundle.ProgramID("groupadd"), bundle.ProgramID("userdel"), bundle.ProgramID("groupdel"):
		if s.Identity.UID != 0 {
			return 0, errors.New("account helper must be root")
		}
		if e := validateAccountCommand(s.Program, s.Argv); e != nil {
			return 0, e
		}
		return uint64(1)<<unix.CAP_CHOWN | uint64(1)<<unix.CAP_DAC_OVERRIDE | uint64(1)<<unix.CAP_FOWNER | uint64(1)<<unix.CAP_SETUID | uint64(1)<<unix.CAP_SETGID, nil
	default:
		return 0, errors.New("unknown service purpose")
	}
}
func validateAccountCommand(id bundle.ProgramID, args []string) error {
	name := func(s string) bool {
		if s == "" || len(s) > 31 {
			return false
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
		return true
	}
	number := func(s string) bool {
		n, e := strconv.ParseUint(s, 10, 32)
		return e == nil && n > 0 && strconv.FormatUint(n, 10) == s
	}
	valid := false
	switch string(id) {
	case "groupadd":
		valid = len(args) == 5 && args[1] == "--system" && args[2] == "--gid" && number(args[3]) && name(args[4])
	case "useradd":
		valid = len(args) == 12 && args[1] == "--system" && args[2] == "--uid" && number(args[3]) && args[4] == "--gid" && number(args[5]) && args[6] == "--no-create-home" && args[7] == "--home-dir" && args[8] == "/nonexistent" && args[9] == "--shell" && args[10] == "/usr/sbin/nologin" && name(args[11])
	case "userdel", "groupdel":
		valid = len(args) == 2 && name(args[1])
	}
	if !valid {
		return errors.New("account command does not match static identity purpose")
	}
	return nil
}
func (d *Systemd) serviceProperties(s OwnedService, f StandardFiles) ([]systemdProperty, string, error) {
	quota, e := finiteLimits(s.Limits)
	if e != nil {
		return nil, "", e
	}
	caps, e := purposePolicy(s)
	if e != nil {
		return nil, "", e
	}
	if !unitName(s.Name) || !strings.HasSuffix(s.Name, ".service") || s.Generation == "" || s.Owner.Name == "" || !unitName(s.Owner.Name) || s.TimeoutStop <= 0 || s.TimeoutStop%time.Microsecond != 0 || !cleanAbsolute(s.WorkingDirectory) {
		return nil, "", errors.New("invalid owned service identity or paths")
	}
	p, exe, args, digest, e := d.program(s.Program)
	if e != nil {
		return nil, "", e
	}
	if s.development != nil {
		if s.Program != bundle.Worker {
			return nil, "", errors.New("development override is worker-only")
		}
		exe = s.development.Executable
		args = append([]string(nil), s.development.Argv...)
		digest = s.development.ExecutableDigest
	}
	if len(s.Argv) > 0 {
		args = append(args, s.Argv[1:]...)
	}
	if s.preparation != nil {
		exe = s.preparation.stagePath
		args = []string{exe, "--prepare", "/chatanium/gate/stage.json"}
		digest = s.preparation.stageDigest
	}
	env := d.programEnvironment(p)
	env = append(env, s.Env...)
	seen := map[string]bool{}
	for _, v := range env {
		k, _, ok := strings.Cut(v, "=")
		if !ok || k == "" || seen[k] || strings.ContainsAny(v, "\x00\n\r") || strings.HasPrefix(k, "LD_") || strings.HasPrefix(k, "GVX_") {
			return nil, "", errors.New("invalid service environment")
		}
		seen[k] = true
	}
	props := []systemdProperty{property("Description", serviceDescription(s, d.bundle.Digest)), property("Type", "exec"), property("Restart", "no"), property("AddRef", true), property("KillMode", "control-group"), property("SendSIGKILL", true), property("TimeoutStopUSec", uint64(s.TimeoutStop/time.Microsecond)), property("BindsTo", []string{s.Owner.Name}), property("After", []string{s.Owner.Name}), property("MemoryMax", uint64(s.Limits.MemoryBytes)), property("MemorySwapMax", uint64(0)), property("TasksMax", uint64(s.Limits.Pids)), property("CPUQuotaPerSecUSec", quota), property("CPUQuotaPeriodUSec", cpuPeriodUSec), property("Delegate", false), property("User", strconv.FormatUint(uint64(s.Identity.UID), 10)), property("Group", strconv.FormatUint(uint64(s.Identity.GID), 10)), property("SupplementaryGroups", []string{}), property("CapabilityBoundingSet", caps), property("AmbientCapabilities", uint64(0)), property("NoNewPrivileges", true), property("WorkingDirectory", s.WorkingDirectory), property("Environment", env), property("ExecStart", []systemdExec{{exe, args, false}})}
	props = append(props, property("CollectMode", "inactive-or-failed"), property("PrivateMounts", true), property("ProtectControlGroups", true))
	if s.RootDirectory != "" {
		props = append(props, property("MountAPIVFS", true))
	}
	if s.Program == bundle.Preparer || s.Program == bundle.Rungv {
		props = append(props, property("TemporaryFileSystem", []systemdTemporaryFS{{"/chatanium", "ro,mode=0755"}}))
		props = append(props, property("PrivateUsers", true))
	}
	if s.Identity.UID != 0 {
		props = append(props, property("ProtectSystem", "strict"), property("ProtectHome", "yes"))
	}
	if s.NetworkNamespacePath != "" {
		if !cleanAbsolute(s.NetworkNamespacePath) {
			return nil, "", errors.New("invalid network namespace path")
		}
		props = append(props, property("NetworkNamespacePath", s.NetworkNamespacePath))
	}
	if s.RootDirectory != "" {
		if !cleanAbsolute(s.RootDirectory) {
			return nil, "", errors.New("invalid private service root")
		}
		props = append(props, property("RootDirectory", s.RootDirectory))
	}
	var ro, rw []systemdBind
	for _, m := range s.Mounts {
		if !cleanAbsolute(m.Source) || !cleanAbsolute(m.Target) {
			return nil, "", errors.New("invalid service bind")
		}
		b := systemdBind{Source: m.Source, Target: m.Target}
		if m.ReadOnly {
			ro = append(ro, b)
		} else {
			rw = append(rw, b)
		}
	}
	if s.preparation != nil {
		ro = append(ro, systemdBind{Source: s.preparation.gate.directory, Target: "/chatanium/gate"})
	}
	if len(ro) > 0 {
		props = append(props, property("BindReadOnlyPaths", ro))
	}
	if len(rw) > 0 {
		props = append(props, property("BindPaths", rw))
	}
	for _, v := range []struct {
		name string
		file *os.File
	}{{"StandardInputFileDescriptor", f.Stdin}, {"StandardOutputFileDescriptor", f.Stdout}, {"StandardErrorFileDescriptor", f.Stderr}} {
		if v.file == nil {
			return nil, "", errors.New("three explicit stdio descriptors required")
		}
		props = append(props, property(v.name, dbus.UnixFD(v.file.Fd())))
	}
	return props, digest, nil
}
func (d *Systemd) StartOwned(ctx context.Context, s OwnedService, f StandardFiles) (observed UnitObservation, err error) {
	dispatched := false
	var ref *systemdReference
	var preparation *preparationGate
	defer func() {
		if preparation != nil {
			_ = preparation.gate.close()
			if !dispatched {
				_ = os.RemoveAll(preparation.gate.directory)
			}
		}
	}()
	defer func() {
		if err == nil {
			return
		}
		if !dispatched {
			err = &notSubmitted{err}
		}
		rejection := systemdRejection(err)
		if ref != nil && rejection != "" {
			d.mu.Lock()
			ref.rejection = rejection
			ref.released = true
			ref.recorded = true
			d.mu.Unlock()
			if ref.intent != "" {
				cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err = errors.Join(err, d.observeHelperRecord(cleanup, ref, nil, rejection))
				cancel()
			}
		} else if ref != nil && dispatched {
			go d.observeUncertain(ref)
		}
	}()
	if (s.Program == bundle.Preparer || s.Program == bundle.Rungv) && s.preparationContext == nil {
		return observed, errors.New("fixed preparation services require StartPreparation")
	}
	if e := d.validateOwnedPurpose(ctx, s); e != nil {
		return observed, e
	}
	if e := d.connected(); e != nil {
		return observed, e
	}
	if s.OfflinePreparation {
		if e := d.validateOffline(ctx, s); e != nil {
			return observed, e
		}
	}
	if s.Program == bundle.Preparer || s.Program == bundle.Rungv {
		var e error
		preparation, e = d.newPreparationGate(ctx, s)
		if e != nil {
			return observed, e
		}
		s.preparation = preparation
	}
	props, digest, e := d.serviceProperties(s, f)
	if e != nil {
		return observed, e
	}
	if _, e = d.Observe(ctx, s.Owner); e != nil {
		return observed, fmt.Errorf("owner identity: %w", e)
	}
	if d.admissionClosed.Load() && (s.Program == bundle.Stage || s.Program == bundle.Worker || s.Program == bundle.Preparer || s.Program == bundle.Rungv) {
		return observed, errors.New("systemd admission remains closed after disconnect")
	}
	if s.OfflinePreparation {
		props = append(props, property("PrivateNetwork", true))
	}
	unset, e := d.unsetEnvironment(ctx, s)
	if e != nil {
		return observed, e
	}
	props = append(props, property("UnsetEnvironment", unset))
	if s.Program != bundle.Stage && s.Program != bundle.Worker {
		duration := 30 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			duration = time.Until(deadline)
		}
		if duration <= 0 {
			return observed, context.DeadlineExceeded
		}
		if duration > time.Hour {
			return observed, errors.New("helper deadline exceeds finite ceiling")
		}
		props = append(props, property("RuntimeMaxUSec", uint64(duration/time.Microsecond)))
	}
	base := UnitIdentity{Name: s.Name, Generation: s.Generation, BootID: d.boot, ExecutableDigest: digest, ResourceFingerprint: launchFingerprint(s, d.bundle.Digest)}
	ref = &systemdReference{service: s, unit: base}
	d.mu.Lock()
	store := d.store
	if store == nil || s.Owner != d.owner {
		d.mu.Unlock()
		ref = nil
		return observed, errors.New("owned service requires bound store and exact live owner")
	}
	if _, ok := d.refs[s.Name]; ok {
		d.mu.Unlock()
		ref = nil
		return observed, ErrCreateAlreadySubmitted
	}
	d.refs[s.Name] = ref
	d.mu.Unlock()
	if s.Ownership.RuntimeInstallationID == "" {
		s.Ownership.RuntimeInstallationID = store.productID
	}
	if s.Ownership.RuntimeInstallationID != store.productID {
		return observed, errors.New("helper product ownership mismatch")
	}
	if s.Ownership.InstanceID != "" {
		if e = store.creationOwner(ctx, s.Ownership); e != nil {
			return observed, e
		}
	}
	ref.service = s
	for _, file := range []*os.File{f.Stdin, f.Stdout, f.Stderr} {
		var st unix.Stat_t
		if e = unix.Fstat(int(file.Fd()), &st); e != nil {
			return observed, e
		}
		if st.Mode&unix.S_IFMT == unix.S_IFIFO {
			target, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
			if e != nil {
				return observed, e
			}
			found := false
			for _, pipe := range ref.pipes {
				if pipe == target {
					found = true
				}
			}
			if !found {
				ref.pipes = append(ref.pipes, target)
			}
		}
	}
	intent := "systemd-" + s.Generation
	revision := ""
	if s.development != nil {
		revision = s.development.Revision
	}
	var writer *PreparationWriterRecord
	if preparation != nil {
		if e = d.verifyPreparationLayout(ctx, s); e != nil {
			return observed, e
		}
		writer = &PreparationWriterRecord{Launch: preparation.launch}
	}
	desired, _ := json.Marshal(ProvisionProperties{Name: s.Name, Unit: &base, Source: string(s.Program), Revision: revision, Limits: &s.Limits, Ownership: &s.Ownership, TransportPipes: ref.pipes, ProductCreated: true, Writer: writer})
	if e = store.BeginProvision(ctx, ProvisionIntent{ID: intent, Kind: "unit", Identity: s.Name, ProductCreated: true, Desired: desired}); e != nil {
		return observed, e
	}
	ref.intent = intent
	var job dbus.ObjectPath
	dispatched = true
	e = d.manager.CallWithContext(ctx, systemdInterface+".Manager.StartTransientUnit", 0, s.Name, "fail", props, []systemdAux{}).Store(&job)
	d.mu.Lock()
	ref.job = job
	if e == nil {
		ref.acquired = true
	}
	d.mu.Unlock()
	if e != nil {
		return observed, e
	}
	for {
		v, e := d.observe(ctx, base)
		if e == nil && v.Unit.InvocationID != "" && (v.Exit != nil || v.Unit.MainPID > 0 && v.Unit.CgroupPath != "") {
			d.mu.Lock()
			ref.unit = v.Unit
			ref.observation = v
			d.mu.Unlock()
			if e = d.observeHelperRecord(ctx, ref, v.Exit, ""); e != nil {
				return v, e
			}
			if v.Exit != nil {
				d.mu.Lock()
				ref.recorded = true
				ref.terminal = v.Exit
				d.mu.Unlock()
			}
			if s.Program != bundle.Stage {
				d.mu.Lock()
				ref.done = make(chan struct{})
				d.mu.Unlock()
				go d.observeHelper(ref)
			}
			if v.Exit != nil && s.Program == bundle.Worker {
				return v, errors.New("worker terminated before live admission")
			}
			if v.Exit == nil {
				if e = verifyCgroups(v.Unit.MainPID, s.Limits); e != nil {
					terminal, readErr := d.observe(ctx, v.Unit)
					if readErr == nil && terminal.Exit != nil && s.Program != bundle.Worker {
						return terminal, nil
					}
					return v, e
				}
				if s.Identity.UID != 0 {
					if e = verifyTaskAuthority(v.Unit, s); e != nil {
						terminal, readErr := d.observe(ctx, v.Unit)
						if readErr == nil && terminal.Exit != nil && s.Program != bundle.Worker {
							return terminal, nil
						}
						return v, e
					}
				}
				if s.Program == bundle.Worker {
					if e = verifyServiceProcess(v.Unit, s, d); e != nil {
						return v, e
					}
				}
				if s.OfflinePreparation {
					var host, actual unix.Stat_t
					if e = unix.Stat("/proc/self/ns/net", &host); e != nil {
						return v, e
					}
					if e = unix.Stat(fmt.Sprintf("/proc/%d/ns/net", v.Unit.MainPID), &actual); e != nil {
						return v, e
					}
					if host.Dev == actual.Dev && host.Ino == actual.Ino {
						return v, errors.New("offline preparation inherited host network")
					}
				}
			}
			if preparation != nil {
				if v.Exit != nil {
					return v, errors.New("preparation gate terminated before authenticated start")
				}
				if v.MountNamespace == nil || v.MountNamespaceDisposition != NamespacePrivate {
					return v, errors.New("preparation has no captured private mount namespace")
				}
				if e = preparation.admit(ctx, d, ref); e != nil {
					return v, e
				}
				v.Writer, e = d.preparationWriterObservation(ctx, ref.intent)
				if e != nil {
					return v, e
				}
			}
			return v, nil
		}
		if e != nil && !systemdMissing(e) && !errors.Is(e, os.ErrNotExist) {
			return observed, e
		}
		if e = d.pause(ctx); e != nil {
			return observed, e
		}
	}
}
func systemdMissing(e error) bool {
	var b dbus.Error
	if errors.As(e, &b) {
		return b.Name == systemdInterface+".NoSuchUnit" || b.Name == "org.freedesktop.DBus.Error.UnknownObject"
	}
	return false
}
func systemdRejection(e error) string {
	var local *notSubmitted
	if errors.As(e, &local) {
		return "not-dispatched"
	}
	var b dbus.Error
	if !errors.As(e, &b) {
		return ""
	}
	switch b.Name {
	case "org.freedesktop.DBus.Error.InvalidArgs", "org.freedesktop.DBus.Error.PropertyReadOnly", systemdInterface + ".InvalidName", systemdInterface + ".UnitExists", systemdInterface + ".UnitTypeNotSupported":
		return "systemd-completed-rejection:" + b.Name
	}
	return ""
}
func (d *Systemd) pause(ctx context.Context) error {
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.changed:
		return d.connected()
	case <-timer.C:
		return d.connected()
	}
}
func (d *Systemd) all(ctx context.Context, path dbus.ObjectPath, iface string) (map[string]dbus.Variant, error) {
	var p map[string]dbus.Variant
	e := d.conn.Load().Object(systemdInterface, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, systemdInterface+"."+iface).Store(&p)
	return p, e
}
func variant[T any](p map[string]dbus.Variant, k string) (T, error) {
	var zero T
	v, ok := p[k]
	if !ok {
		return zero, fmt.Errorf("systemd missing %s", k)
	}
	out, ok := v.Value().(T)
	if !ok {
		return zero, fmt.Errorf("systemd wrong type for %s", k)
	}
	return out, nil
}
func (d *Systemd) Observe(ctx context.Context, u UnitIdentity) (UnitObservation, error) {
	return d.observe(ctx, u)
}
func (d *Systemd) observe(ctx context.Context, u UnitIdentity) (UnitObservation, error) {
	var v UnitObservation
	if e := d.connected(); e != nil {
		return v, e
	}
	if !unitName(u.Name) || u.BootID != "" && u.BootID != d.boot {
		return v, errors.New("unit boot fence or invalid name")
	}
	var path dbus.ObjectPath
	if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.GetUnit", 0, u.Name).Store(&path); e != nil {
		return v, e
	}
	p, e := d.all(ctx, path, "Unit")
	if e != nil {
		return v, e
	}
	id, e := variant[[]byte](p, "InvocationID")
	if e != nil || len(id) != 16 {
		return v, errors.New("invalid systemd invocation bytes")
	}
	actual := hex.EncodeToString(id)
	if u.InvocationID != "" && u.InvocationID != actual {
		return v, errors.New("unit invocation changed")
	}
	u.InvocationID = actual
	u.BootID = d.boot
	v.ActiveState, e = variant[string](p, "ActiveState")
	if e != nil {
		return v, e
	}
	v.SubState, e = variant[string](p, "SubState")
	if e != nil {
		return v, e
	}
	livePID := u.MainPID
	iface := "Service"
	if strings.HasSuffix(u.Name, ".scope") {
		iface = "Scope"
	}
	p, e = d.all(ctx, path, iface)
	if e != nil {
		return v, e
	}
	cg, e := variant[string](p, "ControlGroup")
	if e != nil {
		return v, e
	}
	if u.CgroupPath != "" && cg != "" && u.CgroupPath != cg {
		return v, errors.New("unit cgroup changed")
	}
	if cg != "" {
		u.CgroupPath = cg
	}
	delegated, e := variant[bool](p, "Delegate")
	if e != nil || delegated {
		return v, errors.New("unit cgroup delegation is not disabled")
	}
	if iface == "Service" {
		pid, e := variant[uint32](p, "MainPID")
		if e != nil {
			return v, e
		}
		livePID = int(pid)
		execPID, e := variant[uint32](p, "ExecMainPID")
		if e != nil {
			return v, e
		}
		v.ExecMainPID = int(execPID)
		v.Result, e = variant[string](p, "Result")
		if e != nil {
			return v, e
		}
		v.ExecMainCode, e = variant[int32](p, "ExecMainCode")
		if e != nil {
			return v, e
		}
		v.ExecMainStatus, e = variant[int32](p, "ExecMainStatus")
		if e != nil {
			return v, e
		}
		if u.MainPID == 0 {
			u.MainPID = int(pid)
			if u.MainPID == 0 {
				u.MainPID = int(execPID)
			}
		} else if pid != 0 && int(pid) != u.MainPID {
			return v, errors.New("unit MainPID changed")
		}
	}
	if livePID > 0 {
		start, e := processStart(livePID)
		if e != nil {
			return v, e
		}
		if u.StartTime != 0 && u.StartTime != start {
			return v, errors.New("PID start time changed")
		}
		u.StartTime = start
	}
	if livePID > 0 {
		d.mu.Lock()
		ownerName := d.owner.Name
		store := d.store
		d.mu.Unlock()
		sharedOwner := u.Name == ownerName || store != nil && u.Name == ManagerUnitName(store.productID) || livePID == os.Getpid() && u.ResourceFingerprint == "scope-sole-owner-v1" && strings.HasSuffix(u.Name, ".scope")
		namespace, disposition, captureErr := captureMountNamespace(u, livePID, sharedOwner)
		if captureErr != nil {
			return v, captureErr
		}
		v.MountNamespace = namespace
		v.MountNamespaceDisposition = disposition
	}
	v.Unit = u
	terminalState := v.ActiveState == "inactive" || v.ActiveState == "failed"
	if u.CgroupPath != "" {
		v.CgroupEmpty, e = cgroupEmpty(u.CgroupPath)
		if e != nil {
			return v, e
		}
	} else if terminalState && iface == "Service" {
		if _, e = nativeExit(v); e != nil {
			return v, e
		}
		v.CgroupEmpty = true
	}
	d.mu.Lock()
	ref := d.refs[u.Name]
	d.mu.Unlock()
	if ref != nil {
		d.mu.Lock()
		v.Writer = ref.observation.Writer
		d.mu.Unlock()
	}
	if v.MountNamespace == nil && ref != nil {
		d.mu.Lock()
		v.MountNamespace = ref.observation.MountNamespace
		v.MountNamespaceDisposition = ref.observation.MountNamespaceDisposition
		d.mu.Unlock()
	}
	if ref != nil && iface == "Service" && u.CgroupPath != "" {
		events, readErr := os.ReadFile(filepath.Join("/sys/fs/cgroup", u.CgroupPath, "memory.events"))
		if readErr != nil && !os.IsNotExist(readErr) {
			return v, readErr
		}
		for _, line := range strings.Split(string(events), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && (fields[0] == "oom_kill" || fields[0] == "oom_group_kill") {
				count, e := strconv.ParseUint(fields[1], 10, 64)
				if e != nil {
					return v, e
				}
				if count > 0 {
					d.mu.Lock()
					ref.oomKilled = true
					d.mu.Unlock()
				}
			}
		}
	}
	if ref != nil {
		d.mu.Lock()
		v.JobPath = string(ref.job)
		v.JobResult = d.jobs[ref.job].Result
		d.mu.Unlock()
	}
	if terminalState && v.CgroupEmpty && iface == "Service" {
		exit, e := nativeExit(v)
		if e != nil {
			return v, e
		}
		if ref != nil {
			d.mu.Lock()
			exit.OOMKilled = exit.OOMKilled || ref.oomKilled
			d.mu.Unlock()
		}
		v.Exit = &exit
	}
	if ref != nil {
		d.mu.Lock()
		ref.observation = v
		d.mu.Unlock()
	}
	return v, nil
}
func nativeExit(v UnitObservation) (ProcessExit, error) {
	e := ProcessExit{OOMKilled: v.Result == "oom-kill"}
	switch v.ExecMainCode {
	case 1:
		if v.ExecMainStatus < 0 || v.ExecMainStatus > 255 {
			return e, errors.New("invalid exit code")
		}
		e.Kind = "exit"
		e.Value = uint32(v.ExecMainStatus)
	case 2, 3:
		if v.ExecMainStatus < 1 || v.ExecMainStatus > 64 {
			return e, errors.New("invalid exit signal")
		}
		e.Kind = "signal"
		e.Value = uint32(v.ExecMainStatus)
	default:
		return e, errors.New("UNKNOWN native terminal result")
	}
	return e, nil
}
func processStart(pid int) (uint64, error) {
	raw, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return 0, e
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, errors.New("short process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
func cgroupEmpty(path string) (bool, error) {
	if path == "" || !cleanAbsolute(path) {
		return false, errors.New("missing cgroup identity")
	}
	raw, e := os.ReadFile(filepath.Join("/sys/fs/cgroup", path, "cgroup.events"))
	if os.IsNotExist(e) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "populated 0" {
			return true, nil
		}
		if line == "populated 1" {
			return false, nil
		}
	}
	return false, errors.New("missing cgroup populated evidence")
}
func (d *Systemd) Stop(ctx context.Context, u UnitIdentity) error {
	if e := d.cleanupConnection(ctx); e != nil {
		return e
	}
	if _, e := d.Observe(ctx, u); e != nil {
		d.mu.Lock()
		r := d.refs[u.Name]
		terminal := r != nil && r.unit == u && r.recorded && r.terminal != nil
		d.mu.Unlock()
		if systemdMissing(e) {
			if terminal {
				return d.proveUnitAbsent(ctx, u.Name)
			}
			if r != nil && r.unit == u {
				_, proofErr := d.observedAbsence(ctx, r)
				return proofErr
			}
		}
		return e
	}
	var job dbus.ObjectPath
	return d.manager.CallWithContext(ctx, systemdInterface+".Manager.StopUnit", 0, u.Name, "replace").Store(&job)
}
func (d *Systemd) Wait(ctx context.Context, u UnitIdentity) (ProcessExit, error) {
	d.mu.Lock()
	r := d.refs[u.Name]
	var done chan struct{}
	if r != nil {
		if r.unit != u {
			d.mu.Unlock()
			return ProcessExit{}, errors.New("wait invocation mismatch")
		}
		if r.observation.Absence != nil {
			d.mu.Unlock()
			return ProcessExit{}, errors.New("UNKNOWN native outcome for absent observed invocation")
		}
		if r.recorded && r.released && r.terminal != nil {
			exit := *r.terminal
			d.mu.Unlock()
			return exit, nil
		}
		done = r.done
	}
	d.mu.Unlock()
	if r == nil {
		v, found, e := d.helperIdentity(ctx, u)
		if e != nil {
			return ProcessExit{}, e
		}
		if found {
			if v.Absence != nil {
				return ProcessExit{}, errors.New("UNKNOWN native outcome for absent observed invocation")
			}
			if v.Exit != nil {
				if e = d.ReleaseReference(ctx, u); e != nil {
					return ProcessExit{}, e
				}
				return *v.Exit, nil
			}
		}
	}
	if done != nil {
		select {
		case <-done:
			d.mu.Lock()
			defer d.mu.Unlock()
			if r.terminal == nil {
				return ProcessExit{}, r.terminalErr
			}
			return *r.terminal, r.terminalErr
		case <-ctx.Done():
			return ProcessExit{}, ctx.Err()
		}
	}
	return d.waitNative(ctx, u)
}
func (d *Systemd) ReleaseReference(ctx context.Context, u UnitIdentity) error {
	d.mu.Lock()
	r := d.refs[u.Name]
	d.mu.Unlock()
	if r == nil {
		if _, _, e := d.helperIdentity(ctx, u); e != nil {
			return e
		}
		d.mu.Lock()
		r = d.refs[u.Name]
		d.mu.Unlock()
	}
	if r == nil {
		return errors.New("exact connection-bound reference not owned")
	}
	r.releaseMu.Lock()
	defer r.releaseMu.Unlock()
	d.mu.Lock()
	released := r.released
	recorded := r.recorded
	service := r.service
	same := r.unit == u
	d.mu.Unlock()
	if !same {
		return errors.New("reference invocation mismatch")
	}
	if released {
		return nil
	}
	if !recorded {
		if service.Program != bundle.Stage {
			return errors.New("helper terminal result not durably recorded")
		}
		v, e := d.store.Unit(ctx, service.Ownership)
		if e != nil {
			return e
		}
		if v.Unit != u || v.Exit == nil {
			return errors.New("stage terminal result not durably recorded")
		}
	}
	if _, e := d.Observe(ctx, u); e != nil {
		return e
	}
	if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.UnrefUnit", 0, u.Name).Err; e != nil {
		return e
	}
	d.mu.Lock()
	r.released = true
	r.acquired = false
	r.recorded = true
	r.terminalErr = nil
	d.mu.Unlock()
	return nil
}
func (d *Systemd) Settle(ctx context.Context, u UnitIdentity) (CleanupEvidence, error) {
	out := CleanupEvidence{BootID: d.boot, Units: []UnitIdentity{u}}
	if e := d.cleanupConnection(ctx); e != nil {
		return out, e
	}
	d.mu.Lock()
	r := d.refs[u.Name]
	d.mu.Unlock()
	if r == nil {
		if _, _, e := d.helperIdentity(ctx, u); e != nil {
			return out, e
		}
		d.mu.Lock()
		r = d.refs[u.Name]
		d.mu.Unlock()
	}
	if r == nil {
		return out, errors.New("unit reference release not established")
	}
	if _, e := d.fencePreparation(ctx, r); e != nil {
		return out, e
	}
	d.mu.Lock()
	absence := r.observation.Absence
	d.mu.Unlock()
	if absence != nil {
		evidence, e := d.observedAbsence(ctx, r)
		if e != nil {
			return out, e
		}
		if r.intent != "" && r.service.Program != bundle.Preparer && r.service.Program != bundle.Rungv {
			if e = d.store.CompleteProvisionCleanup(ctx, r.intent, evidence); e != nil {
				return out, e
			}
		}
		if r.service.Program == bundle.Preparer || r.service.Program == bundle.Rungv {
			if e := d.retirePreparationGate(ctx, r); e != nil {
				return out, e
			}
		}
		return evidence, nil
	}
	d.mu.Lock()
	released, rejection, recorded := r.released, r.rejection, r.recorded
	d.mu.Unlock()
	if rejection != "" {
		if e := d.proveUnitAbsent(ctx, u.Name); e != nil {
			return out, e
		}
		// A completed rejection means no owned service namespace was started.
		out.MountsAbsent = true
	} else {
		if !released {
			exit, e := d.Wait(ctx, u)
			if e != nil {
				return out, e
			}
			if r.service.Program == bundle.Stage {
				if e = d.recordStageTerminal(ctx, r.service.Ownership, u, exit); e != nil {
					return out, e
				}
			}
			if e = d.ReleaseReference(ctx, u); e != nil {
				return out, e
			}
		}
		if !recorded {
			d.mu.Lock()
			recorded = r.recorded
			d.mu.Unlock()
			if !recorded {
				return out, errors.New("unit terminal outcome is not durable")
			}
		}
		for {
			var jobs []systemdJob
			if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.ListJobs", 0).Store(&jobs); e != nil {
				return out, e
			}
			pending := false
			for _, job := range jobs {
				if job.Unit == u.Name {
					pending = true
				}
			}
			empty := false
			var e error
			if u.CgroupPath != "" {
				empty, e = cgroupEmpty(u.CgroupPath)
			} else {
				d.mu.Lock()
				empty = r.observation.CgroupEmpty && r.terminal != nil
				d.mu.Unlock()
			}
			if e != nil {
				return out, e
			}
			alive := false
			if u.BootID == d.boot && u.StartTime != 0 {
				if start, e := processStart(u.MainPID); e == nil {
					alive = start == u.StartTime
				} else if !os.IsNotExist(e) {
					return out, e
				}
			}
			if !pending && empty && !alive {
				absenceErr := d.proveUnitAbsent(ctx, u.Name)
				if absenceErr == nil {
					break
				}
				if !errors.Is(absenceErr, ErrCreateUnresolved) {
					return out, absenceErr
				}
			}
			if e = d.pause(ctx); e != nil {
				return out, e
			}
		}
	}
	if u.BootID == d.boot {
		if e := pipeReferencesAbsent(r.pipes); e != nil {
			return out, e
		}
		d.mu.Lock()
		namespace, disposition := r.observation.MountNamespace, r.observation.MountNamespaceDisposition
		d.mu.Unlock()
		if namespace != nil {
			if e := namespaceReferencesAbsent(ctx, namespace, disposition); e != nil {
				return out, e
			}
			out.MountsAbsent = true
		}
	}
	if u.BootID != d.boot {
		out.MountsAbsent = true
	}
	out.JobsAbsent = true
	out.ProcessesAbsent = true
	out.TransportsClosed = true
	out.OpenReferencesAbsent = true
	if r.service.Program == bundle.Preparer || r.service.Program == bundle.Rungv {
		var e error
		out.Details, e = json.Marshal(UnitAbsenceDetails{UnitAbsent: true, CgroupEmpty: true, TransportPipes: r.pipes})
		if e != nil {
			return out, e
		}
	}
	if e := d.persistPreparationSettlement(ctx, r, &out); e != nil {
		return out, e
	}
	if r.intent != "" && r.service.Program != bundle.Preparer && r.service.Program != bundle.Rungv {
		if e := d.store.CompleteProvisionCleanup(ctx, r.intent, out); e != nil {
			return out, e
		}
		if r.service.Program != bundle.Stage {
			d.mu.Lock()
			delete(d.refs, u.Name)
			delete(d.jobs, r.job)
			d.mu.Unlock()
		}
	}
	if r.service.Program == bundle.Preparer || r.service.Program == bundle.Rungv {
		if e := d.retirePreparationGate(ctx, r); e != nil {
			return out, e
		}
	}
	return out, nil
}
func (d *Systemd) RegisterForegroundOwner(ctx context.Context, name string) (UnitIdentity, error) {
	if !safeID(name) {
		return UnitIdentity{}, errors.New("invalid owner product ID")
	}
	gen, e := randomGeneration()
	if e != nil {
		return UnitIdentity{}, e
	}
	sum := sha256.Sum256([]byte(name))
	name = "chatanium-owner-" + hex.EncodeToString(sum[:16]) + "-" + gen + ".scope"
	props := []systemdProperty{property("PIDs", []uint32{uint32(os.Getpid())}), property("Delegate", false), property("AddRef", true)}
	var job dbus.ObjectPath
	if e = d.manager.CallWithContext(ctx, systemdInterface+".Manager.StartTransientUnit", 0, name, "fail", props, []systemdAux{}).Store(&job); e != nil {
		return UnitIdentity{}, e
	}
	u := UnitIdentity{Name: name, Generation: gen, BootID: d.boot, MainPID: os.Getpid()}
	u.StartTime, e = processStart(u.MainPID)
	if e != nil {
		return u, e
	}
	u.ExecutableDigest, e = hashFile(fmt.Sprintf("/proc/%d/exe", u.MainPID))
	if e != nil {
		return u, e
	}
	u.ResourceFingerprint = "scope-sole-owner-v1"
	v, e := d.observe(ctx, u)
	if e != nil {
		return u, e
	}
	raw, e := os.ReadFile(filepath.Join("/sys/fs/cgroup", v.Unit.CgroupPath, "cgroup.procs"))
	if e != nil {
		return u, e
	}
	if strings.TrimSpace(string(raw)) != strconv.Itoa(os.Getpid()) {
		return u, errors.New("owner scope is not sole-process")
	}
	d.mu.Lock()
	d.owner = v.Unit
	d.refs[name] = &systemdReference{unit: v.Unit, job: job}
	d.mu.Unlock()
	return v.Unit, nil
}
func (d *Systemd) CurrentServiceOwner(ctx context.Context, name string) (UnitIdentity, error) {
	gen, e := randomGeneration()
	if e != nil {
		return UnitIdentity{}, e
	}
	u := UnitIdentity{Name: name, Generation: gen, BootID: d.boot, MainPID: os.Getpid()}
	u.StartTime, e = processStart(u.MainPID)
	if e != nil {
		return u, e
	}
	u.ExecutableDigest, e = hashFile("/proc/self/exe")
	if e != nil {
		return u, e
	}
	u.ResourceFingerprint = "service-owner-v1"
	v, e := d.Observe(ctx, u)
	if e != nil {
		return u, e
	}
	d.mu.Lock()
	d.owner = v.Unit
	d.mu.Unlock()
	return v.Unit, nil
}
func hashFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func (d *Systemd) Reload(ctx context.Context) error {
	return d.manager.CallWithContext(ctx, systemdInterface+".Manager.Reload", 0).Err
}
func (d *Systemd) EnableUnit(ctx context.Context, name string) error {
	if e := d.managerName(name); e != nil {
		return e
	}
	return d.manager.CallWithContext(ctx, systemdInterface+".Manager.EnableUnitFiles", 0, []string{name}, false, false).Err
}
func (d *Systemd) DisableUnit(ctx context.Context, name string) error {
	if e := d.managerName(name); e != nil {
		return e
	}
	return d.manager.CallWithContext(ctx, systemdInterface+".Manager.DisableUnitFiles", 0, []string{name}, false).Err
}
func (d *Systemd) StartManager(ctx context.Context, name string) error {
	if e := d.managerName(name); e != nil {
		return e
	}
	var job dbus.ObjectPath
	if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.StartUnit", 0, name, "fail").Store(&job); e != nil {
		return e
	}
	return d.waitJob(ctx, job, name)
}
func (d *Systemd) StopManager(ctx context.Context, name string) error {
	if e := d.managerName(name); e != nil {
		return e
	}
	var job dbus.ObjectPath
	if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.StopUnit", 0, name, "replace").Store(&job); e != nil {
		return e
	}
	return d.waitJob(ctx, job, name)
}

func verifyCgroups(pid int, r ResourceLimits) error {
	raw, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if e != nil {
		return e
	}
	line := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(line, "0::/") || strings.Contains(line, "\n") {
		return errors.New("unified cgroup required")
	}
	return verifyCgroupPath(strings.TrimPrefix(line, "0::"), r)
}
func verifyCgroupPath(path string, r ResourceLimits) error {
	if _, e := finiteLimits(r); e != nil {
		return e
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("invalid owned cgroup")
	}
	root := filepath.Join("/sys/fs/cgroup", path)
	checks := map[string]string{"memory.max": strconv.FormatInt(r.MemoryBytes, 10), "memory.swap.max": "0", "pids.max": strconv.FormatInt(r.Pids, 10), "cpu.max": fmt.Sprintf("%d %d", r.NanoCPUs*int64(cpuPeriodUSec)/1000000000, cpuPeriodUSec)}
	for name, want := range checks {
		raw, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			return e
		}
		if strings.Join(strings.Fields(string(raw)), " ") != want {
			return fmt.Errorf("effective %s differs from approved ceiling", name)
		}
	}
	return nil
}
func (d *Systemd) SettleHelpers(ctx context.Context) (CleanupEvidence, error) {
	d.mu.Lock()
	var units []UnitIdentity
	for _, r := range d.refs {
		if r.unit.Name != d.owner.Name {
			if r.unit.Name == "" {
				d.mu.Unlock()
				return CleanupEvidence{}, ErrCreateUnresolved
			}
			units = append(units, r.unit)
		}
	}
	d.mu.Unlock()
	out := CleanupEvidence{BootID: d.boot, JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, OpenReferencesAbsent: true}
	for _, u := range units {
		evidence, e := d.Settle(ctx, u)
		if e != nil {
			return out, e
		}
		out.Units = append(out.Units, evidence.Units...)
	}
	return out, nil
}
func (d *Systemd) StorageCleanupBarrier(ctx context.Context, o Ownership) (CleanupEvidence, error) {
	d.mu.Lock()
	s := d.store
	d.mu.Unlock()
	if s == nil {
		return CleanupEvidence{}, errors.New("systemd store not bound")
	}
	l, _, e := s.lease(ctx, o.EpochID, o.InstanceID)
	if e != nil {
		return CleanupEvidence{}, e
	}
	v, e := s.Unit(ctx, l.Ownership)
	var out CleanupEvidence
	if errors.Is(e, sql.ErrNoRows) {
		submission, found, lookupErr := s.LookupCreate(ctx, l.Ownership, CreateService)
		if lookupErr != nil {
			return out, lookupErr
		}
		if found {
			if submission.State != CreateRejected {
				return out, ErrCreateUnresolved
			}
			if e = d.settleSubmission(ctx, submission.Identity); e != nil {
				return out, e
			}
		}
		out = CleanupEvidence{BootID: d.boot, JobsAbsent: true, ProcessesAbsent: true}
	} else {
		if e != nil {
			return out, e
		}
		if e = d.retainObserved(ctx, l.Ownership, v); e != nil {
			return out, e
		}
		if v.Exit == nil {
			d.mu.Lock()
			r := d.refs[v.Unit.Name]
			d.mu.Unlock()
			if r == nil {
				return out, ErrCleanupIncomplete
			}
			if _, e = d.observedAbsence(ctx, r); e != nil {
				return out, e
			}
		}
		out, e = d.Settle(ctx, v.Unit)
		if e != nil {
			return out, e
		}
	}
	if e = referencesAbsent([]string{filepath.Dir(l.ScratchPath), l.PersistentPath}); e != nil {
		return out, e
	}
	out.TransportsClosed = true
	out.OpenReferencesAbsent = true
	return out, nil
}
func referencesAbsent(paths []string) error {
	matches := func(target string) bool {
		target = strings.TrimSuffix(target, " (deleted)")
		for _, p := range paths {
			if p != "" && (target == p || strings.HasPrefix(target, p+"/")) {
				return true
			}
		}
		return false
	}
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		for _, dir := range []string{"fd", "map_files"} {
			fds, e := os.ReadDir(filepath.Join(base, dir))
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return e
			}
			for _, f := range fds {
				target, e := os.Readlink(filepath.Join(base, dir, f.Name()))
				if os.IsNotExist(e) {
					continue
				}
				if e != nil {
					return e
				}
				if matches(target) {
					return errors.New("owned storage remains referenced by process")
				}
			}
		}
		for _, name := range []string{"cwd", "root", "exe"} {
			target, e := os.Readlink(filepath.Join(base, name))
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return e
			}
			if matches(target) {
				return errors.New("owned storage remains process root/cwd/exe")
			}
		}
	}
	return nil
}
func (d *Systemd) RunNetwork(ctx context.Context, owner Ownership, id bundle.ProgramID, netns string, argv []string) ([]byte, ProcessExit, error) {
	if e := d.cleanupConnection(ctx); e != nil {
		return nil, ProcessExit{}, e
	}
	switch id {
	case bundle.IP, bundle.IPTables, bundle.IP6Tables, bundle.Conntrack:
	default:
		return nil, ProcessExit{}, errors.New("not a network helper")
	}
	generation, e := randomGeneration()
	if e != nil {
		return nil, ProcessExit{}, e
	}
	args := append([]string{string(id)}, argv...)
	service := OwnedService{Owner: d.Owner(), Ownership: owner, Name: "chatanium-net-" + generation + ".service", Generation: generation, Program: id, Argv: args, Identity: NumericIdentity{}, WorkingDirectory: "/", NetworkNamespacePath: netns, Limits: ResourceLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Pids: 64}, TimeoutStop: 5 * time.Second}
	return d.runBoundedHelper(ctx, service, 1<<20)
}
func serviceDescription(s OwnedService, bundleDigest string) string {
	return "chatanium-owned-v1:" + s.Generation + ":" + string(s.Program) + ":" + bundleDigest + ":" + launchFingerprint(s, bundleDigest)
}
func (d *Systemd) RecoverOwnedUnit(ctx context.Context, name, generation string, program bundle.ProgramID, limits ResourceLimits) (UnitObservation, error) {
	if e := d.cleanupConnection(ctx); e != nil {
		return UnitObservation{}, e
	}
	if cached, found, e := d.cachedHelper(ctx, name, generation, program, limits); e != nil {
		return UnitObservation{}, e
	} else if found {
		return cached, nil
	}
	if !unitName(name) || generation == "" {
		return UnitObservation{}, errors.New("invalid recovery identity")
	}
	p, _, prefix, digest, e := d.program(program)
	if e != nil {
		return UnitObservation{}, e
	}
	if _, e = finiteLimits(limits); e != nil {
		return UnitObservation{}, e
	}
	var path dbus.ObjectPath
	if e = d.manager.CallWithContext(ctx, systemdInterface+".Manager.GetUnit", 0, name).Store(&path); e != nil {
		return UnitObservation{}, errors.Join(ErrCreateUnresolved, e)
	}
	unitProps, e := d.all(ctx, path, "Unit")
	if e != nil {
		return UnitObservation{}, e
	}
	description, e := variant[string](unitProps, "Description")
	if e != nil {
		return UnitObservation{}, e
	}
	props, e := d.all(ctx, path, "Service")
	if e != nil {
		return UnitObservation{}, e
	}
	if program == bundle.Preparer || program == bundle.Rungv {
		return d.recoverPreparationUnit(ctx, name, generation, program, limits, description, props)
	}
	var development *developmentInvocation
	if program == bundle.Worker {
		records, lookupErr := d.store.UnitProvisions(ctx, name)
		if lookupErr != nil {
			return UnitObservation{}, lookupErr
		}
		for _, record := range records {
			if !strings.HasPrefix(record.ID, "systemd-") {
				continue
			}
			var desired ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
				return UnitObservation{}, e
			}
			if desired.Unit == nil || desired.Unit.Generation != generation || desired.Source != string(program) || desired.Revision == "" {
				continue
			}
			development, e = d.developmentWorker(ctx, desired.Revision, false)
			if e != nil {
				return UnitObservation{}, e
			}
			prefix = development.Argv
			digest = development.ExecutableDigest
			break
		}
	}
	var commands []systemdExecObservation
	execVariant, ok := props["ExecStart"]
	if !ok {
		return UnitObservation{}, errors.New("recovery ExecStart missing")
	}
	if e = dbus.Store([]interface{}{execVariant.Value()}, &commands); e != nil || len(commands) != 1 {
		return UnitObservation{}, errors.New("recovery ExecStart type mismatch")
	}
	command := commands[0]
	if command.Path != prefix[0] || command.IgnoreFailure || len(command.Args) < len(prefix) {
		return UnitObservation{}, errors.New("recovery execution closure mismatch")
	}
	for index, v := range prefix {
		if command.Args[index] != v {
			return UnitObservation{}, errors.New("recovery loader/payload binding mismatch")
		}
	}
	env, e := variant[[]string](props, "Environment")
	if e != nil {
		return UnitObservation{}, e
	}
	baseEnv := d.programEnvironment(p)
	if len(env) < len(baseEnv) {
		return UnitObservation{}, errors.New("recovery closure environment mismatch")
	}
	for index, v := range baseEnv {
		if env[index] != v {
			return UnitObservation{}, errors.New("recovery closure environment mismatch")
		}
	}
	privateNetwork, e := variant[bool](props, "PrivateNetwork")
	if e != nil {
		return UnitObservation{}, e
	}
	offline := program == bundle.Preparer && privateNetwork
	s := OwnedService{Name: name, Generation: generation, Program: program, Limits: limits, Argv: append([]string{""}, command.Args[len(prefix):]...), Env: env[len(baseEnv):], OfflinePreparation: offline, development: development}
	fingerprint := launchFingerprint(s, d.bundle.Digest)
	if description != serviceDescription(s, d.bundle.Digest) {
		return UnitObservation{}, errors.New("recovery unit purpose/launch binding mismatch")
	}
	base := UnitIdentity{Name: name, Generation: generation, BootID: d.boot, ExecutableDigest: digest, ResourceFingerprint: fingerprint}
	d.mu.Lock()
	held := d.refs[name]
	if held != nil && held.unit.InvocationID != "" {
		if held.unit.Generation != generation || held.unit.ResourceFingerprint != fingerprint {
			d.mu.Unlock()
			return UnitObservation{}, errors.New("recovery launch differs from held unit")
		}
		base = held.unit
	}
	d.mu.Unlock()
	v, e := d.Observe(ctx, base)
	if e != nil {
		return v, e
	}
	if v.Exit == nil {
		if e = verifyCgroups(v.Unit.MainPID, limits); e != nil {
			return v, e
		}
		actual, e := hashFile(fmt.Sprintf("/proc/%d/exe", v.Unit.MainPID))
		if e != nil {
			return v, e
		}
		expected := digest
		if actual != expected && program == bundle.Stage {
			_, _, _, expected, e = d.program(bundle.Rungv)
			if e != nil {
				return v, e
			}
		}
		if actual != expected {
			return v, errors.New("recovery process executable mismatch")
		}
	}
	d.mu.Lock()
	r := d.refs[name]
	d.mu.Unlock()
	if r == nil {
		if e = d.manager.CallWithContext(ctx, systemdInterface+".Manager.RefUnit", 0, name).Err; e != nil {
			return v, e
		}
		d.mu.Lock()
		d.refs[name] = &systemdReference{unit: v.Unit, service: s, observation: v, terminal: v.Exit, acquired: true}
		d.mu.Unlock()
	} else {
		d.mu.Lock()
		if !r.connectionLost {
			r.acquired = true
		}
		d.mu.Unlock()
	}
	return v, nil
}
func (d *Systemd) waitNative(ctx context.Context, u UnitIdentity) (ProcessExit, error) {
	for {
		v, e := d.Observe(ctx, u)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return ProcessExit{}, e
		}
		if e == nil && v.Exit != nil {
			return *v.Exit, nil
		}
		if e = d.pause(ctx); e != nil {
			return ProcessExit{}, e
		}
	}
}
func (d *Systemd) observeHelper(r *systemdReference) {
	exit, e := d.waitNative(context.Background(), r.unit)
	first := e
	if e != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		e = d.cleanupConnection(cleanup)
		if e == nil {
			e = d.Stop(cleanup, r.unit)
		}
		if e == nil {
			exit, e = d.waitNative(cleanup, r.unit)
		}
		cancel()
	}
	if e == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if r.service.Program == bundle.Stage {
			owner := r.service.Ownership
			owner.Unit = UnitIdentity{}
			_, readErr := d.store.Unit(ctx, owner)
			if errors.Is(readErr, sql.ErrNoRows) {
				e = d.store.RejectCreate(ctx, owner, CreateService, r.unit.Name, "stage-terminal-before-ready")
			} else if readErr != nil {
				e = readErr
			} else {
				e = d.recordStageTerminal(ctx, owner, r.unit, exit)
			}
		}
		if e == nil {
			e = d.observeHelperRecord(ctx, r, &exit, "")
		}
		if e == nil {
			d.mu.Lock()
			r.recorded = true
			r.terminal = &exit
			d.mu.Unlock()
			e = d.ReleaseReference(ctx, r.unit)
		}
		cancel()
	}
	d.mu.Lock()
	r.terminalErr = errors.Join(first, e)
	d.mu.Unlock()
	close(r.done)
}
func pipeReferencesAbsent(targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if _, e = strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		dir := filepath.Join("/proc", entry.Name(), "fd")
		fds, e := os.ReadDir(dir)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		for _, fd := range fds {
			link, e := os.Readlink(filepath.Join(dir, fd.Name()))
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return e
			}
			for _, target := range targets {
				if link == target {
					return errors.New("owned transport descriptor remains open")
				}
			}
		}
	}
	return nil
}

// ManagerUnitName is shared by the unit-file publisher and the typed manager API.
func ManagerUnitName(productID string) string {
	sum := sha256.Sum256([]byte(productID))
	return "chatanium-" + hex.EncodeToString(sum[:16]) + ".service"
}
func (d *Systemd) managerName(name string) error {
	d.mu.Lock()
	s := d.store
	d.mu.Unlock()
	if s == nil || name != ManagerUnitName(s.productID) {
		return errors.New("manager unit is not owned by bound installation")
	}
	return nil
}
func (d *Systemd) waitJob(ctx context.Context, job dbus.ObjectPath, name string) error {
	for {
		d.mu.Lock()
		result, ok := d.jobs[job]
		d.mu.Unlock()
		if ok {
			if result.Unit != name {
				return errors.New("job identity mismatch")
			}
			if result.Result != "done" {
				return fmt.Errorf("systemd job completed: %s", result.Result)
			}
			return nil
		}
		var jobs []systemdJob
		if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.ListJobs", 0).Store(&jobs); e != nil {
			return e
		}
		for _, j := range jobs {
			if j.Path == job && j.Unit != name {
				return errors.New("systemd job changed unit")
			}
		}
		if e := d.pause(ctx); e != nil {
			return e
		}
	}
}
func (d *Systemd) signalLoop() {
	for signal := range d.signals {
		if d.closed.Load() {
			return
		}
		if signal != nil && signal.Name == systemdInterface+".Manager.JobRemoved" && len(signal.Body) == 4 {
			_, idOK := signal.Body[0].(uint32)
			path, pathOK := signal.Body[1].(dbus.ObjectPath)
			unit, unitOK := signal.Body[2].(string)
			result, resultOK := signal.Body[3].(string)
			if idOK && pathOK && unitOK && resultOK {
				d.mu.Lock()
				owned := d.refs[unit] != nil || d.store != nil && unit == ManagerUnitName(d.store.productID)
				if owned {
					d.jobs[path] = systemdJobResult{unit, result}
				}
				d.mu.Unlock()
			}
		}
		select {
		case d.changed <- struct{}{}:
		default:
		}
	}
	select {
	case d.changed <- struct{}{}:
	default:
	}
}

type systemdExecObservation struct {
	Path                                                       string
	Args                                                       []string
	IgnoreFailure                                              bool
	StartRealtime, StartMonotonic, StopRealtime, StopMonotonic uint64
	PID                                                        uint32
	Code, Status                                               int32
}

func (d *Systemd) programEnvironment(p bundle.Program) []string {
	env := make([]string, 0, len(p.Environment))
	for _, entry := range p.Environment {
		k, v, _ := strings.Cut(entry, "=")
		if k == "XTABLES_LIBDIR" {
			v = filepath.Join(d.bundle.Root, v)
		}
		env = append(env, k+"="+v)
	}
	return env
}
func launchFingerprint(s OwnedService, bundleDigest string) string {
	tail := []string{}
	if len(s.Argv) > 1 {
		tail = s.Argv[1:]
	}
	env := s.Env
	if env == nil {
		env = []string{}
	}
	raw, _ := json.Marshal(struct {
		Bundle      string
		Program     bundle.ProgramID
		Args, Env   []string
		Limits      ResourceLimits
		Offline     bool
		Development *developmentInvocation
		Preparation *PreparationWriterLaunch `json:",omitempty"`
	}{Bundle: bundleDigest, Program: s.Program, Args: tail, Env: env, Limits: s.Limits, Offline: s.OfflinePreparation, Development: s.development, Preparation: preparationLaunchFingerprint(s)})
	sum := sha256.Sum256(append([]byte("chatanium-owned-launch-v1\x00"), raw...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (d *Systemd) proveUnitAbsent(ctx context.Context, name string) error {
	if !unitName(name) {
		return errors.New("invalid absence identity")
	}
	if e := d.connected(); e != nil {
		return e
	}
	var jobs []systemdJob
	if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.ListJobs", 0).Store(&jobs); e != nil {
		return e
	}
	for _, job := range jobs {
		if job.Unit == name {
			return ErrCreateUnresolved
		}
	}
	var units []systemdUnit
	if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.ListUnits", 0).Store(&units); e != nil {
		return e
	}
	for _, unit := range units {
		if unit.Name == name {
			return ErrCreateUnresolved
		}
	}
	return nil
}
func (d *Systemd) retainObserved(ctx context.Context, o Ownership, v UnitObservation) error {
	if e := d.cleanupConnection(ctx); e != nil {
		return e
	}
	u := v.Unit
	d.mu.Lock()
	r := d.refs[u.Name]
	d.mu.Unlock()
	if r != nil {
		if r.unit != u {
			return errors.New("observed unit differs from held reference")
		}
		if !r.acquired && !r.released {
			if _, e := d.Observe(ctx, u); e != nil {
				if u.BootID != d.boot || systemdMissing(e) {
					return d.proveUnitAbsent(ctx, u.Name)
				}
				return e
			}
			if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.RefUnit", 0, u.Name).Err; e != nil {
				return e
			}
			d.mu.Lock()
			r.connectionLost = false
			r.acquired = true
			d.mu.Unlock()
		}
		return nil
	}
	released := false
	if u.BootID != d.boot {
		if e := d.proveUnitAbsent(ctx, u.Name); e != nil {
			return e
		}
		released = true
	} else {
		current, e := d.Observe(ctx, u)
		if e != nil {
			if !systemdMissing(e) {
				return e
			}
			if e = d.proveUnitAbsent(ctx, u.Name); e != nil {
				return e
			}
			released = true
		} else {
			if current.Unit != u {
				return errors.New("recovery invocation differs from durable observation")
			}
			if e = d.manager.CallWithContext(ctx, systemdInterface+".Manager.RefUnit", 0, u.Name).Err; e != nil {
				return e
			}
		}
	}
	records, e := d.store.UnitProvisions(ctx, u.Name)
	if e != nil {
		return e
	}
	r = &systemdReference{unit: u, service: OwnedService{Ownership: o, Program: bundle.Stage}, observation: v, acquired: !released, released: released, recorded: v.Exit != nil || v.Absence != nil, terminal: v.Exit}
	for _, record := range records {
		if !strings.HasPrefix(record.ID, "systemd-") {
			continue
		}
		var desired ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return e
		}
		if desired.Unit != nil && desired.Unit.Generation == u.Generation {
			r.intent = record.ID
			r.pipes = desired.TransportPipes
			r.service.Limits = *desired.Limits
			break
		}
	}
	if r.intent == "" {
		return errors.New("stage has no durable native submission intent")
	}
	d.mu.Lock()
	d.refs[u.Name] = r
	d.mu.Unlock()
	return nil
}

type notSubmitted struct{ cause error }

func (e *notSubmitted) Error() string { return e.cause.Error() }
func (e *notSubmitted) Unwrap() error { return e.cause }
func (d *Systemd) observeUncertain(r *systemdReference) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		d.mu.Lock()
		u := r.unit
		d.mu.Unlock()
		v, e := d.Observe(ctx, u)
		if e == nil && v.Unit.InvocationID != "" {
			d.mu.Lock()
			r.unit = v.Unit
			r.observation = v
			d.mu.Unlock()
			if r.intent != "" {
				if e = d.observeHelperRecord(ctx, r, v.Exit, ""); e != nil {
					return
				}
				if v.Exit == nil {
					if e = d.Stop(ctx, v.Unit); e != nil {
						return
					}
				}
				d.mu.Lock()
				if r.done == nil {
					r.done = make(chan struct{})
					go d.observeHelper(r)
				}
				d.mu.Unlock()
			}
			return
		}
		if e != nil && !systemdMissing(e) {
			return
		}
		if e = d.pause(ctx); e != nil {
			return
		}
	}
}

// RecoverHelpers never resumes a helper or adopts its streams. It stops exact
// journal-bound invocations and preserves unknown results until a boot fence.
func (d *Systemd) RecoverHelpers(ctx context.Context) (CleanupEvidence, error) {
	if e := d.cleanupConnection(ctx); e != nil {
		return CleanupEvidence{}, e
	}
	out := CleanupEvidence{BootID: d.boot, JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, OpenReferencesAbsent: true}
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return out, errors.New("helper recovery requires bound store")
	}
	records, e := store.PendingProvisions(ctx)
	if e != nil {
		return out, e
	}
	var targets []*systemdReference
	for _, record := range records {
		if record.Kind != "unit" || !strings.HasPrefix(record.ID, "systemd-") {
			continue
		}
		var desired, observed ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return out, e
		}
		if desired.Unit == nil || desired.Limits == nil || desired.Source == "" || desired.Unit.Name != record.Identity {
			return out, errors.New("helper recovery binding missing")
		}
		if len(record.Observed.Attributes) > 0 {
			if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); e != nil {
				return out, e
			}
		}
		u := *desired.Unit
		if observed.Unit != nil {
			u = *observed.Unit
		}
		d.mu.Lock()
		r := d.refs[u.Name]
		d.mu.Unlock()
		if r == nil {
			r = &systemdReference{unit: u, service: OwnedService{Program: bundle.ProgramID(desired.Source), Limits: *desired.Limits}, observation: UnitObservation{Unit: u, Exit: observed.Exit, CgroupEmpty: observed.CgroupEmpty, Absence: observed.Absence, MountNamespace: observed.MountNamespace, MountNamespaceDisposition: observed.MountNamespaceDisposition, Writer: observed.Writer}, intent: record.ID, pipes: desired.TransportPipes, terminal: observed.Exit, recorded: observed.Exit != nil, rejection: observed.Rejection}
			if desired.Ownership != nil {
				r.service.Ownership = *desired.Ownership
			}
			d.mu.Lock()
			d.refs[u.Name] = r
			d.mu.Unlock()
		}
		if observed.Writer != nil && observed.Writer.Birth != nil {
			if _, e = d.fencePreparation(ctx, r); e != nil {
				return out, e
			}
		}
		if r.rejection != "" {
			if e = d.proveUnitAbsent(ctx, u.Name); e != nil {
				return out, e
			}
			r.released = true
			r.recorded = true
			targets = append(targets, r)
			continue
		}
		if u.BootID != d.boot {
			if e = d.proveUnitAbsent(ctx, u.Name); e != nil {
				return out, e
			}
			if observed.Exit == nil && observed.Unit != nil && validUnit(u) {
				d.mu.Lock()
				r.connectionLost = true
				d.mu.Unlock()
				targets = append(targets, r)
				continue
			}
			if observed.Exit == nil {
				rejection := "boot-fenced:" + strings.ReplaceAll(u.BootID, "-", "")
				if e = d.observeHelperRecord(ctx, r, nil, rejection); e != nil {
					return out, e
				}
				r.rejection = rejection
				if r.service.Program == bundle.Stage {
					if e = store.RejectCreate(ctx, r.service.Ownership, CreateService, u.Name, rejection); e != nil {
						return out, e
					}
				}
			}
			r.released = true
			r.recorded = true
			targets = append(targets, r)
			continue
		}
		current, readErr := d.Observe(ctx, u)
		if readErr != nil {
			if !systemdMissing(readErr) || observed.Unit == nil || !validUnit(u) {
				return out, errors.Join(ErrCreateUnresolved, readErr)
			}
			if e = d.proveUnitAbsent(ctx, u.Name); e != nil {
				return out, e
			}
			if observed.Exit == nil {
				d.mu.Lock()
				r.connectionLost = true
				d.mu.Unlock()
			} else {
				r.released = true
				r.recorded = true
				r.terminal = observed.Exit
			}
			targets = append(targets, r)
			continue
		}
		if u.InvocationID == "" {
			current, e = d.RecoverOwnedUnit(ctx, u.Name, u.Generation, bundle.ProgramID(desired.Source), *desired.Limits)
			if e != nil {
				return out, e
			}
			if desired.Unit.ResourceFingerprint != current.Unit.ResourceFingerprint {
				return out, errors.New("helper launch changed during recovery")
			}
		} else if current.Unit != u {
			return out, errors.New("helper invocation changed during recovery")
		}
		u = current.Unit
		d.mu.Lock()
		r.unit = u
		r.observation = current
		r.terminal = current.Exit
		acquire := !r.acquired && !r.released
		r.connectionLost = false
		d.mu.Unlock()
		if e = d.observeHelperRecord(ctx, r, current.Exit, ""); e != nil {
			return out, e
		}
		if acquire {
			if e = d.manager.CallWithContext(ctx, systemdInterface+".Manager.RefUnit", 0, u.Name).Err; e != nil {
				return out, e
			}
			r.acquired = true
		}
		if r.service.Program == bundle.Stage && desired.Ownership != nil {
			if _, readErr = store.Unit(ctx, *desired.Ownership); errors.Is(readErr, sql.ErrNoRows) {
				if current.Exit != nil {
					if e = store.RejectCreate(ctx, *desired.Ownership, CreateService, u.Name, "stage-terminal-before-ready"); e != nil {
						return out, e
					}
					r.recorded = true
					if e = d.ReleaseReference(ctx, u); e != nil {
						return out, e
					}
					targets = append(targets, r)
					continue
				}
				if e = store.RecordFailure(ctx, *desired.Ownership, PhaseCleanup, FailureStartAPI); e != nil {
					return out, e
				}
				if e = store.RecordUnit(ctx, *desired.Ownership, current); e != nil {
					return out, e
				}
			} else if readErr != nil {
				return out, readErr
			}
		}
		if current.Exit == nil {
			if e = d.Stop(ctx, u); e != nil {
				return out, e
			}
		}
		targets = append(targets, r)
	}
	// Stop every owned writer before waiting on pipes shared with another unit.
	for _, r := range targets {
		d.mu.Lock()
		lost := r.connectionLost && r.terminal == nil
		d.mu.Unlock()
		if lost {
			if _, e = d.observedAbsence(ctx, r); e != nil {
				return out, e
			}
			continue
		}
		if !r.released {
			d.mu.Lock()
			exit := r.terminal
			d.mu.Unlock()
			if exit == nil {
				native, waitErr := d.waitNative(ctx, r.unit)
				if waitErr != nil {
					return out, waitErr
				}
				exit = &native
			}
			if r.service.Program == bundle.Stage {
				if e = d.recordStageTerminal(ctx, r.service.Ownership, r.unit, *exit); e != nil {
					return out, e
				}
			} else if e = d.observeHelperRecord(ctx, r, exit, ""); e != nil {
				return out, e
			}
			d.mu.Lock()
			r.recorded = true
			r.terminal = exit
			d.mu.Unlock()
			if e = d.ReleaseReference(ctx, r.unit); e != nil {
				return out, e
			}
		}
	}
	for _, r := range targets {
		evidence, e := d.Settle(ctx, r.unit)
		if e != nil {
			return out, e
		}
		out.Units = append(out.Units, evidence.Units...)
	}
	return out, nil
}
func (d *Systemd) ManagerState(ctx context.Context, name string) (string, string, UnitIdentity, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return "unknown", "unknown", UnitIdentity{}, errors.New("manager store is not bound")
	}
	return d.managerState(ctx, name, store.LeaseOwner)
}

// ManagerStateFromMetadata uses a fresh passive SQL reader after the installing
// owner's lease has closed. It neither rebinds nor revives that owner.
func (d *Systemd) ManagerStateFromMetadata(ctx context.Context, name string, reader *MetadataReader) (string, string, UnitIdentity, error) {
	if reader == nil {
		return "unknown", "unknown", UnitIdentity{}, errors.New("fresh manager metadata reader required")
	}
	d.mu.Lock()
	bound := d.store
	d.mu.Unlock()
	if bound == nil {
		return "unknown", "unknown", UnitIdentity{}, errors.New("manager store is not bound")
	}
	manifest, err := reader.Installation(ctx)
	if err != nil {
		return "unknown", "unknown", UnitIdentity{}, err
	}
	if manifest.RuntimeInstallationID != bound.productID || manifest.Paths.Control != bound.dir || manifest.BundleDigest != d.bundle.Digest || name != ManagerUnitName(manifest.RuntimeInstallationID) || manifest.State != "READY" || manifest.PendingRevision != "" {
		return "unknown", "unknown", UnitIdentity{}, errors.New("fresh manager metadata differs from the installed unit authority")
	}
	return d.managerState(ctx, name, reader.LeaseOwner)
}

func (d *Systemd) managerState(ctx context.Context, name string, leaseOwner func(context.Context) (UnitIdentity, error)) (enablement, activation string, unit UnitIdentity, err error) {
	enablement, activation = "unknown", "unknown"
	if err = d.managerName(name); err != nil {
		return
	}
	var state string
	err = d.manager.CallWithContext(ctx, systemdInterface+".Manager.GetUnitFileState", 0, name).Store(&state)
	if err != nil {
		return
	}
	switch state {
	case "enabled", "enabled-runtime":
		enablement = "enabled"
	case "disabled", "static", "indirect", "linked", "linked-runtime", "masked", "masked-runtime", "generated", "transient":
		enablement = "disabled"
	default:
		err = errors.New("unknown manager enablement state")
		return
	}
	var path dbus.ObjectPath
	err = d.manager.CallWithContext(ctx, systemdInterface+".Manager.GetUnit", 0, name).Store(&path)
	if systemdMissing(err) {
		if err = d.proveUnitAbsent(ctx, name); err == nil {
			activation = "inactive"
		}
		return
	}
	if err != nil {
		return
	}
	props, e := d.all(ctx, path, "Unit")
	if e != nil {
		err = e
		return
	}
	active, e := variant[string](props, "ActiveState")
	if e != nil {
		err = e
		return
	}
	switch active {
	case "active", "reloading":
		activation = "active"
	case "inactive", "failed":
		activation = "inactive"
	default:
		return
	}
	if activation == "active" {
		owner, e := leaseOwner(ctx)
		if e != nil {
			err = e
			return
		}
		if owner.Name != name {
			err = errors.New("live manager has no matching durable owner")
			return
		}
		observation, e := d.Observe(ctx, owner)
		if e != nil {
			err = e
			return
		}
		unit = observation.Unit
	}
	return
}
func (d *Systemd) ManagerAbsent(ctx context.Context, name string) error {
	if e := d.managerName(name); e != nil {
		return e
	}
	var jobs []systemdJob
	if e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.ListJobs", 0).Store(&jobs); e != nil {
		return e
	}
	for _, job := range jobs {
		if job.Unit == name {
			return ErrCleanupIncomplete
		}
	}
	var path dbus.ObjectPath
	e := d.manager.CallWithContext(ctx, systemdInterface+".Manager.GetUnit", 0, name).Store(&path)
	if systemdMissing(e) {
		return d.proveUnitAbsent(ctx, name)
	}
	if e != nil {
		return e
	}
	props, e := d.all(ctx, path, "Unit")
	if e != nil {
		return e
	}
	active, e := variant[string](props, "ActiveState")
	if e != nil {
		return e
	}
	if active != "inactive" && active != "failed" {
		return ErrCleanupIncomplete
	}
	props, e = d.all(ctx, path, "Service")
	if e != nil {
		return e
	}
	pid, e := variant[uint32](props, "MainPID")
	if e != nil || pid != 0 {
		return errors.Join(ErrCleanupIncomplete, e)
	}
	cg, e := variant[string](props, "ControlGroup")
	if e != nil {
		return e
	}
	if cg != "" {
		empty, e := cgroupEmpty(cg)
		if e != nil || !empty {
			return errors.Join(ErrCleanupIncomplete, e)
		}
	}
	return nil
}

type systemdManager struct{ d *Systemd }

func (m systemdManager) CallWithContext(ctx context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	return m.d.conn.Load().Object(systemdInterface, dbus.ObjectPath("/org/freedesktop/systemd1")).CallWithContext(ctx, method, flags, args...)
}
func (d *Systemd) cleanupConnection(ctx context.Context) error {
	if d.conn.Load().Connected() {
		return nil
	}
	d.admissionClosed.Store(true)
	d.reconnect.Lock()
	defer d.reconnect.Unlock()
	if d.closed.Load() {
		return errors.New("systemd transport explicitly closed")
	}
	if d.conn.Load().Connected() {
		return nil
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	old := d.conn.Load()
	old.RemoveSignal(d.signals)
	_ = old.Close()
	conn, e := dbus.Dial("unix:path=/run/systemd/private")
	if e != nil {
		return e
	}
	fail := func(err error) error { conn.Close(); return err }
	if e = conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); e != nil {
		return fail(e)
	}
	if !conn.SupportsUnixFDs() {
		return fail(errors.New("recovery connection lacks Unix FD passing"))
	}
	conn.Signal(d.signals)
	if e = conn.Object(systemdInterface, dbus.ObjectPath("/org/freedesktop/systemd1")).CallWithContext(ctx, systemdInterface+".Manager.Subscribe", 0).Err; e != nil {
		return fail(e)
	}
	d.mu.Lock()
	for _, r := range d.refs {
		if r.unit.Name == d.owner.Name {
			continue
		}
		r.connectionLost = true
		r.acquired = false
		r.released = r.recorded || r.rejection != ""
	}
	d.mu.Unlock()
	d.conn.Store(conn)
	return nil
}
func (d *Systemd) BindOwner(ctx context.Context, u UnitIdentity) error {
	if u.MainPID != os.Getpid() || u.BootID != d.boot {
		return errors.New("existing owner is not current root process")
	}
	actual, e := d.Observe(ctx, u)
	if e != nil {
		return e
	}
	if actual.Unit != u {
		return errors.New("existing owner invocation changed")
	}
	digest, e := hashFile("/proc/self/exe")
	if e != nil {
		return e
	}
	if digest != u.ExecutableDigest {
		return errors.New("existing owner executable changed")
	}
	raw, e := os.ReadFile("/proc/self/cgroup")
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(raw)) != "0::"+u.CgroupPath {
		return errors.New("existing owner cgroup changed")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.owner.Name != "" && d.owner != u {
		return errors.New("owner rebinding forbidden")
	}
	d.owner = u
	return nil
}
func (d *Systemd) validateOffline(ctx context.Context, s OwnedService) error {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return errors.New("offline preparation requires installed store")
	}
	m, e := store.Installation(ctx)
	if e != nil {
		return e
	}
	if s.Program != bundle.Preparer || s.Identity.UID != m.Identities.Preparer.UID || s.Identity.GID != m.Identities.Preparer.GID || s.Identity.UID == 0 || s.NetworkNamespacePath != "" || s.RootDirectory != "" || s.WorkingDirectory != "/chatanium/work" {
		return errors.New("invalid offline preparation purpose")
	}
	job := ""
	for _, mount := range s.Mounts {
		if mount.Target == "/chatanium/work" {
			job = filepath.Base(mount.Source)
			if mount.Source != filepath.Join(m.Paths.StorageRoot, "preparation", job) {
				return errors.New("offline work mount is not owned")
			}
		}
	}
	if !safeID(job) {
		return errors.New("offline preparation has no owned job")
	}
	allowed := map[string]string{"/chatanium/source": filepath.Join(m.Paths.StorageRoot, "images", job), "/chatanium/cache": filepath.Join(m.Paths.StorageRoot, "prepared", job, "generation"), "/chatanium/work": filepath.Join(m.Paths.StorageRoot, "preparation", job), "/chatanium/base": d.bundle.Root}
	seen := map[string]bool{}
	for _, mount := range s.Mounts {
		source, ok := allowed[mount.Target]
		if !ok || mount.Source != source || seen[mount.Target] || mount.Target == "/chatanium/base" && !mount.ReadOnly {
			return errors.New("offline task mount exceeds fixed inputs/output/base")
		}
		seen[mount.Target] = true
	}
	if len(seen) != len(allowed) {
		return errors.New("offline task is missing required confined mount")
	}
	return nil
}
func (d *Systemd) cachedHelper(ctx context.Context, name, generation string, program bundle.ProgramID, limits ResourceLimits) (UnitObservation, bool, error) {
	d.mu.Lock()
	r := d.refs[name]
	if r != nil && r.unit.Generation == generation && r.service.Program == program && r.service.Limits == limits && r.recorded && (r.terminal != nil || r.observation.Absence != nil) {
		v := r.observation
		v.Unit = r.unit
		if r.terminal != nil {
			exit := *r.terminal
			v.Exit = &exit
		}
		d.mu.Unlock()
		return v, true, nil
	}
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return UnitObservation{}, false, nil
	}
	records, e := store.UnitProvisions(ctx, name)
	if e != nil {
		return UnitObservation{}, false, e
	}
	for _, record := range records {
		if !strings.HasPrefix(record.ID, "systemd-") {
			continue
		}
		var desired, observed ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return UnitObservation{}, false, e
		}
		if desired.Unit == nil || desired.Unit.Generation != generation || desired.Source != string(program) || desired.Limits == nil || *desired.Limits != limits {
			continue
		}
		if len(record.Observed.Attributes) == 0 {
			continue
		}
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); e != nil {
			return UnitObservation{}, false, e
		}
		if observed.Exit == nil && observed.Rejection == "" && observed.Absence == nil {
			continue
		}
		if observed.Unit == nil || observed.Unit.Name != name || observed.Unit.Generation != generation || observed.Unit.BootID != desired.Unit.BootID || observed.Unit.ExecutableDigest != desired.Unit.ExecutableDigest || observed.Unit.ResourceFingerprint != desired.Unit.ResourceFingerprint {
			return UnitObservation{}, false, errors.New("cached helper identity mismatch")
		}
		v := UnitObservation{Unit: *observed.Unit, Exit: observed.Exit, CgroupEmpty: observed.CgroupEmpty, Absence: observed.Absence, MountNamespace: observed.MountNamespace, MountNamespaceDisposition: observed.MountNamespaceDisposition, Writer: observed.Writer}
		r = &systemdReference{unit: v.Unit, service: OwnedService{Program: program, Limits: limits}, observation: v, recorded: true, terminal: v.Exit, intent: record.ID, pipes: desired.TransportPipes, rejection: observed.Rejection}
		if desired.Ownership != nil {
			r.service.Ownership = *desired.Ownership
		}
		if record.CleanupState == "COMPLETE" && (program == bundle.Preparer || program == bundle.Rungv) {
			if _, e = d.fencePreparation(ctx, r); e != nil {
				return UnitObservation{}, false, e
			}
		}
		if record.CleanupState == "COMPLETE" || observed.Rejection != "" || v.Absence != nil || v.Unit.BootID != d.boot {
			if e = d.proveUnitAbsent(ctx, name); e != nil {
				return UnitObservation{}, false, e
			}
			r.released = true
		} else {
			current, readErr := d.Observe(ctx, v.Unit)
			if readErr != nil {
				if !systemdMissing(readErr) {
					return UnitObservation{}, false, readErr
				}
				if e = d.proveUnitAbsent(ctx, name); e != nil {
					return UnitObservation{}, false, e
				}
				r.released = true
			} else {
				if current.Unit != v.Unit {
					return UnitObservation{}, false, errors.New("cached invocation differs from PID1")
				}
				if e = d.manager.CallWithContext(ctx, systemdInterface+".Manager.RefUnit", 0, name).Err; e != nil {
					return UnitObservation{}, false, e
				}
				r.acquired = true
				r.observation = current
			}
		}
		d.mu.Lock()
		if existing := d.refs[name]; existing == nil {
			d.refs[name] = r
		}
		d.mu.Unlock()
		return v, true, nil
	}
	return UnitObservation{}, false, nil
}
func (d *Systemd) recordStageTerminal(ctx context.Context, o Ownership, u UnitIdentity, exit ProcessExit) error {
	d.mu.Lock()
	r := d.refs[u.Name]
	var v UnitObservation
	if r != nil {
		v = r.observation
	}
	d.mu.Unlock()
	if previous, e := d.store.Unit(ctx, o); e == nil && previous.Unit == u && previous.Exit != nil && *previous.Exit == exit && previous.CgroupEmpty {
		v = previous
	}
	if v.Unit != u || v.Exit == nil || *v.Exit != exit || !v.CgroupEmpty {
		return errors.New("exact native terminal observation missing")
	}
	if e := d.store.RecordUnit(ctx, o, v); e != nil {
		return e
	}
	if e := d.observeHelperRecord(ctx, r, &exit, ""); e != nil {
		return e
	}
	d.mu.Lock()
	r.recorded = true
	r.terminal = &exit
	d.mu.Unlock()
	return nil
}
func (d *Systemd) observeHelperRecord(ctx context.Context, r *systemdReference, exit *ProcessExit, rejection string) error {
	r.recordMu.Lock()
	defer r.recordMu.Unlock()
	p, complete, e := d.helperProperties(ctx, r)
	if e != nil {
		return e
	}
	if complete {
		return errors.New("completed native helper observation is immutable")
	}
	d.mu.Lock()
	u, job, pipes := r.unit, r.job, r.pipes
	namespace, disposition := r.observation.MountNamespace, r.observation.MountNamespaceDisposition
	d.mu.Unlock()
	p.Name, p.Unit, p.JobPath = u.Name, &u, string(job)
	p.TransportPipes = pipes
	p.MountNamespace, p.MountNamespaceDisposition = namespace, disposition
	p.ProductCreated = true
	if exit != nil {
		p.Exit, p.CgroupEmpty = exit, true
	}
	if rejection != "" {
		p.Rejection, p.CgroupEmpty = rejection, true
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	return d.store.ObserveProvision(ctx, r.intent, ObjectObservation{Identity: u.Name, Attributes: raw})
}

type developmentInvocation struct {
	Revision, ArtifactDigest, Executable, ExecutableDigest string
	Argv                                                   []string
}

func (d *Systemd) StartDevelopmentWorker(ctx context.Context, s OwnedService, f StandardFiles, revisionID string) (UnitObservation, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return UnitObservation{}, errors.New("development worker requires installed store")
	}
	m, e := store.Installation(ctx)
	if e != nil {
		return UnitObservation{}, e
	}
	if e = validateWorkerProjections(m, s); e != nil {
		return UnitObservation{}, e
	}
	invocation, e := d.developmentWorker(ctx, revisionID, true)
	if e != nil {
		return UnitObservation{}, e
	}
	s.development = invocation
	return d.StartOwned(ctx, s, f)
}
func (d *Systemd) developmentWorker(ctx context.Context, revisionID string, requireLive bool) (*developmentInvocation, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return nil, errors.New("development worker requires installed store")
	}
	if e := store.requireLease(); e != nil {
		return nil, e
	}
	m, e := store.Installation(ctx)
	if e != nil {
		return nil, e
	}
	revision, e := store.Revision(ctx, revisionID)
	if e != nil {
		return nil, e
	}
	binding := revision.DevelopmentWorker
	if binding == nil || !safeID(binding.JobID) || binding.BaseRevision != m.ActiveRevision || revision.BundleDigest != d.bundle.Digest || m.BundleDigest != d.bundle.Digest {
		return nil, errors.New("development worker base is not the active verified release")
	}
	base, e := store.Revision(ctx, binding.BaseRevision)
	if e != nil {
		return nil, e
	}
	if base.DevelopmentWorker != nil || revision.ConfigDigest != base.ConfigDigest {
		return nil, errors.New("development worker configuration differs from release")
	}
	refs, e := store.GenerationReferences(ctx)
	if e != nil {
		return nil, e
	}
	retained, live := false, false
	generation := "development-worker:" + binding.JobID
	for _, ref := range refs {
		if ref.ID != generation {
			continue
		}
		if ref.Kind == "preparation" && ref.Claim == "dev-revision:"+revisionID {
			retained = true
		}
		if ref.Kind == "live" && strings.HasPrefix(ref.Claim, "worker-epoch:") {
			live = true
		}
	}
	if !retained || requireLive && !live {
		return nil, errors.New("development worker generation is unretained or retired")
	}
	records, e := store.PendingProvisions(ctx)
	if e != nil {
		return nil, e
	}
	proven := false
	root := filepath.Join(m.Paths.StorageRoot, "prepared", binding.JobID, "generation")
	for _, record := range records {
		if record.Kind != "development-worker" || record.State != "OBSERVED" || !record.ProductCreated || record.CleanupState == "COMPLETE" {
			continue
		}
		var desired, observed ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return nil, e
		}
		if desired.Name != binding.JobID {
			continue
		}
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); e != nil {
			return nil, e
		}
		if observed.Digest == binding.ArtifactDigest && observed.Revision == binding.BaseRevision && observed.Target == filepath.Dir(root) {
			proven = true
		}
	}
	if !proven {
		return nil, errors.New("development worker lacks published owned generation")
	}
	fd, e := unix.Openat2(unix.AT_FDCWD, filepath.Join(root, bundle.DevelopmentWorkerManifestPath), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(fd), "development-worker-manifest")
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		file.Close()
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&07777 != 0444 || st.Size <= 0 || st.Size > bundle.MaxDevelopmentManifestBytes {
		file.Close()
		return nil, errors.New("unsafe development worker manifest")
	}
	raw, e := io.ReadAll(io.LimitReader(file, bundle.MaxDevelopmentManifestBytes+1))
	closeErr := file.Close()
	if e != nil {
		return nil, e
	}
	if closeErr != nil {
		return nil, closeErr
	}
	manifest, e := bundle.VerifyDevelopmentWorkerManifest(raw, d.bundle.Manifest)
	if e != nil {
		return nil, e
	}
	verified, e := bundle.VerifyDevelopmentWorkerDirectory(ctx, root, manifest, d.bundle)
	if e != nil {
		return nil, e
	}
	if verified.Digest != binding.ArtifactDigest || verified.JobID != binding.JobID {
		return nil, errors.New("development artifact binding mismatch")
	}
	worker := filepath.Join(root, "bin/chatanium-worker")
	var workerDigest string
	for _, member := range verified.Manifest.Files {
		if member.Path == "bin/chatanium-worker" {
			workerDigest = member.Digest
		}
	}
	if workerDigest == "" {
		return nil, errors.New("development worker inventory missing executable")
	}
	invocation := &developmentInvocation{Revision: revisionID, ArtifactDigest: verified.Digest, Executable: worker, ExecutableDigest: workerDigest, Argv: []string{worker}}
	if verified.Manifest.Voice {
		loader := "lib/ld-linux-x86-64.so.2"
		invocation.Executable = filepath.Join(d.bundle.Root, loader)
		invocation.ExecutableDigest = ""
		for _, member := range d.bundle.Manifest.Files {
			if member.Path == loader {
				invocation.ExecutableDigest = member.Digest
			}
		}
		if invocation.ExecutableDigest == "" {
			return nil, errors.New("verified base lacks native worker loader")
		}
		invocation.Argv = []string{invocation.Executable, "--inhibit-cache", "--library-path", filepath.Join(root, "bin/voice-runtime/lib") + ":" + filepath.Join(d.bundle.Root, "lib"), worker}
	}
	return invocation, nil
}

// RunHelper admits only the fixed product OS/account purposes. It is a trusted
// Go API, not a command operation exposed to the application control protocol.
func (d *Systemd) RunHelper(ctx context.Context, owner UnitIdentity, id bundle.ProgramID, args []string, input io.Reader, maxOutput int64) ([]byte, error) {
	if input != nil || maxOutput <= 0 || maxOutput > 1<<20 {
		return nil, errors.New("invalid bounded OS helper IO")
	}
	switch id {
	case bundle.MkfsXFS, bundle.ProgramID("useradd"), bundle.ProgramID("groupadd"), bundle.ProgramID("userdel"), bundle.ProgramID("groupdel"):
	default:
		return nil, errors.New("program is not an OS/account helper")
	}
	generation, e := randomGeneration()
	if e != nil {
		return nil, e
	}
	argv := append([]string{string(id)}, args...)
	service := OwnedService{Owner: owner, Name: "chatanium-os-" + generation + ".service", Generation: generation, Program: id, Argv: argv, Identity: NumericIdentity{}, WorkingDirectory: "/", Limits: ResourceLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Pids: 64}, TimeoutStop: 5 * time.Second}
	output, exit, e := d.runBoundedHelper(ctx, service, maxOutput)
	if e != nil {
		return nil, e
	}
	if exit.Kind != "exit" || exit.Value != 0 || exit.OOMKilled {
		return nil, fmt.Errorf("owned %s helper failed (%s %d, host OOM=%t)", id, exit.Kind, exit.Value, exit.OOMKilled)
	}
	return output, nil
}
func (d *Systemd) runBoundedHelper(ctx context.Context, s OwnedService, maxOutput int64) (output []byte, exit ProcessExit, retErr error) {
	in, e := os.Open("/dev/null")
	if e != nil {
		return nil, exit, e
	}
	defer in.Close()
	reader, writer, e := os.Pipe()
	if e != nil {
		return nil, exit, e
	}
	readDone := make(chan struct{})
	var readOutput []byte
	var readErr error
	go func() {
		defer close(readDone)
		readOutput, readErr = io.ReadAll(io.LimitReader(reader, maxOutput+1))
		if int64(len(readOutput)) > maxOutput {
			readErr = errors.New("owned helper output bound exceeded")
			reader.Close()
		}
	}()
	defer func() { writer.Close(); reader.Close(); <-readDone }()
	v, e := d.StartOwned(ctx, s, StandardFiles{in, writer, writer})
	writer.Close()
	if e == nil {
		exit, e = d.Wait(ctx, v.Unit)
	}
	if e != nil {
		first := e
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		observed, recoverErr := d.RecoverOwnedUnit(cleanup, s.Name, s.Generation, s.Program, s.Limits)
		if recoverErr == nil {
			v = observed
			if v.Exit != nil {
				exit = *v.Exit
			} else {
				recoverErr = d.Stop(cleanup, v.Unit)
				if recoverErr == nil {
					exit, recoverErr = d.waitNative(cleanup, v.Unit)
				}
			}
			if recoverErr == nil {
				d.mu.Lock()
				r := d.refs[v.Unit.Name]
				d.mu.Unlock()
				if r == nil {
					recoverErr = ErrCreateUnresolved
				} else {
					recoverErr = d.observeHelperRecord(cleanup, r, &exit, "")
					if recoverErr == nil {
						d.mu.Lock()
						r.recorded = true
						r.terminal = &exit
						d.mu.Unlock()
						recoverErr = d.ReleaseReference(cleanup, v.Unit)
					}
				}
			}
		}
		reader.Close()
		<-readDone
		if recoverErr == nil {
			_, recoverErr = d.Settle(cleanup, v.Unit)
		}
		cancel()
		return nil, exit, errors.Join(first, recoverErr)
	}
	select {
	case <-readDone:
	case <-ctx.Done():
		reader.Close()
		<-readDone
		readErr = errors.Join(readErr, ctx.Err())
	}
	reader.Close()
	cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, e = d.Settle(cleanup, v.Unit)
	if e != nil || readErr != nil {
		return nil, exit, errors.Join(e, readErr)
	}
	return readOutput, exit, nil
}
func (d *Systemd) validateOwnedPurpose(ctx context.Context, s OwnedService) error {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return errors.New("owned purpose requires store")
	}
	m, e := store.Installation(ctx)
	if e != nil {
		return e
	}
	expected := NumericIdentity{}
	switch s.Program {
	case bundle.Worker:
		expected = m.Identities.App
		if e = validateWorkerProjections(m, s); e != nil {
			return e
		}
	case bundle.Stage:
		expected = m.Identities.Sandbox
	case bundle.Preparer, bundle.Rungv:
		expected = m.Identities.Preparer
	}
	if expected.UID != 0 {
		if s.Identity.UID != expected.UID || s.Identity.GID != expected.GID {
			return errors.New("service identity is not the installed role")
		}
		return nil
	}
	if s.Identity.UID != 0 || s.Identity.GID != 0 {
		return errors.New("privileged helper requires root primary identity")
	}
	switch s.Program {
	case bundle.ProgramID("useradd"), bundle.ProgramID("groupadd"), bundle.ProgramID("userdel"), bundle.ProgramID("groupdel"):
		if e = validateAccountCommand(s.Program, s.Argv); e != nil {
			return e
		}
		name := s.Argv[len(s.Argv)-1]
		for _, identity := range []NumericIdentity{m.Identities.App, m.Identities.Sandbox, m.Identities.Preparer} {
			if identity.Name != name {
				continue
			}
			if !identity.ProductCreated {
				return errors.New("account helper cannot mutate a reused identity")
			}
			switch string(s.Program) {
			case "useradd":
				if s.Argv[3] != strconv.FormatUint(uint64(identity.UID), 10) || s.Argv[5] != strconv.FormatUint(uint64(identity.GID), 10) {
					return errors.New("account numeric identity differs from approval")
				}
			case "groupadd":
				if s.Argv[3] != strconv.FormatUint(uint64(identity.GID), 10) {
					return errors.New("group numeric identity differs from approval")
				}
			}
			return nil
		}
		return errors.New("account helper target is not installed")
	case bundle.MkfsXFS:
		a := s.Argv
		if len(a) != 10 || a[1] != "-q" || a[2] != "-K" || a[3] != "-m" || a[4] != "crc=1,reflink=1" || a[5] != "-L" || a[6] != "chatanium" || a[7] != "-d" || a[8] != "file=1,size="+strconv.FormatInt(m.Backing.SizeBytes, 10) || a[9] != m.Paths.BackingFile || m.Backing.Dev != 0 || m.Backing.Ino != 0 {
			return errors.New("formatter arguments exceed new approved backing")
		}
		var st unix.Stat_t
		if e = unix.Lstat(m.Paths.BackingFile, &st); e != nil {
			return e
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&07777 != 0600 || st.Size != m.Backing.SizeBytes {
			return errors.New("formatter backing metadata mismatch")
		}
		records, e := store.PendingProvisions(ctx)
		if e != nil {
			return e
		}
		for _, record := range records {
			if record.Kind != "backing" || record.Identity != m.Paths.BackingFile || !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" {
				continue
			}
			var p ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
				return e
			}
			if p.Dev == st.Dev && p.Ino == st.Ino && p.SizeBytes == st.Size && p.UUID == "" {
				return nil
			}
		}
		return errors.New("formatter backing is not a new observed owned inode")
	case bundle.IP, bundle.IPTables, bundle.IP6Tables, bundle.Conntrack:
		return nil
	default:
		return errors.New("unsupported owned purpose")
	}
}
func (d *Systemd) helperIdentity(ctx context.Context, u UnitIdentity) (UnitObservation, bool, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()
	if store == nil {
		return UnitObservation{}, false, nil
	}
	records, e := store.UnitProvisions(ctx, u.Name)
	if e != nil {
		return UnitObservation{}, false, e
	}
	for _, record := range records {
		if !strings.HasPrefix(record.ID, "systemd-") {
			continue
		}
		var desired ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return UnitObservation{}, false, e
		}
		if desired.Unit == nil || desired.Unit.Generation != u.Generation || desired.Limits == nil {
			continue
		}
		v, found, e := d.cachedHelper(ctx, u.Name, u.Generation, bundle.ProgramID(desired.Source), *desired.Limits)
		if e != nil || !found {
			return v, found, e
		}
		if v.Unit != u {
			return UnitObservation{}, false, errors.New("helper terminal identity mismatch")
		}
		return v, true, nil
	}
	return UnitObservation{}, false, nil
}
func (d *Systemd) unsetEnvironment(ctx context.Context, s OwnedService) ([]string, error) {
	var value dbus.Variant
	e := d.conn.Load().Object(systemdInterface, dbus.ObjectPath("/org/freedesktop/systemd1")).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, systemdInterface+".Manager", "Environment").Store(&value)
	if e != nil {
		return nil, e
	}
	entries, ok := value.Value().([]string)
	if !ok {
		return nil, errors.New("manager environment type mismatch")
	}
	p, e := d.bundle.Program(s.Program)
	if e != nil {
		return nil, e
	}
	approved := map[string]bool{}
	for _, entry := range append(d.programEnvironment(p), s.Env...) {
		key, _, _ := strings.Cut(entry, "=")
		approved[key] = true
	}
	seen := map[string]bool{}
	var unset []string
	add := func(key string) {
		if !approved[key] && !seen[key] {
			seen[key] = true
			unset = append(unset, key)
		}
	}
	for _, entry := range entries {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.ContainsAny(key, "\x00\r\n") {
			return nil, errors.New("invalid manager environment name")
		}
		add(key)
	}
	for _, key := range []string{"PATH", "HOME", "SHELL", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT", "GCONV_PATH", "GLIBC_TUNABLES", "LOCPATH", "GVX_DEBUG_LOG", "GODEBUG", "GOMEMLIMIT", "GOMAXPROCS", "GOTRACEBACK", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		add(key)
	}
	return unset, nil
}
func (d *Systemd) settleSubmission(ctx context.Context, name string) error {
	records, e := d.store.UnitProvisions(ctx, name)
	if e != nil {
		return e
	}
	for _, record := range records {
		if !strings.HasPrefix(record.ID, "systemd-") {
			continue
		}
		var desired, observed ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return e
		}
		if desired.Unit == nil || desired.Limits == nil {
			return errors.New("native submission identity missing")
		}
		if len(record.Observed.Attributes) == 0 {
			return ErrCreateUnresolved
		}
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); e != nil {
			return e
		}
		if observed.Exit == nil && observed.Rejection == "" {
			return ErrCreateUnresolved
		}
		v, found, lookupErr := d.cachedHelper(ctx, name, desired.Unit.Generation, bundle.ProgramID(desired.Source), *desired.Limits)
		if lookupErr != nil {
			return lookupErr
		}
		if !found {
			return ErrCreateUnresolved
		}
		if _, e = d.Settle(ctx, v.Unit); e != nil {
			return e
		}
	}
	return d.proveUnitAbsent(ctx, name)
}
func captureMountNamespace(u UnitIdentity, pid int, sharedOwner bool) (*NamespaceIdentity, string, error) {
	if pid <= 0 || u.StartTime == 0 {
		return nil, "", errors.New("live namespace capture lacks process start identity")
	}
	before, e := processStart(pid)
	if e != nil || before != u.StartTime {
		return nil, "", errors.Join(ErrCleanupIncomplete, e)
	}
	var actual, host unix.Stat_t
	if e = unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &actual); e != nil {
		return nil, "", e
	}
	if e = unix.Stat("/proc/1/ns/mnt", &host); e != nil {
		return nil, "", e
	}
	after, e := processStart(pid)
	if e != nil || after != before {
		return nil, "", errors.Join(ErrCleanupIncomplete, e)
	}
	shared := actual.Dev == host.Dev && actual.Ino == host.Ino
	disposition := "PRIVATE"
	if sharedOwner {
		if !shared {
			return nil, "", errors.New("owner is outside the PID1 mount namespace")
		}
		disposition = "SHARED_HOST"
	} else if shared {
		return nil, "", errors.New("owned service has no private mount namespace")
	}
	return &NamespaceIdentity{Device: actual.Dev, Inode: actual.Ino}, disposition, nil
}
func namespaceReferencesAbsent(ctx context.Context, identity *NamespaceIdentity, disposition string) error {
	if identity == nil || identity.Device == 0 || identity.Inode == 0 {
		return errors.New("owned mount namespace identity was not durably observed")
	}
	if disposition == "SHARED_HOST" {
		var host unix.Stat_t
		if e := unix.Stat("/proc/1/ns/mnt", &host); e != nil {
			return e
		}
		if host.Dev != identity.Device || host.Ino != identity.Inode {
			return ErrCleanupIncomplete
		}
		return nil
	}
	if disposition != "PRIVATE" {
		return errors.New("unknown mount namespace disposition")
	}
	return privateNamespaceReferencesAbsent(ctx, identity, "mnt")
}
func (d *Systemd) observedAbsence(ctx context.Context, r *systemdReference) (CleanupEvidence, error) {
	d.mu.Lock()
	u, service, intent, pipes := r.unit, r.service, r.intent, r.pipes
	d.mu.Unlock()
	out := CleanupEvidence{BootID: d.boot, Units: []UnitIdentity{u}}
	if !validUnit(u) {
		return out, ErrCreateUnresolved
	}
	records, e := d.store.UnitProvisions(ctx, u.Name)
	if e != nil {
		return out, e
	}
	var saved ProvisionProperties
	recordComplete := false
	found := false
	for _, record := range records {
		if record.ID != intent || record.State != "OBSERVED" {
			continue
		}
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &saved); e != nil {
			return out, e
		}
		if saved.Unit == nil || *saved.Unit != u || saved.Exit != nil && service.Program != bundle.Preparer && service.Program != bundle.Rungv {
			return out, errors.New("absence requires an exact prior native observation")
		}
		recordComplete = record.CleanupState == "COMPLETE"
		found = true
		break
	}
	if !found {
		return out, ErrCreateUnresolved
	}
	if e = d.proveUnitAbsent(ctx, u.Name); e != nil {
		return out, e
	}
	if u.BootID == d.boot {
		empty, e := cgroupEmpty(u.CgroupPath)
		if e != nil || !empty {
			return out, errors.Join(ErrCleanupIncomplete, e)
		}
		if start, e := processStart(u.MainPID); e == nil && start == u.StartTime {
			return out, ErrCleanupIncomplete
		} else if e != nil && !os.IsNotExist(e) {
			return out, e
		}
		if e = pipeReferencesAbsent(pipes); e != nil {
			return out, e
		}
		if e = namespaceReferencesAbsent(ctx, saved.MountNamespace, saved.MountNamespaceDisposition); e != nil {
			return out, e
		}
	}
	if service.Program == bundle.Stage {
		l, _, readErr := d.store.lease(ctx, service.Ownership.EpochID, service.Ownership.InstanceID)
		if readErr != nil {
			return out, readErr
		}
		if e = referencesAbsent([]string{filepath.Dir(l.ScratchPath), l.PersistentPath}); e != nil {
			return out, e
		}
	}
	out.JobsAbsent = true
	out.ProcessesAbsent = true
	out.TransportsClosed = true
	out.MountsAbsent = true
	out.OpenReferencesAbsent = true
	out.Details, e = json.Marshal(UnitAbsenceDetails{UnitAbsent: true, CgroupEmpty: true, TransportPipes: pipes})
	if e != nil {
		return out, e
	}
	if e = d.persistPreparationSettlement(ctx, r, &out); e != nil {
		return out, e
	}
	if service.Program == bundle.Stage {
		owner := service.Ownership
		owner.Unit = UnitIdentity{}
		if e = d.store.RecordUnitAbsence(ctx, owner, u, out); e != nil {
			return out, e
		}
	}
	saved.Absence = &out
	saved.CgroupEmpty = true
	if service.Program == bundle.Preparer || service.Program == bundle.Rungv {
		writer, readErr := d.preparationWriterObservation(ctx, intent)
		if readErr == nil {
			saved.Writer = writer
		} else if !recordComplete {
			return out, readErr
		}
	}
	raw, e := json.Marshal(saved)
	if e != nil {
		return out, e
	}
	if !recordComplete {
		if e = d.store.ObserveProvision(ctx, intent, ObjectObservation{Identity: u.Name, Attributes: raw}); e != nil {
			return out, e
		}
	}
	d.mu.Lock()
	r.recorded = true
	r.released = true
	r.acquired = false
	r.observation.Absence = &out
	r.observation.CgroupEmpty = true
	r.observation.MountNamespace = saved.MountNamespace
	r.observation.MountNamespaceDisposition = saved.MountNamespaceDisposition
	if saved.Exit == nil {
		r.terminalErr = errors.New("UNKNOWN native outcome after exact observed invocation disappeared")
	}
	d.mu.Unlock()
	return out, nil
}

// WorkerService supplies the only writable native worker projections. It is
// root-internal; worker IPC cannot choose mounts, identities, or environment.
func (d *Systemd) WorkerService(ctx context.Context, owner UnitIdentity, name, generation string, limits ResourceLimits, timeout time.Duration) (OwnedService, error) {
	d.mu.Lock()
	store := d.store
	actualOwner := d.owner
	d.mu.Unlock()
	if store == nil || owner != actualOwner {
		return OwnedService{}, errors.New("worker requires the bound live owner")
	}
	manifest, e := store.Installation(ctx)
	if e != nil {
		return OwnedService{}, e
	}
	service := workerService(manifest, owner, name, generation, limits, timeout)
	if e = validateWorkerProjections(manifest, service); e != nil {
		return OwnedService{}, e
	}
	return service, nil
}

func workerService(m InstallationManifest, owner UnitIdentity, name, generation string, limits ResourceLimits, timeout time.Duration) OwnedService {
	app := filepath.Join(m.Paths.StorageRoot, "app")
	native := filepath.Join(app, "native")
	instances := filepath.Join(m.Paths.StorageRoot, "instances")
	return OwnedService{Owner: owner, Name: name, Generation: generation, Program: bundle.Worker, Identity: m.Identities.App, Limits: limits, TimeoutStop: timeout, WorkingDirectory: native, Env: []string{"PATH=/usr/bin:/bin", "HOME=" + native, "TMPDIR=" + native, "LANG=C", "LC_ALL=C"}, Mounts: []OwnedMount{{Source: app, Target: app}, {Source: instances, Target: instances}, {Source: filepath.Join(m.Paths.Control, "runtime.sock"), Target: WorkerControlSocketPath(m), ReadOnly: true}}}
}

func validateWorkerProjections(m InstallationManifest, s OwnedService) error {
	expected := workerService(m, s.Owner, s.Name, s.Generation, s.Limits, s.TimeoutStop)
	if s.Program != bundle.Worker || s.Identity != m.Identities.App || s.Identity.UID == 0 || s.Identity.GID == 0 || s.OfflinePreparation || s.NetworkNamespacePath != "" || s.RootDirectory != "" || s.preparation != nil || len(s.Argv) != 0 || s.WorkingDirectory != expected.WorkingDirectory || !sameGateStrings(s.Env, expected.Env) || len(s.Mounts) != len(expected.Mounts) {
		return errors.New("worker launch exceeds fixed native app projections")
	}
	for index, mount := range expected.Mounts {
		if s.Mounts[index] != mount {
			return errors.New("worker writable projection differs from installed layout")
		}
	}
	app := filepath.Join(m.Paths.StorageRoot, "app")
	for _, path := range []string{app, filepath.Join(app, "native"), filepath.Join(app, "logs"), filepath.Join(app, "uploads")} {
		if e := checkWorkerDirectory(path, m.Identities.App.UID, m.Identities.App.GID, 0700); e != nil {
			return e
		}
	}
	if e := checkWorkerDirectory(filepath.Join(m.Paths.StorageRoot, "instances"), 0, m.Identities.App.GID, 0710); e != nil {
		return e
	}
	var socket unix.Stat_t
	if e := unix.Lstat(filepath.Join(m.Paths.Control, "runtime.sock"), &socket); e != nil {
		return e
	}
	if socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Uid != 0 || socket.Gid != m.Identities.App.GID || socket.Mode&07777 != 0660 {
		return errors.New("worker control source is not the current root-owned runtime socket")
	}
	var target unix.Stat_t
	if e := unix.Lstat(WorkerControlSocketPath(m), &target); e != nil {
		return e
	}
	if target.Mode&unix.S_IFMT != unix.S_IFREG || target.Uid != 0 || target.Mode&07777 != 0600 || target.Nlink != 1 {
		return errors.New("worker socket target is not the protected provisioned placeholder")
	}
	return nil
}

func checkWorkerDirectory(path string, uid, gid uint32, mode uint32) error {
	fd, e := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var info unix.Stat_t
	if e = unix.Fstat(fd, &info); e != nil {
		return e
	}
	if info.Uid != uid || info.Gid != gid || info.Mode&07777 != mode {
		return errors.New("native app directory ownership or permissions changed")
	}
	return nil
}

func (d *Systemd) ProveUnsubmittedPreparation(ctx context.Context, name, generation string, program bundle.ProgramID, limits ResourceLimits) (CleanupEvidence, error) {
	out := CleanupEvidence{BootID: d.boot}
	if program != bundle.Preparer && program != bundle.Rungv {
		return out, errors.New("not a preparation purpose")
	}
	if !safeID(generation) || name != "chatanium-image-"+string(program)+"-"+generation+".service" {
		return out, errors.New("unsubmitted preparation identity mismatch")
	}
	if _, e := finiteLimits(limits); e != nil {
		return out, e
	}
	if e := d.cleanupConnection(ctx); e != nil {
		return out, e
	}
	d.mu.Lock()
	ref := d.refs[name]
	store := d.store
	localRejection := ref != nil && ref.unit.Generation == generation && ref.service.Program == program && ref.intent == "" && ref.rejection == "not-dispatched" && ref.recorded && ref.released && !ref.acquired
	d.mu.Unlock()
	if store == nil || ref != nil && !localRejection {
		return out, ErrCreateUnresolved
	}
	records, e := store.UnitProvisions(ctx, name)
	if e != nil {
		return out, e
	}
	for _, record := range records {
		if strings.HasPrefix(record.ID, "systemd-") {
			return out, ErrCreateUnresolved
		}
	}
	if e = d.proveUnitAbsent(ctx, name); e != nil {
		return out, e
	}
	if localRejection {
		d.mu.Lock()
		delete(d.refs, name)
		d.mu.Unlock()
	}
	// StartOwned cannot send before its internal dispatch intent is committed.
	out.JobsAbsent = true
	out.ProcessesAbsent = true
	out.TransportsClosed = true
	out.MountsAbsent = true
	out.OpenReferencesAbsent = true
	return out, nil
}

func WorkerControlSocketPath(m InstallationManifest) string {
	return filepath.Join(m.Paths.RunRoot, "worker-runtime.sock")
}
