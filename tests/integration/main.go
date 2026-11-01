// Integration entry points use the real host runtime and actual OCI modules.
// They never inject metadata identities or start module binaries directly.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/runner"
	"github.com/thirdscam/chatanium/internal/host"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed fixtures/sandbox/manifest.json
var sandboxManifest []byte

type result struct {
	Scenario string `json:"scenario"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}

func record(scenario, status, evidence string) {
	_ = json.NewEncoder(os.Stdout).Encode(result{scenario, status, evidence})
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "integration:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || (args[0] != "sandbox" && args[0] != "discord" && args[0] != "voice") {
		return errors.New("expected sandbox, discord or voice scenario")
	}
	scenario := args[0]
	flags := flag.NewFlagSet(scenario, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "absolute operator runtime JSON")
	executable := flags.String("runtime", "", "built runtime executable")
	socket := flags.String("supervisor-socket", "", "absolute real supervisor socket")
	uid := flags.Int64("supervisor-uid", -1, "trusted supervisor UID")
	maxBytes := flags.Int("supervisor-max-bytes", 0, "supervisor packet bound")
	deadline := flags.Duration("deadline", 0, "required total scenario deadline")
	observation := flags.Duration("observe", 0, "required running observation interval")
	policyPlan := flags.String("policy-plan", "", "absolute trusted sandbox policy selection/prerequisite JSON; requires root observer")
	policyRunner := flags.String("policy-runner", "", "absolute installed permanent sandbox-policy.py")
	evidence := flags.String("evidence", "", "existing private root-owned policy evidence directory")
	imageCheckOnly := flags.Bool("image-check-only", false, "verify canonical sandbox manifests as the configured non-root peer, without launching modules")
	ipcComponentOnly := flags.Bool("ipc-component-only", false, "exercise actual supervisor retained-socket capture using the canonical fixture")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *deadline <= 0 || *observation <= 0 || *observation >= *deadline || *uid < 0 || *uid > 1<<32-1 || *maxBytes <= 0 || !filepath.IsAbs(*configPath) || !filepath.IsAbs(*socket) || *executable == "" {
		return errors.New("finite deadline/observe, runtime/config and explicit supervisor flags required")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		record(scenario, "NOT_RUN", "operator configuration unavailable")
		return errors.New("configuration unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) > 16<<20 {
		return errors.New("configuration read failed")
	}
	config, err := runtime.DecodeConfig(raw)
	if err != nil {
		return errors.New("invalid operator configuration")
	}
	if len(config.Modules) == 0 {
		return errors.New("scenario requires installed real OCI modules")
	}
	if scenario == "sandbox" && len(config.Backends) != 0 {
		return errors.New("sandbox scenario requires backendless sandbox probe configuration")
	}
	if *imageCheckOnly && (scenario != "sandbox" || *policyPlan != "") {
		return errors.New("image-check-only requires sandbox without policy orchestration")
	}
	if *ipcComponentOnly && (scenario != "sandbox" || *policyPlan != "" || *imageCheckOnly) {
		return errors.New("ipc-component-only requires dedicated sandbox mode")
	}
	if *policyPlan != "" || *policyRunner != "" || *evidence != "" {
		if scenario != "sandbox" || !filepath.IsAbs(*policyPlan) || !filepath.IsAbs(*policyRunner) || !filepath.IsAbs(*evidence) {
			return errors.New("policy mode requires sandbox and absolute policy-plan, policy-runner and evidence paths")
		}
	}
	if scenario != "sandbox" {
		discord, ok := config.Backends["discord"]
		if !ok {
			return errors.New("live scenario requires approved Discord backend")
		}
		if scenario == "voice" {
			var options map[string]json.RawMessage
			if json.Unmarshal(discord.Config, &options) != nil || len(options["voice"]) == 0 || string(options["voice"]) == "null" {
				return errors.New("voice scenario requires explicit finite host voice configuration")
			}
		}
		for _, source := range discord.SecretSources {
			if len(source) < 5 || source[:4] != "env:" {
				return errors.New("host-only environment binding required")
			}
			if value, ok := os.LookupEnv(source[4:]); !ok || value == "" {
				record(scenario, "NOT_RUN", "required host credential binding unavailable")
				return errors.New("live credential prerequisite missing")
			}
		}
	}
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *deadline)
	defer cancel()
	if *policyPlan != "" {
		return runSandboxPolicy(ctx, *policyRunner, *policyPlan, *evidence, *configPath, *executable, *socket, *uid, *maxBytes, *deadline)
	}
	if scenario == "sandbox" && !*ipcComponentOnly {
		client, err := host.Dial(ctx, host.ClientConfig{SocketPath: *socket, SupervisorUID: uint32(*uid), MaxMessageBytes: *maxBytes, OperationTimeout: time.Duration(config.Limits.DockerAPIDeadline)})
		if err != nil {
			return errors.New("sandbox image verification supervisor unavailable")
		}
		defer client.Close()
		expected := new(wire.ModuleManifest)
		if protojson.Unmarshal(sandboxManifest, expected) != nil {
			return errors.New("invalid embedded sandbox fixture manifest")
		}
		for _, spec := range config.Modules {
			raw, e := client.ImageManifest(ctx, spec.ImageDigest)
			actual := new(wire.ModuleManifest)
			if e != nil || protojson.Unmarshal(raw, actual) != nil || !proto.Equal(expected, actual) {
				return errors.New("sandbox scenario requires canonical sandbox fixture images")
			}
		}
	}
	if *imageCheckOnly {
		return nil
	}
	if *ipcComponentOnly {
		return runIPCComponent(ctx, config, *socket, uint32(*uid), *maxBytes)
	}
	command := exec.CommandContext(ctx, *executable, "start", "--config", *configPath, "--supervisor-socket", *socket, "--supervisor-uid", strconv.FormatInt(*uid, 10), "--supervisor-max-bytes", strconv.Itoa(*maxBytes))
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	stdout, err := command.StdoutPipe()
	if err != nil {
		return errors.New("runtime output setup failed")
	}
	if err = command.Start(); err != nil {
		record(scenario, "NOT_RUN", "runtime artifact unavailable")
		return errors.New("runtime start failed")
	}
	running := make(chan bool, 1)
	stopped := make(chan struct{}, 1)
	invalid := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 4096)
		for scanner.Scan() {
			var phase struct {
				Phase   string `json:"phase"`
				Modules int    `json:"modules"`
				Voice   bool   `json:"voice"`
			}
			if json.Unmarshal(scanner.Bytes(), &phase) != nil || phase.Modules != len(config.Modules) {
				select {
				case invalid <- struct{}{}:
				default:
				}
				continue
			}
			switch phase.Phase {
			case "RUNNING":
				select {
				case running <- phase.Voice:
				default:
				}
			case "STOPPED":
				select {
				case stopped <- struct{}{}:
				default:
				}
			default:
				select {
				case invalid <- struct{}{}:
				default:
				}
			}
		}
		scanErr := scanner.Err()
		waitErr := command.Wait()
		done <- errors.Join(scanErr, waitErr)
	}()
	var timer *time.Timer
	var tick <-chan time.Time
	activated, signaled := false, false
	var failure error
	for {
		select {
		case native := <-running:
			if activated {
				failure = errors.New("runtime repeated activation")
				_ = command.Process.Signal(syscall.SIGTERM)
				continue
			}
			activated = true
			if scenario == "voice" && !native {
				failure = errors.New("voice scenario requires voice-enabled artifact")
				_ = command.Process.Signal(syscall.SIGTERM)
				continue
			}
			record(scenario+".activation", "PASS", "actual supervisor OCI launch, authenticated v2 manifest negotiation and INIT/START reached RUNNING")
			timer = time.NewTimer(*observation)
			tick = timer.C
		case <-tick:
			tick = nil
			signaled = true
			if command.Process.Signal(syscall.SIGTERM) != nil {
				failure = errors.New("runtime SIGTERM delivery failed")
			}
		case <-invalid:
			failure = errors.New("runtime reported a backend error or invalid observation")
			_ = command.Process.Signal(syscall.SIGTERM)
		case err := <-done:
			if timer != nil {
				timer.Stop()
			}
			select {
			case <-invalid:
				failure = errors.New("runtime reported a backend error or invalid observation")
			default:
			}
			if err != nil || failure != nil || !activated || !signaled {
				record(scenario+".lifecycle", "FAIL", "runtime did not complete bounded activation, observation and signal cleanup")
				return errors.New("runtime scenario failed")
			}
			select {
			case <-stopped:
				record(scenario+".signal_cleanup", "PASS", "SIGTERM returned after manager/backend/upload owned cleanup reported STOPPED")
			default:
				record(scenario+".signal_cleanup", "FAIL", "runtime omitted cleanup completion")
				return errors.New("cleanup evidence missing")
			}
			if scenario == "sandbox" {
				record("sandbox.boundaries", "PASS", "sandbox fixture INIT checked non-root, read-only rootfs, approved mount I/O, persistent sentinel, absent host environment/Docker socket and configured IPv4/IPv6 NONE-egress denials")
				record("sandbox.full_policy", "NOT_RUN", "baseline only; select --policy-plan, --policy-runner and --evidence for finite host-observed policy cases")
				return nil
			}
			if scenario == "discord" {
				record("discord.interactive_operations", "NOT_RUN", "activation alone is not evidence of approved user moderation, DM, component/modal/autocomplete and attachment round trips")
			}
			if scenario == "voice" {
				record("voice.encrypted_participants", "NOT_RUN", "voice-enabled activation alone is not encrypted playback/receive or participant rekey evidence; approved participants must exercise the module commands")
			}
			return errors.New("live scenario activation complete; interactive acceptance remains NOT_RUN")
		case <-ctx.Done():
			_ = command.Process.Kill()
			<-done
			if timer != nil {
				timer.Stop()
			}
			record(scenario, "FAIL", "scenario cancelled or total deadline exceeded; supervisor epoch cleanup remains authoritative")
			return errors.New("scenario cancelled or deadline exceeded")
		}
	}
}

// Policy execution deliberately remains outside the production control plane.
// The installed observer validates root ownership of itself and every operator
// input, pins exact child identities, and never accepts imported evidence.
func runSandboxPolicy(ctx context.Context, observer, plan, evidence, config, executable, socket string, uid int64, maxBytes int, deadline time.Duration) error {
	if os.Geteuid() != 0 {
		record("sandbox.full_policy", "NOT_RUN", "explicit root-side observer and trusted installed operator inputs required")
		return errors.New("policy observer requires root")
	}
	checker, err := os.Executable()
	if err != nil {
		return errors.New("installed integration image checker unavailable")
	}
	for _, path := range []string{observer, plan, config, executable, checker} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("policy inputs must be canonical absolute installed paths")
		}
		for current := path; ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
				return errors.New("policy input path is writable or untrusted")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return errors.New("policy inputs require root-owned ancestors")
			}
			if current == "/" {
				break
			}
		}
	}
	// Python is an explicit host prerequisite, not a guest dependency. No host
	// environment (including credentials) is inherited by the observer/runtime.
	command := exec.CommandContext(ctx, "/usr/bin/python3", observer,
		"--plan", plan, "--output", evidence, "--config", config, "--runtime", executable, "--image-checker", checker,
		"--supervisor-socket", socket, "--supervisor-uid", strconv.FormatInt(uid, 10),
		"--supervisor-max-bytes", strconv.Itoa(maxBytes),
		"--overall-seconds", strconv.FormatInt(int64(deadline/time.Second), 10))
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/nonexistent"}
	command.Stdout = os.Stdout
	command.Stderr = io.Discard
	command.WaitDelay = 80 * time.Second
	// On cancellation allow the observer's bounded finally/reconciliation path;
	// it owns its exact runtime child. Reserve a bounded 80s cancellation grace
	// for its per-case shutdown/reconciliation window, never broad host cleanup.
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	if err := command.Run(); err != nil {
		return errors.New("selected sandbox policy cases did not all pass; see private evidence")
	}
	return nil
}

// This component case uses real go-plugin bootstrap and the production runner,
// but never Dispense/INIT: only the retained-socket boundary is under test.
func runIPCComponent(ctx context.Context, config runtime.Config, socket string, uid uint32, maxBytes int) (retErr error) {
	if os.Geteuid() == 0 || len(config.Modules) != 1 {
		return errors.New("one canonical fixture and configured non-root peer required")
	}
	spec, l := config.Modules[0], config.Limits
	if len(spec.Args) != 1 || spec.Args[0] != "--fixture-ipc-component" || spec.Approval.EgressPolicy != wire.EgressPolicy_EGRESS_POLICY_NONE {
		return errors.New("dedicated IPC fixture arguments and NONE grant required")
	}
	client, err := host.Dial(ctx, host.ClientConfig{SocketPath: socket, SupervisorUID: uid, MaxMessageBytes: maxBytes, OperationTimeout: time.Duration(l.DockerAPIDeadline)})
	if err != nil {
		return errors.New("IPC supervisor connection failed")
	}
	defer client.Close()
	expected, actual := new(wire.ModuleManifest), new(wire.ModuleManifest)
	declaration, err := client.ImageManifest(ctx, spec.ImageDigest)
	if err != nil || protojson.Unmarshal(sandboxManifest, expected) != nil || protojson.Unmarshal(declaration, actual) != nil || !proto.Equal(expected, actual) {
		return errors.New("IPC component requires canonical sandbox fixture image")
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return errors.New("IPC instance identity unavailable")
	}
	r := spec.Approval.ResourceLimits
	lease, err := client.Acquire(ctx, host.LaunchSpec{ModuleID: string(spec.ModuleID), InstanceID: fmt.Sprintf("%x", random), ImageDigest: spec.ImageDigest,
		Entrypoint: spec.Entrypoint, Args: spec.Args, UID: spec.UID, GID: spec.GID, InitialEgress: host.EgressNone,
		ConfigRevision: spec.ConfigRevision, ApprovalRevision: spec.ApprovalRevision,
		Resources: host.ResourceLimits{NanoCPUs: int64(r.CpuMillicores) * 1000000, MemoryBytes: int64(r.MemoryBytes), Pids: int64(r.MaxPids),
			PersistentBytes: int64(r.PersistentBytes), ScratchBytes: int64(r.ScratchBytes), PersistentInodes: l.PersistentInodeLimit,
			ScratchInodes: l.ScratchInodeLimit, ControlMessageMaxBytes: int64(l.ControlMessageMaxBytes), LogBufferBytes: l.LogBufferBytes,
			LogFileMaxBytes: l.LogFileMaxBytes, LogRetainedFiles: l.LogRetainedFiles}})
	if err != nil {
		return errors.New("IPC allocation failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		retErr = errors.Join(retErr, client.Terminate(cleanup, lease.Ownership.InstanceID), client.Release(cleanup, lease.Ownership.InstanceID))
	}()
	factory := host.NewRunnerFactory(client, lease)
	var socketDir string
	deadline, _ := ctx.Deadline()
	p := plugin.NewClient(&plugin.ClientConfig{HandshakeConfig: core.HandshakeConfig(), Plugins: plugin.PluginSet{},
		RunnerFunc: func(logger hclog.Logger, cmd *exec.Cmd, dir string) (runner.Runner, error) {
			socketDir = dir
			return factory.RunnerFunc(logger, cmd, dir)
		}, AutoMTLS: true, SkipHostEnv: true, GRPCBrokerMultiplex: true, AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		StartTimeout: time.Until(deadline), Logger: hclog.NewNullLogger(), Stderr: io.Discard,
		SyncStdout: io.Discard, SyncStderr: io.Discard, PluginLogBufferSize: l.ControlMessageMaxBytes,
		UnixSocketConfig: &plugin.UnixSocketConfig{TempDir: lease.IPCPath, Group: strconv.FormatUint(uint64(lease.SocketGID), 10)}})
	defer func() {
		p.Kill()
		retErr = errors.Join(retErr, factory.CloseTransport())
	}()
	if _, err = p.Start(); err != nil {
		return errors.New("real IPC fixture bootstrap failed")
	}
	emit := func(phase string, data map[string]any) error {
		data["phase"], data["modules"], data["voice"] = phase, 1, false
		data["pid"], data["instance_id"], data["epoch_id"] = os.Getpid(), lease.Ownership.InstanceID, lease.Ownership.EpochID
		data["installation_id"] = lease.Ownership.InstallationID
		return json.NewEncoder(os.Stdout).Encode(data)
	}
	if err = emit("RUNNING", map[string]any{}); err != nil {
		return err
	}
	// Parent inspects exact lease/container/cgroup before allowing this one use.
	input := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 32), 32)
		input <- scanner.Scan() && scanner.Text() == "exercise"
	}()
	select {
	case ok := <-input:
		if !ok {
			return errors.New("IPC observer command missing")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	name := filepath.Join(filepath.Base(socketDir), "original")
	held, err := client.CaptureSocket(ctx, lease.Ownership.InstanceID, name)
	if err != nil {
		return errors.New("original socket capture failed")
	}
	defer held.Close()
	st, err := held.Stat()
	if err != nil {
		return err
	}
	dial := func(path string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	}
	control, err := dial(filepath.Join(socketDir, "control"))
	if err != nil {
		return errors.New("fixture control unavailable")
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = fmt.Fprintln(control, "replace "+filepath.Join(lease.ScratchPath, "outside")); err != nil {
		return err
	}
	reader := bufio.NewScanner(control)
	reader.Buffer(make([]byte, 128), 128)
	if !reader.Scan() || reader.Text() != "replaced" {
		return errors.New("ordered replacement acknowledgement missing")
	}
	conn, err := dial(fmt.Sprintf("/proc/self/fd/%d", held.Fd()))
	if err != nil {
		return errors.New("retained descriptor dial failed")
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	response := bufio.NewScanner(conn)
	response.Buffer(make([]byte, 128), 128)
	original := response.Scan() && response.Text() == "original"
	_ = conn.Close()
	fresh, captureErr := client.CaptureSocket(ctx, lease.Ownership.InstanceID, name)
	if fresh != nil {
		_ = fresh.Close()
	}
	if !original || captureErr == nil {
		return errors.New("retained identity or replaced-name rejection failed")
	}
	if _, err = fmt.Fprintln(control, "complete"); err != nil || !reader.Scan() || reader.Text() != "complete" {
		return errors.New("fixture completion acknowledgement missing")
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("retained inode identity unavailable")
	}
	if err = emit("IPC_COMPONENT", map[string]any{"order": []string{"captured", "replacement-ack", "held-dial-original", "fresh-capture-rejected", "complete-ack"},
		"device": native.Dev, "inode": native.Ino, "original_reached": original, "fresh_capture_rejected": captureErr != nil}); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
