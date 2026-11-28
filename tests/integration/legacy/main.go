// Integration entry points use the real host runtime and actual OCI modules.
// They never inject metadata identities or start module binaries directly.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/thirdscam/chatanium/internal/legacy/bootstrap"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
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
	executable := flags.String("runtime", "", "installed static launcher executable")
	deadline := flags.Duration("deadline", 0, "required total scenario deadline")
	observation := flags.Duration("observe", 0, "required running observation interval")
	policyPlan := flags.String("policy-plan", "", "absolute trusted sandbox policy selection/prerequisite JSON; requires root observer")
	policyRunner := flags.String("policy-runner", "", "absolute installed permanent sandbox-policy.py")
	evidence := flags.String("evidence", "", "existing private root-owned policy evidence directory")
	imageCheckOnly := flags.Bool("image-check-only", false, "verify committed canonical sandbox image declarations without launching modules")
	prepareImages := flags.Bool("prepare-images", false, "explicitly prepare already-approved exact images through the installed launcher")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *deadline <= 0 || *observation <= 0 || *observation >= *deadline || !filepath.IsAbs(*configPath) || !filepath.IsAbs(*executable) {
		return errors.New("finite deadline/observe and absolute installed runtime/config required")
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
	if err := bootstrap.ValidateInstalledConfig(context.Background(), bootstrap.RuntimeInstallationID(config.Host.RuntimeInstallationID), *configPath, raw); err != nil {
		return errors.New("configuration is not the active installed revision")
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
		return runSandboxPolicy(ctx, *policyRunner, *policyPlan, *evidence, *configPath, *executable, *deadline)
	}
	if *prepareImages {
		for _, spec := range config.Modules {
			command := exec.CommandContext(ctx, *executable, "prepare-image", "--installation-id", config.Host.RuntimeInstallationID,
				"--module-id", string(spec.ModuleID), "--image", spec.ImageDigest,
				"--config-revision", spec.ConfigRevision, "--approval-revision", spec.ApprovalRevision)
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/nonexistent"}
			command.Stdout, command.Stderr = io.Discard, io.Discard
			if err := command.Run(); err != nil {
				return errors.New("approved image preparation failed")
			}
		}
	}
	if scenario == "sandbox" {
		expected := new(wire.ModuleManifest)
		if protojson.Unmarshal(sandboxManifest, expected) != nil {
			return errors.New("invalid embedded sandbox fixture manifest")
		}
		for _, spec := range config.Modules {
			image, err := bootstrap.InspectPreparedImage(ctx, bootstrap.RuntimeInstallationID(config.Host.RuntimeInstallationID), spec.ImageDigest)
			actual := new(wire.ModuleManifest)
			if err != nil || protojson.Unmarshal(image.Declaration, actual) != nil || !proto.Equal(expected, actual) {
				return errors.New("sandbox scenario requires committed canonical sandbox fixture images")
			}
		}
	}
	if *imageCheckOnly {
		return nil
	}
	command := exec.CommandContext(ctx, *executable, "start", "--foreground", "--installation-id", config.Host.RuntimeInstallationID, "--config", *configPath)
	command.Env = os.Environ() // The installed launcher alone selects approved secret bindings.
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
				record("sandbox.boundaries", "PASS", "fixture INIT and authenticated bridge reached RUNNING with approved guest roots, non-root identity and NONE topology")
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
func runSandboxPolicy(ctx context.Context, observer, plan, evidence, config, executable string, deadline time.Duration) error {
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
