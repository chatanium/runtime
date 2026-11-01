package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	discordbackend "github.com/thirdscam/chatanium/internal/backend/discord"
	"github.com/thirdscam/chatanium/internal/host"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"github.com/thirdscam/chatanium/internal/runtime/upload"
	"github.com/thirdscam/chatanium/src/Backends/Discord/Guild"
	"github.com/thirdscam/chatanium/src/Database"
	"golang.org/x/sys/unix"
)

// StartOptions contains only explicit operator inputs; module execution is always
// delegated to the independently authenticated supervisor.
type StartOptions struct {
	ConfigPath         string
	SupervisorSocket   string
	SupervisorUID      int64
	SupervisorMaxBytes int
	Duration           time.Duration
}

func Start(ctx context.Context, options StartOptions) error {
	if !canonicalPath(options.SupervisorSocket) || options.SupervisorUID < 0 || options.SupervisorUID > 1<<32-1 || options.SupervisorMaxBytes <= 0 || options.Duration < 0 {
		return errors.New("invalid runtime arguments")
	}
	raw, err := readOperatorFile(options.ConfigPath)
	if err != nil {
		return err
	}
	config, err := runtime.DecodeConfig(raw)
	if err != nil {
		return errors.New("invalid operator configuration")
	}
	if len(config.Modules) == 0 {
		return errors.New("at least one installed module is required")
	}
	if int64(config.Defaults.DrainDeadline) > int64(^uint64(0)>>1)-int64(config.Limits.TerminationDeadline) {
		return errors.New("combined shutdown deadline overflows")
	}
	if options.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Duration)
		defer cancel()
	}
	return serve(ctx, config, host.ClientConfig{SocketPath: options.SupervisorSocket, SupervisorUID: uint32(options.SupervisorUID), MaxMessageBytes: options.SupervisorMaxBytes, OperationTimeout: time.Duration(config.Limits.DockerAPIDeadline)})
}

type observation struct {
	Phase       string                  `json:"phase"`
	Modules     int                     `json:"modules"`
	Voice       bool                    `json:"voice"`
	StopFailure *stopFailureObservation `json:"stop_failure,omitempty"`
}

func observe(phase string, n int) error {
	if json.NewEncoder(os.Stdout).Encode(observation{Phase: phase, Modules: n, Voice: voiceEnabled}) != nil {
		return errors.New("runtime observation output failed")
	}
	return nil
}

func reconcileHost(ctx context.Context, supervisor interface{ Reconcile(context.Context) error }, output io.Writer, modules int) error {
	err := supervisor.Reconcile(ctx)
	if err == nil {
		return nil
	}
	pending, ok := err.(*host.Error)
	if !ok || pending.Reason != "HOST_RECONCILIATION_PENDING" {
		return errors.New("host reconciliation failed")
	}
	// This result does not release claims or authorize the affected installation.
	// Acquire still enforces its durable exclusive claim.
	if json.NewEncoder(output).Encode(observation{Phase: pending.Reason, Modules: modules, Voice: voiceEnabled}) != nil {
		return errors.New("runtime observation output failed")
	}
	return nil
}

// serve has no executable fallback: every module launch goes through the real
// authenticated supervisor client and Manager's sandbox RunnerFunc.
func serve(ctx context.Context, config runtime.Config, clientConfig host.ClientConfig) (result error) {
	startup, cancel := context.WithTimeout(ctx, time.Duration(config.Defaults.StartupDeadline))
	defer cancel()
	supervisor, err := host.Dial(startup, clientConfig)
	if err != nil {
		return errors.New("host supervisor registration failed")
	}
	defer supervisor.Close()
	if err = reconcileHost(startup, supervisor, os.Stdout, len(config.Modules)); err != nil {
		return err
	}
	files, err := upload.New(startup, upload.Config{ManagementDirectory: config.Host.ManagementDirectory, Limits: config.Limits, ModuleMountRoots: []string{config.Host.StorageRoot, config.Host.IPCRoot}})
	if err != nil {
		return errors.New("upload store initialization failed")
	}
	// Backend lifetime deliberately outlives startup and signal cancellation until
	// the manager has drained all module-owned work.
	life, cancelLife := context.WithCancel(context.Background())
	defer cancelLife()
	var backend *discordbackend.Backend
	var manager *runtime.Manager
	var database *Database.DB
	var stopRecording func()
	defer func() {
		var failures []error
		if manager != nil {
			// Stop independently: one owner's failed cleanup cannot skip another owner.
			done := make(chan *stopFailureObservation, len(config.Modules))
			for _, spec := range config.Modules {
				go func(id runtime.ModuleID) {
					bounded, cancel := context.WithTimeout(context.Background(), time.Duration(config.Defaults.DrainDeadline)+time.Duration(config.Limits.TerminationDeadline))
					defer cancel()
					err := manager.Stop(bounded, id)
					var snapshot *runtime.InstanceSnapshot
					if instance, ok := manager.Instance(id); ok {
						value := instance.Snapshot()
						snapshot = &value
					}
					done <- describeStopFailure(snapshot, err)
				}(spec.ModuleID)
			}
			for range config.Modules {
				if failure := <-done; failure != nil {
					failures = append(failures, errors.New("module stop or terminal failure"))
					if json.NewEncoder(os.Stdout).Encode(observation{Phase: "STOP_FAILED", Modules: len(config.Modules), Voice: voiceEnabled, StopFailure: failure}) != nil {
						failures = append(failures, errors.New("runtime observation output failed"))
					}
				}
			}
		}
		if stopRecording != nil {
			stopRecording()
		}
		if backend != nil {
			if backend.Close() != nil {
				failures = append(failures, errors.New("Discord backend cleanup failed"))
			}
		}
		if database != nil && database.Shutdown() != nil {
			failures = append(failures, errors.New("host database cleanup failed"))
		}
		cancelLife()
		bounded, cancel := context.WithTimeout(context.Background(), time.Duration(config.Limits.TerminationDeadline))
		defer cancel()
		if files.Close(bounded) != nil {
			failures = append(failures, errors.New("upload store cleanup failed"))
		}
		if len(failures) == 0 && manager != nil {
			if e := observe("STOPPED", len(config.Modules)); e != nil {
				failures = append(failures, e)
			}
		}
		result = errors.Join(append([]error{result}, failures...)...)
	}()
	var registrations []runtime.BackendRegistration
	var discordConfig discordOperatorConfig
	backendErrors := make(chan struct{}, 1)
	for id, c := range config.Backends {
		if id != "discord" || c.Major != 2 {
			return errors.New("unsupported backend configuration")
		}
		if strictJSON(c.Config, &discordConfig) != nil {
			return errors.New("invalid Discord operator configuration")
		}
		backend, err = newDiscordBackend(life, config, c, &discordConfig, files, func(error) {
			select {
			case backendErrors <- struct{}{}:
			default:
			}
		})
		if err != nil {
			return err
		}
		registrations = append(registrations, backend.Registration())
	}
	manager, err = runtime.NewManager(config, runtime.ManagerOptions{Host: supervisor, Backends: registrations, FileTransfer: files.RegistrarFactory, FileCleanup: files.CleanupInstance})
	if err != nil {
		return errors.New("runtime manager initialization failed")
	}
	if backend != nil {
		if backend.AttachDispatcher(manager.Dispatcher()) != nil {
			return errors.New("Discord dispatcher attachment failed")
		}
		database = &Database.DB{}
		if database.Start(startup) != nil {
			return errors.New("host database initialization failed")
		}
		stopRecording = Guild.Handle(life, backend.HostSession(), database, time.Duration(discordConfig.HTTP.RequestDeadline), discordConfig.HTTP.ResponseMaxBytes, func(error) {
			select {
			case backendErrors <- struct{}{}:
			default:
			}
		})
		if backend.Open(startup) != nil {
			return errors.New("Discord Gateway startup failed")
		}
	}
	for _, spec := range config.Modules {
		if _, err = manager.Launch(ctx, spec); err != nil {
			return errors.New("module activation failed")
		}
	}
	cancel()
	if err = observe("RUNNING", len(config.Modules)); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Duration(config.Limits.ReadinessPollInterval))
	defer ticker.Stop()
	hadFailure := false
	for {
		select {
		case <-ctx.Done():
			if hadFailure {
				return errors.New("one or more module instances failed")
			}
			return nil
		case <-backendErrors:
			// Report only an allowlisted phase, never raw remote errors or event data.
			if e := observe("BACKEND_ERROR", len(config.Modules)); e != nil {
				return e
			}
		case <-ticker.C:
			allStopped := true
			for _, spec := range config.Modules {
				instance, ok := manager.Instance(spec.ModuleID)
				if !ok {
					return errors.New("module instance disappeared")
				}
				s := instance.Snapshot()
				if s.State == runtime.Running {
					allStopped = false
				}
				if s.State == runtime.Failed {
					hadFailure = true
				}
			}
			if allStopped {
				return errors.New("all module instances stopped")
			}
		}
	}
}

func canonicalPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

const operatorMaxBytes = 16 << 20

func readOperatorFile(path string) ([]byte, error) {
	if !canonicalPath(path) {
		return nil, errors.New("canonical absolute configuration path required")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, errors.New("configuration cannot be opened without symlinks")
	}
	f := os.NewFile(uintptr(fd), "operator-configuration")
	defer f.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Size <= 0 || stat.Size > operatorMaxBytes {
		return nil, errors.New("configuration must be a bounded operator-owned non-writable regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, operatorMaxBytes+1))
	if err != nil || len(raw) > operatorMaxBytes {
		return nil, errors.New("configuration read failed")
	}
	return raw, nil
}
