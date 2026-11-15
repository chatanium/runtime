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
	DevelopmentMode    bool
	DevelopmentSocket  string
	DevelopmentImages  []string
}

func Start(ctx context.Context, options StartOptions) error {
	if err := validateDevelopmentOptions(options); err != nil {
		return err
	}
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
	if err := applyDevelopmentImages(&config, options.DevelopmentImages); err != nil {
		return err
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
	return serve(ctx, config, host.ClientConfig{SocketPath: options.SupervisorSocket, SupervisorUID: uint32(options.SupervisorUID), MaxMessageBytes: options.SupervisorMaxBytes, OperationTimeout: time.Duration(config.Limits.DockerAPIDeadline)}, options)
}

type observation struct {
	Phase           string                      `json:"phase"`
	Modules         int                         `json:"modules"`
	Voice           bool                        `json:"voice"`
	StopFailure     *stopFailureObservation     `json:"stop_failure,omitempty"`
	DevelopmentStop *developmentStopObservation `json:"development_stop,omitempty"`
}

func observe(phase string, n int) error {
	return emitObservation(os.Stdout, observation{Phase: phase, Modules: n, Voice: voiceEnabled})
}

func emitObservation(output io.Writer, value observation) error {
	if json.NewEncoder(output).Encode(value) != nil {
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
func serve(ctx context.Context, config runtime.Config, clientConfig host.ClientConfig, options StartOptions) (result error) {
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
	var development *developmentController
	developmentReady := false
	defer func() {
		var failures []error
		resourcesClean := options.DevelopmentMode && developmentReady && development != nil
		var moduleStops []developmentModuleStop
		if options.DevelopmentMode {
			moduleStops = make([]developmentModuleStop, 0, len(config.Modules))
		}
		// Reject, cancel and join every reload before any module/backend teardown.
		if development != nil {
			if development.Close() != nil {
				failures = append(failures, errors.New("development control cleanup failed"))
				resourcesClean = false
			}
		}
		if manager != nil {
			// Stop independently: one owner's failed cleanup cannot skip another owner.
			done := make(chan developmentModuleStop, len(config.Modules))
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
					done <- describeDevelopmentModuleStop(snapshot, err)
				}(spec.ModuleID)
			}
			for range config.Modules {
				stopped := <-done
				if options.DevelopmentMode {
					moduleStops = append(moduleStops, stopped)
				}
				if failure := stopped.failure; failure != nil {
					failures = append(failures, errors.New("module stop or terminal failure"))
					if json.NewEncoder(os.Stdout).Encode(observation{Phase: "STOP_FAILED", Modules: len(config.Modules), Voice: voiceEnabled, StopFailure: failure}) != nil {
						failures = append(failures, errors.New("runtime observation output failed"))
						resourcesClean = false
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
				resourcesClean = false
			}
		}
		if database != nil && database.Shutdown() != nil {
			failures = append(failures, errors.New("host database cleanup failed"))
			resourcesClean = false
		}
		cancelLife()
		bounded, cancel := context.WithTimeout(context.Background(), time.Duration(config.Limits.TerminationDeadline))
		defer cancel()
		if files.Close(bounded) != nil {
			failures = append(failures, errors.New("upload store cleanup failed"))
			resourcesClean = false
		}
		if len(failures) == 0 && manager != nil {
			if e := observe("STOPPED", len(config.Modules)); e != nil {
				failures = append(failures, e)
				resourcesClean = false
			}
		}
		if err := emitDevelopmentStopped(os.Stdout, manager, config.Modules, moduleStops, resourcesClean); err != nil {
			failures = append(failures, err)
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
	manager, err = runtime.NewManager(config, runtime.ManagerOptions{Host: supervisor, Backends: registrations, FileTransfer: files.RegistrarFactory, FileCleanup: files.CleanupInstance, DevelopmentMode: options.DevelopmentMode})
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
	startupObservation, err := activateInitialModules(ctx, manager, config.Modules, options.DevelopmentMode)
	if err != nil {
		return err
	}
	cancel()
	development, err = startDevelopmentController(ctx, options, config, manager)
	if err != nil {
		return err
	}
	var developmentDone <-chan struct{}
	if development != nil {
		developmentDone = development.done
	}
	if err = emitObservation(os.Stdout, startupObservation); err != nil {
		return err
	}
	developmentReady = options.DevelopmentMode
	ticker := time.NewTicker(time.Duration(config.Limits.ReadinessPollInterval))
	defer ticker.Stop()
	hadFailure := false
	for {
		select {
		case <-ctx.Done():
			if options.DevelopmentMode {
				if development.Close() != nil {
					return errors.New("development control cleanup failed")
				}
				_, hadFailure, err = moduleHealth(manager, config.Modules)
				if err != nil {
					return err
				}
			}
			if hadFailure {
				return errors.New("one or more module instances failed")
			}
			return nil
		case <-developmentDone:
			return errors.New("development control listener stopped")
		case <-backendErrors:
			// Report only an allowlisted phase, never raw remote errors or event data.
			if e := observe("BACKEND_ERROR", len(config.Modules)); e != nil {
				developmentReady = false
				return e
			}
		case <-ticker.C:
			allStopped, failed, healthErr := moduleHealth(manager, config.Modules)
			if healthErr != nil {
				return healthErr
			}
			if options.DevelopmentMode {
				hadFailure = failed
			} else {
				hadFailure = hadFailure || failed
			}
			if allStopped && !options.DevelopmentMode {
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
