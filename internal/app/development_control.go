//go:build linux

package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const developmentBodyMaxBytes = 4096

type developmentManager interface {
	ModuleSnapshot(runtime.ModuleID) (runtime.ModuleSnapshot, bool)
	DevelopmentReload(context.Context, runtime.ModuleID, runtime.InstanceID, string) (runtime.ModuleSnapshot, error)
}

type developmentModule struct {
	ModuleID        runtime.ModuleID     `json:"module_id"`
	InstanceID      runtime.InstanceID   `json:"instance_id"`
	Image           string               `json:"image"`
	CommittedImage  string               `json:"committed_image"`
	State           runtime.RuntimeState `json:"state"`
	Reloading       bool                 `json:"reloading"`
	CleanupComplete bool                 `json:"cleanup_complete"`
}

func developmentRecord(snapshot runtime.ModuleSnapshot) developmentModule {
	return developmentModule{ModuleID: snapshot.Principal.ModuleID, InstanceID: snapshot.Principal.InstanceID, Image: snapshot.ImageDigest, CommittedImage: snapshot.CommittedImageDigest, State: snapshot.State, Reloading: snapshot.Reloading, CleanupComplete: snapshot.CleanupComplete}
}

type developmentReloadRequest struct {
	ModuleID           runtime.ModuleID   `json:"module_id"`
	ExpectedInstanceID runtime.InstanceID `json:"expected_instance_id"`
	Image              string             `json:"image"`
}

type developmentPeerKey struct{}

// The handler's admission mutex makes shutdown a positive join barrier: once
// stopping is set, no request can add work behind the wait group.
type developmentController struct {
	manager   developmentManager
	modules   []runtime.ModuleID
	deadline  time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	stopping  bool
	handlers  sync.WaitGroup
	server    *http.Server
	socket    *developmentSocket
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func startDevelopmentController(ctx context.Context, options StartOptions, config runtime.Config, manager developmentManager) (*developmentController, error) {
	if err := validateDevelopmentOptions(options); err != nil {
		return nil, err
	}
	if !options.DevelopmentMode {
		return nil, nil
	}
	deadline := time.Duration(config.Defaults.StartupDeadline)
	for _, value := range []time.Duration{time.Duration(config.Defaults.DrainDeadline), time.Duration(config.Limits.TerminationDeadline)} {
		if value <= 0 || deadline <= 0 || deadline > time.Duration(1<<63-1)-value {
			return nil, errors.New("invalid development request deadline")
		}
		deadline += value
	}
	socket, err := listenDevelopmentSocket(options.DevelopmentSocket, config.Host.StorageRoot, config.Host.IPCRoot)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	control := &developmentController{manager: manager, deadline: deadline, ctx: life, cancel: cancel, socket: socket, done: make(chan struct{})}
	control.modules = make([]runtime.ModuleID, 0, len(config.Modules))
	for _, spec := range config.Modules {
		control.modules = append(control.modules, spec.ModuleID)
	}
	control.server = &http.Server{
		Handler:           control,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      deadline,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    8192,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return life },
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			// Only authenticated SO_PEERCRED connections leave our listener.
			return context.WithValue(ctx, developmentPeerKey{}, true)
		},
	}
	control.server.SetKeepAlivesEnabled(false)
	go func() {
		defer close(control.done)
		// Only the closed channel is public; never expose raw listener errors.
		_ = control.server.Serve(socket.listener)
	}()
	return control, nil
}

func (control *developmentController) Close() error {
	control.closeOnce.Do(func() {
		control.mu.Lock()
		control.stopping = true
		control.cancel()
		control.mu.Unlock()
		serverErr := control.server.Close()
		control.handlers.Wait()
		<-control.done
		socketErr := control.socket.Close()
		if serverErr != nil || socketErr != nil {
			control.closeErr = errors.New("development control cleanup failed")
		}
	})
	return control.closeErr
}

func (control *developmentController) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if authorized, _ := request.Context().Value(developmentPeerKey{}).(bool); !authorized {
		developmentError(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	control.mu.Lock()
	if control.stopping || control.ctx.Err() != nil {
		control.mu.Unlock()
		developmentError(w, http.StatusServiceUnavailable, "SHUTTING_DOWN")
		return
	}
	control.handlers.Add(1)
	control.mu.Unlock()
	defer control.handlers.Done()
	ctx, cancel := context.WithTimeout(control.ctx, control.deadline)
	defer cancel()
	// Client disconnects also cancel a reload, without allowing it to escape
	// the controller lifetime or configured finite lifecycle deadline.
	stop := context.AfterFunc(request.Context(), cancel)
	defer stop()
	if request.URL.RawQuery != "" || request.URL.Fragment != "" {
		developmentError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	switch request.URL.Path {
	case "/v1/modules":
		if request.Method != http.MethodGet {
			developmentError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		modules := make([]developmentModule, 0, len(control.modules))
		for _, id := range control.modules {
			snapshot, ok := control.manager.ModuleSnapshot(id)
			if !ok {
				developmentError(w, http.StatusServiceUnavailable, "MODULE_UNAVAILABLE")
				return
			}
			modules = append(modules, developmentRecord(snapshot))
		}
		developmentJSON(w, http.StatusOK, struct {
			Modules []developmentModule `json:"modules"`
		}{Modules: modules})
	case "/v1/modules/reload":
		if request.Method != http.MethodPost {
			developmentError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			developmentError(w, http.StatusUnsupportedMediaType, "JSON_REQUIRED")
			return
		}
		if request.ContentLength > developmentBodyMaxBytes {
			developmentError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
			return
		}
		raw, err := io.ReadAll(io.LimitReader(request.Body, developmentBodyMaxBytes+1))
		if len(raw) > developmentBodyMaxBytes {
			developmentError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
			return
		}
		var reload developmentReloadRequest
		var fields map[string]json.RawMessage
		if err != nil || strictJSON(raw, &reload) != nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 3 || fields["module_id"] == nil || fields["expected_instance_id"] == nil || fields["image"] == nil || reload.ModuleID == "" || reload.ExpectedInstanceID == "" || reload.Image == "" {
			developmentError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		snapshot, err := control.manager.DevelopmentReload(ctx, reload.ModuleID, reload.ExpectedInstanceID, reload.Image)
		if err != nil {
			code, reason := developmentReloadError(err)
			developmentError(w, code, reason)
			return
		}
		developmentJSON(w, http.StatusOK, developmentRecord(snapshot))
	default:
		developmentError(w, http.StatusNotFound, "NOT_FOUND")
	}
}

func developmentReloadError(err error) (int, string) {
	switch status.Code(err) {
	case codes.NotFound:
		return http.StatusNotFound, "MODULE_NOT_FOUND"
	case codes.Aborted, codes.AlreadyExists:
		return http.StatusConflict, "RELOAD_CONFLICT"
	case codes.InvalidArgument:
		return http.StatusBadRequest, "INVALID_REQUEST"
	case codes.PermissionDenied, codes.FailedPrecondition:
		return http.StatusConflict, "RELOAD_REJECTED"
	case codes.Canceled, codes.DeadlineExceeded:
		return http.StatusRequestTimeout, "REQUEST_TIMEOUT"
	default:
		return http.StatusInternalServerError, "RELOAD_FAILED"
	}
}

func developmentError(w http.ResponseWriter, code int, reason string) {
	developmentJSON(w, code, struct {
		Error string `json:"error"`
	}{Error: reason})
}

func developmentJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func moduleHealth(manager developmentManager, modules []runtime.ModuleSpec) (allStopped, failed bool, err error) {
	allStopped = true
	for _, spec := range modules {
		snapshot, ok := manager.ModuleSnapshot(spec.ModuleID)
		if !ok {
			return false, false, errors.New("module instance disappeared")
		}
		if snapshot.State == runtime.Running || snapshot.Reloading {
			allStopped = false
		}
		if snapshot.State == runtime.Failed && !snapshot.Reloading {
			failed = true
		}
	}
	return allStopped, failed, nil
}
