package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type developmentManagerFixture struct {
	mu       sync.Mutex
	snapshot runtime.ModuleSnapshot
	reloads  int
	reload   func(context.Context, runtime.ModuleID, runtime.InstanceID, string) (runtime.ModuleSnapshot, error)
}

func (manager *developmentManagerFixture) ModuleSnapshot(id runtime.ModuleID) (runtime.ModuleSnapshot, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.snapshot, manager.snapshot.Principal.ModuleID == id
}

func (manager *developmentManagerFixture) DevelopmentReload(ctx context.Context, id runtime.ModuleID, expected runtime.InstanceID, image string) (runtime.ModuleSnapshot, error) {
	manager.mu.Lock()
	manager.reloads++
	reload := manager.reload
	manager.mu.Unlock()
	if reload != nil {
		return reload(ctx, id, expected, image)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.snapshot.Principal.InstanceID = "replacement"
	manager.snapshot.ImageDigest = image
	manager.snapshot.CommittedImageDigest = image
	manager.snapshot.State = runtime.Running
	return manager.snapshot, nil
}

func developmentFixtureManager() *developmentManagerFixture {
	return &developmentManagerFixture{snapshot: runtime.ModuleSnapshot{
		Principal:   runtime.InstancePrincipal{ModuleID: "module", InstanceID: "original"},
		ImageDigest: "registry.test/team/module@sha256:" + strings.Repeat("1", 64), State: runtime.Running,
		CommittedImageDigest: "registry.test/team/module@sha256:" + strings.Repeat("1", 64),
	}}
}

func developmentTestPaths(t *testing.T) (string, runtime.Config) {
	t.Helper()
	// Keep the public pathname within sockaddr_un's limit even for long test names.
	root, err := os.MkdirTemp("", "chatanium-dev-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for _, name := range []string{"control", "storage", "ipc"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, "control", "control.sock"), runtime.Config{
		Host:     runtime.HostConfig{StorageRoot: filepath.Join(root, "storage"), IPCRoot: filepath.Join(root, "ipc")},
		Defaults: runtime.Defaults{StartupDeadline: runtime.Duration(time.Second), DrainDeadline: runtime.Duration(time.Second)},
		Limits:   runtime.Limits{TerminationDeadline: runtime.Duration(time.Second)},
		Modules:  []runtime.ModuleSpec{{ModuleID: "module"}},
	}
}

func startDevelopmentTestControl(t *testing.T, manager developmentManager) (*developmentController, *http.Client, string) {
	t.Helper()
	path, config := developmentTestPaths(t)
	control, err := startDevelopmentController(context.Background(), StartOptions{DevelopmentMode: true, DevelopmentSocket: path}, config, manager)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := control.Close(); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return control, &http.Client{Transport: transport, Timeout: 5 * time.Second}, path
}

func authorizedDevelopmentRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request.WithContext(context.WithValue(request.Context(), developmentPeerKey{}, true))
}

func TestDevelopmentControlPublishesOnlySnapshotsAndReloads(t *testing.T) {
	manager := developmentFixtureManager()
	_, client, _ := startDevelopmentTestControl(t, manager)
	response, err := client.Get("http://development/v1/modules")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var listing struct {
		Modules []map[string]json.RawMessage `json:"modules"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&listing) != nil || len(listing.Modules) != 1 || len(listing.Modules[0]) != 7 || listing.Modules[0]["committed_image"] == nil {
		t.Fatal("snapshot listing did not match the minimal public protocol")
	}
	image := "registry.test/team/module@sha256:" + strings.Repeat("2", 64)
	body := `{"module_id":"module","expected_instance_id":"original","image":"` + image + `"}`
	response, err = client.Post("http://development/v1/modules/reload", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var replacement developmentModule
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&replacement) != nil || replacement.InstanceID != "replacement" || replacement.Image != image {
		t.Fatal("synchronous reload did not return the launched instance")
	}
}

func TestDevelopmentControlRejectsUnauthorizedAndMalformedRequests(t *testing.T) {
	manager := developmentFixtureManager()
	control, _, _ := startDevelopmentTestControl(t, manager)
	response := httptest.NewRecorder()
	control.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/modules", nil))
	if response.Code != http.StatusForbidden {
		t.Fatal("request without an authenticated peer was accepted")
	}
	valid := `{"module_id":"module","expected_instance_id":"original","image":"image"}`
	for _, test := range []struct {
		name, method, path, body, contentType string
		want                                  int
	}{
		{"duplicate", "POST", "/v1/modules/reload", `{"module_id":"module","module_id":"other","expected_instance_id":"original","image":"image"}`, "application/json", 400},
		{"unknown", "POST", "/v1/modules/reload", `{"module_id":"module","expected_instance_id":"original","image":"image","approval":{}}`, "application/json", 400},
		{"trailing", "POST", "/v1/modules/reload", valid + `{}`, "application/json", 400},
		{"case alias", "POST", "/v1/modules/reload", `{"MODULE_ID":"module","expected_instance_id":"original","image":"image"}`, "application/json", 400},
		{"missing", "POST", "/v1/modules/reload", `{"module_id":"module","image":"image"}`, "application/json", 400},
		{"null", "POST", "/v1/modules/reload", `null`, "application/json", 400},
		{"empty", "POST", "/v1/modules/reload", `{}`, "application/json", 400},
		{"body bound", "POST", "/v1/modules/reload", strings.Repeat("x", developmentBodyMaxBytes+1), "application/json", 413},
		{"content type", "POST", "/v1/modules/reload", valid, "text/plain", 415},
		{"query", "POST", "/v1/modules/reload?approval=true", valid, "application/json", 400},
		{"method", "GET", "/v1/modules/reload", "", "application/json", 405},
		{"unknown route", "POST", "/v1/other", valid, "application/json", 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := authorizedDevelopmentRequest(test.method, test.path, test.body)
			request.Header.Set("Content-Type", test.contentType)
			// Also exercise a chunked/unknown-length oversized body.
			request.ContentLength = -1
			response := httptest.NewRecorder()
			control.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("got %d, want %d", response.Code, test.want)
			}
		})
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.reloads != 0 {
		t.Fatal("rejected request reached the lifecycle manager")
	}
}

func TestDevelopmentControlSanitizesReloadErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want int
	}{
		{status.Error(codes.NotFound, "private-daemon-detail"), 404},
		{status.Error(codes.Aborted, "private-daemon-detail"), 409},
		{status.Error(codes.PermissionDenied, "private-daemon-detail"), 409},
		{status.Error(codes.FailedPrecondition, "private-daemon-detail"), 409},
		{status.Error(codes.InvalidArgument, "private-daemon-detail"), 400},
		{status.Error(codes.DeadlineExceeded, "private-daemon-detail"), 408},
		{errors.New("private-daemon-detail"), 500},
	} {
		manager := developmentFixtureManager()
		manager.reload = func(context.Context, runtime.ModuleID, runtime.InstanceID, string) (runtime.ModuleSnapshot, error) {
			return runtime.ModuleSnapshot{}, test.err
		}
		life, cancel := context.WithCancel(context.Background())
		control := &developmentController{manager: manager, ctx: life, cancel: cancel, deadline: time.Second}
		response := httptest.NewRecorder()
		control.ServeHTTP(response, authorizedDevelopmentRequest("POST", "/v1/modules/reload", `{"module_id":"module","expected_instance_id":"original","image":"image"}`))
		cancel()
		if response.Code != test.want || strings.Contains(response.Body.String(), "private-daemon-detail") {
			t.Fatal("reload error was misclassified or exposed private data")
		}
	}
}

func TestDevelopmentShutdownCancelsAndJoinsReload(t *testing.T) {
	manager := developmentFixtureManager()
	entered, canceled, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	manager.reload = func(ctx context.Context, _ runtime.ModuleID, _ runtime.InstanceID, _ string) (runtime.ModuleSnapshot, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		defer close(exited)
		return runtime.ModuleSnapshot{}, status.FromContextError(ctx.Err()).Err()
	}
	control, client, _ := startDevelopmentTestControl(t, manager)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		response, err := client.Post("http://development/v1/modules/reload", "application/json", strings.NewReader(`{"module_id":"module","expected_instance_id":"original","image":"image"}`))
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("reload did not enter manager")
	}
	closed := make(chan error, 1)
	go func() { closed <- control.Close() }()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel reload")
	}
	response := httptest.NewRecorder()
	control.ServeHTTP(response, authorizedDevelopmentRequest("POST", "/v1/modules/reload", `{"module_id":"module","expected_instance_id":"original","image":"image"}`))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("shutdown accepted new lifecycle work")
	}
	select {
	case <-closed:
		t.Fatal("shutdown returned before its active reload joined")
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not join released reload")
	}
	select {
	case <-exited:
	default:
		t.Fatal("manager teardown could race unfinished reload")
	}
	<-requestDone
}

func TestDevelopmentControlBoundsHeadersAndLifecycleDeadline(t *testing.T) {
	manager := developmentFixtureManager()
	control, client, _ := startDevelopmentTestControl(t, manager)
	request, err := http.NewRequest(http.MethodGet, "http://development/v1/modules", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Oversized", strings.Repeat("x", 32<<10))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatal("development listener accepted unbounded request headers")
	}
	manager.mu.Lock()
	manager.reload = func(ctx context.Context, _ runtime.ModuleID, _ runtime.InstanceID, _ string) (runtime.ModuleSnapshot, error) {
		<-ctx.Done()
		return runtime.ModuleSnapshot{}, status.FromContextError(ctx.Err()).Err()
	}
	manager.mu.Unlock()
	deadlineControl := &developmentController{manager: manager, ctx: context.Background(), deadline: 10 * time.Millisecond}
	bounded := httptest.NewRecorder()
	deadlineControl.ServeHTTP(bounded, authorizedDevelopmentRequest("POST", "/v1/modules/reload", `{"module_id":"module","expected_instance_id":"original","image":"image"}`))
	if bounded.Code != http.StatusRequestTimeout {
		t.Fatal("reload escaped the finite controller deadline")
	}
	if control.server.ReadTimeout <= 0 || control.server.ReadHeaderTimeout <= 0 || control.server.WriteTimeout <= 0 || control.server.IdleTimeout <= 0 {
		t.Fatal("development HTTP server is missing finite connection deadlines")
	}
}

func TestDevelopmentHealthTracksCurrentInstanceAndReloadMarker(t *testing.T) {
	manager := developmentFixtureManager()
	modules := []runtime.ModuleSpec{{ModuleID: "module"}}
	manager.snapshot.State = runtime.Failed
	allStopped, failed, err := moduleHealth(manager, modules)
	if err != nil || !allStopped || !failed {
		t.Fatal("terminal current instance was not observed")
	}
	manager.snapshot.Reloading = true
	allStopped, failed, err = moduleHealth(manager, modules)
	if err != nil || allStopped || failed {
		t.Fatal("reload transition was mistaken for terminal failure")
	}
	manager.snapshot.Reloading = false
	manager.snapshot.State = runtime.Running
	manager.snapshot.Principal.InstanceID = "replacement"
	allStopped, failed, err = moduleHealth(manager, modules)
	if err != nil || allStopped || failed {
		t.Fatal("recovered old-instance failure remained sticky")
	}
}
