//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var reloadOldImage = "registry.example/modules/test@sha256:" + strings.Repeat("a", 64)
var reloadNewImage = "registry.example/modules/test@sha256:" + strings.Repeat("b", 64)

// Exercise the real legacy host client boundary, not an injected manager launch
// or cleanup hook. This supervisor peer owns no actual sandbox/storage claims.
// Acquire deliberately rejects activation so these isolated tests need neither
// root, a sandbox engine nor a substitute module transport.
type reloadHostRequest struct {
	Operation   string           `json:"operation"`
	ImageDigest string           `json:"image_digest"`
	InstanceID  string           `json:"instance_id"`
	Spec        *host.LaunchSpec `json:"spec"`
}

type reloadHostResponse struct {
	Version  int             `json:"version"`
	EpochID  string          `json:"epoch_id,omitempty"`
	Manifest json.RawMessage `json:"manifest,omitempty"`
	Error    *host.Error     `json:"error,omitempty"`
}

type reloadHost struct {
	mu       sync.Mutex
	requests []reloadHostRequest
}

func (h *reloadHost) recorded() []reloadHostRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]reloadHostRequest(nil), h.requests...)
}

func reloadSupervisor(t *testing.T, override func(reloadHostRequest, <-chan struct{}) *reloadHostResponse) (*legacyhost.Client, *reloadHost) {
	t.Helper()
	// Subtest declaration names can exceed sockaddr_un's short path bound.
	directory, err := os.MkdirTemp("", "runtime-reload-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "host.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	h := new(reloadHost)
	done := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				data, ancillary := make([]byte, 65536), make([]byte, 256)
				n, on, _, _, err := conn.ReadMsgUnix(data, ancillary)
				if err != nil {
					return
				}
				messages, err := unix.ParseSocketControlMessage(ancillary[:on])
				if err != nil {
					t.Error(err)
					return
				}
				for _, message := range messages {
					fds, err := unix.ParseUnixRights(&message)
					if err != nil {
						t.Error(err)
						return
					}
					for _, fd := range fds {
						_ = unix.Close(fd)
					}
				}
				var request reloadHostRequest
				if err := json.Unmarshal(data[:n], &request); err != nil {
					t.Error(err)
					return
				}
				h.mu.Lock()
				h.requests = append(h.requests, request)
				h.mu.Unlock()
				response := reloadHostResponse{Version: 2}
				switch request.Operation {
				case "register":
					response.EpochID = strings.Repeat("c", 32)
				case "image_manifest":
					response.Manifest = json.RawMessage(`{"protocolMajor":2}`)
				case "acquire":
					response.Error = &host.Error{Reason: "HOST_OPERATION_FAILED", Message: "private activation detail"}
				case "terminate", "release":
				default:
					t.Errorf("unexpected host operation %q", request.Operation)
					response.Error = &host.Error{Reason: "HOST_OPERATION_FAILED"}
				}
				if override != nil {
					if replacement := override(request, done); replacement != nil {
						response = *replacement
					}
				}
				raw, err := json.Marshal(response)
				if err != nil {
					t.Error(err)
					return
				}
				_, _, _ = conn.WriteMsgUnix(raw, nil, nil)
			}()
		}
	}()
	t.Cleanup(func() {
		close(done)
		_ = listener.Close()
		workers.Wait()
	})
	client, err := legacyhost.Dial(context.Background(), legacyhost.ClientConfig{SocketPath: path, SupervisorUID: uint32(os.Geteuid()), MaxMessageBytes: 65536, OperationTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, h
}

func reloadFixture(t *testing.T, client *legacyhost.Client) (*Manager, *Instance, *Instance) {
	t.Helper()
	m := regressionManager()
	m.options.DevelopmentMode = true
	m.options.Host = client
	m.options.FileCleanup = func(context.Context, InstancePrincipal) error { return nil }
	m.config.applyDefaults()
	m.config.Defaults.StartupDeadline = Duration(3 * time.Second)
	m.config.Defaults.DrainDeadline = Duration(time.Second)
	m.config.Limits.TerminationDeadline = Duration(time.Second)
	m.config.Limits.ConfigMaxBytes = 4096
	m.config.Limits.PersistentInodeLimit = 1024
	m.config.Limits.ScratchInodeLimit = 1024
	m.config.Limits.LogBufferBytes = 8192
	m.config.Limits.LogFileMaxBytes = 8192
	m.config.Limits.LogRetainedFiles = 2
	m.config.Backends = map[string]BackendConfig{regressionBackend: {Major: 1}}
	owner, other := regressionInstance(t, m, "owner"), regressionInstance(t, m, "other")
	for _, i := range []*Instance{owner, other} {
		i.grants.ResourceClass = wire.ResourceClass_RESOURCE_CLASS_GENERAL
		i.grants.ResourceLimits = m.config.ResourceProfiles["general"].wire()
		i.grants.EgressPolicy = wire.EgressPolicy_EGRESS_POLICY_NONE
		i.spec = ModuleSpec{ModuleID: i.principal.ModuleID, ImageDigest: reloadOldImage, Entrypoint: []string{"/module"}, Args: []string{"--configured"}, UID: 1001, GID: 1002, Config: &wire.JSONValue{Json: []byte(`{"value":1}`)}, Approval: proto.Clone(i.grants).(*wire.Grants), ConfigRevision: "operator-config", ApprovalRevision: "operator-approval", CredentialBindings: []ProvisionedCredentialBinding{{Name: "configured", BackendID: regressionBackend, SecretID: "host-secret-id", Purpose: "respond", Resource: regressionScope("group", "a").GetSelector()}}}
		i.launchDone = make(chan struct{})
		close(i.launchDone)
		i.laneDone = make(chan struct{})
		close(i.laneDone)
		i.stopDone = make(chan struct{})
		i.drainReady = make(chan struct{})
	}
	return m, owner, other
}

func TestDevelopmentReloadRejectsUnauthorizedAndStaleRequestsWithoutDisruption(t *testing.T) {
	for _, test := range []struct {
		name     string
		disabled bool
		id       ModuleID
		expected InstanceID
		image    string
		want     error
	}{
		{name: "disabled", disabled: true, id: "owner", expected: "owner-instance", image: reloadNewImage, want: ErrDevelopmentDisabled},
		{name: "uninstalled", id: "uninstalled", expected: "owner-instance", image: reloadNewImage, want: ErrModuleNotInstalled},
		{name: "empty expected", id: "owner", image: reloadNewImage, want: ErrStaleInstance},
		{name: "stale", id: "owner", expected: "previous-instance", image: reloadNewImage, want: ErrStaleInstance},
		{name: "mutable", id: "owner", expected: "owner-instance", image: "registry.example/modules/test:dev", want: ErrInvalidReloadImage},
		{name: "repository", id: "owner", expected: "owner-instance", image: "registry.example/another@sha256:" + strings.Repeat("b", 64), want: ErrImageRepositoryChanged},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, old, other := reloadFixture(t, nil)
			m.options.DevelopmentMode = !test.disabled
			before, _ := m.ModuleSnapshot("owner")
			_, err := m.DevelopmentReload(context.Background(), test.id, test.expected, test.image)
			if err != test.want {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			var typed *Error
			if !errors.As(err, &typed) || status.Code(err) == codes.Unknown {
				t.Fatalf("reload rejection lost typed finite status: %v", err)
			}
			after, _ := m.ModuleSnapshot("owner")
			if before != after || m.instances["owner"] != old || m.instances["other"] != other {
				t.Fatal("rejected reload disrupted an instance")
			}
		})
	}
	m, _, _ := reloadFixture(t, nil)
	m.installed["not-launched"] = struct{}{}
	_, err := m.DevelopmentReload(context.Background(), "not-launched", "expected", reloadNewImage)
	if err != ErrModuleInstanceNotFound {
		t.Fatalf("missing current instance: %v", err)
	}
}

func TestDevelopmentReloadPreflightPreservesHealthyInstance(t *testing.T) {
	for _, declaration := range []string{"unavailable", `{}`, `{"protocolMajor":2,"requiredCapabilities":[{"name":"unapproved","resourceScopes":[{"selector":{}}]}]}`, `{"protocolMajor":2,"backendRequirements":[{"backendId":"uninstalled","protocolMajor":1,"required":true}]}`} {
		t.Run(declaration, func(t *testing.T) {
			client, h := reloadSupervisor(t, func(request reloadHostRequest, _ <-chan struct{}) *reloadHostResponse {
				if request.Operation != "image_manifest" {
					return nil
				}
				response := &reloadHostResponse{Version: 1}
				if declaration == "unavailable" {
					response.Error = &host.Error{Reason: "HOST_OPERATION_FAILED", Message: "RAW_SECRET"}
				} else {
					response.Manifest = json.RawMessage(declaration)
				}
				return response
			})
			m, old, other := reloadFixture(t, client)
			ref, _, _ := regressionCredential(t, old)
			before, _ := m.ModuleSnapshot("owner")
			result, err := m.DevelopmentReload(context.Background(), "owner", old.principal.InstanceID, reloadNewImage)
			if err != ErrReloadPreflight || result != before {
				t.Fatalf("preflight changed healthy old instance: %+v, %v", result, err)
			}
			if m.instances["owner"] != old || other.Snapshot().State != Running || old.credentials[ref.OpaqueId] == nil || old.credentialsRevoked {
				t.Fatal("preflight rejection changed instance/credential ownership")
			}
			for _, request := range h.recorded() {
				if request.Operation != "register" && (request.Operation != "image_manifest" || request.ImageDigest != reloadNewImage) {
					t.Fatalf("preflight disrupted host state: %+v", request)
				}
			}
		})
	}
}

func TestDevelopmentReloadSerializesOneModuleWithoutBlockingAnother(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	client, _ := reloadSupervisor(t, func(request reloadHostRequest, done <-chan struct{}) *reloadHostResponse {
		if request.Operation == "image_manifest" {
			close(entered)
			select {
			case <-release:
			case <-done:
			}
			return &reloadHostResponse{Version: 1, Manifest: json.RawMessage(`{}`)}
		}
		return nil
	})
	m, old, _ := reloadFixture(t, client)
	finished := make(chan struct{})
	var reloadErr error
	go func() {
		_, reloadErr = m.DevelopmentReload(context.Background(), "owner", old.principal.InstanceID, reloadNewImage)
		close(finished)
	}()
	regressionWait(t, entered)
	snapshot, ok := m.ModuleSnapshot("owner")
	if !ok || !snapshot.Reloading || snapshot.Principal != old.principal || snapshot.State != Running {
		t.Fatalf("missing atomic in-flight snapshot: %+v", snapshot)
	}
	_, err := m.DevelopmentReload(context.Background(), "owner", old.principal.InstanceID, reloadNewImage)
	if err != ErrReloadInProgress {
		t.Fatalf("concurrent reload was not rejected: %v", err)
	}
	for _, operation := range []string{"launch", "stop"} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		if operation == "launch" {
			_, err = m.Launch(ctx, old.spec)
		} else {
			err = m.Stop(ctx, "owner")
		}
		cancel()
		if status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("%s ignored context while waiting for reload: %v", operation, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Stop(ctx, "other"); err != nil {
		t.Fatalf("unrelated module blocked behind reload: %v", err)
	}
	close(release)
	regressionWait(t, finished)
	if reloadErr != ErrReloadPreflight {
		t.Fatalf("unexpected preflight result: %v", reloadErr)
	}
	snapshot, _ = m.ModuleSnapshot("owner")
	if snapshot.Reloading || snapshot.State != Running || snapshot.Principal != old.principal {
		t.Fatalf("rejected reload left a marker or stopped old: %+v", snapshot)
	}
}

func TestDevelopmentReloadCleanupFailureBlocksReplacement(t *testing.T) {
	client, h := reloadSupervisor(t, nil)
	m, old, other := reloadFixture(t, client)
	m.options.FileCleanup = func(context.Context, InstancePrincipal) error { return errors.New("RAW_SECRET") }
	for _, image := range []string{reloadNewImage, reloadOldImage} {
		snapshot, err := m.DevelopmentReload(context.Background(), "owner", old.principal.InstanceID, image)
		if err != ErrReloadCleanup || snapshot.CleanupComplete || snapshot.Reloading || snapshot.Principal != old.principal || snapshot.State != Failed {
			t.Fatalf("failed cleanup allowed replacement: %+v, %v", snapshot, err)
		}
	}
	if m.instances["owner"] != old || other.Snapshot().State != Running {
		t.Fatal("failed cleanup replaced an instance")
	}
	for _, request := range h.recorded() {
		if request.Operation == "acquire" || request.Operation == "release" {
			t.Fatalf("cleanup failure crossed positive cleanup barrier: %+v", request)
		}
	}
}

func TestDevelopmentReloadPositiveCleanupUsesFreshInstanceAndOnlyChangesImage(t *testing.T) {
	client, h := reloadSupervisor(t, nil)
	m, old, other := reloadFixture(t, client)
	ref, requirement, key := regressionCredential(t, old)
	otherRef, _, _ := regressionCredential(t, other)
	original := cloneSpec(old.spec)
	cleanupEntered, allowCleanup := make(chan struct{}), make(chan struct{})
	m.options.FileCleanup = func(ctx context.Context, principal InstancePrincipal) error {
		if principal == old.principal {
			close(cleanupEntered)
			select {
			case <-allowCleanup:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	finished := make(chan struct{})
	var result ModuleSnapshot
	var reloadErr error
	go func() {
		result, reloadErr = m.DevelopmentReload(context.Background(), "owner", old.principal.InstanceID, reloadNewImage)
		close(finished)
	}()
	regressionWait(t, cleanupEntered)
	for _, request := range h.recorded() {
		if request.Operation == "acquire" {
			t.Fatal("replacement acquired host claims before cleanup completed")
		}
	}
	close(allowCleanup)
	regressionWait(t, finished)
	if reloadErr != ErrReloadLaunch {
		t.Fatalf("expected actual host activation rejection, got %v", reloadErr)
	}
	fresh, ok := m.Instance("owner")
	if !ok || fresh == old || fresh.principal == old.principal || fresh.principal.ModuleID != old.principal.ModuleID || result.Principal != fresh.principal || result.ImageDigest != reloadNewImage || result.Reloading {
		t.Fatalf("replacement reused old identity or marker: %+v", result)
	}
	regressionWait(t, fresh.stopDone)
	if !old.Snapshot().CleanupComplete || old.credentials[ref.OpaqueId] != nil || !old.credentialsRevoked {
		t.Fatal("replacement preceded positive cleanup/credential revocation")
	}
	_, err := m.credentials.Issue(context.Background(), old.principal, CredentialBinding{BackendID: requirement.BackendID, Purpose: requirement.Purpose, Resource: requirement.Resource, ExpiresAt: time.Now().Add(time.Minute), BackendHandle: key})
	if err == nil {
		t.Fatal("old instance retained credential issuance authority")
	}
	if fresh.spec.ImageDigest != reloadNewImage || fresh.spec.ModuleID != original.ModuleID || fresh.spec.UID != original.UID || fresh.spec.GID != original.GID || fresh.spec.ConfigRevision != original.ConfigRevision || fresh.spec.ApprovalRevision != original.ApprovalRevision || !reflect.DeepEqual(fresh.spec.Entrypoint, original.Entrypoint) || !reflect.DeepEqual(fresh.spec.Args, original.Args) || !proto.Equal(fresh.spec.Config, original.Config) || !proto.Equal(fresh.spec.Approval, original.Approval) {
		t.Fatal("reload changed operator authority or configuration")
	}
	if len(fresh.spec.CredentialBindings) != 1 || fresh.spec.CredentialBindings[0].SecretID != original.CredentialBindings[0].SecretID || !proto.Equal(fresh.spec.CredentialBindings[0].Resource, original.CredentialBindings[0].Resource) {
		t.Fatal("reload changed provisioned credential binding")
	}
	fresh.spec.Entrypoint[0] = "/changed"
	fresh.spec.Config.Json[0] = ' '
	fresh.spec.Approval.Backends[0].BackendId = "changed"
	fresh.spec.CredentialBindings[0].Resource.ResourceIds["group"] = "changed"
	if old.spec.Entrypoint[0] != original.Entrypoint[0] || !proto.Equal(old.spec.Config, original.Config) || !proto.Equal(old.spec.Approval, original.Approval) || !proto.Equal(old.spec.CredentialBindings[0].Resource, original.CredentialBindings[0].Resource) {
		t.Fatal("new spec aliases old mutable authority/configuration")
	}
	if current, _ := m.Instance("other"); current != other || other.Snapshot().State != Running || other.credentialsRevoked || other.credentials[otherRef.OpaqueId] == nil {
		t.Fatal("replacement disrupted unrelated instance or credentials")
	}
	acquired := 0
	for _, request := range h.recorded() {
		if request.Operation == "acquire" {
			acquired++
			if request.Spec == nil || request.Spec.ImageDigest != reloadNewImage || request.Spec.InstanceID != string(fresh.principal.InstanceID) || request.Spec.ModuleID != string(old.principal.ModuleID) || request.Spec.UID != original.UID || request.Spec.GID != original.GID {
				t.Fatalf("ordinary launch received wrong replacement identity/spec: %+v", request)
			}
		}
	}
	if acquired != 1 {
		t.Fatalf("failed activation rolled back/retried automatically: %d acquisitions", acquired)
	}
}

func TestModuleSnapshotObservesInstanceAndReloadMarkerTogether(t *testing.T) {
	m := regressionManager()
	old := regressionInstance(t, m, "owner")
	old.spec.ImageDigest = reloadOldImage
	fresh := &Instance{principal: InstancePrincipal{ModuleID: "owner", InstanceID: "new-instance"}, spec: ModuleSpec{ImageDigest: reloadNewImage}, state: Running}
	m.lifecycles = map[ModuleID]*moduleLifecycle{"owner": {committedImageDigest: reloadOldImage}}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for range 1000 {
			m.mu.Lock()
			m.instances["owner"] = fresh
			m.lifecycles["owner"].reloading = true
			m.lifecycles["owner"].committedImageDigest = reloadNewImage
			m.mu.Unlock()
			m.mu.Lock()
			m.instances["owner"] = old
			m.lifecycles["owner"].reloading = false
			m.lifecycles["owner"].committedImageDigest = reloadOldImage
			m.mu.Unlock()
		}
	}()
	for range 1000 {
		snapshot, ok := m.ModuleSnapshot("owner")
		if !ok || (snapshot.Principal == old.principal && (snapshot.Reloading || snapshot.ImageDigest != reloadOldImage || snapshot.CommittedImageDigest != reloadOldImage || snapshot.State != Running)) || (snapshot.Principal == fresh.principal && (!snapshot.Reloading || snapshot.ImageDigest != reloadNewImage || snapshot.CommittedImageDigest != reloadNewImage || snapshot.State != Running)) {
			t.Fatalf("snapshot mixed generations/marker: %+v", snapshot)
		}
	}
	regressionWait(t, finished)
	if _, ok := m.ModuleSnapshot("missing"); ok {
		t.Fatal("snapshot fabricated a missing instance")
	}
}

func TestDevelopmentReloadRetainsCommittedImageThroughFailedCandidateAndStop(t *testing.T) {
	client, _ := reloadSupervisor(t, nil)
	m, old, other := reloadFixture(t, client)
	// The regression fixture begins at an already-running instance boundary.
	// Supply its known committed image without substituting any launch path.
	lifecycle, err := m.acquireLifecycle(context.Background(), "owner", false)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	lifecycle.committedImageDigest = reloadOldImage
	m.mu.Unlock()
	m.releaseLifecycle(lifecycle, false)
	before, _ := m.ModuleSnapshot("owner")
	if before.CommittedImageDigest != reloadOldImage {
		t.Fatal("running fixture lost its committed image")
	}
	result, err := m.DevelopmentReload(context.Background(), "owner", old.principal.InstanceID, reloadNewImage)
	if err != ErrReloadLaunch || result.ImageDigest != reloadNewImage || result.CommittedImageDigest != reloadOldImage || result.State != Failed || result.Principal == old.principal {
		t.Fatalf("failed candidate replaced committed image or rolled back: %+v, %v", result, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.Stop(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	settled, _ := m.ModuleSnapshot("owner")
	if !settled.CleanupComplete || settled.ImageDigest != reloadNewImage || settled.CommittedImageDigest != reloadOldImage || settled.Principal != result.Principal {
		t.Fatalf("stop lost committed image or changed failed attempt: %+v", settled)
	}
	if other.Snapshot().State != Running {
		t.Fatal("failed candidate disturbed another installation")
	}
}

func TestFailedPublicLaunchDoesNotCommitImage(t *testing.T) {
	client, _ := reloadSupervisor(t, nil)
	m, old, _ := reloadFixture(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.Stop(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	spec := cloneSpec(old.spec)
	spec.ImageDigest = reloadNewImage
	instance, err := m.Launch(ctx, spec)
	if err == nil || instance == nil {
		t.Fatalf("expected ordinary host activation rejection: %v", err)
	}
	if err := m.Stop(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := m.ModuleSnapshot("owner")
	if snapshot.ImageDigest != reloadNewImage || snapshot.CommittedImageDigest != "" || !snapshot.CleanupComplete {
		t.Fatalf("failed public launch falsely committed image: %+v", snapshot)
	}
}

func TestDevelopmentReloadRetriesCurrentImageOnlyAfterPositiveCleanup(t *testing.T) {
	retryPreflight := make(chan struct{})
	var manifestMu sync.Mutex
	manifests := 0
	client, h := reloadSupervisor(t, func(request reloadHostRequest, _ <-chan struct{}) *reloadHostResponse {
		if request.Operation == "image_manifest" {
			manifestMu.Lock()
			manifests++
			// First attempt has ordinary preflight and launch declarations;
			// the third request is the same-image retry's preflight.
			if manifests == 3 {
				close(retryPreflight)
			}
			manifestMu.Unlock()
		}
		return nil
	})
	m, old, other := reloadFixture(t, client)
	cleanupEntered, allowCleanup := make(chan struct{}), make(chan struct{})
	var firstCandidateCleanup sync.Once
	m.options.FileCleanup = func(ctx context.Context, principal InstancePrincipal) error {
		var cleanupErr error
		if principal.ModuleID == old.principal.ModuleID && principal != old.principal {
			firstCandidateCleanup.Do(func() {
				close(cleanupEntered)
				select {
				case <-allowCleanup:
				case <-ctx.Done():
					cleanupErr = ctx.Err()
				}
			})
		}
		return cleanupErr
	}
	first, err := m.DevelopmentReload(context.Background(), "owner", old.principal.InstanceID, reloadNewImage)
	if err != ErrReloadLaunch || first.ImageDigest != reloadNewImage || first.State != Failed {
		t.Fatalf("expected ordinary candidate activation failure: %+v, %v", first, err)
	}
	regressionWait(t, cleanupEntered)
	finished := make(chan struct{})
	var retry ModuleSnapshot
	var retryErr error
	go func() {
		retry, retryErr = m.DevelopmentReload(context.Background(), "owner", first.Principal.InstanceID, first.ImageDigest)
		close(finished)
	}()
	regressionWait(t, retryPreflight)
	waiting, _ := m.ModuleSnapshot("owner")
	if waiting.Principal != first.Principal || !waiting.Reloading || waiting.CleanupComplete {
		t.Fatalf("same-image retry bypassed pending cleanup: %+v", waiting)
	}
	acquisitions := 0
	for _, request := range h.recorded() {
		if request.Operation == "acquire" {
			acquisitions++
		}
	}
	if acquisitions != 1 {
		t.Fatalf("same-image retry acquired before positive cleanup: %d", acquisitions)
	}
	close(allowCleanup)
	regressionWait(t, finished)
	if retryErr != ErrReloadLaunch || retry.Principal == first.Principal || retry.Principal.ModuleID != first.Principal.ModuleID || retry.ImageDigest != first.ImageDigest || retry.Reloading {
		t.Fatalf("same-image retry did not use a fresh ordinary launch: %+v, %v", retry, retryErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.Stop(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, request := range h.recorded() {
		if request.Operation == "acquire" {
			if request.Spec == nil || request.Spec.ImageDigest != reloadNewImage {
				t.Fatalf("retry acquired the wrong immutable image: %+v", request)
			}
			ids = append(ids, request.Spec.InstanceID)
		}
	}
	if len(ids) != 2 || ids[0] != string(first.Principal.InstanceID) || ids[1] != string(retry.Principal.InstanceID) || ids[0] == ids[1] {
		t.Fatalf("retry reused identity, skipped activation, or rolled back: %v", ids)
	}
	if other.Snapshot().State != Running {
		t.Fatal("same-image retry disturbed another installation")
	}
}
