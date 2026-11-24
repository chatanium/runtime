// Package runtime owns backend-neutral module authority and lifecycle.
package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/thirdscam/chatanium/internal/host"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type ModuleID string
type InstanceID string
type InstancePrincipal struct {
	ModuleID   ModuleID
	InstanceID InstanceID
}
type RuntimeState string

const (
	Starting     RuntimeState = "STARTING"
	Initializing RuntimeState = "INITIALIZING"
	Ready        RuntimeState = "READY"
	Running      RuntimeState = "RUNNING"
	Draining     RuntimeState = "DRAINING"
	Stopped      RuntimeState = "STOPPED"
	Failed       RuntimeState = "FAILED"
)

type ProvisionedCredentialBinding struct {
	Name      string                 `json:"name"`
	BackendID string                 `json:"backend_id"`
	SecretID  string                 `json:"secret_id"`
	Purpose   string                 `json:"purpose"`
	Resource  *wire.ResourceSelector `json:"resource"`
}
type ModuleSpec struct {
	ModuleID                         ModuleID
	ImageDigest                      string
	Entrypoint, Args                 []string
	UID, GID                         uint32
	Config                           *wire.JSONValue
	Approval                         *wire.Grants
	CredentialBindings               []ProvisionedCredentialBinding
	ConfigRevision, ApprovalRevision string
}
type InstanceSnapshot struct {
	Principal        InstancePrincipal
	State            RuntimeState
	FailureReason    string
	CleanupComplete  bool
	CleanupError     error
	RetainedEvents   int
	RetainedBytes    int64
	IncompleteEvents int
	Grants           *wire.Grants
}

// ModuleSnapshot contains only lightweight polling data, never configuration,
// credentials or cloned grants.
type ModuleSnapshot struct {
	Principal            InstancePrincipal
	ImageDigest          string
	CommittedImageDigest string
	State                RuntimeState
	FailureReason        string
	Reloading            bool
	CleanupComplete      bool
}

// Instance has one authoritative lock for lifecycle, authority, queues and leases.
// All externally visible protobuf values are immutable copies.
type Instance struct {
	mu                 sync.Mutex
	manager            *Manager
	principal          InstancePrincipal
	spec               ModuleSpec
	state              RuntimeState
	failure            string
	launchDone         chan struct{}
	connectDone        chan struct{}
	killDone           chan struct{}
	factory            host.RunnerTransport
	primaryTransport   *primaryTransport
	drainReady         chan struct{}
	bound              bool
	grants             *wire.Grants
	activating         bool
	gate               chan struct{}
	changed            chan struct{}
	startup            context.Context
	cancelStartup      context.CancelFunc
	lifetime           context.Context
	cancelLifetime     context.CancelFunc
	drain              context.Context
	cancelDrain        context.CancelFunc
	controls           int
	admissions         map[*Admission]struct{}
	workRef            string
	workContext        context.Context
	queue              [][]byte
	retainedCount      int
	retainedBytes      int64
	incomplete         int
	stopStarted        bool
	stopDone           chan struct{}
	cleanupComplete    bool
	cleanupError       error
	lease              *host.Lease
	plugin             *plugin.Client
	hooks              *core.HookClient
	brokerGuard        *core.BrokerGuard
	registered         []BackendRegistration
	prepared           []BackendRegistration
	laneDone           chan struct{}
	drainSent          bool
	callbackActive     bool
	credentials        map[string]*credentialRecord
	credentialsRevoked bool
}

func (i *Instance) Snapshot() InstanceSnapshot {
	i.mu.Lock()
	defer i.mu.Unlock()
	s := InstanceSnapshot{Principal: i.principal, State: i.state, FailureReason: i.failure, CleanupComplete: i.cleanupComplete, CleanupError: i.cleanupError, RetainedEvents: i.retainedCount, RetainedBytes: i.retainedBytes, IncompleteEvents: i.incomplete}
	if i.grants != nil {
		s.Grants = proto.Clone(i.grants).(*wire.Grants)
	}
	return s
}
func (i *Instance) Principal() InstancePrincipal { return i.principal }
func (i *Instance) signalLocked()                { close(i.changed); i.changed = make(chan struct{}) }
func (i *Instance) openGateLocked() {
	if i.activating {
		i.activating = false
		close(i.gate)
	}
	i.signalLocked()
}
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Error is a fixed runtime failure with a machine-readable reason and status.
type Error struct {
	code   codes.Code
	reason string
}

func (e *Error) Error() string  { return e.reason }
func (e *Error) Reason() string { return e.reason }
func (e *Error) GRPCStatus() *status.Status {
	s := status.New(e.code, e.reason)
	d, err := s.WithDetails(&wire.ErrorDetail{Origin: wire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, Reason: e.reason, RemoteOutcome: wire.RemoteOutcome_REMOTE_OUTCOME_NOT_SENT})
	if err == nil {
		return d
	}
	return s
}
func runtimeError(code codes.Code, reason string) error { return &Error{code: code, reason: reason} }

var (
	ErrModuleNotInstalled     = runtimeError(codes.NotFound, "MODULE_NOT_INSTALLED")
	ErrModuleAlreadyActive    = runtimeError(codes.AlreadyExists, "MODULE_ALREADY_ACTIVE")
	ErrDevelopmentDisabled    = runtimeError(codes.PermissionDenied, "DEVELOPMENT_MODE_DISABLED")
	ErrModuleInstanceNotFound = runtimeError(codes.FailedPrecondition, "MODULE_INSTANCE_NOT_FOUND")
	ErrStaleInstance          = runtimeError(codes.Aborted, "STALE_INSTANCE")
	ErrReloadInProgress       = runtimeError(codes.Aborted, "RELOAD_IN_PROGRESS")
	ErrInvalidReloadImage     = runtimeError(codes.InvalidArgument, "INVALID_RELOAD_IMAGE")
	ErrImageRepositoryChanged = runtimeError(codes.PermissionDenied, "IMAGE_REPOSITORY_CHANGED")
	ErrReloadPreflight        = runtimeError(codes.FailedPrecondition, "RELOAD_PREFLIGHT_FAILED")
	ErrReloadCleanup          = runtimeError(codes.FailedPrecondition, "RELOAD_CLEANUP_INCOMPLETE")
	ErrReloadLaunch           = runtimeError(codes.FailedPrecondition, "RELOAD_LAUNCH_FAILED")
)

func invalidConfig() error                   { return runtimeError(codes.InvalidArgument, "INVALID_CONFIGURATION") }
func contextError(ctx context.Context) error { return status.FromContextError(ctx.Err()).Err() }

type BackendPreparation struct {
	Requirement *wire.BackendRequirement
	Approved    *wire.BackendGrant
}
type BackendBinding struct{ Grant *wire.BackendGrant }
type BackendAdapter interface {
	Prepare(context.Context, InstancePrincipal, BackendPreparation) (*BackendBinding, error)
	Activate(context.Context, InstancePrincipal) error
	Drain(context.Context, InstancePrincipal) error
	Cleanup(context.Context, InstancePrincipal) error
}

// Register is called before helper Serve; Prepare must never register services.
type BackendRegistration struct {
	ID                        string
	Major                     uint32
	Adapter                   BackendAdapter
	Register                  func(InstanceServices) (core.HelperRegistrar, error)
	Operations                []OperationPolicy
	Events                    []EventPolicy
	ValidateSelector          func(*wire.ResourceSelector) error
	ValidateConstraints       func(*wire.CapabilityGrant) error
	ValidateConstraintsSubset func(actual, ceiling *wire.CapabilityGrant) error
}
type InstanceServices struct {
	Principal           InstancePrincipal
	Authorizer          *Authorizer
	Credentials         *CredentialRegistry
	Limits              Limits
	ManagementDirectory string
	CredentialBindings  []ProvisionedCredentialBinding
}
type FileTransferFactory func(InstanceServices) (core.HelperRegistrar, error)
type InstanceCleanup func(context.Context, InstancePrincipal) error
type ManagerOptions struct {
	DevelopmentMode bool
	Host            host.RuntimeHost
	Backends        []BackendRegistration
	FileTransfer    FileTransferFactory
	FileCleanup     InstanceCleanup
}
