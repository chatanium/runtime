// Package host defines the trusted sandbox and worker boundary. The legacy
// native supervisor implementation is available only on Linux.
package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

type EgressPolicy string

const (
	EgressNone           EgressPolicy = "NONE"
	EgressPublicInternet EgressPolicy = "PUBLIC"
)

type NetworkProfile string

const (
	NetworkNone       NetworkProfile = "NONE"
	NetworkPublicV4   NetworkProfile = "PUBLIC-v4"
	NetworkPublicDual NetworkProfile = "PUBLIC-dual"
	DataMountpoint                   = "/var/lib/flexmodule/data"
	ScratchMountpoint                = "/var/lib/flexmodule/scratch"
)

type UnitIdentity struct {
	Name                string `json:"name"`
	InvocationID        string `json:"invocation_id"`
	BootID              string `json:"boot_id"`
	CgroupPath          string `json:"cgroup_path"`
	Generation          string `json:"generation"`
	ExecutableDigest    string `json:"executable_digest"`
	ResourceFingerprint string `json:"resource_fingerprint"`
	MainPID             int    `json:"main_pid"`
	StartTime           uint64 `json:"start_time"`
}
type EndpointIdentity struct {
	Directory    string `json:"directory"`
	Path         string `json:"path"`
	DirectoryDev uint64 `json:"directory_dev"`
	DirectoryIno uint64 `json:"directory_ino"`
	SocketDev    uint64 `json:"socket_dev"`
	SocketIno    uint64 `json:"socket_ino"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	Mode         uint32 `json:"mode"`
}

type ResourceLimits struct {
	NanoCPUs               int64 `json:"nano_cpus"`
	MemoryBytes            int64 `json:"memory_bytes"`
	Pids                   int64 `json:"pids"`
	PersistentBytes        int64 `json:"persistent_bytes"`
	ScratchBytes           int64 `json:"scratch_bytes"`
	PersistentInodes       int64 `json:"persistent_inodes"`
	ScratchInodes          int64 `json:"scratch_inodes"`
	ControlMessageMaxBytes int64 `json:"control_message_max_bytes"`
	LogBufferBytes         int64 `json:"log_buffer_bytes"`
	LogFileMaxBytes        int64 `json:"log_file_max_bytes"`
	LogRetainedFiles       int   `json:"log_retained_files"`
}

type LaunchSpec struct {
	ModuleID         string         `json:"module_id"`
	InstanceID       string         `json:"instance_id"`
	ImageDigest      string         `json:"image_digest"`
	InitialEgress    EgressPolicy   `json:"initial_egress"`
	Entrypoint       []string       `json:"entrypoint"`
	Args             []string       `json:"args"`
	UID              uint32         `json:"uid"`
	GID              uint32         `json:"gid"`
	Resources        ResourceLimits `json:"resources"`
	ConfigRevision   string         `json:"config_revision"`
	ApprovalRevision string         `json:"approval_revision"`
}

type Ownership struct {
	RuntimeInstallationID string       `json:"runtime_installation_id"`
	InstallationID        string       `json:"installation_id"`
	EpochID               string       `json:"epoch_id"`
	InstanceID            string       `json:"instance_id"`
	Unit                  UnitIdentity `json:"unit"`
}

type Lease struct {
	Ownership             Ownership      `json:"ownership"`
	Spec                  LaunchSpec     `json:"spec"`
	PersistentPath        string         `json:"persistent_path"`
	ScratchPath           string         `json:"scratch_path"`
	IPCPath               string         `json:"ipc_path"`
	LogPath               string         `json:"log_path"`
	BootstrapPath         string         `json:"bootstrap_path"`
	PersistentProject     uint32         `json:"persistent_project"`
	ScratchProject        uint32         `json:"scratch_project"`
	SocketGID             uint32         `json:"socket_gid"`
	ImageRecordID         string         `json:"image_record_id"`
	CacheGenerationID     string         `json:"cache_generation_id"`
	NetworkGeneration     string         `json:"network_generation"`
	Topology              NetworkProfile `json:"topology"`
	SandboxUID            uint32         `json:"sandbox_uid"`
	SandboxGID            uint32         `json:"sandbox_gid"`
	StartupDeadlineBootNS int64          `json:"startup_deadline_boot_ns"`
}

type StageProcess struct {
	Unit                                      UnitIdentity
	Init                                      gvxcontract.BridgeInit
	EndpointIdentity                          EndpointIdentity
	Stdin, Stdout, Stderr, Listener, Endpoint *os.File
}

type ProcessExit struct {
	Kind      string `json:"kind"`
	Value     uint32 `json:"value"`
	OOMKilled bool   `json:"oom_killed"`
}

type CreateKind string

const (
	CreateService CreateKind = "service"
	CreateNetwork CreateKind = "network"
)

type CreateState string

const (
	CreateSubmitted CreateState = "SUBMITTED"
	CreateObserved  CreateState = "OBSERVED"
	CreateRejected  CreateState = "REJECTED"
)

type CreateRecord struct {
	Identity  string
	State     CreateState
	ObjectID  string
	Rejection string
}

// CreateJournal commits submissions before dispatch. Uncertain outcomes retain
// claims until an authoritative rejection or boot-fenced settlement is durable.
type CreateJournal interface {
	SubmitCreate(context.Context, Ownership, CreateKind, string) error
	ObserveCreated(context.Context, Ownership, CreateKind, string, string) error
	RejectCreate(context.Context, Ownership, CreateKind, string, string) error
	LookupCreate(context.Context, Ownership, CreateKind) (CreateRecord, bool, error)
	RecordFailure(context.Context, Ownership, FailurePhase, FailureReason) error
}

// Platform retains ownership after uncertain outcomes and proves cleanup before
// returning success. Create returns five caller-owned transfer descriptors.
type Platform interface {
	BindCreateJournal(CreateJournal) error
	Preflight(context.Context) error
	ImageManifest(context.Context, string, int64) ([]byte, error)
	Create(context.Context, LaunchSpec, Lease, []string) (*StageProcess, error)
	Start(context.Context, Ownership) error
	ConfirmGuestStorage(context.Context, Ownership, gvxcontract.RootInitResult) error
	Wait(context.Context, Ownership) (ProcessExit, error)
	Terminate(context.Context, Ownership) error
	SetEgress(context.Context, Ownership, EgressPolicy) error
	Reconcile(context.Context, Ownership) error
}

type ClientConfig struct {
	SocketPath       string        `json:"socket_path"`
	SupervisorUID    uint32        `json:"supervisor_uid"`
	MaxMessageBytes  int           `json:"max_message_bytes"`
	OperationTimeout time.Duration `json:"operation_timeout"`
}

type SupervisorConfig struct {
	SocketPath            string          `json:"socket_path"`
	RuntimeUID            uint32          `json:"runtime_uid"`
	RuntimeGID            uint32          `json:"runtime_gid"`
	ManagementDirectory   string          `json:"management_directory"`
	StorageRoot           string          `json:"storage_root"`
	IPCRoot               string          `json:"ipc_root"`
	MaxMessageBytes       int             `json:"max_message_bytes"`
	OperationTimeout      time.Duration   `json:"operation_timeout"`
	ReconcileInterval     time.Duration   `json:"reconcile_interval"`
	MaxConnections        int             `json:"max_connections"`
	RuntimeInstallationID string          `json:"runtime_installation_id"`
	App                   NumericIdentity `json:"app"`
	Sandbox               NumericIdentity `json:"sandbox"`
	Preparer              NumericIdentity `json:"preparer"`
	Worker                UnitIdentity    `json:"worker"`
	PublicProfile         NetworkProfile  `json:"public_profile"`
	StartupTimeout        time.Duration   `json:"startup_timeout"`
}

type Error struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (e *Error) Error() string               { return e.Reason + ": " + e.Message }
func failure(reason string, err error) error { return &Error{Reason: reason, Message: err.Error()} }

var ErrCleanupIncomplete = errors.New("host cleanup incomplete")
var ErrCreateUnresolved = errors.New("submitted create remains unresolved")
var ErrCreateAlreadySubmitted = errors.New("create was already submitted")

func prerequisite(err error) error { return failure("HOST_PREREQUISITE_FAILED", err) }
func invalid(s string) error       { return failure("INVALID_CONFIGURATION", fmt.Errorf("%s", s)) }
