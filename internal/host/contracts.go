// Package host implements the trusted Linux supervisor boundary. No module
// configuration, backend secret, or caller-provided host path belongs here.
package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

type EgressPolicy string

const (
	EgressNone           EgressPolicy = "NONE"
	EgressPublicInternet EgressPolicy = "PUBLIC_INTERNET"
)

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
	InstallationID string `json:"installation_id"`
	EpochID        string `json:"epoch_id"`
	InstanceID     string `json:"instance_id"`
	ContainerID    string `json:"container_id"`
}

type Lease struct {
	Ownership         Ownership  `json:"ownership"`
	Spec              LaunchSpec `json:"spec"`
	PersistentPath    string     `json:"persistent_path"`
	ScratchPath       string     `json:"scratch_path"`
	IPCPath           string     `json:"ipc_path"`
	LogPath           string     `json:"log_path"`
	PersistentProject uint32     `json:"persistent_project"`
	ScratchProject    uint32     `json:"scratch_project"`
	SocketGID         uint32     `json:"socket_gid"`
}

type Container struct {
	ID     string
	Stdout *os.File
	Stderr *os.File
}

type Exit struct {
	Code      int64 `json:"code"`
	OOMKilled bool  `json:"oom_killed"`
}

type CreateKind string

const (
	CreateContainer CreateKind = "container"
	CreateNetwork   CreateKind = "network"
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

// CreateJournal commits the submission before Docker dispatch. A successful
// response or an exact ownership-checked observation must be durable before
// deleting the created object. Only an authoritative completed negative response
// may reject a submission; absence, deadlines and transport errors never do.
type CreateJournal interface {
	SubmitCreate(context.Context, Ownership, CreateKind, string) error
	ObserveCreated(context.Context, Ownership, CreateKind, string, string) error
	RejectCreate(context.Context, Ownership, CreateKind, string, string) error
	LookupCreate(context.Context, Ownership, CreateKind) (CreateRecord, bool, error)
	RecordFailure(context.Context, Ownership, FailurePhase, FailureReason) error
}

// Platform implementations must retain ownership after any uncertain remote
// outcome. Terminate/Reconcile prove all labeled resources absent before success.
// Create attaches bounded stdout/stderr before Start; returned files are owned
// by the caller. The final Create argument is the approved host socket directory.
type Platform interface {
	BindCreateJournal(CreateJournal) error
	Preflight(context.Context) error
	ImageManifest(context.Context, string, int64) ([]byte, error)
	Create(context.Context, LaunchSpec, Lease, []string, string) (*Container, error)
	Start(context.Context, Ownership) error
	Wait(context.Context, Ownership) (Exit, error)
	Terminate(context.Context, Ownership) error
	SetEgress(context.Context, Ownership, EgressPolicy) error
	Reconcile(context.Context, Ownership) error
}

type ClientConfig struct {
	SocketPath       string
	SupervisorUID    uint32
	MaxMessageBytes  int
	OperationTimeout time.Duration
}

type SupervisorConfig struct {
	SocketPath          string        `json:"socket_path"`
	RuntimeUID          uint32        `json:"runtime_uid"`
	RuntimeGID          uint32        `json:"runtime_gid"`
	ManagementDirectory string        `json:"management_directory"`
	StorageRoot         string        `json:"storage_root"`
	IPCRoot             string        `json:"ipc_root"`
	MaxMessageBytes     int           `json:"max_message_bytes"`
	OperationTimeout    time.Duration `json:"operation_timeout"`
	ReconcileInterval   time.Duration `json:"reconcile_interval"`
	MaxConnections      int           `json:"max_connections"`
}

type Error struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (e *Error) Error() string               { return e.Reason + ": " + e.Message }
func failure(reason string, err error) error { return &Error{Reason: reason, Message: err.Error()} }

var ErrCleanupIncomplete = errors.New("host cleanup incomplete")
var ErrCreateUnresolved = errors.New("submitted Docker create remains unresolved")
var ErrCreateAlreadySubmitted = errors.New("Docker create was already submitted")

func prerequisite(err error) error { return failure("HOST_PREREQUISITE_FAILED", err) }
func invalid(s string) error       { return failure("INVALID_CONFIGURATION", fmt.Errorf("%s", s)) }
