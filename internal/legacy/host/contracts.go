// Package host implements the legacy Linux sandbox supervisor and worker client.
package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
)

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

type StageProcess struct {
	Unit                                      sharedhost.UnitIdentity
	Init                                      gvxcontract.BridgeInit
	EndpointIdentity                          EndpointIdentity
	Stdin, Stdout, Stderr, Listener, Endpoint *os.File
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
	SubmitCreate(context.Context, sharedhost.Ownership, CreateKind, string) error
	ObserveCreated(context.Context, sharedhost.Ownership, CreateKind, string, string) error
	RejectCreate(context.Context, sharedhost.Ownership, CreateKind, string, string) error
	LookupCreate(context.Context, sharedhost.Ownership, CreateKind) (CreateRecord, bool, error)
	RecordFailure(context.Context, sharedhost.Ownership, FailurePhase, FailureReason) error
}

// Platform retains ownership after uncertain outcomes and proves cleanup before
// returning success. Create returns five caller-owned transfer descriptors.
type Platform interface {
	BindCreateJournal(CreateJournal) error
	Preflight(context.Context) error
	ImageManifest(context.Context, string, int64) ([]byte, error)
	Create(context.Context, sharedhost.LaunchSpec, sharedhost.Lease, []string) (*StageProcess, error)
	Start(context.Context, sharedhost.Ownership) error
	ConfirmGuestStorage(context.Context, sharedhost.Ownership, gvxcontract.RootInitResult) error
	Wait(context.Context, sharedhost.Ownership) (sharedhost.ProcessExit, error)
	Terminate(context.Context, sharedhost.Ownership) error
	SetEgress(context.Context, sharedhost.Ownership, sharedhost.EgressPolicy) error
	Reconcile(context.Context, sharedhost.Ownership) error
}

type ClientConfig struct {
	SocketPath       string        `json:"socket_path"`
	SupervisorUID    uint32        `json:"supervisor_uid"`
	MaxMessageBytes  int           `json:"max_message_bytes"`
	OperationTimeout time.Duration `json:"operation_timeout"`
}

type SupervisorConfig struct {
	SocketPath            string                    `json:"socket_path"`
	RuntimeUID            uint32                    `json:"runtime_uid"`
	RuntimeGID            uint32                    `json:"runtime_gid"`
	ManagementDirectory   string                    `json:"management_directory"`
	StorageRoot           string                    `json:"storage_root"`
	IPCRoot               string                    `json:"ipc_root"`
	MaxMessageBytes       int                       `json:"max_message_bytes"`
	OperationTimeout      time.Duration             `json:"operation_timeout"`
	ReconcileInterval     time.Duration             `json:"reconcile_interval"`
	MaxConnections        int                       `json:"max_connections"`
	RuntimeInstallationID string                    `json:"runtime_installation_id"`
	App                   NumericIdentity           `json:"app"`
	Sandbox               NumericIdentity           `json:"sandbox"`
	Preparer              NumericIdentity           `json:"preparer"`
	Worker                sharedhost.UnitIdentity   `json:"worker"`
	PublicProfile         sharedhost.NetworkProfile `json:"public_profile"`
	StartupTimeout        time.Duration             `json:"startup_timeout"`
}

func failure(reason string, err error) error { return &sharedhost.Error{Reason: reason, Message: err.Error()} }

var ErrCreateUnresolved = errors.New("submitted create remains unresolved")
var ErrCreateAlreadySubmitted = errors.New("create was already submitted")

func prerequisite(err error) error { return failure("HOST_PREREQUISITE_FAILED", err) }
func invalid(s string) error       { return failure("INVALID_CONFIGURATION", fmt.Errorf("%s", s)) }
