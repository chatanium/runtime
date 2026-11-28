// Package host defines the trusted runtime sandbox boundary.
package host

import "errors"

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

type InstallationPaths struct {
	Launcher     string `json:"launcher"`
	Config       string `json:"config"`
	Secrets      string `json:"secrets"`
	Installation string `json:"installation"`
	Control      string `json:"control"`
	BackingFile  string `json:"backing_file"`
	StorageRoot  string `json:"storage_root"`
	EngineRoot   string `json:"engine_root"`
	RunRoot      string `json:"run_root"`
}

type ProcessExit struct {
	Kind      string `json:"kind"`
	Value     uint32 `json:"value"`
	OOMKilled bool   `json:"oom_killed"`
}

type Error struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Reason + ": " + e.Message }
var ErrCleanupIncomplete = errors.New("host cleanup incomplete")
