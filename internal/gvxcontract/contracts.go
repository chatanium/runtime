// Package gvxcontract contains the versioned, privilege-boundary value contracts.
package gvxcontract

const (
	RuntimeControlVersion     = 2
	StageControlVersion       = 1
	WorkerControlVersion      = 1
	RootManagementVersion     = 1
	BridgeMagic               = "CTGVXIPC1"
	RootPayloadVersion        = 1
	InstallationFormat        = "chatanium-gvx"
	InstallationFormatVersion = 1
	SchemaVersion             = 1
	BundleManifestVersion     = 1
	ImageRecordVersion        = 1
	RootDispositionNew        = "new"
	RootDispositionRetained   = "retained"
	RootDigestDomain          = "chatanium-root-init-v1"
)

const (
	PortableRootPayloadVersion = 2
	BridgeLegacyArg            = "--stdio-v1"
	BridgePortableArg          = "--stdio-portable-v2"
	PortablePersistentPath     = "/var/lib/flexmodule/data"
	PortableScratchPath        = "/var/lib/flexmodule/scratch"
	PortableTmpPath            = "/tmp"
	PortableShmPath            = "/dev/shm"
)

type BridgeInit struct {
	Argv      []string         `json:"argv"`
	Env       []string         `json:"env"`
	Workdir   string           `json:"workdir"`
	UID       uint32           `json:"uid"`
	GID       uint32           `json:"gid"`
	SocketDir string           `json:"socket_dir"`
	Roots     RootInitManifest `json:"roots"`
}
type RootInitManifest struct {
	Digest  string `json:"digest"`
	Payload []byte `json:"payload"`
}
type RootInitPayload struct {
	Version               uint8               `json:"version"`
	RuntimeInstallationID string              `json:"runtime_installation_id"`
	EpochID               string              `json:"epoch_id"`
	InstanceID            string              `json:"instance_id"`
	IntentID              string              `json:"intent_id"`
	Nonce                 string              `json:"nonce"`
	Roots                 []RootInitEntry     `json:"roots"`
	PortableLimits        *PortableRootLimits `json:"portable_limits,omitempty"`
}

// RootBinding is the instance and durable intent to which ROOTS_READY belongs.
type RootBinding struct {
	RuntimeInstallationID string
	EpochID               string
	InstanceID            string
	IntentID              string
	Nonce                 string
}

// PortableRootLimits binds the approved GVX limits to INIT. The disk limits
// express whole image maxima. Zero ShmBytes disables shared-memory storage.
type PortableRootLimits struct {
	MaxPIDs         int64 `json:"max_pids"`
	PersistentBytes int64 `json:"persistent_bytes"`
	ScratchBytes    int64 `json:"scratch_bytes"`
	ShmBytes        int64 `json:"shm_bytes"`
}

type RootAttrs struct {
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Mode uint32 `json:"mode"`
}
type RootInitEntry struct {
	RootID      string    `json:"root_id"`
	Mountpoint  string    `json:"mountpoint"`
	Disposition string    `json:"disposition"`
	Pre         RootAttrs `json:"pre"`
	Target      RootAttrs `json:"target"`
}
type RootStepResult struct {
	RootID   string    `json:"root_id"`
	Step     uint8     `json:"step"`
	Observed RootAttrs `json:"observed"`
}
type RootInitResult struct {
	Digest  string           `json:"digest"`
	Nonce   string           `json:"nonce"`
	Results []RootStepResult `json:"results"`
}
