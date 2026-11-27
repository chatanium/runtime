package host

import (
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/provision"
)

type InstallationManifest struct {
	Format                string            `json:"format"`
	FormatVersion         uint32            `json:"format_version"`
	SchemaVersion         uint32            `json:"schema_version"`
	RuntimeInstallationID string            `json:"runtime_installation_id"`
	State                 string            `json:"state"`
	DesiredRunState       string            `json:"desired_run_state"`
	DesiredIntentID       string            `json:"desired_intent_id"`
	ActiveRevision        string            `json:"active_revision"`
	PendingRevision       string            `json:"pending_revision"`
	BundleDigest          string            `json:"bundle_digest"`
	ManifestGeneration    uint64            `json:"manifest_generation"`
	Paths                 InstallationPaths `json:"paths"`
	Identities            ProductIdentities `json:"identities"`
	Backing               BackingIdentity   `json:"backing"`
	Budget                StorageBudget     `json:"budget"`
	Terminal              *TerminalWitness  `json:"terminal,omitempty"`
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
type NumericIdentity struct {
	Name           string `json:"name"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	ProductCreated bool   `json:"product_created"`
}
type ProductIdentities struct {
	App      NumericIdentity `json:"app"`
	Sandbox  NumericIdentity `json:"sandbox"`
	Preparer NumericIdentity `json:"preparer"`
}
type BackingIdentity struct {
	Dev       uint64 `json:"dev"`
	Ino       uint64 `json:"ino"`
	XFSUUID   string `json:"xfs_uuid"`
	SizeBytes int64  `json:"size_bytes"`
}
type StorageBudget struct {
	DataBytes              int64 `json:"data_bytes"`
	DataInodes             int64 `json:"data_inodes"`
	SourceBytes            int64 `json:"source_bytes"`
	AppBytes               int64 `json:"app_bytes"`
	AppInodes              int64 `json:"app_inodes"`
	SourceInodes           int64 `json:"source_inodes"`
	CacheBytes             int64 `json:"cache_bytes"`
	CacheInodes            int64 `json:"cache_inodes"`
	PreparationBytes       int64 `json:"preparation_bytes"`
	PreparationInodes      int64 `json:"preparation_inodes"`
	MetadataHeadroomBytes  int64 `json:"metadata_headroom_bytes"`
	MetadataHeadroomInodes int64 `json:"metadata_headroom_inodes"`
}
type RevisionRecord struct {
	ID                string                    `json:"id"`
	ConfigDigest      string                    `json:"config_digest"`
	BundleDigest      string                    `json:"bundle_digest"`
	Config            []byte                    `json:"config"`
	Images            []ApprovedImageBinding    `json:"images"`
	LaunchPolicies    []LaunchSpec              `json:"launch_policies"`
	PublicProfile     NetworkProfile            `json:"public_profile"`
	DevelopmentWorker *DevelopmentWorkerBinding `json:"development_worker,omitempty"`
}
type ApprovedImageBinding struct {
	ModuleID         string `json:"module_id"`
	ImageSelector    string `json:"image_selector"`
	ImageRecordID    string `json:"image_record_id"`
	ConfigRevision   string `json:"config_revision"`
	ApprovalRevision string `json:"approval_revision"`
}
type ProvisionIntent struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Identity       string `json:"identity"`
	ExistedBefore  bool   `json:"existed_before"`
	ProductCreated bool   `json:"product_created"`
	Desired        []byte `json:"desired"`
}
type ObjectObservation struct {
	Identity   string `json:"identity"`
	Attributes []byte `json:"attributes"`
}
type ProvisionRecord struct {
	ProvisionIntent
	Observed     ObjectObservation `json:"observed"`
	State        string            `json:"state"`
	CleanupState string            `json:"cleanup_state"`
	FirstFailure string            `json:"first_failure"`
}
type CleanupEvidence struct {
	BootID               string         `json:"boot_id"`
	Units                []UnitIdentity `json:"units"`
	JobsAbsent           bool           `json:"jobs_absent"`
	ProcessesAbsent      bool           `json:"processes_absent"`
	TransportsClosed     bool           `json:"transports_closed"`
	MountsAbsent         bool           `json:"mounts_absent"`
	OpenReferencesAbsent bool           `json:"open_references_absent"`
	QuotaReclaimed       bool           `json:"quota_reclaimed"`
	Details              []byte         `json:"details"`
}
type UnitObservation struct {
	Unit                      UnitIdentity             `json:"unit"`
	JobPath                   string                   `json:"job_path"`
	JobResult                 string                   `json:"job_result"`
	ActiveState               string                   `json:"active_state"`
	SubState                  string                   `json:"sub_state"`
	Result                    string                   `json:"result"`
	ExecMainPID               int                      `json:"exec_main_pid"`
	ExecMainCode              int32                    `json:"exec_main_code"`
	ExecMainStatus            int32                    `json:"exec_main_status"`
	Exit                      *ProcessExit             `json:"exit,omitempty"`
	CgroupEmpty               bool                     `json:"cgroup_empty"`
	Absence                   *CleanupEvidence         `json:"absence,omitempty"`
	MountNamespace            *NamespaceIdentity       `json:"mount_namespace,omitempty"`
	MountNamespaceDisposition string                   `json:"mount_namespace_disposition,omitempty"`
	Writer                    *PreparationWriterRecord `json:"writer,omitempty"`
}
type NativeRootIdentity struct {
	RootID   string `json:"root_id"`
	HostPath string `json:"host_path"`
	Dev      uint64 `json:"dev"`
	Ino      uint64 `json:"ino"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Mode     uint32 `json:"mode"`
	Project  uint32 `json:"project"`
}
type NativeRootIntent struct {
	Native          NativeRootIdentity        `json:"native"`
	Guest           gvxcontract.RootInitEntry `json:"guest"`
	StorageIntentID string                    `json:"storage_intent_id"`
}
type RootIntentRecord struct {
	Ownership Ownership                    `json:"ownership"`
	Manifest  gvxcontract.RootInitManifest `json:"manifest"`
	Native    []NativeRootIntent           `json:"native"`
	Confirmed bool                         `json:"confirmed"`
	Result    *gvxcontract.RootInitResult  `json:"result,omitempty"`
}
type CacheGeneration struct {
	ID                     string                    `json:"id"`
	BundleDigest           string                    `json:"bundle_digest"`
	ImageRecordID          string                    `json:"image_record_id"`
	CanonicalArchiveDigest string                    `json:"canonical_archive_digest"`
	ManifestDigest         string                    `json:"manifest_digest"`
	Directory              string                    `json:"directory"`
	InventoryDigest        string                    `json:"inventory_digest"`
	State                  string                    `json:"state"`
	Files                  []provision.FileIntegrity `json:"files"`
}
type NetworkRecord struct {
	Generation          string         `json:"generation"`
	Profile             NetworkProfile `json:"profile"`
	NetnsPath           string         `json:"netns_path"`
	NetnsDev            uint64         `json:"netns_dev"`
	NetnsIno            uint64         `json:"netns_ino"`
	BootID              string         `json:"boot_id"`
	NetnsPlaceholderDev uint64         `json:"netns_placeholder_dev"`
	NetnsPlaceholderIno uint64         `json:"netns_placeholder_ino"`
	HostInterface       string         `json:"host_interface"`
	PeerInterface       string         `json:"peer_interface"`
	HostIfIndex         int            `json:"host_if_index"`
	PeerIfIndex         int            `json:"peer_if_index"`
	HostMAC             string         `json:"host_mac"`
	PeerMAC             string         `json:"peer_mac"`
	IPv4Prefix          string         `json:"ipv4_prefix"`
	IPv6Prefix          string         `json:"ipv6_prefix"`
	HostIPv4            string         `json:"host_ipv4"`
	PeerIPv4            string         `json:"peer_ipv4"`
	HostIPv6            string         `json:"host_ipv6"`
	PeerIPv6            string         `json:"peer_ipv6"`
	Uplink4             string         `json:"uplink4"`
	Uplink6             string         `json:"uplink6"`
	Source4             string         `json:"source4"`
	Source6             string         `json:"source6"`
	FilterGeneration    string         `json:"filter_generation"`
	NATGeneration       string         `json:"nat_generation"`
	State               string         `json:"state"`
	InventoryDigest     string         `json:"inventory_digest"`
}

type GenerationReference struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Claim string `json:"claim"`
}

type DevelopmentWorkerBinding struct {
	BaseRevision   string `json:"base_revision"`
	ArtifactDigest string `json:"artifact_digest"`
	JobID          string `json:"job_id"`
}

type UnitAbsenceDetails struct {
	UnitAbsent                bool               `json:"unit_absent"`
	CgroupEmpty               bool               `json:"cgroup_empty"`
	TransportPipes            []string           `json:"transport_pipes"`
	WriterUserNamespace       *NamespaceIdentity `json:"writer_user_namespace,omitempty"`
	WriterUserNamespaceAbsent bool               `json:"writer_user_namespace_absent,omitempty"`
}

type NamespaceIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

const (
	NamespacePrivate    = "PRIVATE"
	NamespaceSharedHost = "SHARED_HOST"
)

// Legacy installation records cross the client/operator boundary as data only.

type TerminalNativeIdentity struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
	Links  uint64 `json:"links"`
	Digest string `json:"digest,omitempty"`
	Absent bool   `json:"absent"`
}
type TerminalWitness struct {
	Version        uint32 `json:"version"`
	InstallationID string `json:"installation_id"`
	Incarnation    string `json:"incarnation"`
	TransactionID  string `json:"transaction_id"`
	ApprovalDigest string `json:"approval_digest"`
	ScopeDigest    string `json:"scope_digest"`
	ReceiptPath    string `json:"receipt_path"`
}
type ManagementAnchorObservation struct {
	Root   TerminalNativeIdentity `json:"root"`
	Lock   TerminalNativeIdentity `json:"lock"`
	Marker string                 `json:"marker"`
}
// PreparationStorageView is root-derived native identity, not path or mount authority.
type PreparationStorageRoot struct {
	Barrier  NativeRootIdentity `json:"barrier"`
	Data     NativeRootIdentity `json:"data"`
	ReadOnly bool               `json:"read_only"`
}
type PreparationStorageView struct {
	Version     uint32                 `json:"version"`
	JobID       string                 `json:"job_id"`
	ProvisionID string                 `json:"provision_id"`
	Source      PreparationStorageRoot `json:"source"`
	Cache       PreparationStorageRoot `json:"cache"`
	Work        PreparationStorageRoot `json:"work"`
}
type PreparationWriterLaunch struct {
	Version           uint32                 `json:"version"`
	ProtocolVersion   uint32                 `json:"protocol_version"`
	FilterVersion     uint32                 `json:"filter_version"`
	InstallationID    string                 `json:"installation_id"`
	JobID             string                 `json:"job_id"`
	ProvisionID       string                 `json:"provision_id"`
	UnitName          string                 `json:"unit_name"`
	Generation        string                 `json:"generation"`
	BootID            string                 `json:"boot_id"`
	Purpose           string                 `json:"purpose"`
	BundleDigest      string                 `json:"bundle_digest"`
	StageDigest       string                 `json:"stage_digest"`
	TargetDigest      string                 `json:"target_digest"`
	StagePath         string                 `json:"stage_path"`
	TargetPath        string                 `json:"target_path"`
	ArgumentDigest    string                 `json:"argument_digest"`
	DeclarationDigest string                 `json:"declaration_digest"`
	PreparerUID       uint32                 `json:"preparer_uid"`
	PreparerGID       uint32                 `json:"preparer_gid"`
	Layout            PreparationStorageView `json:"layout"`
}
type PreparationIDMap struct {
	Inside  uint32 `json:"inside"`
	Outside uint32 `json:"outside"`
	Length  uint32 `json:"length"`
}
type PreparationTaskSnapshot struct {
	ThreadCount             uint32    `json:"thread_count"`
	SnapshotDigest          string    `json:"snapshot_digest"`
	UIDs                    [4]uint32 `json:"uids"`
	GIDs                    [4]uint32 `json:"gids"`
	SupplementaryGID        uint32    `json:"supplementary_gid"`
	SupplementaryGroupCount uint32    `json:"supplementary_group_count"`
	Capabilities            [5]uint64 `json:"capabilities"`
	NoNewPrivileges         bool      `json:"no_new_privileges"`
	SeccompMode             uint32    `json:"seccomp_mode"`
	SeccompFilters          uint32    `json:"seccomp_filters"`
}
type PreparationWriterBirth struct {
	Version               uint32                  `json:"version"`
	Unit                  UnitIdentity            `json:"unit"`
	PeerPID               int                     `json:"peer_pid"`
	PeerUID               uint32                  `json:"peer_uid"`
	PeerGID               uint32                  `json:"peer_gid"`
	PIDFDDevice           uint64                  `json:"pidfd_device"`
	PIDFDInode            uint64                  `json:"pidfd_inode"`
	UserNamespace         NamespaceIdentity       `json:"user_namespace"`
	ParentUserNamespace   NamespaceIdentity       `json:"parent_user_namespace"`
	HostUserNamespace     NamespaceIdentity       `json:"host_user_namespace"`
	UserNamespaceType     uint32                  `json:"user_namespace_type"`
	UserNamespaceOwnerUID uint32                  `json:"user_namespace_owner_uid"`
	UIDMap                [2]PreparationIDMap     `json:"uid_map"`
	GIDMap                [2]PreparationIDMap     `json:"gid_map"`
	SetgroupsDenied       bool                    `json:"setgroups_denied"`
	MountNamespace        NamespaceIdentity       `json:"mount_namespace"`
	Tasks                 PreparationTaskSnapshot `json:"tasks"`
}
type PreparationWriterEvidence struct {
	Version         uint32                  `json:"version"`
	ProtocolVersion uint32                  `json:"protocol_version"`
	FilterVersion   uint32                  `json:"filter_version"`
	FilterDigest    string                  `json:"filter_digest"`
	AuditArch       uint32                  `json:"audit_arch"`
	RejectX32       bool                    `json:"reject_x32"`
	TSYNC           bool                    `json:"tsync"`
	FilterReady     bool                    `json:"filter_ready"`
	Tasks           PreparationTaskSnapshot `json:"tasks"`
}
type PreparationWriterRecord struct {
	Launch         PreparationWriterLaunch    `json:"launch"`
	Birth          *PreparationWriterBirth    `json:"birth,omitempty"`
	Evidence       *PreparationWriterEvidence `json:"evidence,omitempty"`
	StartIntent    bool                       `json:"start_intent,omitempty"`
	StartForbidden bool                       `json:"start_forbidden,omitempty"`
}

// Inventory is bounded canonical JSON of the closed native fact types below.
// It is observation data only: verification always recollects the kernel facts,
// and no inventory byte is interpreted as a command, path, or permission grant.
type NetworkPrerequisiteObservation struct {
	Version             uint32         `json:"version"`
	Profile             NetworkProfile `json:"profile"`
	ConfigurationDigest string         `json:"configuration_digest"`
	Inventory           []byte         `json:"inventory"`
	Digest              string         `json:"digest"`
}
const NetworkPrerequisiteInventoryMaxBytes = 16 << 20
const NetworkPrerequisiteInventoryMaxDepth = 12
// ImageSpace reserves compressed input, immutable output and simultaneous
// decompression/load workspace separately. All directories carry hard XFS quotas.
type ImageSpace struct {
	JobID              string `json:"job_id"`
	ProvisionID        string `json:"provision_id"`
	Committed          bool   `json:"committed"`
	ReusedSource       bool   `json:"reused_source"`
	SourceGenerationID string `json:"source_generation_id"`
	Source             string `json:"source"`
	Cache              string `json:"cache"`
	Work               string `json:"work"`
	SourceProject      uint32 `json:"source_project"`
	CacheProject       uint32 `json:"cache_project"`
	WorkProject        uint32 `json:"work_project"`
}

// ProvisionProperties is the closed, non-executable filesystem/account/unit
// description accepted in provisioning intents and observations.
type ProvisionProperties struct {
	Exit                      *ProcessExit                  `json:"exit,omitempty"`
	CgroupEmpty               bool                          `json:"cgroup_empty,omitempty"`
	ImageSpace                *ImageSpace                   `json:"image_space,omitempty"`
	ApprovedImageInput        *provision.ApprovedImageInput `json:"approved_image_input,omitempty"`
	Volume                    *BackingIdentity              `json:"volume,omitempty"`
	JobPath                   string                        `json:"job_path,omitempty"`
	Limits                    *ResourceLimits               `json:"limits,omitempty"`
	PrepareLimits             *provision.PrepareLimits      `json:"prepare_limits,omitempty"`
	Ownership                 *Ownership                    `json:"ownership,omitempty"`
	Rejection                 string                        `json:"rejection,omitempty"`
	TransportPipes            []string                      `json:"transport_pipes,omitempty"`
	Absence                   *CleanupEvidence              `json:"absence,omitempty"`
	MountNamespace            *NamespaceIdentity            `json:"mount_namespace,omitempty"`
	MountNamespaceDisposition string                        `json:"mount_namespace_disposition,omitempty"`
	Name                      string                        `json:"name,omitempty"`
	Path                      string                        `json:"path,omitempty"`
	Parent                    string                        `json:"parent,omitempty"`
	Source                    string                        `json:"source,omitempty"`
	Target                    string                        `json:"target,omitempty"`
	Digest                    string                        `json:"digest,omitempty"`
	Revision                  string                        `json:"revision,omitempty"`
	UID                       uint32                        `json:"uid,omitempty"`
	GID                       uint32                        `json:"gid,omitempty"`
	Mode                      uint32                        `json:"mode,omitempty"`
	Dev                       uint64                        `json:"dev,omitempty"`
	Ino                       uint64                        `json:"ino,omitempty"`
	SizeBytes                 int64                         `json:"size_bytes,omitempty"`
	UUID                      string                        `json:"uuid,omitempty"`
	Unit                      *UnitIdentity                 `json:"unit,omitempty"`
	ReadOnly                  bool                          `json:"read_only,omitempty"`
	ProductCreated            bool                          `json:"product_created,omitempty"`
	Writer                    *PreparationWriterRecord      `json:"writer,omitempty"`
}

