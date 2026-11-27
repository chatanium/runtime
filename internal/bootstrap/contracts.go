// Package bootstrap owns installation and root-owner lifecycle operations.
package bootstrap

import (
	"encoding/json"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
	"time"
)

type RuntimeInstallationID string
type RunMode string

const (
	Foreground RunMode = "foreground"
	Service    RunMode = "service"
)

type RunOptions struct {
	Duration            time.Duration `json:"duration"`
	DevelopmentMode     bool          `json:"development_mode"`
	DevelopmentSocket   string        `json:"development_socket"`
	DevelopmentImages   []string      `json:"development_images"`
	DevelopmentRevision string        `json:"development_revision,omitempty"`
}
type SecretSource struct {
	BackendID       string `json:"backend_id"`
	SecretName      string `json:"secret_name"`
	SourceKind      string `json:"source_kind"`
	SourceReference string `json:"source_reference"`
}
type ApprovedObject struct {
	Kind              string `json:"kind"`
	Identity          string `json:"identity"`
	Action            string `json:"action"`
	ObservationDigest string `json:"observation_digest"`
}
type InitModuleInput struct {
	Candidate runtime.ModuleSpec           `json:"candidate"`
	Image     provision.ApprovedImageInput `json:"image"`
}
type ApprovedInitPlan struct {
	PlanID               string                              `json:"plan_id"`
	PlanDigest           string                              `json:"plan_digest"`
	InstallationID       RuntimeInstallationID               `json:"installation_id"`
	Paths                host.InstallationPaths              `json:"paths"`
	Identities           host.ProductIdentities              `json:"identities"`
	Budget               host.StorageBudget                  `json:"budget"`
	BundleDigest         string                              `json:"bundle_digest"`
	BaseConfig           []byte                              `json:"base_config"`
	Modules              []InitModuleInput                   `json:"modules"`
	Objects              []ApprovedObject                    `json:"objects"`
	SecretSources        []SecretSource                      `json:"secret_sources"`
	NetworkPrerequisites host.NetworkPrerequisiteObservation `json:"network_prerequisites"`
	ManagementAnchor     host.ManagementAnchorObservation    `json:"management_anchor"`
}
type ModuleReview struct {
	PlanID       string                `json:"plan_id"`
	ReviewDigest string                `json:"review_digest"`
	Candidate    runtime.ModuleSpec    `json:"candidate"`
	Image        provision.ImageRecord `json:"image"`
	HostLimits   host.ResourceLimits   `json:"host_limits"`
}
type ApprovedModuleConfig struct {
	ReviewDigest  string             `json:"review_digest"`
	ImageRecordID string             `json:"image_record_id"`
	ImageRevision string             `json:"image_revision"`
	Module        runtime.ModuleSpec `json:"module"`
}
type PurgeApproval struct {
	InstallationID         RuntimeInstallationID            `json:"installation_id"`
	PlanID                 string                           `json:"plan_id"`
	PlanDigest             string                           `json:"plan_digest"`
	ExpectedActiveRevision string                           `json:"expected_active_revision"`
	Scope                  []ApprovedObject                 `json:"scope"`
	ManagementAnchor       host.ManagementAnchorObservation `json:"management_anchor"`
	TerminalReceiptPath    string                           `json:"terminal_receipt_path"`
	PublicationProbePaths  [2]string                        `json:"publication_probe_paths"`
}
type ReacquiredPreparation struct {
	ModuleID              string `json:"module_id"`
	PreviousImageRecordID string `json:"previous_image_record_id"`
	PreparationPlanID     string `json:"preparation_plan_id"`
	PreparationPlanDigest string `json:"preparation_plan_digest"`
}

type ApprovedUpdatePlan struct {
	InstallationID         RuntimeInstallationID   `json:"installation_id"`
	PlanID                 string                  `json:"plan_id"`
	PlanDigest             string                  `json:"plan_digest"`
	ExpectedActiveRevision string                  `json:"expected_active_revision"`
	CandidateBundleDigest  string                  `json:"candidate_bundle_digest"`
	BackupID               string                  `json:"backup_id"`
	CandidateRevision      host.RevisionRecord     `json:"candidate_revision"`
	ReacquiredPreparations []ReacquiredPreparation `json:"reacquired_preparations,omitempty"`
	Objects                []ApprovedObject        `json:"objects"`
}
type OperationFailure struct {
	Phase   string `json:"phase"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
type ObjectResult struct {
	Kind     string             `json:"kind"`
	Identity string             `json:"identity"`
	State    string             `json:"state"`
	Failures []OperationFailure `json:"failures"`
}
type DoctorCheck struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}
type DoctorReport struct {
	Checks []DoctorCheck `json:"checks"`
}
type CleanupReport struct {
	InstallationID  RuntimeInstallationID `json:"installation_id"`
	DesiredRunState string                `json:"desired_run_state"`
	ObservedState   string                `json:"observed_state"`
	Complete        bool                  `json:"complete"`
	Removed         []ObjectResult        `json:"removed"`
	Preserved       []ObjectResult        `json:"preserved"`
	Pending         []ObjectResult        `json:"pending"`
	Failures        []OperationFailure    `json:"failures"`
}
type ServiceResult struct {
	InstallationID    RuntimeInstallationID `json:"installation_id"`
	Unit              host.UnitIdentity     `json:"unit"`
	DesiredRunState   string                `json:"desired_run_state"`
	InstallationState string                `json:"installation_state"`
	EnablementState   string                `json:"enablement_state"`
	ActivationState   string                `json:"activation_state"`
	Pending           []ObjectResult        `json:"pending"`
	Failures          []OperationFailure    `json:"failures"`
}
type RemovalResult struct {
	InstallationID RuntimeInstallationID `json:"installation_id"`
	Removed        []ObjectResult        `json:"removed"`
	Preserved      []ObjectResult        `json:"preserved"`
	Pending        []ObjectResult        `json:"pending"`
	Failures       []OperationFailure    `json:"failures"`
}
type WorkerInit struct {
	Version               uint32            `json:"version"`
	RuntimeInstallationID string            `json:"runtime_installation_id"`
	Revision              string            `json:"revision"`
	EpochID               string            `json:"epoch_id"`
	Config                []byte            `json:"config"`
	Host                  host.ClientConfig `json:"host"`
	Options               RunOptions        `json:"options"`
	Secrets               map[string]string `json:"secrets"`
}
type WorkerCommand struct {
	Version     uint32      `json:"version"`
	Type        string      `json:"type"`
	Init        *WorkerInit `json:"init,omitempty"`
	OperationID string      `json:"operation_id,omitempty"`
	RemainingNS int64       `json:"remaining_ns,omitempty"`
}
type WorkerEvent struct {
	Version     uint32             `json:"version"`
	Type        string             `json:"type"`
	OperationID string             `json:"operation_id,omitempty"`
	Observation json.RawMessage    `json:"observation,omitempty"`
	Drain       *WorkerDrainResult `json:"drain,omitempty"`
	Failure     *OperationFailure  `json:"failure,omitempty"`
}
type WorkerDrainResult struct {
	Modules  []WorkerModuleCleanup `json:"modules"`
	Failures []OperationFailure    `json:"failures"`
}
type WorkerModuleCleanup struct {
	ModuleID        string             `json:"module_id"`
	InstanceID      string             `json:"instance_id"`
	FailureReason   string             `json:"failure_reason"`
	CleanupComplete bool               `json:"cleanup_complete"`
	CleanupErrors   []OperationFailure `json:"cleanup_errors"`
}
