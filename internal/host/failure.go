package host

import (
	"context"
	"errors"
)

// These finite codes are host-selected diagnostics, never module text, paths,
// certificates, output, or daemon error bodies.
type FailurePhase string
type FailureReason string

const (
	PhaseAttach    FailurePhase = "ATTACH"
	PhasePrestart  FailurePhase = "PRESTART"
	PhaseStart     FailurePhase = "START"
	PhasePoststart FailurePhase = "POSTSTART"
	PhaseRunning   FailurePhase = "RUNNING"
	PhaseCleanup   FailurePhase = "CLEANUP"
)
const (
	FailureBootstrapFormat        FailureReason = "BOOTSTRAP_FORMAT_INVALID"
	FailureBootstrapProtocol      FailureReason = "BOOTSTRAP_PROTOCOL_INVALID"
	FailureBootstrapNetwork       FailureReason = "BOOTSTRAP_NETWORK_INVALID"
	FailureBootstrapMux           FailureReason = "BOOTSTRAP_MULTIPLEX_REQUIRED"
	FailureBootstrapTLS           FailureReason = "BOOTSTRAP_CERTIFICATE_INVALID"
	FailureBootstrapSocket        FailureReason = "BOOTSTRAP_SOCKET_OUT_OF_SCOPE"
	FailureBootstrapLimit         FailureReason = "BOOTSTRAP_MESSAGE_TOO_LARGE"
	FailureBootstrapEOF           FailureReason = "BOOTSTRAP_EOF"
	FailureBootstrapForward       FailureReason = "BOOTSTRAP_FORWARD_FAILED"
	FailureAttachRead             FailureReason = "ATTACH_STREAM_READ_FAILED"
	FailureAttachFrame            FailureReason = "ATTACH_FRAME_INVALID"
	FailureAttachEOF              FailureReason = "ATTACH_EOF_WHILE_RUNNING"
	FailureLogSink                FailureReason = "LOG_SINK_IO_FAILED"
	FailureInspect                FailureReason = "CONTAINER_INSPECT_FAILED"
	FailureStartAPI               FailureReason = "CONTAINER_START_API_FAILED"
	FailureNotRunning             FailureReason = "CONTAINER_NOT_RUNNING"
	FailureIsolation              FailureReason = "CONTAINER_ISOLATION_MISMATCH"
	FailureIdentity               FailureReason = "CONTAINER_IDENTITY_MISMATCH"
	FailureImage                  FailureReason = "CONTAINER_IMAGE_PROCESS_MISMATCH"
	FailureDNS                    FailureReason = "CONTAINER_RESOLVER_MISMATCH"
	FailureMount                  FailureReason = "CONTAINER_MOUNT_MISMATCH"
	FailureNetwork                FailureReason = "CONTAINER_NETWORK_TOPOLOGY_MISMATCH"
	FailureCgroupMembership       FailureReason = "CGROUP_MEMBERSHIP_UNAVAILABLE"
	FailureCgroupMemoryRead       FailureReason = "CGROUP_MEMORY_READ_FAILED"
	FailureCgroupMemory           FailureReason = "CGROUP_MEMORY_LIMIT_MISMATCH"
	FailureCgroupSwapRead         FailureReason = "CGROUP_SWAP_READ_FAILED"
	FailureCgroupSwap             FailureReason = "CGROUP_SWAP_LIMIT_MISMATCH"
	FailureCgroupPidsRead         FailureReason = "CGROUP_PIDS_READ_FAILED"
	FailureCgroupPids             FailureReason = "CGROUP_PIDS_LIMIT_MISMATCH"
	FailureCgroupCPURead          FailureReason = "CGROUP_CPU_READ_FAILED"
	FailureCgroupCPU              FailureReason = "CGROUP_CPU_LIMIT_MISMATCH"
	FailureCleanupPlatform        FailureReason = "PLATFORM_RECONCILE_FAILED"
	FailureCleanupCreateGuard     FailureReason = "CREATE_GUARD_FAILED"
	FailureCleanupScratch         FailureReason = "SCRATCH_REMOVAL_FAILED"
	FailureCleanupIPC             FailureReason = "IPC_REMOVAL_FAILED"
	FailureCleanupLogs            FailureReason = "LOG_REMOVAL_FAILED"
	FailureCleanupSync            FailureReason = "QUOTA_SYNC_FAILED"
	FailureCleanupBarrier         FailureReason = "QUOTA_RECLAMATION_BARRIER_FAILED"
	FailureCleanupQuotaRead       FailureReason = "QUOTA_READ_FAILED"
	FailureCleanupQuotaReferences FailureReason = "QUOTA_REFERENCES_REMAIN"
	FailureCleanupJournal         FailureReason = "JOURNAL_COMPLETE_FAILED"
)

func validFailurePhase(p FailurePhase) bool {
	switch p {
	case PhaseAttach, PhasePrestart, PhaseStart, PhasePoststart, PhaseRunning, PhaseCleanup:
		return true
	}
	return false
}
func validFailureReason(r FailureReason) bool {
	switch r {
	case FailureCleanupPlatform, FailureCleanupCreateGuard, FailureCleanupScratch, FailureCleanupIPC, FailureCleanupLogs, FailureCleanupSync, FailureCleanupBarrier, FailureCleanupQuotaRead, FailureCleanupQuotaReferences, FailureCleanupJournal:
		return true
	case FailureBootstrapFormat, FailureBootstrapProtocol, FailureBootstrapNetwork, FailureBootstrapMux, FailureBootstrapTLS, FailureBootstrapSocket, FailureBootstrapLimit, FailureBootstrapEOF, FailureBootstrapForward, FailureAttachRead, FailureAttachFrame, FailureAttachEOF, FailureLogSink, FailureInspect, FailureStartAPI, FailureNotRunning, FailureIsolation, FailureIdentity, FailureImage, FailureDNS, FailureMount, FailureNetwork, FailureCgroupMembership, FailureCgroupMemoryRead, FailureCgroupMemory, FailureCgroupSwapRead, FailureCgroupSwap, FailureCgroupPidsRead, FailureCgroupPids, FailureCgroupCPURead, FailureCgroupCPU:
		return true
	}
	return false
}

type sandboxFailure struct {
	reason FailureReason
	cause  error
}

func (f *sandboxFailure) Error() string { return string(f.reason) }
func (f *sandboxFailure) Unwrap() error { return f.cause }
func classifiedFailure(reason FailureReason, cause error) error {
	return &sandboxFailure{reason: reason, cause: cause}
}
func failureReason(err error, fallback FailureReason) FailureReason {
	var f *sandboxFailure
	if errors.As(err, &f) && validFailureReason(f.reason) {
		return f.reason
	}
	return fallback
}

func (j *journal) RecordFailure(ctx context.Context, o Ownership, phase FailurePhase, reason FailureReason) error {
	if !validFailurePhase(phase) || !validFailureReason(reason) {
		return invalid("invalid sandbox failure diagnostic code")
	}
	if err := j.creationOwner(ctx, o); err != nil {
		return err
	}
	return j.state(ctx, o.InstanceID, "FAILED", string(phase)+":"+string(reason))
}
func (p *DockerPlatform) recordFailure(o Ownership, phase FailurePhase, err error, fallback FailureReason) error {
	if err == nil {
		return nil
	}
	reason := failureReason(err, fallback)
	diagnostic := err
	if _, typed := err.(*sandboxFailure); !typed {
		diagnostic = classifiedFailure(reason, err)
	}
	if p.creates == nil {
		return errors.Join(diagnostic, errors.New("durable failure journal is not bound"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.APIDeadline)
	defer cancel()
	if recordErr := p.creates.RecordFailure(ctx, o, phase, reason); recordErr != nil {
		return errors.Join(diagnostic, recordErr)
	}
	return diagnostic
}
