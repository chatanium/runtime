// Package store is the portable-v2 installation's SQLite authority. Native
// process and filesystem observations come from the trusted installation owner;
// this package does not start children, open volumes or perform recovery I/O.
package store

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	Format               = "portable-v2"
	VolumeResourceFormat = Format
	DatabaseName         = "supervisor.sqlite"
	VolumeAlignmentBytes = 16 << 20
	MinVolumeBytes       = VolumeAlignmentBytes
	MaxVolumeBytes       = 64 << 40

	Initializing = "INITIALIZING"
	Ready        = "READY"
	Uninstalling = "UNINSTALLING"
	Uninstalled  = "UNINSTALLED"
	Purging      = "PURGING"
	Purged       = "PURGED"

	Reserved       = "RESERVED"
	Starting       = "STARTING"
	Running        = "RUNNING"
	Unknown        = "UNKNOWN"
	CleanupPending = "CLEANUP_PENDING"
	Writing        = "WRITING"
	Prepared       = "PREPARED"
	Published      = "PUBLISHED"
	Verified       = "VERIFIED"

	DesiredRunning = "RUNNING"
	DesiredStopped = "STOPPED"
	EgressClosed   = "CLOSED"
	EgressOpen     = "OPEN"
	EgressSealed   = "SEALED"

	NetworkNone   = "NONE"
	NetworkPublic = "PUBLIC_INTERNET"
)

var (
	ErrFormat           = errors.New("not a portable-v2 supervisor ledger or unsupported schema")
	ErrIdentity         = errors.New("installation or epoch identity mismatch")
	ErrInvalid          = errors.New("invalid portable-v2 ledger record")
	ErrApprovalMismatch = errors.New("APPROVAL_MISMATCH")
	ErrBudgetExceeded   = errors.New("BUDGET_EXCEEDED")
	ErrVolumeBusy       = errors.New("VOLUME_BUSY")
	ErrCleanupPending   = errors.New("CLEANUP_PENDING")
	ErrEgressRevoked    = errors.New("EGRESS_REVOKED")
	ErrState            = errors.New("invalid portable-v2 state transition")
	ErrNotFound         = errors.New("portable-v2 ledger record not found")
	ErrReferenced       = errors.New("portable-v2 generation remains referenced")
)

// InstallationIdentity is also checked against the approved installation
// manifest before any operation. Owner identifies the native UID or SID.
type InstallationIdentity struct {
	ID, Owner, Target, BundleDigest, EngineDigest string
}

type Installation struct {
	InstallationIdentity
	PlanDigest                           string
	BudgetBytes, MetadataBytes, LogBytes int64
}

type InstallationRecord struct {
	Installation
	State, Desired, ConfigRevision, ConfigDigest, EpochID, PurgeDigest string
	WorkerPending                                                      bool
}

type EpochIdentity struct {
	BootID        string
	PID           int
	StartIdentity string
}

type Epoch struct {
	EpochIdentity
	ID string
}

type NetworkProfile struct {
	Mode              string   `json:"mode"`
	AddressFamily     string   `json:"address_family"`
	PolicyDigest      string   `json:"policy_digest"`
	ExcludedAddresses []string `json:"excluded_addresses"`
	DNSServers        []string `json:"dns_servers"`
	NetTXBPS          uint64   `json:"net_tx_bps"`
	NetRXBPS          uint64   `json:"net_rx_bps"`
	AllowUnlimitedTX  bool     `json:"allow_unlimited_tx"`
	AllowUnlimitedRX  bool     `json:"allow_unlimited_rx"`
}

type Approval struct {
	ModuleID, ReviewDigest, ImageDigest, ImageGeneration, ResourceFormat, DeclarationDigest string
	UID, GID                                                                                uint32
	PersistentBytes, ScratchBytes, CPUMillicores, MemoryBytes, MaxPIDs                      int64
	Network                                                                                 NetworkProfile
}

type Configuration struct {
	Revision, ConfigDigest string
	Approvals              []Approval
}

type RunRequest struct {
	EpochID, InstanceID, ModuleID, ConfigRevision, ReviewDigest string
}

type RunKey struct {
	EpochID, ID string
}

type Run struct {
	LaunchBegun, CleanupPending                                               bool
	Key                                                                       RunKey
	InstanceID, ConfigRevision, State, Desired, EgressState, EgressGeneration string
	EngineID, InstancePath, ScratchID                                         string
	Approval                                                                  Approval
	Persistent                                                                Volume
	Image                                                                     Image
	LogBytes                                                                  int64
}

type Volume struct {
	ModuleID, ID, Path, NativeID string
	MaxBytes                     int64
	// A NativeID is provisional until Initialized. Only its originating
	// CreationRunID can remove the exact provisional backing during cleanup.
	CreationRunID string
	Initialized   bool
}

// PersistentObservation identifies the exact admitted volume or its exclusive
// birth candidate. The caller must reject links/nonregular files and hold the
// native ownership/launch guard. Identity is a native file identity, not a
// pathname, timestamp or process ID.
type PersistentObservation struct {
	Exists    bool
	NativeID  string
	SizeBytes int64
}

// RunCleanup attests that every child in the run's owned process tree has
// exited, their backing handles are closed, and all instance-owned
// temporary files (including logs, sockets and failed-creation files) are gone.
type RunCleanup struct {
	ChildrenExited, BackingClosed, TemporaryFilesAbsent bool
	// An initialized volume must remain. For an uninitialized, begun launch,
	// the caller must separately observe that the durable volume path is absent.
	PersistentBackingAbsent bool
}

// RemovalProof applies to the exact generation being retired, not just a PID
// or a successful stop or delete request.
type RemovalProof struct {
	WritersExited, FilesAbsent bool
}

type PublishProof struct {
	WritersExited, Verified, ReadOnly, Synchronized bool
}

type BackupProof struct {
	WritersExited, Verified, Synchronized bool
}

type Preparation struct {
	ID, EpochID, Path, State string
	MaxBytes                 int64
}

type Image struct {
	ID, EpochID, PreparationID, Digest, EngineDigest, Path, State string
	MaxBytes                                                      int64
}

type Backup struct {
	ID, EpochID, Path, State, PlanDigest, ConfigRevision, ConfigDigest string
	// A purge receipt must retain both the backup ID and its owning installation ID.
	InstallationIdentity `json:"installation_identity"`

	MaxBytes, SQLiteBytes    int64
	ForUpdate, UpdatePending bool
	Volumes                  []Volume
	Images                   []Image
}

// BackupVolumeBinding attests to the identity and logical content of one
// initialized volume after an owner-locked no-follow copy, hash comparison and
// synchronization. VolumeID identifies the unchanged ledger volume generation;
// SourceNativeID and NativeID identify separate source/destination backings.
type BackupVolumeBinding struct {
	VolumeID, SourceNativeID, NativeID, Digest string
	SizeBytes                                  int64
}

type Usage struct {
	BudgetBytes, MetadataBytes, PersistentBytes, ScratchBytes int64
	PreparationBytes, CacheBytes, LogBytes, BackupBytes       int64
}

func (u Usage) Total() int64 {
	return u.MetadataBytes + u.PersistentBytes + u.ScratchBytes + u.PreparationBytes + u.CacheBytes + u.LogBytes + u.BackupBytes
}

type PurgePlan struct {
	InstallationIdentity `json:"installation_identity"`

	Digest  string
	Volumes []Volume
	Images  []Image
	Backups []Backup
}

func validToken(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i != 0 && (c == '-' || c == '_' || c == '.') {
			continue
		}
		return false
	}
	return true
}

func validOpaque(s string) bool {
	if len(s) == 0 || len(s) > 512 {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && lowerHex(s[len("sha256:"):], hex.EncodedLen(32))
}

func validVolumeSize(n int64) bool {
	return n >= MinVolumeBytes && n <= MaxVolumeBytes && n%VolumeAlignmentBytes == 0
}

func (i InstallationIdentity) valid() bool {
	return validToken(i.ID) && validOpaque(i.Owner) && validOpaque(i.Target) && validDigest(i.BundleDigest) && validDigest(i.EngineDigest)
}

func (a Approval) validate() error {
	if !validToken(a.ModuleID) || !validDigest(a.ReviewDigest) || !validDigest(a.ImageDigest) || !lowerHex(a.ImageGeneration, 32) || !validDigest(a.DeclarationDigest) || a.ResourceFormat != VolumeResourceFormat || a.UID == 0 || a.GID == 0 || !validVolumeSize(a.PersistentBytes) || !validVolumeSize(a.ScratchBytes) || a.CPUMillicores <= 0 || a.MemoryBytes < 6<<20 || a.MaxPIDs <= 0 {
		return fmt.Errorf("%w: module approval", ErrInvalid)
	}
	p := a.Network
	switch p.Mode {
	case NetworkNone:
		if p.AddressFamily == "" && (p.PolicyDigest == "" || validDigest(p.PolicyDigest)) && len(p.ExcludedAddresses) == 0 && len(p.DNSServers) == 0 && p.NetTXBPS == 0 && p.NetRXBPS == 0 && !p.AllowUnlimitedTX && !p.AllowUnlimitedRX {
			return nil
		}
	case NetworkPublic:
		if (p.AddressFamily != "ipv4" && p.AddressFamily != "dual-stack") || !validDigest(p.PolicyDigest) || len(p.DNSServers) == 0 || len(p.DNSServers) > 64 || len(p.ExcludedAddresses) > 4096 || (p.NetTXBPS == 0) != p.AllowUnlimitedTX || (p.NetRXBPS == 0) != p.AllowUnlimitedRX {
			break
		}
		for _, dns := range p.DNSServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil || addr.Zone() != "" || p.AddressFamily == "ipv4" && !addr.Unmap().Is4() {
				return fmt.Errorf("%w: DNS address in module approval", ErrInvalid)
			}
		}
		for _, excluded := range p.ExcludedAddresses {
			if addr, err := netip.ParseAddr(excluded); err == nil && addr.Zone() == "" {
				continue
			}
			if _, err := netip.ParsePrefix(excluded); err != nil {
				return fmt.Errorf("%w: excluded address in module approval", ErrInvalid)
			}
		}
		return nil
	}
	return fmt.Errorf("%w: network profile in module approval", ErrInvalid)
}

func (p RemovalProof) complete() bool { return p.WritersExited && p.FilesAbsent }
