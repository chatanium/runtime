// Package engine renders and verifies the portable GVX contract for
// v0.22.10002026111600 (a90476e02630e7d35861e1da16d407e03e71e8b7).
// It neither launches nor adopts host processes and never uses guest stdio.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	DataMountpoint    = "/var/lib/flexmodule/data"
	ScratchMountpoint = "/var/lib/flexmodule/scratch"
	// GVX mounts shallowest paths first. Install the verified single file
	// after data and scratch so no image-path alias can later shadow it.
	BridgeMountpoint    = "/run/chatanium-bootstrap/portable/verified/guest-bridge"
	PreparationCompiler = "/chatanium-compiler"
	PreparationWork     = "/chatanium-work"
	EphemeralVolumeDir  = "ephemeral-volumes"
	minMemoryBytes      = 6 << 20
	volumeGroupBytes    = 16 << 20
	maxVolumeBytes      = 64 << 40
	minCPUMillicores    = 10 // 1 ms of quota per 100 ms; smaller values silently round up in GVX.
	maxPIDs             = 4 * 1024 * 1024
	bridgeArg           = "--stdio-portable-v2"
	executionRefPrefix  = "chatanium.invalid/module-cache@sha256:"
)

var (
	ErrUnsupportedTarget = errors.New("UNSUPPORTED_TARGET")
	ErrCapabilityMissing = errors.New("ENGINE_CAPABILITY_MISSING")
	ErrApprovalMismatch  = errors.New("APPROVAL_MISMATCH")
	ErrEgressRevoked     = errors.New("EGRESS_REVOKED")
	ErrControlLost       = errors.New("GVX control connection lost")
	ErrPeerExited        = errors.New("GVX peer exited")
	ErrPeerClosing       = errors.New("GVX reported orderly sandbox shutdown; peer exit not yet observed")
	ErrExitUnconfirmed   = errors.New("GVX peer exit unconfirmed")
)

// Target is the native target tuple. HostCPUs is the count visible to rungv
// (GVX validates and sizes the guest against its own runtime.NumCPU()).
type Target struct {
	OS, Arch string
	HostCPUs int
}

type ResourceLimits struct {
	CPUMillicores, MemoryBytes, MaxPIDs int64
}

// InstanceIdentity binds a plan and its later authorization to one live
// instance. The caller must allocate a fresh instance ID and check the grant
// against the installation's current approval before calling SetEgress.
type InstanceIdentity struct {
	InstallationID, EpochID, InstanceID, ReviewDigest string
}

type ApprovedGrant struct {
	Identity InstanceIdentity
	Limits   ResourceLimits
	Network  NetworkGrant
	Launch   LaunchSpec
}

// LaunchSpec is trusted supervisor input, never image-supplied configuration.
// HelperPath must be the verified standalone bridge. ClearImageEnvironment
// must include every image Env key; Environment may supply trusted replacements.
// ImageRef must be the prepared cache execution reference; the caller must use
// an owned working directory where it cannot resolve as a local image archive.
// CacheDir is an owned cache view with read-only prepared image objects and a
// writable ephemeral-volumes directory reserved in the run's budget.
// The bridge, not rungv flags, owns the approved /dev/shm and scratch aliases.
type LaunchSpec struct {
	CacheDir, ImageRef, HelperPath                 string
	HelperArgs, Environment, ClearImageEnvironment []string
	Endpoint                                       Endpoint
	DenyPolicyPath                                 string
}

// VolumeLease describes resources already reserved and protected by the caller.
// A permanent image stays leased through verified engine exit. Scratch remains
// leased through exit and backing-file cleanup, not just RPC acknowledgement.
type VolumeLease struct {
	PersistentPath                string
	PersistentBytes, ScratchBytes int64
}

// PreparationSpec selects two verified native-target Linux helpers and an
// owned disposable cache directory. Send untrusted input only after Connect
// succeeds. The preparer must not run module code.
type PreparationSpec struct {
	CacheDir, HelperPath, CompilerPath string
	ScratchBytes                       int64
	Identity                           InstanceIdentity
	Endpoint                           Endpoint
}

// Endpoint denotes the GVX host-side AF_UNIX path, never a module endpoint.
// Callers must create a fresh per-instance owner-only directory (0700 on
// Unix; protected owner-only ACL on Windows), with trusted ancestors, outside
// every guest mount. Never reuse it or expose it in guest env/stdin. SocketPath
// and TokenPath must be siblings. The verified GVX process creates the socket
// and, if specified, a 32-byte random token encoded as 64 lowercase hex digits
// in TokenPath; Windows requires TokenPath. Keep both paths until peer exit.
// The client checks endpoint ownership and peer UID on Unix, and directory and
// token ACL plus HELLO token authentication on Windows. No TCP fallback.
type Endpoint struct {
	SocketPath, TokenPath string
}

type RunPlan struct {
	args      []string
	target    Target
	backend   string
	identity  InstanceIdentity
	sandboxID string
	endpoint  Endpoint
	limits    ResourceLimits
	network   plannedNetwork
	mounts    []expectedMount
}

type expectedMount struct {
	target, kind, source string
	readOnly             bool
}

// Args returns the immutable plan's argv excluding the caller-verified rungv
// executable. Launch directly, with a trusted working directory and a clean
// host environment; do not add flags or use a shell.
func (p RunPlan) Args() []string    { return append([]string(nil), p.args...) }
func (p RunPlan) SandboxID() string { return p.sandboxID }

// DenyPolicyJSON returns bytes to publish, without symlinks or replacement, at
// the approved DenyPolicyPath before launch. It is nil for network NONE.
func (p RunPlan) DenyPolicyJSON() []byte {
	if p.network.mode == NetworkPublicInternet {
		return []byte(denyPolicyJSON)
	}
	return nil
}

// EgressPolicyDigest is the SHA-256 of the canonical complete approved NAT
// policy, or empty for NONE. Include it and the approved QoS in the review.
func (p RunPlan) EgressPolicyDigest() string { return p.network.digest }

// PlanRun builds startup arguments; PUBLIC_INTERNET is always deny-first.
func PlanRun(target Target, grant ApprovedGrant, volumes VolumeLease) (RunPlan, error) {
	l := grant.Launch
	p, err := basePlan(target, grant.Identity, grant.Limits, l.CacheDir, l.Endpoint)
	if err != nil {
		return RunPlan{}, err
	}
	if !validHostPath(target, volumes.PersistentPath) || !strings.HasSuffix(volumes.PersistentPath, ".ext4") ||
		strings.Contains(volumes.PersistentPath, ",") {
		return RunPlan{}, errors.New("persistent lease requires a clean absolute .ext4 path representable by GVX")
	}
	if err := validateVolumeSize(volumes.PersistentBytes); err != nil {
		return RunPlan{}, fmt.Errorf("persistent lease: %w", err)
	}
	if err := validateVolumeSize(volumes.ScratchBytes); err != nil {
		return RunPlan{}, fmt.Errorf("scratch lease: %w", err)
	}
	if !validHostPath(target, l.HelperPath) || strings.Contains(l.HelperPath, ",") || !validCacheRef(l.ImageRef) {
		return RunPlan{}, errors.New("module launch requires a verified host bridge and a prepared cache execution reference")
	}
	if p.network, err = planNetwork(grant.Network); err != nil {
		return RunPlan{}, err
	}
	if p.network.mode == NetworkPublicInternet {
		if !validHostPath(target, l.DenyPolicyPath) || !strings.HasSuffix(l.DenyPolicyPath, ".json") ||
			sameHostPath(target, l.DenyPolicyPath, p.endpoint.TokenPath) || sameHostPath(target, l.DenyPolicyPath, p.endpoint.SocketPath) {
			return RunPlan{}, errors.New("NAT requires an owned deny JSON path distinct from control credentials")
		}
		p.args = append(p.args, "--net=nat", "--isolate-lan=true", "--nat-policy-file="+l.DenyPolicyPath,
			"--net-tx-bps="+strconv.FormatUint(p.network.tx, 10), "--net-rx-bps="+strconv.FormatUint(p.network.rx, 10),
			"--control-disable="+controlDisable)
		for _, server := range p.network.dns {
			p.args = append(p.args, "--host-dns="+server.String())
		}
	} else {
		if l.DenyPolicyPath != "" {
			return RunPlan{}, errors.New("NONE cannot carry a NAT policy file")
		}
		p.useNoNetwork()
	}
	p.addMount("type=volume,src="+volumes.PersistentPath+",dst="+DataMountpoint+",driver=ext4lite,size="+volumeSize(volumes.PersistentBytes),
		expectedMount{target: DataMountpoint, kind: "ext4lite", source: volumes.PersistentPath})
	p.addScratch(ScratchMountpoint, volumes.ScratchBytes)
	p.addMount("type=bind,src="+l.HelperPath+",dst="+BridgeMountpoint+",readonly",
		expectedMount{target: BridgeMountpoint, kind: "hostfs", source: l.HelperPath, readOnly: true})
	if err := p.addEnvironment(l.ClearImageEnvironment, l.Environment); err != nil {
		return RunPlan{}, err
	}
	if len(l.HelperArgs) != 0 && (len(l.HelperArgs) != 1 || l.HelperArgs[0] != bridgeArg) {
		return RunPlan{}, errors.New("only the portable-v2 bridge argument is supported")
	}
	p.args = append(p.args, "--entrypoint="+BridgeMountpoint, "--image="+l.ImageRef, "--", bridgeArg)
	return p, nil
}

// PlanPreparation builds a networkless raw ELF boot with one disposable volume.
func PlanPreparation(target Target, limits ResourceLimits, spec PreparationSpec) (RunPlan, error) {
	p, err := basePlan(target, spec.Identity, limits, spec.CacheDir, spec.Endpoint)
	if err != nil {
		return RunPlan{}, err
	}
	if !validHostPath(target, spec.HelperPath) || !validHostPath(target, spec.CompilerPath) || strings.Contains(spec.CompilerPath, ",") {
		return RunPlan{}, errors.New("preparation requires verified helper and compiler paths")
	}
	if err := validateVolumeSize(spec.ScratchBytes); err != nil {
		return RunPlan{}, fmt.Errorf("preparation scratch: %w", err)
	}
	p.useNoNetwork()
	p.addMount("type=bind,src="+spec.CompilerPath+",dst="+PreparationCompiler+",readonly",
		expectedMount{target: PreparationCompiler, kind: "hostfs", source: spec.CompilerPath, readOnly: true})
	p.addScratch(PreparationWork, spec.ScratchBytes)
	p.args = append(p.args, "--bin="+spec.HelperPath, "--", "portable-v2")
	return p, nil
}

// Only the operations in GVXAdapter's contract survive this disable list. GVX
// disables groups by prefix, so mount.list and lifecycle.stop stay explicit.
const controlDisable = "system.ping,sandbox.stats,sandbox.events,lifecycle.pause,checkpoint,exec,fs,port,net.dial,net.unix_forward,mount.tmpfs,mount.remount,mount.remove,mount.volume_attach,mount.bind_attach,mount.bind,mount.serve,proc,kernel,debug,resource.tuning"

func basePlan(t Target, id InstanceIdentity, limits ResourceLimits, cache string, endpoint Endpoint) (RunPlan, error) {
	var backend string
	switch {
	case t.OS == "linux" && (t.Arch == "amd64" || t.Arch == "arm64"):
		backend = "systrap"
	case t.OS == "darwin" && t.Arch == "arm64":
		backend = "hvf"
	case t.OS == "windows" && (t.Arch == "amd64" || t.Arch == "arm64"):
		backend = "whpx"
	default:
		return RunPlan{}, fmt.Errorf("%w: %s/%s", ErrUnsupportedTarget, t.OS, t.Arch)
	}
	if err := ValidateResourceLimits(t, limits); err != nil {
		return RunPlan{}, err
	}
	for _, field := range []string{id.InstallationID, id.EpochID, id.InstanceID, id.ReviewDigest} {
		if field == "" || strings.ContainsRune(field, 0) {
			return RunPlan{}, fmt.Errorf("%w: incomplete run identity", ErrApprovalMismatch)
		}
	}
	if !validHostPath(t, cache) || !validHostPath(t, endpoint.SocketPath) || len(endpoint.SocketPath) > 100 ||
		(t.OS == "windows" && endpoint.TokenPath == "") ||
		(endpoint.TokenPath != "" && (!validHostPath(t, endpoint.TokenPath) || sameHostPath(t, endpoint.TokenPath, endpoint.SocketPath) ||
			!sameHostPath(t, hostDir(t, endpoint.TokenPath), hostDir(t, endpoint.SocketPath)))) {
		return RunPlan{}, errors.New("GVX requires short absolute AF_UNIX socket and separate sibling token paths")
	}
	sum := sha256.Sum256([]byte(id.InstallationID + "\x00" + id.EpochID + "\x00" + id.InstanceID + "\x00" + id.ReviewDigest))
	name := "ct-" + hex.EncodeToString(sum[:])
	args := []string{
		"run", "--backend=" + backend, "--platform=linux/" + t.Arch, "--name=" + name,
		"--lockdown=true", "--privileged=false", "--net-raw=false", "--allow-packet-socket-write=false", "--allow-suid=false",
		"--allow-unconfined-systrap=false", "--allow-volume-attach=false", "--allow-bind-attach=false",
		"--read-only=true", "--user=0:0", "--workdir=/", "--host-ca-certs=false", "--keep-blobs=false",
		"-P=false", "--auto-publish=false", "--dynamic-ports=false", "--pull=never", "--registry-url=https://chatanium.invalid",
		"--cache-dir=" + cache, "--control-socket=unix:" + endpoint.SocketPath, "--control-policy=default",
		"--cpus=" + cpuDecimal(limits.CPUMillicores), "--memory=" + strconv.FormatInt(limits.MemoryBytes, 10),
		"--pids-limit=" + strconv.FormatInt(limits.MaxPIDs, 10),
	}
	if endpoint.TokenPath != "" {
		args = append(args, "--control-token-file="+endpoint.TokenPath)
	}
	return RunPlan{args: args, target: t, backend: backend, identity: id, sandboxID: name, endpoint: endpoint, limits: limits,
		mounts: []expectedMount{{target: "/", source: "rootfs", readOnly: true}}}, nil
}

func (p *RunPlan) useNoNetwork() {
	p.network.mode = NetworkNone
	p.args = append(p.args, "--net=none", "--control-disable="+controlDisable+",net.policy,resource.network")
}

func (p *RunPlan) addScratch(dst string, size int64) {
	p.addMount("type=volume,dst="+dst+",driver=ext4lite,size="+volumeSize(size)+",ephemeral",
		expectedMount{target: dst, kind: "ext4lite", source: "volume"})
}

func (p *RunPlan) addMount(spec string, expected expectedMount) {
	p.args = append(p.args, "--mount="+spec)
	p.mounts = append(p.mounts, expected)
}

func (p *RunPlan) addEnvironment(clear, trusted []string) error {
	seen := make(map[string]bool, len(clear)+len(trusted))
	for _, entry := range trusted {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || seen[key] || strings.ContainsRune(entry, 0) || strings.TrimSpace(key) != key {
			return errors.New("trusted guest environment must contain unique explicit KEY=VALUE entries")
		}
		seen[key] = true
		p.args = append(p.args, "--env="+entry)
	}
	for _, key := range clear {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.TrimSpace(key) != key {
			return errors.New("invalid image environment key")
		}
		if !seen[key] {
			p.args = append(p.args, "--env="+key+"=")
			seen[key] = true
		}
	}
	return nil
}

func validHostPath(target Target, p string) bool {
	if p == "" || strings.TrimSpace(p) != p || strings.ContainsAny(p, "\r\n\x00") {
		return false
	}
	if target.OS != "windows" {
		return p != "/" && path.IsAbs(p) && path.Clean(p) == p
	}
	// Accept only canonical drive-local paths, not UNC, device, drive-relative
	// names, alternate data streams, or Win32 trailing-dot/space aliases.
	if len(p) < 4 || !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", rune(p[0])) ||
		p[1:3] != `:\` || strings.ContainsAny(p[3:], `:/"<>|?*`) {
		return false
	}
	for _, part := range strings.Split(p[3:], `\`) {
		if part == "" || strings.TrimRight(part, ". ") != part {
			return false
		}
	}
	return true
}

func sameHostPath(target Target, a, b string) bool {
	if target.OS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func hostDir(target Target, p string) string {
	if target.OS == "windows" {
		return p[:strings.LastIndexByte(p, '\\')]
	}
	return path.Dir(p)
}

func validCacheRef(ref string) bool {
	digest, ok := strings.CutPrefix(ref, executionRefPrefix)
	if !ok || len(digest) != 64 {
		return false
	}
	var decoded [32]byte
	_, err := hex.Decode(decoded[:], []byte(digest))
	return err == nil && strings.ToLower(digest) == digest
}

// ValidateResourceLimits checks the pinned CLI and guest kernel bounds before
// a caller asks for approval or creates a volume.
func ValidateResourceLimits(target Target, r ResourceLimits) error {
	if target.HostCPUs < 1 || int64(target.HostCPUs) > math.MaxInt64/int64(time.Second) ||
		r.CPUMillicores < minCPUMillicores || r.CPUMillicores > int64(target.HostCPUs)*1000 {
		return fmt.Errorf("GVX CPU quota must be between %d millicores and available host CPU capacity", minCPUMillicores)
	}
	if r.MemoryBytes < minMemoryBytes || float64(r.MemoryBytes) >= float64(math.MaxInt64) || int64(float64(r.MemoryBytes)) != r.MemoryBytes {
		return errors.New("GVX memory must be at least 6 MiB and exactly representable by its size parser")
	}
	if r.MaxPIDs < 1 || r.MaxPIDs > maxPIDs {
		return fmt.Errorf("GVX PID limit must be in [1, %d]", maxPIDs)
	}
	return nil
}

func cpuDecimal(millis int64) string {
	return fmt.Sprintf("%d.%03d", millis/1000, millis%1000)
}

func validateVolumeSize(size int64) error {
	if size < volumeGroupBytes || size > maxVolumeBytes || size%volumeGroupBytes != 0 {
		return errors.New("ext4lite image size must be 16 MiB–64 TiB in 16 MiB increments")
	}
	return nil
}

func volumeSize(size int64) string { return strconv.FormatInt(size>>20, 10) + "m" }
