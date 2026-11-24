// Package images isolates external OCI preparation and only publishes the
// pinned GVX cache representation after its preparation process has exited.
package images

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/provision"
)

const (
	RegistryURL      = provision.RegistryOverride
	ResourceLabel    = provision.PortableResourceLabel
	ResourceVersion  = provision.PortableResourceVersion
	ManifestLabel    = provision.ImageManifestLabel
	metadataReserve  = 32 << 20
	maxProgramBytes  = 128 << 20
	bootstrapReserve = maxProgramBytes + (16 << 20)
)

type Limits = provision.PrepareLimits

// Source binds either a concrete approved repository + digest, or the digest
// of the complete offline tar stream. Optional network authorities are also
// committed to the plan; nothing in an OCI object can add an authority.
type Source struct {
	Kind          string   `json:"kind"`
	Reference     string   `json:"reference,omitempty"`
	Digest        string   `json:"digest"`
	TokenURL      string   `json:"token_url,omitempty"`
	TokenService  string   `json:"token_service,omitempty"`
	RedirectHosts []string `json:"redirect_hosts,omitempty"`
}

type Plan struct {
	Source         Source `json:"source"`
	Architecture   string `json:"architecture"`
	EngineDigest   string `json:"engine_digest"`
	CompilerDigest string `json:"compiler_digest"`
	PreparerDigest string `json:"preparer_digest"`
	Limits         Limits `json:"limits"`
}

func (p Plan) Digest() (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return provision.DomainDigest("chatanium-portable-image-plan-v2", b), nil
}

func (p Plan) validate() error {
	if p.Architecture != "amd64" && p.Architecture != "arm64" {
		return errors.New("unsupported preparation architecture")
	}
	for _, d := range []string{p.Source.Digest, p.EngineDigest, p.CompilerDigest, p.PreparerDigest} {
		if !provision.ValidDigest(d) {
			return errors.New("portable preparation requires pinned sha256 source and program digests")
		}
	}
	if err := p.Limits.Validate(); err != nil {
		return err
	}
	l := p.Limits
	if l.NanoCPUs%1_000_000 != 0 || l.Tasks < 2 || l.JSONBytes > 1<<20 || l.Deadline > time.Hour || l.InputBytes > 1<<40 || l.OutputBytes > 1<<40 || l.ExpandedBytes > 1<<40 {
		return errors.New("preparation bounds cannot be represented by the pinned portable runtime")
	}
	if err := engine.ValidateResourceLimits(engine.Target{OS: runtime.GOOS, Arch: p.Architecture, HostCPUs: runtime.NumCPU()}, engine.ResourceLimits{CPUMillicores: l.NanoCPUs / 1_000_000, MemoryBytes: l.MemoryBytes, MaxPIDs: l.Tasks}); err != nil {
		return err
	}
	switch p.Source.Kind {
	case "registry":
		_, err := parseRepository(p.Source)
		return err
	case "oci-archive", "docker-archive":
		if p.Source.Reference != "" || p.Source.TokenURL != "" || p.Source.TokenService != "" || len(p.Source.RedirectHosts) != 0 {
			return errors.New("offline source cannot include registry settings")
		}
		return nil
	default:
		return errors.New("unknown portable image source kind")
	}
}

func (p Plan) scratchBytes() int64 {
	const group = 16 << 20
	// Guest source objects + canonical archive + compiler staging and EROFS,
	// all contained in a single size-capped ephemeral ext4lite volume.
	n := p.Limits.InputBytes*2 + p.Limits.OutputBytes*2 + metadataReserve
	return (n + group - 1) / group * group
}

func (p Plan) DiskBounds() (preparationBytes, cacheBytes int64, err error) {
	if err = p.validate(); err != nil {
		return 0, 0, err
	}
	// One bounded, reusable host staging file for registry responses, plus
	// private stock GVX bootstrap cache and ext4lite scratch image.
	var staged int64
	if p.Source.Kind == "registry" {
		staged = p.Limits.InputBytes
	}
	return p.scratchBytes() + staged + bootstrapReserve, p.Limits.OutputBytes + metadataReserve, nil
}

func (p Plan) Budget() (int64, error) {
	work, cache, err := p.DiskBounds()
	return work + cache, err
}

// PreparationLaunch contains the only inputs the trusted host starter should
// use. Start must attest the no-network sandbox, approved resource bounds,
// readonly compiler bind and scratch mount before handing back its process.
type PreparationLaunch struct {
	Engine, GuestPreparer, GuestCompiler, Supervisor       string
	Directory, CacheDir                                    string
	Architecture, InstallationID, Epoch, JobID, PlanDigest string
	Limits                                                 Limits
	ScratchBytes                                           int64
	Stdin, Stdout, Stderr                                  *os.File
}

// PreparationProcess is an owned engine. Stop returning nil proves that no
// descendant or writer retains the preparation resources. Wait returning nil
// proves successful exit and that all descendants and writers are gone.
type PreparationProcess interface {
	Wait() error
	Stop(context.Context, func(context.Context) error) error
}

type Preparer struct {
	Root                                               *os.Root
	InstallationID, Epoch, GenerationID, PreparationID string
	Supervisor, Engine, GuestPreparer, GuestCompiler   string
	Start                                              func(context.Context, PreparationLaunch) (PreparationProcess, error)
}

func addressedID(id string) bool {
	if len(id) != 32 || id != strings.ToLower(id) {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func checkedPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, ",\x00\r\n")
}

func (p Preparer) validate(plan Plan) error {
	if p.Root == nil || !checkedPath(p.Root.Name()) || p.Start == nil || p.InstallationID == "" || len(p.InstallationID) > 128 || strings.ContainsAny(p.InstallationID, "\x00\r\n") || !addressedID(p.Epoch) || !addressedID(p.GenerationID) || !addressedID(p.PreparationID) {
		return errors.New("portable preparation requires rooted installation-owned reservations")
	}
	if !checkedPath(p.Supervisor) || !checkedPath(p.Engine) || !checkedPath(p.GuestPreparer) || !checkedPath(p.GuestCompiler) {
		return errors.New("invalid verified portable program location")
	}
	if plan.Architecture != runtime.GOARCH || runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" || runtime.GOOS == "darwin" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("unsupported portable preparation target %s/%s for guest %s", runtime.GOOS, runtime.GOARCH, plan.Architecture)
	}
	return nil
}

// The pinned hostarch implementation uses 4 KiB on amd64 and Darwin arm64,
// emulates 4 KiB on 16 KiB Linux arm64 and otherwise accepts 64 KiB on arm64.
// The guest preparer checks its actual auxv page size against this choice.
// https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/hostarch/hostarch_arm64_xplat.go
func cacheFormat() string {
	if runtime.GOARCH == "arm64" && runtime.GOOS != "darwin" && os.Getpagesize() == 65536 {
		return "gvx-erofs-v3-b65536"
	}
	return provision.PortableCompilerFormat
}
