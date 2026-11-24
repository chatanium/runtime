// The release probe runs only as an unprivileged Linux guest module.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-plugin"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed manifest.json
var manifest []byte

const (
	publicEndpoint = "1.1.1.1:443"
	volumeBytes    = 16 << 20
)

type module struct {
	run    atomic.Pointer[volumeRun]
	config core.CoreClient
}

type volumeRun struct {
	persistent, scratch string
	checkCaps           bool
}

func dial(ctx context.Context, address string, allowed bool) error {
	timeout := time.Second
	if allowed {
		timeout = 2 * time.Second
	}
	c, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp4", address)
	if c != nil {
		_ = c.Close()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if allowed && err == nil {
		return nil
	}
	if !allowed && err != nil && (errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded)) {
		return nil
	}
	return fmt.Errorf("fixture TCP policy inconclusive for %s (expected allowed=%t): %v", address, allowed, err)
}

func (m *module) GetManifest(ctx context.Context) (*wire.ModuleManifest, error) {
	// GetManifest precedes the worker's approval and must see egress closed,
	// including the PUBLIC_INTERNET instance that opens egress in INIT below.
	if err := dial(ctx, publicEndpoint, false); err != nil {
		return nil, err
	}
	var declared wire.ModuleManifest
	return &declared, protojson.Unmarshal(manifest, &declared)
}

func (m *module) GetStatus(context.Context) (*wire.Status, error) {
	r := wire.Readiness_READINESS_NOT_READY
	if m.run.Load() != nil {
		r = wire.Readiness_READINESS_READY
	}
	return &wire.Status{Readiness: r}, nil
}

func (*module) OnEvent(context.Context, *wire.EventEnvelope) error { return nil }

func (m *module) OnStage(ctx context.Context, req *wire.StageRequest) error {
	if req.GetStage() == wire.Stage_STAGE_START {
		run := m.run.Load()
		if run == nil {
			return errors.New("release probe did not complete INIT")
		}
		if run.checkCaps {
			return checkVolumeCaps(ctx, run.persistent, run.scratch)
		}
	}
	if req.GetStage() != wire.Stage_STAGE_INIT {
		return ctx.Err()
	}
	i := req.GetInitContext()
	g := i.GetGrants()
	limits := g.GetResourceLimits()
	if g == nil || len(g.Backends) != 0 || limits.GetPersistentBytes() != volumeBytes || limits.GetScratchBytes() != volumeBytes ||
		limits.GetCpuMillicores() != 500 || limits.GetMemoryBytes() != 256<<20 || limits.GetMaxPids() != 128 ||
		os.Getuid() != 1000 || os.Getgid() != 1000 {
		return errors.New("release probe lacks the approved bounded nonroot INIT context")
	}
	value, err := m.config.GetConfig(ctx)
	if err != nil {
		return err
	}
	var cfg struct {
		ExpectPersistent bool   `json:"expect_persistent"`
		PrivateEndpoint  string `json:"private_endpoint"`
	}
	if err = json.Unmarshal(value.GetJson(), &cfg); err != nil {
		return err
	}
	want := wire.EgressPolicy_EGRESS_POLICY_NONE
	if cfg.ExpectPersistent {
		want = wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET
	}
	if g.GetEgressPolicy() != want {
		return errors.New("release probe received a different network grant")
	}
	host, _, err := net.SplitHostPort(cfg.PrivateEndpoint)
	if err != nil || !net.ParseIP(host).IsPrivate() {
		return errors.New("release probe requires an actual private host listener")
	}
	if err = dial(ctx, publicEndpoint, cfg.ExpectPersistent); err != nil {
		return err
	}
	if err = dial(ctx, cfg.PrivateEndpoint, false); err != nil {
		return err
	}
	run := &volumeRun{i.GetPersistentDirectory(), i.GetScratchDirectory(), cfg.ExpectPersistent}
	if err = checkVolumeGeneration(run.persistent, run.scratch, run.checkCaps); err != nil {
		return err
	}
	m.run.Store(run)
	return nil
}

func checkVolumeGeneration(persistent, scratch string, expectPersistent bool) error {
	var rootFS unix.Statfs_t
	var temp, work, data unix.Stat_t
	if unix.Statfs("/", &rootFS) != nil || rootFS.Flags&unix.ST_RDONLY == 0 ||
		unix.Stat("/tmp", &temp) != nil || unix.Stat(scratch, &work) != nil || unix.Stat(persistent, &data) != nil ||
		temp.Dev != work.Dev || temp.Ino == work.Ino || data.Dev == work.Dev {
		return errors.New("release probe expected readonly root, a shared tmp/scratch volume with distinct paths, and separate persistent volume")
	}
	byteMark := []byte("portable-volume-probe\n")
	seed := filepath.Join(persistent, "portable-release-seed")
	got, err := os.ReadFile(seed)
	if expectPersistent && (err != nil || !bytes.Equal(got, byteMark)) || !expectPersistent && !errors.Is(err, os.ErrNotExist) {
		return errors.New("persistent seed did not match launch generation")
	}
	for _, path := range []string{scratch, "/tmp"} {
		mark := filepath.Join(path, "portable-release-per-run")
		if _, err := os.Lstat(mark); !errors.Is(err, os.ErrNotExist) {
			return errors.New("scratch data survived the prior run")
		}
		if err := os.WriteFile(mark, byteMark, 0600); err != nil {
			return err
		}
	}
	return os.WriteFile(seed, byteMark, 0600)
}

func checkVolumeCaps(ctx context.Context, persistent, scratch string) error {
	// Individually both writes fit. Together they cannot fit one 16 MiB
	// image; verify the actual write/sync error rather than infer from sizes.
	block := make([]byte, 1<<20)
	if err := denseWrite(ctx, filepath.Join(scratch, "portable-release-allocation"), 9, block); err != nil {
		return fmt.Errorf("first scratch allocation: %w", err)
	}
	if err := denseWrite(ctx, "/tmp/portable-release-allocation", 9, block); !errors.Is(err, unix.ENOSPC) {
		return fmt.Errorf("tmp allocation did not hit the shared ceiling: %v", err)
	}
	if err := os.WriteFile(filepath.Join(persistent, "portable-release-seed"), []byte("portable-volume-probe\n"), 0600); err != nil {
		return fmt.Errorf("full scratch affected separate persistent volume: %w", err)
	}
	if err := denseWrite(ctx, filepath.Join(persistent, "portable-release-allocation"), 17, block); !errors.Is(err, unix.ENOSPC) {
		return fmt.Errorf("persistent allocation did not hit its image ceiling: %v", err)
	}
	return os.Remove(filepath.Join(persistent, "portable-release-allocation"))
}

func denseWrite(ctx context.Context, path string, blocks int, block []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	for n := 0; n < blocks && err == nil; n++ {
		if err = ctx.Err(); err == nil {
			_, err = f.Write(block)
		}
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func main() {
	ctx := context.Background()
	m := new(module)
	p, err := core.NewModulePlugin(ctx, m, func(_ context.Context, conn grpc.ClientConnInterface) error {
		var err error
		m.config, err = core.NewCoreClient(conn, core.JSONLimits{MaxBytes: 8 << 10, MaxDepth: 4})
		return err
	}, core.TransportLimits{MaxReceiveBytes: 4 << 20, MaxSendBytes: 4 << 20})
	if err != nil {
		panic(err)
	}
	defer p.Close()
	plugin.Serve(p.ServeConfig())
}
