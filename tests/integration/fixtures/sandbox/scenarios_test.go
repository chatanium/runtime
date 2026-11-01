package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

func TestFixtureRejectsUnboundedWork(t *testing.T) {
	for _, c := range []probeConfig{
		{Lifecycle: &lifecycleConfig{InitDelayMS: -1}},
		{Lifecycle: &lifecycleConfig{ReadinessDelayMS: 60001}},
		{Lifecycle: &lifecycleConfig{FailStage: "unknown"}},
		{Scenario: &scenarioConfig{Kind: "cpu", TimeoutSeconds: 121, Workers: 1}},
		{Scenario: &scenarioConfig{Kind: "cpu", TimeoutSeconds: 1, Workers: 129}},
		{Scenario: &scenarioConfig{Kind: "memory", TimeoutSeconds: 1, MemoryBytes: 2<<30 + 1}},
		{Scenario: &scenarioConfig{Kind: "fork", TimeoutSeconds: 1, Attempts: 257, HoldMS: 1}},
		{Scenario: &scenarioConfig{Kind: "thread", TimeoutSeconds: 1, Attempts: 1}},
		{Scenario: &scenarioConfig{Kind: "flood", TimeoutSeconds: 1, StdoutBytes: 64<<20 + 1}},
		{Scenario: &scenarioConfig{Kind: "quota", TimeoutSeconds: 1, Quota: &quotaConfig{Operation: "bytes", Target: "scratch", TargetBytes: 1}}},
		{Scenario: &scenarioConfig{Kind: "quota", TimeoutSeconds: 1, Quota: &quotaConfig{Operation: "inodes", Target: "ipc", TargetFiles: 65537}}},
		{Scenario: &scenarioConfig{Kind: "quota", TimeoutSeconds: 1, Quota: &quotaConfig{Operation: "held-file", Target: "persistent", TargetBytes: 1, ChunkBytes: 4096}}},
	} {
		if err := validateControls(c); err == nil {
			t.Fatalf("unbounded or ambiguous workload accepted: %+v", c)
		}
	}
}

func TestLifecycleDelayHonorsIncomingCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lifecycleStep(ctx, nil, "init", 60000, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled INIT did not return cancellation: %v", err)
	}
	m := &module{ready: wire.Readiness_READINESS_READY, readyAt: time.Now().Add(time.Minute), config: probeConfig{Lifecycle: &lifecycleConfig{ReadinessDelayMS: 60000}}}
	if _, err := m.GetStatus(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled readiness did not return cancellation: %v", err)
	}
	if m.readyAt.IsZero() {
		t.Fatal("cancelled readiness incorrectly completed the delay")
	}
	if err := lifecycleStep(context.Background(), nil, "start", 0, "start"); err == nil {
		t.Fatal("deliberate START failure returned success")
	}
}

func TestQuotaAllocationIsBoundedAndCleansOnlyOwnedFiles(t *testing.T) {
	persistent, scratch := t.TempDir(), t.TempDir()
	foreign := filepath.Join(scratch, "not-owned-by-fixture")
	if err := os.WriteFile(foreign, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := newProbeSession(persistent, scratch)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	q := &quotaConfig{Operation: "bytes", Target: "scratch", TargetBytes: 8193, ChunkBytes: 4096, RetainFiles: true}
	if err := quotaProbe(context.Background(), q, p); err != nil {
		t.Fatal(err)
	}
	owned, err := filepath.Glob(filepath.Join(scratch, "probe-quota-*", "allocation"))
	if err != nil || len(owned) != 1 {
		t.Fatal("retained fixture allocation not found")
	}
	stat, err := os.Stat(owned[0])
	if err != nil || stat.Size() != q.TargetBytes || stat.Mode().Perm() != 0600 {
		t.Fatal("dense allocation did not stop at its exact target")
	}
	q.RetainFiles = false
	if err := quotaProbe(context.Background(), q, p); err != nil {
		t.Fatal(err)
	}
	after, err := filepath.Glob(filepath.Join(scratch, "probe-quota-*", "allocation"))
	if err != nil || len(after) != 1 || after[0] != owned[0] {
		t.Fatal("cleanup touched a different fixture run's retained allocation")
	}
	data, err := os.ReadFile(foreign)
	if err != nil || string(data) != "preserve" {
		t.Fatal("cleanup touched an unowned file")
	}
}

func TestHeldQuotaAllocationKeepsOnlyItsUnlinkedHandle(t *testing.T) {
	dir := t.TempDir()
	r := &quotaRoot{kind: "scratch", path: dir, owned: dir}
	q := &quotaConfig{Operation: "held-file", Target: "scratch", TargetBytes: 8193, ChunkBytes: 4096, HoldMS: 1, UnlinkHeld: true}
	if err := quotaBytes(context.Background(), q, []*quotaRoot{r}, nil); err != nil {
		t.Fatal(err)
	}
	defer r.file.Close()
	if _, err := os.Stat(r.file.Name()); !os.IsNotExist(err) {
		t.Fatal("held file was not unlinked")
	}
	stat, err := r.file.Stat()
	if err != nil || stat.Size() != q.TargetBytes || r.written != q.TargetBytes {
		t.Fatal("unlinked owned handle did not retain its exact allocation")
	}
}

func TestCancelledQuotaAllocationReclaimsOwnedDirectory(t *testing.T) {
	p, err := newProbeSession(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q := &quotaConfig{Operation: "inodes", Target: "scratch", TargetFiles: 65536}
	if err := quotaProbe(ctx, q, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled allocation did not return cancellation: %v", err)
	}
	files, err := os.ReadDir(p.scratch)
	if err != nil || len(files) != 0 {
		t.Fatal("cancelled quota allocation leaked an owned directory")
	}
}

func TestIPCProbeRequiresRunnerDirectoryAndRejectsSymlink(t *testing.T) {
	t.Setenv("PLUGIN_UNIX_SOCKET_DIR", "")
	if _, err := guestIPCDirectory(); err == nil {
		t.Fatal("missing runner directory fell back to another mount")
	}
	actual := t.TempDir()
	t.Setenv("PLUGIN_UNIX_SOCKET_DIR", actual)
	if got, err := guestIPCDirectory(); err != nil || got != actual {
		t.Fatal("runner directory was not used verbatim")
	}
	link := filepath.Join(t.TempDir(), "broker-link")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLUGIN_UNIX_SOCKET_DIR", link)
	if _, err := guestIPCDirectory(); err == nil {
		t.Fatal("symlinked broker directory accepted")
	}
}

func TestFloodDoesNotBlockBeyondDeadlineWhenReaderStops(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	n, err := boundedOutput(ctx, int(w.Fd()), 64<<20)
	if !errors.Is(err, context.DeadlineExceeded) || n >= 64<<20 {
		t.Fatalf("blocked reader escaped bounded output: bytes=%d err=%v", n, err)
	}
}

func TestPrivateReportIsBoundedAndDoesNotRecordRawErrors(t *testing.T) {
	p, err := newProbeSession(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := p.file.Name()
	for range 200 {
		p.record("test", "error", errors.New("private-value-must-not-be-serialized"), nil)
	}
	p.close()
	stat, err := os.Stat(name)
	if err != nil || stat.Mode().Perm() != 0600 || stat.Size() > 128*4096 {
		t.Fatal("private bounded report contract violated")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-value") {
		t.Fatal("raw error leaked into report")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	count := 0
	for {
		var v observation
		err := decoder.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil || v.Sequence != count+1 {
			t.Fatalf("invalid observation: %v", err)
		}
		count++
	}
	if count != 128 {
		t.Fatalf("record bound not enforced: %d", count)
	}
}
