package main

import (
	"context"
	"errors"
	"os"
	"time"
)

// All controls are integration-fixture-only config, obtained through authenticated INIT.
// A missing control preserves the baseline. Explicit workloads start after START.
type lifecycleConfig struct {
	InitDelayMS      int    `json:"init_delay_ms"`
	ReadinessDelayMS int    `json:"readiness_delay_ms"`
	StartDelayMS     int    `json:"start_delay_ms"`
	FailStage        string `json:"fail_stage"`
	InitArtifact     bool   `json:"init_artifact"`
}

type scenarioConfig struct {
	Kind           string         `json:"kind"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	TriggerDelayMS int            `json:"trigger_delay_ms"`
	Workers        int            `json:"workers"`
	MemoryBytes    int64          `json:"memory_bytes"`
	Attempts       int            `json:"attempts"`
	HoldMS         int            `json:"hold_ms"`
	Quota          *quotaConfig   `json:"quota,omitempty"`
	StdoutBytes    int64          `json:"stdout_bytes"`
	StderrBytes    int64          `json:"stderr_bytes"`
	Network        *networkConfig `json:"network,omitempty"`
}

type quotaConfig struct {
	Operation   string `json:"operation"`
	Target      string `json:"target"`
	TargetBytes int64  `json:"target_bytes"`
	TargetFiles int    `json:"target_files"`
	ChunkBytes  int    `json:"chunk_bytes"`
	HoldMS      int    `json:"hold_ms"`
	RetainFiles bool   `json:"retain_files"`
	UnlinkHeld  bool   `json:"unlink_held"`
}

func validateControls(c probeConfig) error {
	invalid := errors.New("invalid finite fixture controls")
	if c.EndpointRace && (c.Scenario == nil || c.Scenario.Kind != "identity") {
		return invalid
	}
	if l := c.Lifecycle; l != nil {
		for _, ms := range []int{l.InitDelayMS, l.ReadinessDelayMS, l.StartDelayMS} {
			if ms < 0 || ms > 60000 {
				return invalid
			}
		}
		switch l.FailStage {
		case "", "init", "readiness", "start":
		default:
			return invalid
		}
	}
	s := c.Scenario
	if s == nil {
		return nil
	}
	if s.TimeoutSeconds < 1 || s.TimeoutSeconds > 120 || s.TriggerDelayMS < 0 || s.TriggerDelayMS > 60000 || s.HoldMS < 0 || s.HoldMS > s.TimeoutSeconds*1000 {
		return invalid
	}
	switch s.Kind {
	case "cpu":
		if s.Workers < 1 || s.Workers > 128 {
			return invalid
		}
	case "memory":
		if s.MemoryBytes < 1 || s.MemoryBytes > 2<<30 {
			return invalid
		}
	case "fork", "thread":
		if s.Attempts < 1 || s.Attempts > 256 || s.HoldMS == 0 {
			return invalid
		}
	case "identity", "crash":
	case "network":
		if err := validateNetwork(s.Network); err != nil {
			return err
		}
	case "flood":
		if s.StdoutBytes < 0 || s.StderrBytes < 0 || s.StdoutBytes > 64<<20 || s.StderrBytes > 64<<20 || s.StdoutBytes+s.StderrBytes == 0 {
			return invalid
		}
	case "quota":
		q := s.Quota
		if q == nil || q.HoldMS < 0 || q.HoldMS > s.TimeoutSeconds*1000 {
			return invalid
		}
		switch q.Operation {
		case "bytes", "inodes", "held-file":
			if q.Target != "persistent" && q.Target != "scratch" && q.Target != "ipc" {
				return invalid
			}
		case "combined-bytes", "combined-inodes", "cross-project-link":
			if q.Target != "" {
				return invalid
			}
		default:
			return invalid
		}
		switch q.Operation {
		case "bytes", "combined-bytes", "held-file":
			if q.TargetBytes < 1 || q.TargetBytes > 4<<30 || q.ChunkBytes < 4096 || q.ChunkBytes > 1<<20 {
				return invalid
			}
		case "inodes", "combined-inodes":
			if q.TargetFiles < 1 || q.TargetFiles > 65536 {
				return invalid
			}
		}
		if q.Operation == "held-file" && q.HoldMS == 0 || q.UnlinkHeld && q.Operation != "held-file" {
			return invalid
		}
	default:
		return invalid
	}
	return nil
}

func waitUntil(ctx context.Context, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := time.NewTimer(time.Until(until))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return ctx.Err()
	}
}

func lifecycleStep(ctx context.Context, p *probeSession, stage string, ms int, fail string) error {
	p.record(stage, "delay-started", nil, map[string]any{"delay_ms": ms})
	if err := waitUntil(ctx, time.Now().Add(time.Duration(ms)*time.Millisecond)); err != nil {
		p.record(stage, "cancelled", err, nil)
		return err
	}
	if fail == stage {
		p.record(stage, "deliberate-failure", nil, nil)
		return errors.New("deliberate fixture lifecycle failure")
	}
	p.record(stage, "delay-completed", nil, nil)
	return nil
}

func (m *module) awaitTrigger(ctx context.Context, done chan struct{}, c *scenarioConfig, p *probeSession) {
	defer close(done)
	// Only authenticated, installation-approved config can arm this timer.
	// The delay is outside the workload budget; cancellation joins it on STOP.
	gate := time.NewTimer(time.Duration(c.TriggerDelayMS) * time.Millisecond)
	defer gate.Stop()
	p.record(c.Kind, "approved-trigger-armed", nil, map[string]any{"delay_ms": c.TriggerDelayMS})
	select {
	case <-ctx.Done():
		p.record(c.Kind, "cancelled-before-trigger", ctx.Err(), nil)
		return
	case <-gate.C:
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	p.record(c.Kind, "triggered", nil, map[string]any{"timeout_seconds": c.TimeoutSeconds, "termination_requires_host_evidence": c.Kind == "memory" || c.Kind == "fork" || c.Kind == "thread" || c.Kind == "crash"})
	var err error
	if m.config.EndpointRace {
		err = ipcComponentProbe(ctx, p)
		if err != nil {
			p.record("ipc-component", "operation-failed", err, nil)
			return
		}
		config, rpcErr := m.core.GetConfig(ctx)
		p.record("ipc-component", "core-rpc-after-replacement", rpcErr,
			map[string]any{"response_received": rpcErr == nil && config != nil && len(config.Json) > 0})
		if rpcErr != nil || config == nil || len(config.Json) == 0 {
			return
		}
	}
	switch c.Kind {
	case "cpu", "memory", "fork", "thread", "identity":
		err = resourceProbe(ctx, c, p)
	case "quota":
		err = quotaProbe(ctx, c.Quota, p)
	case "flood":
		err = floodProbe(ctx, c, p)
	case "network":
		err = networkProbe(ctx, c.Network, p)
	case "crash":
		p.record("crash", "intentional-exit-86-next", nil, nil)
		os.Exit(86)
	}
	p.record(c.Kind, "returned-not-policy-proof", err, nil)
}
