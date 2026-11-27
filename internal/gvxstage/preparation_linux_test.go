//go:build linux

package gvxstage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

func testPreparationConfig(t *testing.T) PreparationConfig {
	t.Helper()
	now, err := BootNS()
	if err != nil {
		t.Fatal(err)
	}
	return PreparationConfig{Version: gvxcontract.PreparationWriterProtocolVersion, WriterDomainVersion: gvxcontract.PreparationWriterDomainVersion, FilterVersion: gvxcontract.PreparationWriterFilterVersion, Purpose: PreparationPurpose, RuntimeInstallationID: "product", Generation: "0123456789abcdef", GatePath: "/chatanium/gate/gate.sock", Executable: "/chatanium/base/bin/gvx-preparer", ExecutableDigest: "sha256:" + strings.Repeat("a", 64), Workdir: "/chatanium/work", Argv: []string{"/chatanium/base/bin/gvx-preparer"}, Env: []string{"TMPDIR=/chatanium/work"}, DeadlineBootNS: now + int64(time.Minute)}
}

func TestPreparationGateClosedPurposes(t *testing.T) {
	good := testPreparationConfig(t)
	if err := ValidatePreparation(good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*PreparationConfig){
		"legacy-protocol":           func(c *PreparationConfig) { c.Version = 1 },
		"missing-writer-domain":     func(c *PreparationConfig) { c.WriterDomainVersion = 0 },
		"unknown-filter":            func(c *PreparationConfig) { c.FilterVersion++ },
		"unknown-purpose":           func(c *PreparationConfig) { c.Purpose = "EXEC" },
		"preparer-command-argument": func(c *PreparationConfig) { c.Argv = append(c.Argv, "-c", "arbitrary") },
		"outside-verified-base":     func(c *PreparationConfig) { c.Executable = "/bin/sh"; c.Argv = []string{c.Executable} },
		"run-in-load-role": func(c *PreparationConfig) {
			c.Purpose = LoadPurpose
			c.Executable = "/chatanium/base/bin/rungv"
			c.Argv = []string{c.Executable, "run", "image"}
		},
		"duplicate-environment":    func(c *PreparationConfig) { c.Env = append(c.Env, "TMPDIR=/other") },
		"dynamic-loader-injection": func(c *PreparationConfig) { c.Env = append(c.Env, "LD_PRELOAD=/other") },
		"nul-argument":             func(c *PreparationConfig) { c.Purpose = LoadPurpose; c.Argv = append(c.Argv, "load", "bad\x00value") },
		"expired-before-gate":      func(c *PreparationConfig) { c.DeadlineBootNS = 1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := testPreparationConfig(t)
			change(&candidate)
			if err := ValidatePreparation(candidate); err == nil {
				t.Fatal("accepted an unauthorized preparation declaration")
			}
		})
	}
	load := testPreparationConfig(t)
	load.Purpose = LoadPurpose
	load.Executable = "/chatanium/base/bin/rungv"
	load.Argv = []string{load.Executable, "load", "/chatanium/source/image.tar"}
	if err := ValidatePreparation(load); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationGateExpiredDeclarationDoesNotAuthorizeStart(t *testing.T) {
	config := testPreparationConfig(t)
	config.DeadlineBootNS = 1
	if err := validatePreparationDeclaration(config); err != nil {
		t.Fatalf("bounded recovery declaration rejected: %v", err)
	}
	if err := ValidatePreparation(config); err == nil {
		t.Fatal("expired recovery metadata authorized execution")
	}
	if _, err := Deadline(config.Binding()); err == nil {
		t.Fatal("expired original gate deadline became live")
	}
}

func TestPreparationStrictStream(t *testing.T) {
	c := testPreparationConfig(t)
	for _, kind := range []string{PreparationReady, PreparationArm, PreparationFilterReady, PreparationStart, PreparationError} {
		message := preparationMessage(c, kind)
		if kind == PreparationError {
			message.Error = "refused"
		}
		var stream bytes.Buffer
		if err := WritePreparationMessage(&stream, message); err != nil {
			t.Fatal(err)
		}
		got, err := ReadPreparationMessage(&stream)
		if err != nil || got != message || !MatchesPreparation(got, c) {
			t.Fatalf("round trip = %+v, %v", got, err)
		}
		if err := WriteMessage(&stream, Message{Version: 1, Type: "START", EpochID: "e", InstanceID: "i", Generation: "g"}); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPreparationMessage(&stream); err == nil {
			t.Fatal("run-v1 frame accepted by preparation")
		}
	}
	valid, err := json.Marshal(preparationMessage(c, PreparationArm))
	if err != nil {
		t.Fatal(err)
	}
	invalidFilter := preparationMessage(c, PreparationArm)
	invalidFilter.FilterVersion = 0
	invalidFilterRaw, err := json.Marshal(invalidFilter)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		string(valid[:len(valid)-1]) + `,"type":"START"}`,
		string(valid[:len(valid)-1]) + `,"extra":true}`,
		string(valid) + ` {}`,
		strings.Replace(string(valid), `"ARM"`, `"EXEC"`, 1),
		string(invalidFilterRaw),
		string(valid[:len(valid)-1]) + `,"error":"ignored"}`,
	} {
		var stream bytes.Buffer
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
		stream.Write(header[:])
		stream.WriteString(raw)
		if _, err := ReadPreparationMessage(&stream); err == nil {
			t.Fatalf("malformed preparation frame accepted: %s", raw)
		}
	}
	for _, size := range []uint32{0, MaxMessageBytes + 1, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if _, err := ReadPreparationMessage(bytes.NewReader(header[:])); err == nil {
			t.Fatalf("preparation length %d accepted", size)
		}
	}
	message := preparationMessage(c, PreparationArm)
	message.Generation = "stale"
	if MatchesPreparation(message, c) {
		t.Fatal("stale preparation generation accepted")
	}
	var stream bytes.Buffer
	if err := WritePreparationMessage(&stream, preparationMessage(c, PreparationStart)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMessage(&stream); err == nil {
		t.Fatal("preparation frame accepted by unchanged run wire")
	}
}

func TestPreparationBarrierOrdering(t *testing.T) {
	for _, scenario := range []string{"success", "start-before-arm", "filter-failure", "ack-eof", "arm-instead-of-start", "stale-start", "error"} {
		t.Run(scenario, func(t *testing.T) {
			c := testPreparationConfig(t)
			stage, controller := net.Pipe()
			defer controller.Close()
			deadline := time.Now().Add(5 * time.Second)
			if err := stage.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := controller.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			type result struct {
				err   error
				armed bool
			}
			done := make(chan result, 1)
			go func() {
				armed := false
				err := exchangePreparation(stage, c, func() error {
					armed = true
					if scenario == "filter-failure" {
						return errors.New("TSYNC refused")
					}
					return nil
				})
				stage.Close()
				done <- result{err, armed}
			}()
			ready, err := ReadPreparationMessage(controller)
			if err != nil || ready.Type != PreparationReady {
				t.Fatalf("READY = %+v, %v", ready, err)
			}
			arm := preparationMessage(c, PreparationArm)
			if scenario == "start-before-arm" {
				arm.Type = PreparationStart
			}
			if err := WritePreparationMessage(controller, arm); err != nil {
				t.Fatal(err)
			}
			if scenario != "filter-failure" && scenario != "start-before-arm" {
				filterReady, err := ReadPreparationMessage(controller)
				if err != nil || filterReady.Type != PreparationFilterReady {
					t.Fatalf("FILTER_READY = %+v, %v", filterReady, err)
				}
				start := preparationMessage(c, PreparationStart)
				switch scenario {
				case "ack-eof":
					controller.Close()
				case "arm-instead-of-start":
					start.Type = PreparationArm
				case "stale-start":
					start.Generation = "stale"
				case "error":
					start.Type, start.Error = PreparationError, "refused"
				}
				if scenario != "ack-eof" {
					if err := WritePreparationMessage(controller, start); err != nil {
						t.Fatal(err)
					}
				}
			}
			got := <-done
			if (got.err == nil) != (scenario == "success") {
				t.Fatalf("target release error = %v", got.err)
			}
			if got.armed == (scenario == "start-before-arm") {
				t.Fatalf("unexpected filter installation: %v", got.armed)
			}
			if scenario == "filter-failure" {
				if _, err := ReadPreparationMessage(controller); !errors.Is(err, io.EOF) {
					t.Fatalf("filter failure emitted FILTER_READY: %v", err)
				}
			}
		})
	}
}
