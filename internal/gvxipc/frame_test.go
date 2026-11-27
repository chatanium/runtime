//go:build linux

package gvxipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

func wireFrame(typ byte, p []byte) []byte {
	b := make([]byte, 8+len(p))
	b[0] = typ
	binary.BigEndian.PutUint32(b[4:8], uint32(len(p)))
	copy(b[8:], p)
	return b
}
func testLimits() Limits {
	return Limits{ControlMessageMaxBytes: MaxControl, LogBufferBytes: 1024 * 1024}
}
func primeHost(t *testing.T, tail []byte) *Codec {
	t.Helper()
	stream := append(wireFrame(RootsReady, []byte("{}")), wireFrame(Handshake, []byte("line\n"))...)
	stream = append(stream, wireFrame(OpenOK, nil)...)
	stream = append(stream, tail...)
	c, e := NewCodec(bytes.NewReader(stream), io.Discard, Host, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Write(Init, []byte("{}")); e != nil {
		t.Fatal(e)
	}
	if typ, _, e := c.Read(); e != nil || typ != RootsReady {
		t.Fatal(typ, e)
	}
	if e = c.Write(RootsCommit, nil); e != nil {
		t.Fatal(e)
	}
	if typ, _, e := c.Read(); e != nil || typ != Handshake {
		t.Fatal(typ, e)
	}
	if e = c.Write(Open, nil); e != nil {
		t.Fatal(e)
	}
	if typ, _, e := c.Read(); e != nil || typ != OpenOK {
		t.Fatal(typ, e)
	}
	return c
}
func TestGvxFramesAndTerminalEOF(t *testing.T) {
	t.Run("half-close and terminal boundary", func(t *testing.T) {
		tail := wireFrame(Data, []byte("opaque TLS/yamux bytes"))
		tail = append(tail, wireFrame(Fin, nil)...)
		tail = append(tail, wireFrame(Exit, []byte(`{"kind":"exit","value":0}`))...)
		c := primeHost(t, tail)
		if typ, p, e := c.Read(); e != nil || typ != Data || string(p) != "opaque TLS/yamux bytes" {
			t.Fatal(typ, string(p), e)
		}
		if typ, _, e := c.Read(); e != nil || typ != Fin {
			t.Fatal(typ, e)
		}
		if e := c.Write(Data, []byte("reverse half remains open")); e != nil {
			t.Fatal(e)
		}
		if typ, _, e := c.Read(); e != nil || typ != Exit {
			t.Fatal(typ, e)
		}
		if _, _, e := c.Read(); e != io.EOF {
			t.Fatalf("terminal boundary EOF: %v", e)
		}
		if e := c.Write(Data, []byte("late")); e == nil {
			t.Fatal("DATA accepted after EXIT")
		}
	})
	for _, tc := range []struct {
		name string
		tail []byte
	}{
		{"premature EOF", nil}, {"partial header", []byte{Data, 0}}, {"partial payload", wireFrame(Data, []byte("abc"))[:9]},
		{"duplicate open ack", wireFrame(OpenOK, nil)}, {"DATA after FIN", append(wireFrame(Fin, nil), wireFrame(Data, []byte("late"))...)},
		{"unknown type", wireFrame(255, nil)}, {"nonempty FIN", wireFrame(Fin, []byte("x"))},
		{"oversized DATA", wireFrame(Data, make([]byte, MaxData+1))},
		{"wrong direction", wireFrame(RootsCommit, nil)},
		{"truncated after EXIT", append(wireFrame(Exit, []byte(`{"kind":"exit","value":0}`)), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := primeHost(t, tc.tail)
			for range 3 {
				_, _, e := c.Read()
				if e != nil {
					if e == io.EOF {
						t.Fatal("invalid stream classified as completion")
					}
					return
				}
			}
			t.Fatal("invalid stream accepted")
		})
	}
	t.Run("reserved and declared size rejected before body", func(t *testing.T) {
		for _, h := range [][]byte{{Data, 1, 0, 0, 0, 0, 0, 1}, {Data, 0, 0, 0, 255, 255, 255, 255}} {
			c := primeHost(t, h)
			if _, _, e := c.Read(); e == nil || errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) {
				t.Fatalf("header not rejected before body: %v", e)
			}
		}
	})
	t.Run("mandatory roots commit", func(t *testing.T) {
		c, _ := NewCodec(bytes.NewReader(wireFrame(Handshake, []byte("line\n"))), io.Discard, Host, testLimits())
		c.Write(Init, []byte("{}"))
		if _, _, e := c.Read(); e == nil {
			t.Fatal("handshake accepted before durable roots commit")
		}
	})
	t.Run("closed terminal payloads", func(t *testing.T) {
		for _, raw := range []string{`{"kind":"exit"}`, `{"kind":"exit","value":null}`, `{"kind":"signal","value":0}`, `{"kind":"exit","value":256}`, `{"kind":"exit","value":0,"value":1}`, `{"kind":"exit","value":0,"extra":true}`, `{"kind":"exit","value":0} {}`} {
			if _, e := DecodeExit([]byte(raw), MaxControl); e == nil {
				t.Fatalf("accepted invalid EXIT: %s", raw)
			}
		}
		if _, e := DecodeExit([]byte(`{"kind":"exit","value":0}`), MaxControl); e != nil {
			t.Fatal(e)
		}
		for _, raw := range []string{`{"code":"IO_FAILED"}`, `{"code":"OTHER","message":""}`, `{"code":"IO_FAILED","message":"\u0000"}`} {
			if _, e := DecodeError([]byte(raw), MaxControl); e == nil {
				t.Fatalf("accepted invalid ERROR: %s", raw)
			}
		}
	})
}

func TestGvxRootConfirmationBinding(t *testing.T) {
	p := gvxcontract.RootInitPayload{Version: 1, RuntimeInstallationID: "product", EpochID: "epoch", InstanceID: "instance", IntentID: "intent", Nonce: "fresh-nonce"}
	target := gvxcontract.RootAttrs{UID: 1000, GID: 1000, Mode: 0700}
	for _, r := range []struct{ id, path string }{{"persistent", "/var/lib/flexmodule/data"}, {"scratch", "/var/lib/flexmodule/scratch"}, {"tmp", "/tmp"}} {
		p.Roots = append(p.Roots, gvxcontract.RootInitEntry{RootID: r.id, Mountpoint: r.path, Disposition: "new", Pre: gvxcontract.RootAttrs{Mode: 0755}, Target: target})
	}
	raw, _ := json.Marshal(p)
	m := gvxcontract.RootInitManifest{Digest: gvxcontract.RootDigest(raw), Payload: raw}
	result := gvxcontract.RootInitResult{Digest: m.Digest, Nonce: p.Nonce}
	for _, r := range p.Roots {
		result.Results = append(result.Results, gvxcontract.RootStepResult{RootID: r.RootID, Step: 2, Observed: target})
	}
	if e := ValidateRootResult(m, result, MaxControl); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*gvxcontract.RootInitResult){func(r *gvxcontract.RootInitResult) { r.Nonce = "old-nonce" }, func(r *gvxcontract.RootInitResult) { r.Digest = "sha256:other" }, func(r *gvxcontract.RootInitResult) { r.Results = r.Results[:2] }, func(r *gvxcontract.RootInitResult) { r.Results[1].RootID = r.Results[0].RootID }, func(r *gvxcontract.RootInitResult) { r.Results[0].Step = 1 }, func(r *gvxcontract.RootInitResult) { r.Results[0].Observed.UID = 0 }} {
		bad := result
		bad.Results = append([]gvxcontract.RootStepResult(nil), result.Results...)
		mutate(&bad)
		if e := ValidateRootResult(m, bad, MaxControl); e == nil {
			t.Fatal("unbound/incomplete result accepted")
		}
	}
	entry := p.Roots[0]
	for want, attrs := range []gvxcontract.RootAttrs{entry.Pre, {UID: target.UID, GID: target.GID, Mode: entry.Pre.Mode}, entry.Target} {
		step, e := rootStep(entry, attrs)
		if e != nil || step != want {
			t.Fatalf("known root step %d: got %d, %v", want, step, e)
		}
	}
	if _, e := rootStep(entry, gvxcontract.RootAttrs{UID: target.UID, GID: 0, Mode: 0700}); e == nil {
		t.Fatal("unknown pending root state accepted")
	}
	entry.Disposition = "retained"
	entry.Pre = entry.Target
	if _, e := rootStep(entry, gvxcontract.RootAttrs{Mode: 0700}); e == nil {
		t.Fatal("retained mismatch permitted repair")
	}
}
