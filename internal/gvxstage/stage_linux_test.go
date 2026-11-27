//go:build linux

package gvxstage

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestGvxStageStrictGate(t *testing.T) {
	valid := Message{Version: 1, Type: "READY", EpochID: "epoch", InstanceID: "instance", Generation: "generation"}
	var buffer bytes.Buffer
	if e := WriteMessage(&buffer, valid); e != nil {
		t.Fatal(e)
	}
	got, e := ReadMessage(&buffer)
	if e != nil || got != valid {
		t.Fatalf("round trip = %+v,%v", got, e)
	}
	for _, raw := range []string{`{"version":1,"type":"START","epoch_id":"e","instance_id":"i","generation":"g","type":"READY"}`, `{"version":1,"type":"START","epoch_id":"e","instance_id":"i","generation":"g","extra":true}`, `{"version":1,"type":"START","epoch_id":"e","instance_id":"i","generation":"g"} {}`, `{"version":1,"type":"EXEC","epoch_id":"e","instance_id":"i","generation":"g"}`, `{"version":1,"type":"START","epoch_id":"e","instance_id":"i","generation":"g","error":"ignored"}`} {
		buffer.Reset()
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
		buffer.Write(header[:])
		buffer.WriteString(raw)
		if _, e = ReadMessage(&buffer); e == nil {
			t.Fatalf("malformed gate message accepted: %s", raw)
		}
	}
	for _, n := range []uint32{0, MaxMessageBytes + 1, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], n)
		if _, e = ReadMessage(bytes.NewReader(header[:])); e == nil {
			t.Fatalf("length %d accepted", n)
		}
	}
	c := Config{EpochID: "epoch", InstanceID: "instance", Generation: "generation"}
	if !Matches(valid, c) {
		t.Fatal("exact gate binding rejected")
	}
	c.Generation = "stale"
	if Matches(valid, c) {
		t.Fatal("stale generation accepted")
	}
}
