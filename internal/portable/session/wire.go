// Package session defines the private supervisor/worker protocol. Guest code
// receives only go-plugin bootstrap material and never sees this protocol.
package session

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

const (
	GuestSocketDir  = "/tmp/plugin-dir-portable"
	WorkerArg       = "--portable"
	maxRPCBytes     = 16 << 20
	maxInitBytes    = 32 << 20
	maxWorkerConfig = 16 << 20
	maxSecrets      = 1 << 20
	maxWorkerEvent  = 1 << 20
	maxEpochLength  = 128
	maxTokenLength  = 32
	maxModules      = 512
)

var errProtocol = errors.New("invalid portable worker protocol")

type Credentials struct {
	Epoch string `json:"epoch"`
	Token string `json:"token"`
}

func NewCredentials(epoch string) (Credentials, error) {
	if !validEpoch(epoch) {
		return Credentials{}, errProtocol
	}
	var token [maxTokenLength]byte
	if _, err := rand.Read(token[:]); err != nil {
		return Credentials{}, err
	}
	return Credentials{Epoch: epoch, Token: hex.EncodeToString(token[:])}, nil
}

func validEpoch(epoch string) bool {
	if len(epoch) == 0 || len(epoch) > maxEpochLength {
		return false
	}
	for _, c := range epoch {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (c Credentials) valid() bool {
	return validEpoch(c.Epoch) && lowercaseHex(c.Token, maxTokenLength)
}

func lowercaseHex(s string, size int) bool {
	if len(s) != size*2 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func readFrame(r io.Reader, maxBytes int, v any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > uint32(maxBytes) {
		return errProtocol
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return err
	}
	if gvxcontract.DecodeStrict(raw, maxBytes, 32, v) != nil {
		return errProtocol
	}
	return nil
}

func writeFrame(w io.Writer, maxBytes int, v any) error {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > maxBytes {
		return errProtocol
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if err = writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, raw)
}

func writeAll(w io.Writer, b []byte) error {
	_, err := io.Copy(w, bytes.NewReader(b))
	return err
}

type WorkerInit struct {
	Endpoint    string            `json:"endpoint"`
	Credentials Credentials       `json:"credentials"`
	Config      json.RawMessage   `json:"config"`
	Secrets     map[string]string `json:"secrets,omitempty"`
}

type workerInitFrame struct {
	Type        string            `json:"type"`
	Endpoint    string            `json:"endpoint"`
	Credentials Credentials       `json:"credentials"`
	Config      []byte            `json:"config"`
	Secrets     map[string]string `json:"secrets,omitempty"`
}

func (v WorkerInit) valid() bool {
	if !filepath.IsAbs(v.Endpoint) || filepath.Clean(v.Endpoint) != v.Endpoint || strings.ContainsAny(v.Endpoint, "\x00\r\n") || !v.Credentials.valid() || len(v.Config) > maxWorkerConfig || !json.Valid(v.Config) {
		return false
	}
	remaining := maxSecrets
	for name, secret := range v.Secrets {
		remaining -= len(name) + len(secret)
		if name == "" || !utf8.ValidString(name) || !utf8.ValidString(secret) || strings.ContainsRune(name, 0) || strings.ContainsRune(secret, 0) || remaining < 0 {
			return false
		}
	}
	return true
}

func WriteWorkerInit(w io.Writer, init WorkerInit) error {
	if !init.valid() {
		return errProtocol
	}
	return writeFrame(w, maxInitBytes, workerInitFrame{Type: "INIT", Endpoint: init.Endpoint,
		Credentials: init.Credentials, Config: init.Config, Secrets: init.Secrets})
}

func ReadWorkerInit(r io.Reader) (WorkerInit, error) {
	var msg workerInitFrame
	if err := readFrame(r, maxInitBytes, &msg); err != nil {
		return WorkerInit{}, err
	}
	init := WorkerInit{Endpoint: msg.Endpoint, Credentials: msg.Credentials, Config: msg.Config, Secrets: msg.Secrets}
	if msg.Type != "INIT" || !init.valid() {
		return WorkerInit{}, errProtocol
	}
	return init, nil
}

type workerDrainFrame struct {
	Type     string    `json:"type"`
	Deadline time.Time `json:"deadline"`
}

func WriteWorkerDrain(w io.Writer, deadline time.Time) error {
	if deadline.IsZero() {
		return errProtocol
	}
	return writeFrame(w, 256, workerDrainFrame{Type: "DRAIN", Deadline: deadline.UTC()})
}

func ReadWorkerDrain(r io.Reader) (time.Time, error) {
	var msg workerDrainFrame
	if err := readFrame(r, 256, &msg); err != nil {
		return time.Time{}, err
	}
	if msg.Type != "DRAIN" || msg.Deadline.IsZero() {
		return time.Time{}, errProtocol
	}
	return msg.Deadline, nil
}

type ModuleStatus struct {
	ModuleID        string `json:"module_id"`
	InstanceID      string `json:"instance_id,omitempty"`
	State           string `json:"state"`
	Reason          string `json:"reason,omitempty"`
	CleanupComplete bool   `json:"cleanup_complete"`
}

// READY and DRAINED may be empty; the supervisor checks the approved count.
type WorkerEvent struct {
	Type    string         `json:"type"`
	Modules []ModuleStatus `json:"modules,omitempty"`
	Clean   bool           `json:"clean,omitempty"`
	Reason  string         `json:"reason,omitempty"`
}

func (ev WorkerEvent) valid() bool {
	if len(ev.Modules) > maxModules {
		return false
	}
	for _, module := range ev.Modules {
		if module.ModuleID == "" || len(module.ModuleID) > 256 || !utf8.ValidString(module.ModuleID) ||
			strings.ContainsAny(module.ModuleID, "\x00\r\n") || len(module.Reason) > 128 ||
			ev.Clean && !module.CleanupComplete || ev.Type == "READY" && module.State != "RUNNING" {
			return false
		}
		switch module.State {
		case "NOT_STARTED":
			if module.InstanceID != "" {
				return false
			}
		case "STARTING", "INITIALIZING", "READY", "RUNNING", "DRAINING", "STOPPED", "FAILED":
			if !lowercaseHex(module.InstanceID, 16) {
				return false
			}
		default:
			return false
		}
	}
	switch ev.Type {
	case "READY":
		return !ev.Clean && ev.Reason == ""
	case "STATUS":
		return !ev.Clean && (ev.Reason == "" || ev.Reason == "BACKEND_ERROR")
	case "DRAINED":
		return ev.Reason == ""
	case "FAILED":
		switch ev.Reason {
		case "INVALID_INIT", "INVALID_CONFIGURATION", "INVALID_SECRET_BINDINGS", "INVALID_SUPERVISOR_SESSION",
			"WORKER_FAILED", "WORKER_CANCELLED", "SUPERVISOR_CONTROL_LOST":
			return !ev.Clean
		}
		return false
	default:
		return false
	}
}

func ReadWorkerEvent(r io.Reader) (WorkerEvent, error) {
	var ev WorkerEvent
	if err := readFrame(r, maxWorkerEvent, &ev); err != nil {
		return WorkerEvent{}, err
	}
	if !ev.valid() {
		return WorkerEvent{}, errProtocol
	}
	return ev, nil
}

func WriteWorkerEvent(w io.Writer, ev WorkerEvent) error {
	if !ev.valid() {
		return errProtocol
	}
	return writeFrame(w, maxWorkerEvent, ev)
}
