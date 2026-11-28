package bootstrap

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/runtime"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	WorkerControlVersion      uint32 = 1
	WorkerControlMaxBytes            = 32 << 20
	WorkerConfigMaxBytes             = 16 << 20
	WorkerSecretMaxBytes             = 1 << 20
	WorkerObservationMaxBytes        = 60 << 10
	WorkerJSONMaxDepth               = 16
)

func ValidateWorkerInit(v WorkerInit) error {
	if v.Version != 1 || !validID(v.RuntimeInstallationID) || v.Revision == "" || v.EpochID == "" || len(v.Config) == 0 || len(v.Config) > WorkerConfigMaxBytes || v.Host.SocketPath == "" || v.Host.SupervisorUID != 0 || v.Host.MaxMessageBytes <= 0 || v.Host.OperationTimeout <= 0 || v.Options.Duration < 0 {
		return errors.New("invalid worker initialization")
	}
	if v.Options.DevelopmentRevision != "" && (!v.Options.DevelopmentMode || v.Options.DevelopmentRevision != v.Revision) {
		return errors.New("inconsistent development worker revision")
	}
	c, e := runtime.DecodeConfig(v.Config)
	if e != nil {
		return e
	}
	if c.Host.RuntimeInstallationID != v.RuntimeInstallationID {
		return errors.New("worker installation mismatch")
	}
	total := 0
	for k, s := range v.Secrets {
		if k == "" || strings.ContainsRune(k, 0) || !utf8.ValidString(k) || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
			return errors.New("invalid worker secret")
		}
		total += len(k) + len(s)
		if total > WorkerSecretMaxBytes {
			return errors.New("worker secrets exceed bound")
		}
	}
	return nil
}
func validateCommand(v WorkerCommand) error {
	if v.Version != 1 {
		return errors.New("unsupported worker protocol")
	}
	switch v.Type {
	case "INIT":
		if v.Init == nil || v.OperationID != "" || v.RemainingNS != 0 {
			return errors.New("invalid INIT fields")
		}
		return ValidateWorkerInit(*v.Init)
	case "DRAIN":
		if v.Init != nil || !validID(v.OperationID) || v.RemainingNS <= 0 {
			return errors.New("invalid DRAIN fields")
		}
	default:
		return errors.New("unknown worker command")
	}
	return nil
}
func validateEvent(v WorkerEvent) error {
	if v.Version != 1 {
		return errors.New("unsupported worker protocol")
	}
	switch v.Type {
	case "READY":
		if v.OperationID != "" || len(v.Observation) != 0 || v.Drain != nil || v.Failure != nil {
			return errors.New("invalid READY fields")
		}
	case "OBSERVATION":
		if v.OperationID != "" || len(v.Observation) == 0 || len(v.Observation) > WorkerObservationMaxBytes || v.Drain != nil || v.Failure != nil {
			return errors.New("invalid OBSERVATION fields")
		}
		var raw any
		if e := gvxcontract.DecodeStrict(v.Observation, WorkerObservationMaxBytes, WorkerJSONMaxDepth, &raw); e != nil {
			return e
		}
	case "DRAINED":
		if !validID(v.OperationID) || len(v.Observation) != 0 || v.Drain == nil || v.Failure != nil {
			return errors.New("invalid DRAINED fields")
		}
	case "FAILED":
		if len(v.Observation) != 0 || v.Drain != nil || v.Failure == nil || v.Failure.Code == "" || len(v.Failure.Message) > 4096 || v.OperationID != "" && !validID(v.OperationID) {
			return errors.New("invalid FAILED fields")
		}
	default:
		return errors.New("unknown worker event")
	}
	return nil
}
func readControl(r io.Reader, v any) error {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > WorkerControlMaxBytes {
		return errors.New("worker packet exceeds bound")
	}
	raw := make([]byte, int(n))
	if _, e := io.ReadFull(r, raw); e != nil {
		return e
	}
	return gvxcontract.DecodeStrict(raw, WorkerControlMaxBytes, WorkerJSONMaxDepth, v)
}
func encodedControl(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	if len(raw) == 0 || len(raw) > WorkerControlMaxBytes {
		return nil, errors.New("worker packet exceeds bound")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(raw)))
	return append(h[:], raw...), nil
}
func writeControl(w io.Writer, v any) error {
	raw, e := encodedControl(v)
	if e != nil {
		return e
	}
	_, e = io.Copy(w, bytes.NewReader(raw))
	return e
}
func ReadWorkerCommand(r io.Reader) (WorkerCommand, error) {
	var v WorkerCommand
	e := readControl(r, &v)
	if e == nil {
		e = validateCommand(v)
	}
	return v, e
}
func WriteWorkerCommand(w io.Writer, v WorkerCommand) error {
	if e := validateCommand(v); e != nil {
		return e
	}
	return writeControl(w, v)
}
func ReadWorkerEvent(r io.Reader) (WorkerEvent, error) {
	var v WorkerEvent
	e := readControl(r, &v)
	if e == nil {
		e = validateEvent(v)
	}
	return v, e
}
func WriteWorkerEvent(w io.Writer, v WorkerEvent) error {
	if e := validateEvent(v); e != nil {
		return e
	}
	return writeControl(w, v)
}
