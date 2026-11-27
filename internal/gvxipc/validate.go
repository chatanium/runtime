package gvxipc

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

func canonicalAbsolute(s string) bool {
	return path.IsAbs(s) && path.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n") && utf8.ValidString(s)
}
func envName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (i == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return true
}
func ValidateInit(v gvxcontract.BridgeInit, max int) (gvxcontract.RootInitPayload, error) {
	var zero gvxcontract.RootInitPayload
	if max > MaxControl {
		max = MaxControl
	}
	// Charge vector entries against the same finite parsing workspace, before
	// allocating the duplicate-environment index.
	if max <= 0 || len(v.Argv) > max/32 || len(v.Env) > max/32 {
		return zero, errors.New("launch vectors exceed control workspace")
	}
	if len(v.Argv) == 0 || !canonicalAbsolute(v.Argv[0]) || !canonicalAbsolute(v.Workdir) || !canonicalAbsolute(v.SocketDir) || path.Dir(v.SocketDir) != gvxcontract.PortableTmpPath || !strings.HasPrefix(path.Base(v.SocketDir), "plugin-dir") || v.UID == 0 || v.GID == 0 || v.UID == ^uint32(0) || v.GID == ^uint32(0) {
		return zero, errors.New("invalid approved launch identity or path")
	}
	for _, a := range v.Argv {
		if strings.IndexByte(a, 0) >= 0 || !utf8.ValidString(a) {
			return zero, errors.New("invalid argv")
		}
	}
	values := make(map[string]string, len(v.Env))
	for _, entry := range v.Env {
		k, value, ok := strings.Cut(entry, "=")
		if !ok || !envName(k) || strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
			return zero, errors.New("invalid child environment")
		}
		if _, ok = values[k]; ok {
			return zero, errors.New("duplicate child environment")
		}
		switch k {
		case "CHATANIUM_GVX_STARTUP_TIMEOUT_NS", "CHATANIUM_GVX_CONTROL_MAX_BYTES", "CHATANIUM_GVX_LOG_BUFFER_BYTES":
			return zero, errors.New("controller environment in child")
		}
		values[k] = value
	}
	if values["FLEXMODULE_PLUGIN"] != "CHATANIUM_FOREVER" || values["PLUGIN_PROTOCOL_VERSIONS"] != "2" || values["PLUGIN_MULTIPLEX_GRPC"] != "true" || values["PLUGIN_CLIENT_CERT"] == "" || values["PLUGIN_UNIX_SOCKET_DIR"] != v.SocketDir || values["PLUGIN_UNIX_SOCKET_GROUP"] != strconv.FormatUint(uint64(v.GID), 10) {
		return zero, errors.New("mandatory AutoMTLS/multiplex bootstrap missing")
	}
	p, e := gvxcontract.DecodeRootManifest(v.Roots, max, 16)
	if e != nil {
		return zero, e
	}
	if len(p.Roots) != 3 {
		return zero, errors.New("exactly three approved roots required")
	}
	for _, r := range p.Roots {
		if r.Target.UID != v.UID || r.Target.GID != v.GID {
			return zero, errors.New("root target differs from launch identity")
		}
	}
	for _, s := range []string{p.RuntimeInstallationID, p.EpochID, p.InstanceID, p.IntentID, p.Nonce} {
		if strings.IndexByte(s, 0) >= 0 {
			return zero, errors.New("NUL in root binding")
		}
	}
	return p, nil
}

func ValidateRootResult(m gvxcontract.RootInitManifest, result gvxcontract.RootInitResult, max int) error {
	p, e := gvxcontract.DecodeRootManifest(m, max, 16)
	if e != nil {
		return e
	}
	return validateRootResult(m.Digest, p, result)
}

func validateRootResult(digest string, p gvxcontract.RootInitPayload, result gvxcontract.RootInitResult) error {
	if result.Digest != digest || result.Nonce != p.Nonce || len(result.Results) != len(p.Roots) {
		return errors.New("root confirmation binding mismatch")
	}
	for i, r := range p.Roots {
		got := result.Results[i]
		if got.RootID != r.RootID || got.Step != 2 || got.Observed != r.Target {
			return errors.New("root confirmation step mismatch")
		}
	}
	return nil
}

// ValidateHandshake validates the actual go-plugin v1/core-v2 Unix AutoMTLS
// handshake. The certificate stays opaque; AutoMTLS authenticates the transport.
func ValidateHandshake(line []byte, dir string) (string, error) {
	if len(line) == 0 || line[len(line)-1] != '\n' || bytes.ContainsAny(line[:len(line)-1], "\x00\r\n") || !utf8.Valid(line) {
		return "", errors.New("invalid handshake line")
	}
	fields := strings.Split(string(line[:len(line)-1]), "|")
	if len(fields) != 7 || fields[0] != "1" || fields[1] != "2" || fields[2] != "unix" || fields[4] != "grpc" || fields[6] != "true" {
		return "", errors.New("Unix core-v2 AutoMTLS/multiplex handshake required")
	}
	name := fields[3]
	if !canonicalAbsolute(name) || path.Dir(name) != dir || path.Base(name) == "." || path.Base(name) == ".." {
		return "", errors.New("handshake path is not a canonical direct child")
	}
	cert, e := base64.RawStdEncoding.Strict().DecodeString(fields[5])
	if e != nil {
		return "", errors.New("invalid handshake certificate encoding")
	}
	var envelope, tbs, algorithm, signature asn1.RawValue
	rest, e := asn1.Unmarshal(cert, &envelope)
	if e != nil || len(rest) != 0 || envelope.Tag != 16 || !envelope.IsCompound {
		return "", errors.New("invalid certificate envelope")
	}
	rest, e = asn1.Unmarshal(envelope.Bytes, &tbs)
	if e != nil || tbs.Tag != 16 || !tbs.IsCompound {
		return "", errors.New("invalid certificate body")
	}
	rest, e = asn1.Unmarshal(rest, &algorithm)
	if e != nil || algorithm.Tag != 16 || !algorithm.IsCompound {
		return "", errors.New("invalid certificate algorithm")
	}
	rest, e = asn1.Unmarshal(rest, &signature)
	if e != nil || len(rest) != 0 || signature.Tag != 3 || len(signature.Bytes) < 2 {
		return "", errors.New("invalid certificate signature")
	}
	return name, nil
}
