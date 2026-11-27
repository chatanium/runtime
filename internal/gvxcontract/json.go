package gvxcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// DecodeStrict rejects ambiguous JSON before populating out. Bounds cover the
// complete encoded value, including any base64 representation of byte fields.
func DecodeStrict(raw []byte, maxBytes, maxDepth int, out any) error {
	if maxBytes <= 0 || maxDepth <= 0 || len(raw) > maxBytes || !utf8.Valid(raw) {
		return errors.New("JSON exceeds bounds or is not UTF-8")
	}
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return errors.New("JSON destination must be nonnil pointer")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := scanJSON(d, t.Elem(), 0, maxDepth); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})
var anyJSONType = reflect.TypeOf((*any)(nil)).Elem()

func scanJSON(d *json.Decoder, t reflect.Type, depth, maxDepth int) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType {
		t = anyJSONType
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, compound := tok.(json.Delim)
	if !compound {
		return nil
	}
	if depth >= maxDepth {
		return errors.New("JSON nesting limit exceeded")
	}
	switch delim {
	case '{':
		fields := map[string]reflect.Type{}
		if t.Kind() == reflect.Struct {
			for i := range t.NumField() {
				f := t.Field(i)
				if f.PkgPath != "" {
					continue
				}
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name == "-" {
					continue
				}
				if name == "" {
					name = f.Name
				}
				fields[name] = f.Type
			}
		}
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid JSON key")
			}
			seen[key] = true
			child := reflect.TypeOf((*any)(nil)).Elem()
			switch t.Kind() {
			case reflect.Struct:
				var found bool
				child, found = fields[key]
				if !found {
					return fmt.Errorf("unknown JSON key %q", key)
				}
			case reflect.Map:
				child = t.Elem()
			case reflect.Interface:
			default:
				return errors.New("JSON object does not match destination")
			}
			if e = scanJSON(d, child, depth+1, maxDepth); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil {
			return e
		}
		if end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		child := reflect.TypeOf((*any)(nil)).Elem()
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			child = t.Elem()
		} else if t.Kind() != reflect.Interface {
			return errors.New("JSON array does not match destination")
		}
		for d.More() {
			if e := scanJSON(d, child, depth+1, maxDepth); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil {
			return e
		}
		if end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

// RootDigest hashes the exact legacy payload bytes; callers must not reserialize them.
func RootDigest(payload []byte) string {
	return rootDigest(RootDigestDomain, payload)
}

func rootDigest(domain string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(payload)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func DecodeRootManifest(m RootInitManifest, maxBytes, maxDepth int) (RootInitPayload, error) {
	var p RootInitPayload
	if maxBytes <= 0 || len(m.Payload) > maxBytes {
		return p, errors.New("root manifest exceeds bounds")
	}
	domain := RootDigestDomain
	if m.Digest != rootDigest(domain, m.Payload) {
		domain = portableRootDigestDomain
		if m.Digest != rootDigest(domain, m.Payload) {
			return p, errors.New("root manifest digest mismatch")
		}
	}
	if err := DecodeStrict(m.Payload, maxBytes, maxDepth, &p); err != nil {
		return p, err
	}
	if p.RuntimeInstallationID == "" || p.EpochID == "" || p.InstanceID == "" || p.IntentID == "" || p.Nonce == "" || len(p.Roots) != 3 {
		return p, errors.New("invalid root manifest binding")
	}
	switch p.Version {
	case RootPayloadVersion:
		if domain != RootDigestDomain || p.PortableLimits != nil {
			return p, errors.New("legacy root manifest cannot carry portable limits")
		}
	case PortableRootPayloadVersion:
		if domain != portableRootDigestDomain || p.PortableLimits == nil || !p.PortableLimits.valid() {
			return p, errors.New("invalid portable root limits or digest domain")
		}
		if !validPortableBinding(RootBinding{p.RuntimeInstallationID, p.EpochID, p.InstanceID, p.IntentID, p.Nonce}) {
			return p, errors.New("invalid portable root manifest binding")
		}
	default:
		return p, errors.New("unknown root payload version")
	}
	mounts := map[string]bool{}
	previous := ""
	for _, r := range p.Roots {
		if r.RootID == "" || r.RootID <= previous || mounts[r.Mountpoint] || r.Pre.Mode&^uint32(0777) != 0 || r.Target.Mode != 0700 || r.Target.UID == 0 || r.Target.GID == 0 {
			return p, errors.New("invalid root manifest entry")
		}
		switch r.RootID {
		case "persistent":
			if r.Mountpoint != PortablePersistentPath {
				return p, errors.New("invalid persistent mountpoint")
			}
		case "scratch":
			if r.Mountpoint != PortableScratchPath {
				return p, errors.New("invalid scratch mountpoint")
			}
		case "tmp":
			if r.Mountpoint != PortableTmpPath {
				return p, errors.New("invalid tmp mountpoint")
			}
		default:
			return p, errors.New("unknown root ID")
		}
		if r.Disposition != RootDispositionNew && r.Disposition != RootDispositionRetained || r.Disposition == RootDispositionRetained && r.Pre != r.Target {
			return p, errors.New("invalid root disposition")
		}
		if p.Version == PortableRootPayloadVersion && !validPortableRoot(r, p.Roots[0].Target) {
			return p, errors.New("invalid portable root initialization entry")
		}
		previous = r.RootID
		mounts[r.Mountpoint] = true
	}
	return p, nil
}
