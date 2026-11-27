// Package bundle verifies immutable, product-owned runtime distributions. It never
// embeds payloads or executes programs; initial release authentication is external.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

type Source interface {
	Manifest() ([]byte, error)
	Open() (io.ReadCloser, error)
}
type ProgramID string

const (
	Worker      ProgramID = "worker"
	Stage       ProgramID = "stage"
	GuestBridge ProgramID = "guest-bridge"
	Preparer    ProgramID = "preparer"
	Rungv       ProgramID = "rungv"
	MkfsXFS     ProgramID = "mkfs-xfs"
	XFSQuota    ProgramID = "xfs-quota"
	IP          ProgramID = "ip"
	IPTables    ProgramID = "iptables"
	IP6Tables   ProgramID = "ip6tables"
	Conntrack   ProgramID = "conntrack"
	UserAdd     ProgramID = "useradd"
	GroupAdd    ProgramID = "groupadd"
	UserDel     ProgramID = "userdel"
	GroupDel    ProgramID = "groupdel"
)
const MaxManifestBytes = 8 << 20
const MaxBundleBytes int64 = 4 << 30
const HostfsMetadataVersion = "GVXMETA4"

var programIDs = []ProgramID{Worker, Stage, GuestBridge, Preparer, Rungv, MkfsXFS, XFSQuota, IP, IPTables, IP6Tables, Conntrack, UserAdd, GroupAdd, UserDel, GroupDel}

type File struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}
type Program struct {
	ID                 ProgramID `json:"id"`
	Path               string    `json:"path"`
	Interpreter        string    `json:"interpreter,omitempty"`
	LibraryDirectories []string  `json:"library_directories,omitempty"`
	Environment        []string  `json:"environment,omitempty"`
}
type Provenance struct {
	Source          string   `json:"source"`
	SourceDigest    string   `json:"source_digest"`
	ArtifactDigest  string   `json:"artifact_digest"`
	RepositoryID    string   `json:"repository_id,omitempty"`
	OwnerID         string   `json:"owner_id,omitempty"`
	Signer          string   `json:"signer,omitempty"`
	Workflow        string   `json:"workflow,omitempty"`
	SourceRef       string   `json:"source_ref,omitempty"`
	VerifierVersion string   `json:"verifier_version,omitempty"`
	PolicyPath      string   `json:"policy_path,omitempty"`
	ResultPath      string   `json:"result_path,omitempty"`
	Notices         []string `json:"notices"`
}
type Manifest struct {
	Version                uint32       `json:"version"`
	Digest                 string       `json:"digest,omitempty"`
	Platform               string       `json:"platform"`
	CPUBaseline            string       `json:"cpu_baseline"`
	NativeABI              string       `json:"native_abi"`
	FormatVersions         []uint32     `json:"format_versions"`
	SchemaVersions         []uint32     `json:"schema_versions"`
	HostfsMetadataVersions []string     `json:"hostfs_metadata_versions"`
	Files                  []File       `json:"files"`
	Programs               []Program    `json:"programs"`
	Provenance             []Provenance `json:"provenance"`
	SBOMPath               string       `json:"sbom_path"`
	LicenseDirectory       string       `json:"license_directory"`
}
type Verified struct {
	Root, Digest string
	Manifest     Manifest
}

func validPath(s string) bool {
	return s != "" && s != "." && !strings.ContainsAny(s, "\\\x00") && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../")
}
func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil && strings.ToLower(s) == s
}

// uniqueJSON rejects duplicate keys, including nested objects, before typed decode.
func uniqueJSON(d *json.Decoder, depth, maxDepth int) error {
	if depth > maxDepth {
		return errors.New("bundle JSON nesting exceeds limit")
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || keys[s] {
					return errors.New("duplicate bundle JSON key")
				}
				keys[s] = true
				if e = uniqueJSON(d, depth+1, maxDepth); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = uniqueJSON(d, depth+1, maxDepth); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid bundle JSON delimiter")
		}
		_, e = d.Token()
		return e
	}
	return nil
}

// ManifestDigest hashes domain-separated canonical JSON with the digest member
// absent. Map key ordering is lexical; generated input uses the same encoding.
func ManifestDigest(raw []byte) (string, error) { return canonicalDigest(raw, "chatanium-bundle-v1") }
func canonicalDigest(raw []byte, domain string) (string, error) {
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if e := decoder.Decode(&fields); e != nil {
		return "", e
	}
	if _, e := decoder.Token(); e != io.EOF {
		return "", errors.New("trailing bundle digest payload")
	}
	delete(fields, "digest")
	payload, e := json.Marshal(fields)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(payload)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func VerifyManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > MaxManifestBytes || !utf8.Valid(raw) {
		return m, errors.New("invalid bundle manifest size or UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if e := uniqueJSON(d, 0, 32); e != nil {
		return m, e
	}
	if _, e := d.Token(); e != io.EOF {
		return m, errors.New("trailing bundle JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&m); e != nil {
		return m, e
	}
	digest, e := ManifestDigest(raw)
	if e != nil {
		return m, e
	}
	if m.Version != 1 || m.Platform != "linux/amd64" || m.CPUBaseline != "amd64-v2" || m.NativeABI != "EL9" || !validDigest(m.Digest) || m.Digest != digest {
		return m, errors.New("unsupported bundle or manifest digest mismatch")
	}
	if len(m.FormatVersions) != 1 || m.FormatVersions[0] != 1 || len(m.SchemaVersions) != 1 || m.SchemaVersions[0] != 1 || len(m.HostfsMetadataVersions) != 1 || m.HostfsMetadataVersions[0] != HostfsMetadataVersion {
		return m, errors.New("unsupported bundle data compatibility")
	}
	files := map[string]File{}
	var total int64
	for _, f := range m.Files {
		if !validPath(f.Path) || f.Path == "manifest.json" || !validDigest(f.Digest) || f.Size < 0 || f.Size > MaxBundleBytes-total || (f.Mode != 0444 && f.Mode != 0555) {
			return m, fmt.Errorf("invalid bundle file %q", f.Path)
		}
		if _, ok := files[f.Path]; ok {
			return m, errors.New("duplicate bundle file")
		}
		files[f.Path] = f
		total += f.Size
	}
	if len(files) == 0 || len(files) > 50000 || !validPath(m.LicenseDirectory) {
		return m, errors.New("invalid bundle inventory")
	}
	if _, ok := files[m.SBOMPath]; !ok {
		return m, errors.New("missing bundle SBOM")
	}
	dirs := map[string]bool{}
	for p := range files {
		for p = path.Dir(p); p != "."; p = path.Dir(p) {
			dirs[p] = true
		}
	}
	if !dirs[m.LicenseDirectory] {
		return m, errors.New("missing bundle licenses")
	}
	programs := map[ProgramID]bool{}
	for _, p := range m.Programs {
		allowed := false
		for _, id := range programIDs {
			allowed = allowed || p.ID == id
		}
		f, ok := files[p.Path]
		if !allowed || programs[p.ID] || !ok || f.Mode != 0555 {
			return m, fmt.Errorf("invalid bundle program %q", p.ID)
		}
		programs[p.ID] = true
		if p.Interpreter != "" {
			if f, ok = files[p.Interpreter]; !ok || f.Mode != 0555 {
				return m, errors.New("missing program loader")
			}
		}
		for _, s := range p.LibraryDirectories {
			if !validPath(s) || !dirs[s] {
				return m, errors.New("missing library directory")
			}
		}
		for _, s := range p.Environment {
			if !strings.HasPrefix(s, "XTABLES_LIBDIR=") || !dirs[strings.TrimPrefix(s, "XTABLES_LIBDIR=")] {
				return m, errors.New("invalid fixed program environment")
			}
		}
	}
	if len(programs) != len(programIDs) {
		return m, errors.New("incomplete runtime program closure")
	}
	if len(m.Provenance) == 0 {
		return m, errors.New("missing bundle provenance")
	}
	for _, p := range m.Provenance {
		if p.Source == "" || p.SourceDigest == "" || !validDigest(p.ArtifactDigest) || len(p.Notices) == 0 {
			return m, errors.New("incomplete bundle provenance")
		}
		for _, s := range append(append([]string{}, p.Notices...), p.PolicyPath, p.ResultPath) {
			if s != "" {
				if _, ok := files[s]; !ok {
					return m, fmt.Errorf("missing provenance member %s", s)
				}
			}
		}
	}
	return m, nil
}

func (v Verified) Program(id ProgramID) (Program, error) {
	for _, p := range v.Manifest.Programs {
		if p.ID == id {
			return p, nil
		}
	}
	return Program{}, fmt.Errorf("unknown bundle program %q", id)
}
