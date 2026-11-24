package bundle

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

const PortableFormat = "portable-v2"
const GuestRungv ProgramID = "guest-rungv"

// PortableTarget reports the native engine target and minimum CPU baseline. It
// does not assert the current machine has the required hypervisor or features.
type PortableTarget struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Backend     string `json:"backend"`
	CPUBaseline string `json:"cpu_baseline"`
}

// PortableEngine identifies one original, attested upstream executable.
// NativeSignature is empty unless the original bytes use the recorded native
// signature. An ad-hoc HVF signature is not notarization or a Developer ID.
type PortableEngine struct {
	Release           string `json:"release"`
	Commit            string `json:"commit"`
	ArchiveDigest     string `json:"archive_digest"`
	AttestationDigest string `json:"attestation_digest"`
	ExecutableDigest  string `json:"executable_digest"`
	NativeSignature   string `json:"native_signature,omitempty"`
}

type PortableManifest struct {
	Format      string         `json:"format"`
	Digest      string         `json:"digest,omitempty"`
	Target      PortableTarget `json:"target"`
	Engine      PortableEngine `json:"engine"`
	GuestEngine PortableEngine `json:"guest_engine"`
	NativeVoice bool           `json:"native_voice"`
	Files       []File         `json:"files"`
}

type portableAssetLock struct {
	Backend          string `json:"backend"`
	CPUBaseline      string `json:"cpu_baseline"`
	ArchiveSHA256    string `json:"archive_sha256"`
	ExecutableSHA256 string `json:"executable_sha256"`
	NativeSignature  string `json:"native_signature"`
}

type portableReleaseLock struct {
	Release           string                       `json:"release"`
	Commit            string                       `json:"commit"`
	AttestationSHA256 string                       `json:"attestation_sha256"`
	AttestationSize   int64                        `json:"attestation_size"`
	Targets           map[string]portableAssetLock `json:"targets"`
}

//go:embed portable-release-lock.json
var portableLockJSON string

var portableLock = func() portableReleaseLock {
	var lock portableReleaseLock
	if err := json.Unmarshal([]byte(portableLockJSON), &lock); err != nil {
		panic(err)
	}
	return lock
}()

func (a portableAssetLock) engine() PortableEngine {
	return PortableEngine{
		Release: portableLock.Release, Commit: portableLock.Commit,
		ArchiveDigest: "sha256:" + a.ArchiveSHA256, AttestationDigest: "sha256:" + portableLock.AttestationSHA256,
		ExecutableDigest: "sha256:" + a.ExecutableSHA256, NativeSignature: a.NativeSignature,
	}
}

type portableProgram struct {
	id   ProgramID
	path string
}

func portablePrograms(os string) [5]portableProgram {
	suffix, guestRungv := "", "guest/rungv"
	if os == "windows" {
		suffix = ".exe"
	}
	if os == "linux" {
		guestRungv = "bin/rungv"
	}
	return [5]portableProgram{
		{Worker, "bin/chatanium-worker" + suffix}, {Rungv, "bin/rungv" + suffix},
		{GuestBridge, "guest/gvx-guest-bridge"}, {Preparer, "guest/gvx-preparer"}, {GuestRungv, guestRungv},
	}
}

// Program returns a verified inventory entry, whose Path is slash-delimited and
// relative to the code generation root. It does not open or execute that file.
func (m PortableManifest) Program(id ProgramID) (File, error) {
	for _, p := range portablePrograms(m.Target.OS) {
		if p.id == id {
			for _, f := range m.Files {
				if f.Path == p.path && f.Mode == 0555 {
					return f, nil
				}
			}
			break
		}
	}
	return File{}, fmt.Errorf("missing portable bundle program %q", id)
}

// portablePath restricts even an archive verified on a different build host to
// an unambiguous Win32/POSIX name (no device names, stream syntax or aliases).
func portablePath(name string) bool {
	if len(name) > 255 || !validPath(name) {
		return false
	}
	for part := range strings.SplitSeq(name, "/") {
		if len(part) > 100 || strings.HasSuffix(part, ".") {
			return false
		}
		for _, c := range part {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("._@+-", c) {
				return false
			}
		}
		base, _, _ := strings.Cut(part, ".")
		switch strings.ToUpper(base) {
		case "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
			"LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
			return false
		}
	}
	return true
}

// VerifyPortableManifest validates an inventory against the requested OS/ISA,
// both engine pins, and the portable data format. The verified outer launcher
// provides the trust anchor for the product-built programs, not this digest.
func VerifyPortableManifest(raw []byte, goos, goarch string) (PortableManifest, error) {
	var m PortableManifest
	fail := func(err error) (PortableManifest, error) { return PortableManifest{}, err }
	if len(raw) == 0 || len(raw) > MaxManifestBytes || !utf8.Valid(raw) {
		return fail(errors.New("invalid portable manifest size or UTF-8"))
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSON(d, 0, 32); err != nil {
		return fail(err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fail(errors.New("trailing portable manifest JSON"))
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return fail(err)
	}
	digest, err := canonicalDigest(raw, "chatanium-bundle-portable-v2")
	if err != nil {
		return fail(err)
	}
	if m.Format != PortableFormat || m.Digest != digest {
		return fail(errors.New("not a portable-v2 bundle or manifest digest mismatch"))
	}
	host, hostOK := portableLock.Targets[goos+"/"+goarch]
	guest, guestOK := portableLock.Targets["linux/"+goarch]
	if !hostOK || !guestOK || m.Target != (PortableTarget{OS: goos, Arch: goarch, Backend: host.Backend, CPUBaseline: host.CPUBaseline}) {
		return fail(fmt.Errorf("unsupported or wrong portable bundle target for %s/%s", goos, goarch))
	}
	if m.NativeVoice || m.Engine != host.engine() || m.GuestEngine != guest.engine() {
		return fail(errors.New("portable bundle engine release or native voice binding mismatch"))
	}
	if len(m.Files) == 0 || len(m.Files) > 4096 {
		return fail(errors.New("invalid portable file inventory size"))
	}
	var total int64
	files := make(map[string]File, len(m.Files))
	names := make(map[string]string, len(m.Files))
	programs := portablePrograms(goos)
	for _, f := range m.Files {
		if !portablePath(f.Path) || !validDigest(f.Digest) || f.Size < 0 || f.Size > MaxBundleBytes-total {
			return fail(fmt.Errorf("invalid portable file %q", f.Path))
		}
		mode := uint32(0444)
		for _, p := range programs {
			if f.Path == p.path {
				mode = 0555
				break
			}
		}
		if f.Mode != mode || (mode == 0555 && f.Size == 0) {
			return fail(fmt.Errorf("invalid portable file mode or executable size for %q", f.Path))
		}
		if _, ok := files[f.Path]; ok {
			return fail(fmt.Errorf("duplicate portable file %q", f.Path))
		}
		for name := f.Path; name != "."; name = path.Dir(name) {
			folded := strings.ToLower(name)
			if prev, ok := names[folded]; ok && prev != name {
				return fail(fmt.Errorf("portable path aliases %q and %q", prev, name))
			}
			if strings.EqualFold(name, "manifest.json") {
				return fail(errors.New("portable path aliases manifest"))
			}
			names[folded] = name
		}
		files[f.Path] = f
		total += f.Size
	}
	for name := range files {
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if _, ok := files[dir]; ok {
				return fail(fmt.Errorf("portable file is also a directory: %q", dir))
			}
		}
	}
	for _, p := range programs {
		f, ok := files[p.path]
		if !ok {
			return fail(fmt.Errorf("missing portable program %q", p.id))
		}
		if (p.id == Rungv && f.Digest != m.Engine.ExecutableDigest) ||
			(p.id == GuestRungv && f.Digest != m.GuestEngine.ExecutableDigest) {
			return fail(fmt.Errorf("portable %s executable digest mismatch", p.id))
		}
	}
	attestation := files["provenance/rungv.sigstore.json"]
	if attestation.Digest != m.Engine.AttestationDigest || attestation.Size != portableLock.AttestationSize ||
		files["sbom.json"].Size == 0 || files["licenses/CHATANIUM-LICENSE"].Size == 0 {
		return fail(errors.New("missing portable provenance, SBOM or notices"))
	}
	return m, nil
}
