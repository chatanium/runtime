package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const MaxDevelopmentManifestBytes = 1 << 20
const MaxDevelopmentFiles = 4096
const DevelopmentWorkerManifestPath = "worker-manifest.json"

type DevelopmentWorkerInput struct {
	ArchiveDigest string `json:"archive_digest"`
	ArchiveBytes  int64  `json:"archive_bytes"`
}

type DevelopmentWorkerManifest struct {
	Version               uint32 `json:"version"`
	Digest                string `json:"digest,omitempty"`
	BaseBundleDigest      string `json:"base_bundle_digest"`
	Platform              string `json:"platform"`
	CPUBaseline           string `json:"cpu_baseline"`
	NativeABI             string `json:"native_abi"`
	WorkerControlVersion  uint32 `json:"worker_control_version"`
	RuntimeControlVersion uint32 `json:"runtime_control_version"`
	RuntimeConfigVersion  uint32 `json:"runtime_config_version"`
	Voice                 bool   `json:"voice"`
	Files                 []File `json:"files"`
}

type VerifiedDevelopmentWorker struct {
	Root, Digest, JobID string
	Manifest            DevelopmentWorkerManifest
}

// VerifyDevelopmentWorkerManifest checks only bounded integrity/compatibility
// metadata. The unprivileged preparer owns ELF parsing; unsigned metadata does
// not authenticate code or grant privileged-program replacement authority.
func VerifyDevelopmentWorkerManifest(raw []byte, base Manifest) (DevelopmentWorkerManifest, error) {
	var manifest DevelopmentWorkerManifest
	if len(raw) == 0 || len(raw) > MaxDevelopmentManifestBytes || !utf8.Valid(raw) {
		return manifest, errors.New("invalid development worker manifest bounds")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSON(decoder, 0, 16); err != nil {
		return manifest, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return manifest, errors.New("trailing development worker manifest")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	digest, err := canonicalDigest(raw, "chatanium-development-worker-v1")
	if err != nil {
		return manifest, err
	}
	if manifest.Version != 1 || !validDigest(manifest.Digest) || manifest.Digest != digest ||
		!validDigest(base.Digest) || manifest.BaseBundleDigest != base.Digest ||
		manifest.Platform != "linux/amd64" || manifest.Platform != base.Platform ||
		manifest.CPUBaseline != "amd64-v2" || manifest.CPUBaseline != base.CPUBaseline ||
		manifest.NativeABI != "EL9" || manifest.NativeABI != base.NativeABI ||
		manifest.WorkerControlVersion != 1 || manifest.RuntimeControlVersion != 2 || manifest.RuntimeConfigVersion != 2 {
		return manifest, errors.New("development worker identity or compatibility mismatch")
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxDevelopmentFiles {
		return manifest, errors.New("development worker inventory bound exceeded")
	}
	worker, libraries, notices := false, false, false
	previous := ""
	var total int64
	for _, file := range manifest.Files {
		if !validPath(file.Path) || file.Path <= previous || !validDigest(file.Digest) || file.Size < 0 || file.Size > MaxBundleBytes-total {
			return manifest, errors.New("invalid or unsorted development worker inventory")
		}
		previous = file.Path
		total += file.Size
		switch {
		case file.Path == "bin/chatanium-worker":
			if file.Mode != 0555 || file.Size == 0 {
				return manifest, errors.New("invalid development worker executable")
			}
			worker = true
		case strings.HasPrefix(file.Path, "bin/voice-runtime/lib/"):
			name := strings.TrimPrefix(file.Path, "bin/voice-runtime/lib/")
			if !manifest.Voice || name == "" || strings.Contains(name, "/") || file.Mode != 0555 || file.Size == 0 {
				return manifest, errors.New("invalid development native library")
			}
			libraries = true
		case strings.HasPrefix(file.Path, "licenses/voice/"):
			if file.Mode != 0444 {
				return manifest, errors.New("invalid development notice mode")
			}
			notices = true
		case strings.HasPrefix(file.Path, "provenance/voice/"):
			if file.Mode != 0444 {
				return manifest, errors.New("invalid development provenance mode")
			}
		default:
			return manifest, fmt.Errorf("development worker may not replace %q", file.Path)
		}
	}
	if !worker || (manifest.Voice && (!libraries || !notices)) || (!manifest.Voice && libraries) {
		return manifest, errors.New("incomplete development worker closure")
	}
	if manifest.Voice {
		loader := false
		for _, file := range base.Files {
			if file.Path == "lib/ld-linux-x86-64.so.2" && file.Mode == 0555 {
				loader = true
			}
		}
		if !loader {
			return manifest, errors.New("verified base does not provide the native worker loader")
		}
	}
	return manifest, nil
}
