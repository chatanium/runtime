package provision

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	PortableGuestArg            = "portable-v2"
	PortableCompiler            = "/chatanium-compiler"
	PortableWork                = "/chatanium-work"
	PortableCompilerFormat      = "gvx-erofs-v3-b4096"
	PortableFetchManifest  byte = 1
	PortableFetchBlob      byte = 2
	PortableResult         byte = 3
)

// PortableTask contains no host paths, endpoint URLs or credentials. It is
// sent only after the host has attested the offline preparation sandbox.
type PortableTask struct {
	PlanDigest   string        `json:"plan_digest"`
	Kind         string        `json:"kind"`
	Digest       string        `json:"digest"`
	Architecture string        `json:"architecture"`
	Limits       PrepareLimits `json:"limits"`
}

// PortableRecord is a bounded projection, not an OCI or GVX cache document.
// It crosses the sandbox boundary before any of the EROFS layer streams.
type PortableRecord struct {
	Version        string        `json:"version"`
	Architecture   string        `json:"architecture"`
	CacheFormat    string        `json:"cache_format"`
	PlanDigest     string        `json:"plan_digest"`
	SourceDigest   string        `json:"source_digest"`
	ManifestDigest string        `json:"manifest_digest"`
	Declaration    []byte        `json:"declaration"`
	ImageEnv       []string      `json:"image_env"`
	Entrypoint     []string      `json:"entrypoint"`
	Cmd            []string      `json:"cmd"`
	Workdir        string        `json:"workdir"`
	Layers         []LayerRecord `json:"layers"`
}

func (r PortableRecord) Validate(t PortableTask) error {
	if r.Version != PortableResourceVersion || r.Architecture != t.Architecture || r.PlanDigest != t.PlanDigest || r.SourceDigest != t.Digest || !ValidDigest(r.ManifestDigest) || len(r.Layers) == 0 || int64(len(r.Layers)) > t.Limits.DescriptorCount {
		return errors.New("portable image record binding mismatch")
	}
	if r.CacheFormat != PortableCompilerFormat && r.CacheFormat != "gvx-erofs-v3-b65536" {
		return errors.New("unsupported portable compiler block size")
	}
	layerSources := make(map[string]LayerRecord, len(r.Layers))
	remaining := t.Limits.InputBytes
	for _, l := range r.Layers {
		if !ValidDigest(l.Digest) || !ValidDigest(l.DiffID) || l.Size <= 0 || l.Size > t.Limits.InputBytes || !supportedLayerMedia(l.MediaType) {
			return errors.New("invalid portable layer projection")
		}
		if previous, ok := layerSources[l.Digest]; ok {
			if l != previous {
				return errors.New("conflicting repeated source layer")
			}
			continue
		}
		if l.Size > remaining {
			return errors.New("portable layer input byte bound exceeded")
		}
		remaining -= l.Size
		layerSources[l.Digest] = l
	}
	if int64(len(layerSources))*2+1 > t.Limits.Inodes {
		return errors.New("portable cache entries exceed bound")
	}
	var value any
	if err := gvxcontract.DecodeStrict(r.Declaration, int(t.Limits.JSONBytes), 32, &value); err != nil {
		return fmt.Errorf("portable module declaration: %w", err)
	}
	var m wire.ModuleManifest
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: 32}).Unmarshal(r.Declaration, &m); err != nil || m.ProtocolMajor != 2 {
		return errors.New("invalid portable module declaration")
	}
	if len(r.Entrypoint)+len(r.Cmd) == 0 || len(r.Entrypoint)+len(r.Cmd) > 256 || len(r.ImageEnv) > 256 {
		return errors.New("invalid portable module command or environment count")
	}
	entry := r.Cmd
	if len(r.Entrypoint) != 0 {
		entry = r.Entrypoint
	}
	if !portableGuestPath(entry[0]) || entry[0] == "/" || !portableGuestPath(r.Workdir) {
		return errors.New("portable module command and work directory must be absolute Linux paths")
	}
	for _, args := range [][]string{r.Entrypoint, r.Cmd} {
		for _, a := range args {
			if len(a) > 4096 || !utf8.ValidString(a) || strings.ContainsRune(a, 0) {
				return errors.New("invalid portable module argument")
			}
		}
	}
	seen := make(map[string]struct{}, len(r.ImageEnv))
	for _, e := range r.ImageEnv {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || len(e) > 4096 || !utf8.ValidString(e) || strings.ContainsRune(e, 0) || k == "FLEXMODULE_PLUGIN" || strings.HasPrefix(k, "PLUGIN_") || strings.HasPrefix(k, "CHATANIUM_GVX_") {
			return errors.New("invalid or reserved portable module environment")
		}
		if _, duplicate := seen[k]; duplicate {
			return errors.New("duplicate portable module environment variable")
		}
		for i, c := range k {
			if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
				return errors.New("invalid portable module environment name")
			}
		}
		seen[k] = struct{}{}
	}
	return nil
}

func portableGuestPath(p string) bool {
	return len(p) <= 4096 && utf8.ValidString(p) && path.IsAbs(p) && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}

// The trusted bridge will be a single-file bind under this reserved literal
// path. Prevent lower layers from aliasing its parent chain (including
// whiteouts); the pinned GVX compiler consumes the same Go tar member names.
func portableLayerPath(name string, kind byte) bool {
	const reserved = "run/chatanium-bootstrap"
	switch name {
	case "", ".", "run":
		return kind == tar.TypeDir
	case "..", ".wh.run", "run/.wh.chatanium-bootstrap", reserved:
		return false
	default:
		return !strings.HasPrefix(name, reserved+"/")
	}
}

func WritePortableSize(w io.Writer, n int64) error {
	if n < 0 {
		return errors.New("negative portable stream length")
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return writePortable(w, b[:])
}

func ReadPortableSize(r io.Reader, max int64) (int64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	if n := binary.BigEndian.Uint64(b[:]); max >= 0 && n <= uint64(max) {
		return int64(n), nil
	}
	return 0, errors.New("portable stream length exceeds bound")
}

func WritePortableJSON(w io.Writer, v any, max int64) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if int64(len(b)) > max {
		return errors.New("portable metadata exceeds bound")
	}
	if err = WritePortableSize(w, int64(len(b))); err != nil {
		return err
	}
	return writePortable(w, b)
}

func writePortable(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

func ReadPortableJSON(r io.Reader, out any, max int64) error {
	n, err := ReadPortableSize(r, max)
	if err != nil {
		return err
	}
	b := make([]byte, int(n))
	if _, err = io.ReadFull(r, b); err != nil {
		return err
	}
	return gvxcontract.DecodeStrict(b, int(max), 32, out)
}

// ReadPortableFetch reads the fixed-width remainder of a fetch after its opcode.
func ReadPortableFetch(r io.Reader, max int64) (string, int64, error) {
	var b [32]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", 0, err
	}
	n, err := ReadPortableSize(r, max)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(b[:]), n, nil
}

func writePortableFetch(w io.Writer, kind byte, digest string, size int64) error {
	if !ValidDigest(digest) {
		return errors.New("invalid portable fetch digest")
	}
	var b [41]byte
	b[0] = kind
	if _, err := hex.Decode(b[1:33], []byte(digest[7:])); err != nil {
		return err
	}
	binary.BigEndian.PutUint64(b[33:], uint64(size))
	return writePortable(w, b[:])
}

func (p *preparation) portableRegistry(in io.Reader, out io.Writer, digest string) (ImageRecord, error) {
	acquire := func(digest string, kind byte, size, bound int64) (string, error) {
		key := "blobs/sha256/" + digest[7:]
		if p.files[key] != "" {
			if size != 0 && p.sizes[key] != size {
				return "", errors.New("repeated descriptor size mismatch")
			}
			return key, nil
		}
		if err := writePortableFetch(out, kind, digest, size); err != nil {
			return "", err
		}
		n, err := ReadPortableSize(in, bound)
		if err != nil {
			return "", err
		}
		if n <= 0 || size != 0 && n != size {
			return "", errors.New("source response size mismatch")
		}
		body := &io.LimitedReader{R: in, N: n}
		got, err := p.save(key, body, n)
		if err != nil {
			return "", err
		}
		if body.N != 0 || got != digest {
			return "", errors.New("source response digest or length mismatch")
		}
		return key, nil
	}
	l := p.in.Limits
	key, err := acquire(digest, PortableFetchManifest, 0, l.JSONBytes)
	if err != nil {
		return ImageRecord{}, err
	}
	original, err := p.read(key)
	if err != nil {
		return ImageRecord{}, err
	}
	var head struct {
		MediaType string          `json:"mediaType"`
		Manifests json.RawMessage `json:"manifests"`
	}
	if err = json.Unmarshal(original, &head); err != nil {
		return ImageRecord{}, err
	}
	if head.MediaType == "" {
		head.MediaType = ociManifest
		if head.Manifests != nil {
			head.MediaType = ociIndex
		}
	}
	meta := func(d descriptor) ([]byte, error) {
		if d.Size <= 0 || d.Size > l.JSONBytes {
			return nil, errors.New("source descriptor exceeds JSON bound")
		}
		kind := PortableFetchBlob
		switch d.MediaType {
		case ociManifest, ociIndex, dockerManifest, dockerIndex:
			kind = PortableFetchManifest
		}
		key, err := acquire(d.Digest, kind, d.Size, l.JSONBytes)
		if err != nil {
			return nil, err
		}
		return p.read(key)
	}
	raw, err := p.resolve(original, head.MediaType, meta, 0)
	if err != nil {
		return ImageRecord{}, err
	}
	var selected manifest
	if err = decode(raw, l, &selected); err != nil {
		return ImageRecord{}, err
	}
	if err = checkManifest(selected, l); err != nil {
		return ImageRecord{}, err
	}
	for _, layer := range selected.Layers {
		if layer.Size <= 0 {
			return ImageRecord{}, errors.New("empty layer descriptor")
		}
		if _, err = acquire(layer.Digest, PortableFetchBlob, layer.Size, l.InputBytes); err != nil {
			return ImageRecord{}, err
		}
	}
	r, err := p.build(original, head.MediaType, raw, meta)
	r.SourceDigest = digest
	return r, err
}

// RunPortablePreparer is the guest entry point. The work filesystem and the
// compiler path are fixed at launch; the only input from the host is stdin.
func RunPortablePreparer(ctx context.Context, in io.Reader, out, diagnostics io.Writer) error {
	var t PortableTask
	if err := ReadPortableJSON(in, &t, TaskMaxBytes); err != nil {
		return err
	}
	if err := t.Limits.Validate(); err != nil {
		return err
	}
	if runtime.GOOS != "linux" || t.Architecture != runtime.GOARCH || t.Architecture != "amd64" && t.Architecture != "arm64" || !ValidDigest(t.PlanDigest) || !ValidDigest(t.Digest) {
		return errors.New("portable preparer task architecture or digest mismatch")
	}
	ctx, cancel := context.WithTimeout(ctx, t.Limits.Deadline)
	defer cancel()
	work, err := os.MkdirTemp(PortableWork, "image-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	block := os.Getpagesize()
	if block == 16384 || t.Architecture == "amd64" {
		block = 4096
	}
	format := "gvx-erofs-v3-b" + strconv.Itoa(block)
	if _, err = CacheBlockSize(format); err != nil {
		return err
	}
	p := &preparation{ctx: ctx, in: ApprovedImageInput{SourceKind: t.Kind, ArchiveDigest: t.Digest, Platform: "linux/" + t.Architecture, Limits: t.Limits}, dir: work, canonicalDir: work, portableArch: t.Architecture, files: map[string]string{}, sizes: map[string]int64{}, used: map[string]bool{}}
	var r ImageRecord
	switch t.Kind {
	case "registry":
		r, err = p.portableRegistry(in, out, t.Digest)
	case "oci-archive", "docker-archive":
		r, err = p.offline(in)
	default:
		return errors.New("unsupported portable image source")
	}
	if err != nil {
		return err
	}
	pr := PortableRecord{Version: PortableResourceVersion, Architecture: t.Architecture, CacheFormat: format, PlanDigest: t.PlanDigest, SourceDigest: r.SourceDigest, ManifestDigest: r.ManifestDigest, Declaration: r.Declaration, ImageEnv: r.ImageEnv, Entrypoint: r.Entrypoint, Cmd: r.Cmd, Workdir: r.Workdir, Layers: r.Layers}
	if pr.Workdir == "" {
		pr.Workdir = "/"
	}
	if err = pr.Validate(t); err != nil {
		return err
	}
	if err = p.canonical(&r); err != nil {
		return err
	}
	cache := filepath.Join(work, "compiled")
	cmd := exec.CommandContext(ctx, PortableCompiler, "load", "--quiet", "--keep-blobs=false", "--arch="+t.Architecture, "--cache-dir="+cache, "--input="+filepath.Join(work, "canonical.tar"),
		"--tune=oci.max_json_bytes="+strconv.FormatInt(max(t.Limits.JSONBytes, 64<<10), 10),
		"--tune=oci.max_blob_bytes="+strconv.FormatInt(max(t.Limits.InputBytes, 1<<20), 10),
		"--tune=oci.max_layer_bytes="+strconv.FormatInt(max(t.Limits.ExpandedBytes, 1<<20), 10),
		"--tune=oci.max_image_bytes="+strconv.FormatInt(max(t.Limits.ExpandedBytes, 1<<20), 10),
		"--tune=oci.max_entry_bytes="+strconv.FormatInt(max(t.Limits.ExpandedBytes, 1<<10), 10),
		"--tune=oci.max_entries="+strconv.FormatInt(t.Limits.Inodes, 10),
		"--tune=oci.max_archive_entries="+strconv.FormatInt(t.Limits.Inodes, 10),
		"--tune=oci.max_zstd_window_bytes="+strconv.FormatInt(max(min(t.Limits.MemoryBytes/2, 16<<30), 1<<20), 10))
	cmd.Dir = work
	cmd.Env = []string{"HOME=" + work, "TMPDIR=" + work}
	cmd.Stdout, cmd.Stderr = diagnostics, diagnostics
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("offline GVX compiler: %w", err)
	}
	if _, err = out.Write([]byte{PortableResult}); err != nil {
		return err
	}
	if err = WritePortableJSON(out, pr, t.Limits.JSONBytes*4); err != nil {
		return err
	}
	remaining := t.Limits.OutputBytes
	seen := make(map[string]bool, len(pr.Layers))
	for _, layer := range pr.Layers {
		if seen[layer.Digest] {
			continue
		}
		seen[layer.Digest] = true
		if err = p.check(); err != nil {
			return err
		}
		name := filepath.Join(cache, layer.Digest[7:]+"."+format+".erofs")
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		size, err := func() (int64, error) {
			defer f.Close()
			s, err := f.Stat()
			if err != nil {
				return 0, err
			}
			if !s.Mode().IsRegular() || s.Size() < int64(block) || s.Size()%int64(block) != 0 || s.Size() > remaining {
				return 0, errors.New("compiled layer exceeds output bound")
			}
			if err = WritePortableSize(out, s.Size()); err != nil {
				return 0, err
			}
			return io.CopyN(out, f, s.Size())
		}()
		if err != nil {
			return err
		}
		remaining -= size
	}
	return nil
}
