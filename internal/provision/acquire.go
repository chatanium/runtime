package provision

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/klauspost/compress/zstd"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

// Task is delivered on a private stdin pipe, never argv/environment/journal.
// Directory names are selected by the root manager and quota-isolated beforehand.
type Task struct {
	Input              ApprovedImageInput     `json:"input,omitempty,omitzero"`
	Directory          string                 `json:"directory,omitempty"`
	CanonicalDirectory string                 `json:"canonical_directory,omitempty"`
	Credential         []byte                 `json:"credential,omitempty"`
	RebuildRecordID    string                 `json:"rebuild_record_id,omitempty"`
	DevelopmentWorker  *DevelopmentWorkerTask `json:"development_worker,omitempty"`
}

const TaskMaxBytes = 1 << 20

func WriteTask(w io.Writer, t Task) error {
	b, e := json.Marshal(t)
	if e != nil {
		return e
	}
	if len(b) > TaskMaxBytes {
		return errors.New("task exceeds bound")
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, e = w.Write(n[:]); e != nil {
		return e
	}
	_, e = w.Write(b)
	return e
}
func readTask(r io.Reader) (Task, error) {
	var t Task
	var n [4]byte
	if _, e := io.ReadFull(r, n[:]); e != nil {
		return t, e
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > TaskMaxBytes {
		return t, errors.New("invalid task length")
	}
	b := make([]byte, size)
	if _, e := io.ReadFull(r, b); e != nil {
		return t, e
	}
	e := gvxcontract.DecodeStrict(b, TaskMaxBytes, 32, &t)
	return t, e
}
func RunPreparer(ctx context.Context, in io.Reader, out, diagnostics io.Writer) error {
	t, e := readTask(in)
	if e != nil {
		return e
	}
	if t.DevelopmentWorker != nil {
		if t.Input != (ApprovedImageInput{}) || t.Directory != "" || t.CanonicalDirectory != "" || len(t.Credential) != 0 || t.RebuildRecordID != "" {
			return errors.New("mixed development/image preparation task")
		}
		return runDevelopmentWorker(ctx, *t.DevelopmentWorker, in, out)
	}
	if e = t.Input.Validate(); e != nil {
		return e
	}
	if !filepath.IsAbs(t.Directory) || filepath.Clean(t.Directory) != t.Directory {
		return errors.New("invalid private task directory")
	}
	ctx, cancel := context.WithTimeout(ctx, t.Input.Limits.Deadline)
	defer cancel()
	p := &preparation{ctx: ctx, in: t.Input, dir: t.Directory, canonicalDir: t.CanonicalDirectory, files: map[string]string{}, sizes: map[string]int64{}, used: map[string]bool{}}
	var r ImageRecord
	if t.RebuildRecordID != "" {
		if len(t.Credential) != 0 || !ValidDigest(t.RebuildRecordID) {
			return errors.New("invalid retained source task")
		}
		r, e = p.retained(t.RebuildRecordID)
	} else {
		switch t.Input.SourceKind {
		case "registry":
			r, e = p.registry(t.Credential)
		case "oci-archive", "docker-archive":
			r, e = p.offline(in)
		}
	}
	for i := range t.Credential {
		t.Credential[i] = 0
	}
	if e != nil {
		return e
	}
	originalCanonical := r.CanonicalArchiveDigest
	if e = p.canonical(&r); e != nil {
		return e
	}
	if t.RebuildRecordID != "" && r.CanonicalArchiveDigest != originalCanonical {
		return errors.New("retained source canonical identity changed")
	}
	r.ID = RecordID(r)
	if e = ValidateRecord(r, t.Input.Limits); e != nil {
		return e
	}
	if t.RebuildRecordID == "" {
		metadata := SourceMetadata{Chain: p.chain, Members: map[string]string{}}
		for k, v := range p.files {
			metadata.Members[k] = filepath.Base(v)
		}
		meta, e := json.Marshal(metadata)
		if e != nil {
			return e
		}
		if int64(len(meta)) > p.in.Limits.JSONBytes*int64(p.in.Limits.IndexDepth+2) {
			return errors.New("source metadata exceeds bound")
		}
		if e = os.WriteFile(filepath.Join(p.dir, "source.json"), meta, 0600); e != nil {
			return e
		}
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if int64(len(raw)) > t.Input.Limits.JSONBytes*8 {
		return errors.New("record exceeds bound")
	}
	_, e = out.Write(raw)
	return e
}

type preparation struct {
	ctx                                  context.Context
	in                                   ApprovedImageInput
	dir, canonicalDir                    string
	portableArch                         string
	files                                map[string]string
	sizes                                map[string]int64
	used                                 map[string]bool
	chain                                [][]byte
	diffs                                map[string]string
	input, expanded, inodes, descriptors int64
}

func (p *preparation) arch() string {
	if p.portableArch != "" {
		return p.portableArch
	}
	return "amd64"
}

func (p *preparation) check() error {
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	default:
		return nil
	}
}
func (p *preparation) save(key string, r io.Reader, max int64) (string, error) {
	if e := p.check(); e != nil {
		return "", e
	}
	if _, ok := p.files[key]; ok {
		return "", errors.New("duplicate source object")
	}
	p.inodes++
	if p.inodes > p.in.Limits.Inodes {
		return "", errors.New("inode bound exceeded")
	}
	f, e := os.CreateTemp(p.dir, "blob-")
	if e != nil {
		return "", e
	}
	h := sha256.New()
	if remaining := p.in.Limits.InputBytes - p.input; max > remaining {
		max = remaining
	}
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, max+1))
	if e == nil && n > max {
		e = errors.New("source object exceeds bound")
	}
	p.input += n
	if p.input > p.in.Limits.InputBytes {
		e = errors.New("aggregate source bound exceeded")
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return "", e
	}
	p.files[key] = f.Name()
	p.sizes[key] = n
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func (p *preparation) read(key string) ([]byte, error) {
	f, ok := p.files[key]
	if !ok {
		return nil, fmt.Errorf("missing image member %s", key)
	}
	if p.sizes[key] > p.in.Limits.JSONBytes {
		return nil, errors.New("JSON object exceeds bound")
	}
	p.used[key] = true
	return os.ReadFile(f)
}
func safeName(s string) bool {
	return s != "" && s != "." && !path.IsAbs(s) && !strings.ContainsAny(s, "\\\x00") && path.Clean(s) == s && !strings.HasPrefix(s, "../")
}
func archiveName(s string) (string, error) {
	if s == "" || path.IsAbs(s) || strings.ContainsAny(s, "\\\x00") {
		return "", errors.New("unsafe archive name")
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." {
			return "", errors.New("archive traversal")
		}
	}
	n := path.Clean(s)
	if n != "." && !safeName(n) {
		return "", errors.New("unsafe archive name")
	}
	return n, nil
}
func (p *preparation) offline(r io.Reader) (ImageRecord, error) {
	var zero ImageRecord
	h := sha256.New()
	var archive *os.File
	var copyTo io.Writer = h
	if p.portableArch == "" {
		var e error
		archive, e = os.OpenFile(filepath.Join(p.dir, "source.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return zero, e
		}
		defer archive.Close()
		copyTo = io.MultiWriter(h, archive)
	}
	limited := &io.LimitedReader{R: io.TeeReader(r, copyTo), N: p.in.Limits.InputBytes + 1}
	tr := tar.NewReader(limited)
	seen := map[string]bool{}
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return zero, e
		}
		n, e := archiveName(hdr.Name)
		if e != nil || seen[n] || hdr.Size < 0 {
			return zero, errors.New("unsafe or duplicate archive name")
		}
		if int64(len(seen)) >= p.in.Limits.Inodes {
			return zero, errors.New("archive entry inode bound exceeded")
		}
		seen[n] = true
		if hdr.Typeflag == tar.TypeDir {
			if hdr.Size != 0 || hdr.Linkname != "" || len(hdr.PAXRecords) != 0 {
				return zero, errors.New("invalid archive directory")
			}
			continue
		}
		if n == "." || hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA || len(hdr.PAXRecords) != 0 || hdr.Linkname != "" {
			return zero, errors.New("unsupported archive entry")
		}
		if _, e = p.save(n, tr, hdr.Size); e != nil {
			return zero, e
		}
	}
	// Hash the complete source, including padding, rejecting trailing nonzero data.
	tail := make([]byte, 32<<10)
	for {
		n, e := limited.Read(tail)
		for _, b := range tail[:n] {
			if b != 0 {
				return zero, errors.New("trailing archive content")
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return zero, e
		}
	}
	if limited.N <= 0 {
		return zero, errors.New("archive input exceeds bound")
	}
	source := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if source != p.in.ArchiveDigest {
		return zero, errors.New("archive digest mismatch")
	}
	if archive != nil {
		if e := archive.Sync(); e != nil {
			return zero, e
		}
	}
	var rec ImageRecord
	var e error
	if p.in.SourceKind == "oci-archive" {
		rec, e = p.ociArchive()
	} else {
		rec, e = p.dockerArchive()
	}
	if e != nil {
		return zero, e
	}
	for key := range p.files {
		if !p.used[key] {
			return zero, fmt.Errorf("unknown archive member %s", key)
		}
	}
	for n := range seen {
		if n == "." {
			continue
		}
		if _, ok := p.files[n]; ok {
			continue
		}
		valid := false
		for key := range p.files {
			if strings.HasPrefix(key, n+"/") {
				valid = true
				break
			}
		}
		if !valid {
			return zero, errors.New("unknown archive directory")
		}
	}
	rec.SourceDigest = source
	return rec, nil
}
func (p *preparation) ociArchive() (ImageRecord, error) {
	var z ImageRecord
	b, e := p.read("oci-layout")
	if e != nil {
		return z, e
	}
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	if e = decode(b, p.in.Limits, &layout); e != nil || layout.Version != "1.0.0" {
		return z, errors.New("invalid OCI layout")
	}
	root, e := p.read("index.json")
	if e != nil {
		return z, e
	}
	fetch := func(d descriptor) ([]byte, error) {
		b, e := p.read("blobs/sha256/" + strings.TrimPrefix(d.Digest, "sha256:"))
		if e != nil {
			return nil, e
		}
		if int64(len(b)) != d.Size || Digest(b) != d.Digest {
			return nil, errors.New("descriptor byte mismatch")
		}
		return b, nil
	}
	raw, e := p.resolve(root, ociIndex, fetch, 0)
	if e != nil {
		return z, e
	}
	record, e := p.build(root, ociIndex, raw, fetch)
	if e != nil {
		return z, e
	}
	count := int64(0)
	if e = p.reachableOCI(root, ociIndex, 0, &count, map[string]bool{}); e != nil {
		return z, e
	}
	return record, nil
}
func (p *preparation) resolve(raw []byte, media string, fetch func(descriptor) ([]byte, error), depth int64) ([]byte, error) {
	if p.portableArch == "" {
		p.chain = append(p.chain, append([]byte(nil), raw...))
	}
	if depth > p.in.Limits.IndexDepth {
		return nil, errors.New("index depth exceeded")
	}
	if media == ociManifest || media == dockerManifest {
		var m manifest
		if e := decode(raw, p.in.Limits, &m); e != nil {
			return nil, e
		}
		if m.MediaType != "" && m.MediaType != media {
			return nil, errors.New("manifest media descriptor mismatch")
		}
		if e := checkManifest(m, p.in.Limits); e != nil {
			return nil, e
		}
		cfg, e := fetch(m.Config)
		if e != nil {
			return nil, e
		}
		if int64(len(cfg)) != m.Config.Size || Digest(cfg) != m.Config.Digest {
			return nil, errors.New("platform config descriptor mismatch")
		}
		if p.portableArch == "" {
			p.chain = append(p.chain, append([]byte(nil), cfg...))
		}
		var c imageConfig
		if e = decode(cfg, p.in.Limits, &c); e != nil {
			return nil, e
		}
		if c.OS != "linux" || c.Architecture != p.arch() || !imageVariant(p.arch(), c.Variant, p.portableArch != "") {
			return nil, errNoPlatform
		}
		return raw, nil
	}
	if media != ociIndex && media != dockerIndex {
		return nil, errors.New("unsupported root media")
	}
	var idx index
	if e := decode(raw, p.in.Limits, &idx); e != nil {
		return nil, e
	}
	if idx.SchemaVersion != 2 || idx.Subject != nil || idx.ArtifactType != "" || idx.MediaType != "" && idx.MediaType != media {
		return nil, errors.New("invalid image index")
	}
	var candidates []descriptor
	for _, d := range idx.Manifests {
		p.descriptors++
		if p.descriptors > p.in.Limits.DescriptorCount {
			return nil, errors.New("descriptor count exceeded")
		}
		if e := checkDescriptor(d, p.in.Limits); e != nil {
			return nil, e
		}
		if d.MediaType != ociIndex && d.MediaType != dockerIndex && d.MediaType != ociManifest && d.MediaType != dockerManifest {
			return nil, errors.New("unsupported index member")
		}
		if d.Platform == nil || d.Platform.OS == "linux" && d.Platform.Architecture == p.arch() && imageVariant(p.arch(), d.Platform.Variant, p.portableArch != "") && d.Platform.OSVersion == "" && len(d.Platform.OSFeatures) == 0 {
			candidates = append(candidates, d)
		}
	}
	var selected []byte
	for _, d := range candidates {
		b, e := fetch(d)
		if e != nil {
			return nil, e
		}
		if Digest(b) != d.Digest || int64(len(b)) != d.Size {
			return nil, errors.New("selected descriptor mismatch")
		}
		candidate, e := p.resolve(b, d.MediaType, fetch, depth+1)
		if errors.Is(e, errNoPlatform) {
			if d.Platform != nil {
				return nil, errors.New("descriptor/config platform mismatch")
			}
			continue
		}
		if e != nil {
			return nil, e
		}
		if selected != nil {
			return nil, errors.New("ambiguous Linux image architecture")
		}
		selected = candidate
	}
	if selected == nil {
		return nil, errNoPlatform
	}
	return selected, nil
}

var errNoPlatform = errors.New("missing image for requested Linux architecture")

func (p *preparation) build(original []byte, media string, raw []byte, fetch func(descriptor) ([]byte, error)) (ImageRecord, error) {
	r := ImageRecord{Version: 1, Revision: Revision(p.in), SourceKind: p.in.SourceKind, SourceRef: p.in.SourceRef, OriginalMediaType: media, Original: original, OriginalDigest: Digest(original), Manifest: raw, ManifestDigest: Digest(raw)}
	var m manifest
	if e := decode(raw, p.in.Limits, &m); e != nil {
		return r, e
	}
	if e := checkManifest(m, p.in.Limits); e != nil {
		return r, e
	}
	cfg, e := fetch(m.Config)
	if e != nil {
		return r, e
	}
	if Digest(cfg) != m.Config.Digest || int64(len(cfg)) != m.Config.Size {
		return r, errors.New("config bytes mismatch")
	}
	c, d, e := parseImageConfig(cfg, p.in.Limits, len(m.Layers), p.arch(), p.portableArch != "")
	if e != nil {
		return r, e
	}
	r.Config = cfg
	r.ConfigDigest = Digest(cfg)
	r.Declaration = d
	r.DeclarationDigest = Digest(d)
	r.ImageEnv = c.Config.Env
	r.Entrypoint = c.Config.Entrypoint
	r.Cmd = c.Config.Cmd
	r.Workdir = c.Config.WorkingDir
	r.ExecutionRef = ExecutionRef(r.ManifestDigest)
	for i, d := range m.Layers {
		key := "blobs/sha256/" + d.Digest[7:]
		if _, ok := p.files[key]; !ok {
			return r, errors.New("missing acquired layer")
		}
		p.used[key] = true
		if p.sizes[key] != d.Size {
			return r, errors.New("layer descriptor size mismatch")
		}
		diff, e := p.layer(key, d.MediaType)
		if e != nil {
			return r, e
		}
		if diff != c.RootFS.DiffIDs[i] {
			return r, errors.New("layer diffID mismatch")
		}
		r.Layers = append(r.Layers, LayerRecord{d.Digest, diff, d.MediaType, d.Size})
	}
	return r, nil
}
func (p *preparation) layer(key, media string) (string, error) {
	if d := p.diffs[key]; d != "" {
		return d, nil
	}
	f, e := os.Open(p.files[key])
	if e != nil {
		return "", e
	}
	defer f.Close()
	compressed := sha256.New()
	source := io.TeeReader(f, compressed)
	var r io.Reader = source
	var closeFn func() error
	switch {
	case strings.HasSuffix(media, "+gzip") || strings.HasSuffix(media, ".gzip"):
		g, e := gzip.NewReader(source)
		if e != nil {
			return "", e
		}
		r = g
		closeFn = g.Close
	case strings.HasSuffix(media, "+zstd"):
		z, e := zstd.NewReader(source, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(p.in.Limits.MemoryBytes/2)))
		if e != nil {
			return "", e
		}
		r = z
		closeFn = func() error { z.Close(); return nil }
	}
	if closeFn != nil {
		defer closeFn()
	}
	h := sha256.New()
	remaining := p.in.Limits.ExpandedBytes - p.expanded
	lr := &io.LimitedReader{R: io.TeeReader(r, h), N: remaining + 1}
	tr := tar.NewReader(lr)
	for {
		header, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
		p.inodes++
		if p.inodes > p.in.Limits.Inodes {
			return "", errors.New("expanded inode bound exceeded")
		}
		name := strings.TrimPrefix(strings.TrimSuffix(header.Name, "/"), "./")
		if name != "" && name != "." && !safeName(name) {
			return "", errors.New("unsafe layer path")
		}
		if p.portableArch != "" && !portableLayerPath(name, header.Typeflag) {
			return "", errors.New("image layer alters the reserved portable bridge namespace")
		}
		if _, e = io.Copy(io.Discard, tr); e != nil {
			return "", e
		}
		if e = p.check(); e != nil {
			return "", e
		}
	}
	tail := make([]byte, 32<<10)
	for {
		n, e := lr.Read(tail)
		for _, b := range tail[:n] {
			if b != 0 {
				return "", errors.New("nonzero trailing layer bytes")
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	n := remaining + 1 - lr.N
	p.expanded += n
	if n > remaining {
		return "", errors.New("aggregate expanded layer bound exceeded")
	}
	if _, e = io.Copy(io.Discard, source); e != nil {
		return "", e
	}
	got := "sha256:" + hex.EncodeToString(compressed.Sum(nil))
	if strings.HasPrefix(key, "blobs/sha256/") && got != "sha256:"+strings.TrimPrefix(key, "blobs/sha256/") {
		return "", errors.New("compressed layer digest mismatch")
	}
	diff := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if p.diffs == nil {
		p.diffs = map[string]string{}
	}
	p.diffs[key] = diff
	return diff, nil
}
func (p *preparation) dockerArchive() (ImageRecord, error) {
	var z ImageRecord
	original, e := p.read("manifest.json")
	if e != nil {
		return z, e
	}
	var entries []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	if e = decode(original, p.in.Limits, &entries); e != nil {
		return z, e
	}
	if len(entries) != 1 {
		return z, errors.New("Docker save must contain one concrete image")
	}
	entry := entries[0]
	if !safeName(entry.Config) || int64(len(entry.Layers)) > p.in.Limits.DescriptorCount {
		return z, errors.New("invalid Docker save manifest")
	}
	cfg, e := p.read(entry.Config)
	if e != nil {
		return z, e
	}
	cfgDigest := Digest(cfg)
	if path.Base(entry.Config) != cfgDigest[7:]+".json" && entry.Config != "blobs/sha256/"+cfgDigest[7:] {
		return z, errors.New("Docker config name mismatch")
	}
	c, _, e := parseImageConfig(cfg, p.in.Limits, len(entry.Layers), p.arch(), p.portableArch != "")
	if e != nil {
		return z, e
	}
	m := manifest{SchemaVersion: 2, MediaType: ociManifest, Config: descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: cfgDigest, Size: int64(len(cfg))}}
	for i, key := range entry.Layers {
		if !safeName(key) {
			return z, errors.New("invalid Docker layer name")
		}
		if _, ok := p.files[key]; !ok {
			return z, errors.New("missing Docker layer")
		}
		p.used[key] = true
		diff, e := p.layer(key, "application/vnd.oci.image.layer.v1.tar")
		if e != nil {
			return z, e
		}
		if diff != c.RootFS.DiffIDs[i] {
			return z, errors.New("Docker layer diffID mismatch")
		}
		dest := "blobs/sha256/" + diff[7:]
		p.files[dest] = p.files[key]
		p.sizes[dest] = p.sizes[key]
		p.used[dest] = true
		p.diffs[dest] = diff
		m.Layers = append(m.Layers, descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: diff, Size: p.sizes[key]})
	}
	if e = p.dockerAux(entry.Layers); e != nil {
		return z, e
	}
	raw, e := json.Marshal(m)
	if e != nil {
		return z, e
	}
	fetch := func(d descriptor) ([]byte, error) {
		if d.Digest == cfgDigest {
			return cfg, nil
		}
		return nil, errors.New("unexpected Docker descriptor")
	}
	return p.build(original, "application/vnd.chatanium.docker-save.manifest.v1+json", raw, fetch)
}
func (p *preparation) canonical(r *ImageRecord) error {
	blobs := map[string][]byte{"blobs/sha256/" + r.ManifestDigest[7:]: r.Manifest, "blobs/sha256/" + r.ConfigDigest[7:]: r.Config, "oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`)}
	var m manifest
	if e := decode(r.Manifest, p.in.Limits, &m); e != nil {
		return e
	}
	media := m.MediaType
	if media == "" {
		media = ociManifest
		if m.Config.MediaType == "application/vnd.docker.container.image.v1+json" {
			media = dockerManifest
		}
	}
	idx := index{SchemaVersion: 2, MediaType: ociIndex, Manifests: []descriptor{{MediaType: media, Digest: r.ManifestDigest, Size: int64(len(r.Manifest)), Platform: &platform{OS: "linux", Architecture: p.arch()}, Annotations: map[string]string{"io.containerd.image.name": Annotation(r.ManifestDigest)}}}}
	b, e := json.Marshal(idx)
	if e != nil {
		return e
	}
	blobs["index.json"] = b
	names := make([]string, 0, len(blobs)+len(r.Layers))
	for n := range blobs {
		names = append(names, n)
	}
	for _, l := range r.Layers {
		n := "blobs/sha256/" + l.Digest[7:]
		if _, ok := blobs[n]; !ok {
			blobs[n] = nil
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if !filepath.IsAbs(p.canonicalDir) || filepath.Clean(p.canonicalDir) != p.canonicalDir {
		return errors.New("invalid canonical directory")
	}
	f, e := os.OpenFile(filepath.Join(p.canonicalDir, "canonical.tar"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	h := sha256.New()
	bounded := &limitWriter{w: io.MultiWriter(f, h), remaining: p.in.Limits.OutputBytes}
	tw := tar.NewWriter(bounded)
	for _, n := range names {
		if e = p.check(); e != nil {
			break
		}
		data := blobs[n]
		size := int64(len(data))
		if data == nil {
			size = p.sizes[n]
		}
		e = tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: size, Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR})
		if e != nil {
			break
		}
		if data != nil {
			_, e = tw.Write(data)
		} else {
			var src *os.File
			src, e = os.Open(p.files[n])
			if e == nil {
				_, e = io.Copy(tw, src)
				e = errors.Join(e, src.Close())
			}
		}
		if e != nil {
			break
		}
	}
	e = errors.Join(e, tw.Close(), f.Sync(), f.Close())
	if e != nil {
		return e
	}
	r.CanonicalArchiveDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return nil
}

type limitWriter struct {
	w         io.Writer
	remaining int64
}

func (w *limitWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.remaining {
		return 0, errors.New("output bound exceeded")
	}
	n, e := w.w.Write(b)
	w.remaining -= int64(n)
	return n, e
}

type boundedTransport struct {
	base      http.RoundTripper
	remaining int64
	max       int64
	mu        sync.Mutex
}

func (t *boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, e := t.base.RoundTrip(r)
	if e != nil {
		return nil, e
	}
	if resp.ContentLength > t.max {
		resp.Body.Close()
		return nil, errors.New("registry response exceeds bound")
	}
	resp.Body = &responseBody{ReadCloser: resp.Body, t: t, remaining: t.max}
	return resp, nil
}

type responseBody struct {
	io.ReadCloser
	t         *boundedTransport
	remaining int64
}

func (b *responseBody) Read(p []byte) (int, error) {
	b.t.mu.Lock()
	defer b.t.mu.Unlock()
	if b.t.remaining <= 0 {
		return 0, errors.New("registry aggregate byte bound exceeded")
	}
	if b.remaining < 0 {
		return 0, errors.New("registry response byte bound exceeded")
	}
	if int64(len(p)) > b.t.remaining {
		p = p[:b.t.remaining]
	}
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, e := b.ReadCloser.Read(p)
	b.t.remaining -= int64(n)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return n, errors.New("registry response byte bound exceeded")
	}
	return n, e
}
func (p *preparation) registry(credential []byte) (ImageRecord, error) {
	var z ImageRecord
	ref, e := name.ParseReference(p.in.SourceRef, name.StrictValidation)
	if e != nil {
		return z, errors.New("invalid registry reference")
	}
	auth := authn.Anonymous
	if len(credential) > 0 {
		if len(credential) > 64<<10 {
			return z, errors.New("credential exceeds bound")
		}
		var c struct {
			Username      string `json:"username"`
			Password      string `json:"password"`
			IdentityToken string `json:"identity_token"`
			RegistryToken string `json:"registry_token"`
		}
		if e = gvxcontract.DecodeStrict(credential, 64<<10, 4, &c); e != nil {
			return z, errors.New("invalid private registry credential")
		}
		auth = authn.FromConfig(authn.AuthConfig{Username: c.Username, Password: c.Password, IdentityToken: c.IdentityToken, RegistryToken: c.RegistryToken})
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	bt := &boundedTransport{base: transport, remaining: p.in.Limits.InputBytes, max: p.in.Limits.JSONBytes}
	options := []remote.Option{remote.WithContext(p.ctx), remote.WithAuth(auth), remote.WithTransport(bt), remote.WithJobs(1)}
	top, e := remote.Get(ref, options...)
	if e != nil {
		return z, errors.New("registry root acquisition failed")
	}
	original := top.Manifest
	if int64(len(original)) > p.in.Limits.JSONBytes || Digest(original) != top.Digest.String() || int64(len(original)) != top.Size {
		return z, errors.New("registry root descriptor mismatch")
	}
	if d, ok := ref.(name.Digest); ok && d.DigestStr() != Digest(original) {
		return z, errors.New("requested registry digest mismatch")
	}
	acquired := map[string][]byte{Digest(original): original}
	fetch := func(d descriptor) ([]byte, error) {
		if e := checkDescriptor(d, p.in.Limits); e != nil {
			return nil, e
		}
		if d.Size > p.in.Limits.JSONBytes {
			return nil, errors.New("registry JSON bound exceeded")
		}
		if b, ok := acquired[d.Digest]; ok {
			if int64(len(b)) != d.Size {
				return nil, errors.New("cached descriptor size mismatch")
			}
			return b, nil
		}
		var b []byte
		if d.MediaType == "application/vnd.oci.image.config.v1+json" || d.MediaType == "application/vnd.docker.container.image.v1+json" {
			layer, e := remote.Layer(ref.Context().Digest(d.Digest), options...)
			if e != nil {
				return nil, errors.New("registry config acquisition failed")
			}
			stream, e := layer.Compressed()
			if e != nil {
				return nil, errors.New("registry config stream failed")
			}
			b, e = io.ReadAll(io.LimitReader(stream, p.in.Limits.JSONBytes+1))
			e = errors.Join(e, stream.Close())
			if e != nil {
				return nil, errors.New("registry config read failed")
			}
		} else {
			obj, e := remote.Get(ref.Context().Digest(d.Digest), options...)
			if e != nil {
				return nil, errors.New("registry descriptor acquisition failed")
			}
			b = obj.Manifest
		}
		if Digest(b) != d.Digest || int64(len(b)) != d.Size {
			return nil, errors.New("registry descriptor mismatch")
		}
		acquired[d.Digest] = b
		return b, nil
	}
	raw, e := p.resolve(original, string(top.MediaType), fetch, 0)
	if e != nil {
		return z, e
	}
	var m manifest
	if e = decode(raw, p.in.Limits, &m); e != nil {
		return z, e
	}
	if e = checkManifest(m, p.in.Limits); e != nil {
		return z, e
	}
	bt.max = p.in.Limits.InputBytes
	for _, d := range m.Layers {
		key := "blobs/sha256/" + d.Digest[7:]
		if _, ok := p.files[key]; ok {
			if p.sizes[key] != d.Size {
				return z, errors.New("duplicate layer size mismatch")
			}
			continue
		}
		hash, e := v1.NewHash(d.Digest)
		if e != nil {
			return z, e
		}
		layer, e := remote.Layer(ref.Context().Digest(hash.String()), options...)
		if e != nil {
			return z, errors.New("registry layer acquisition failed")
		}
		stream, e := layer.Compressed()
		if e != nil {
			return z, errors.New("registry layer stream failed")
		}
		got, e := p.save(key, stream, d.Size)
		e = errors.Join(e, stream.Close())
		if e != nil {
			return z, e
		}
		if got != d.Digest {
			return z, errors.New("registry layer digest mismatch")
		}
	}
	r, e := p.build(original, string(top.MediaType), raw, fetch)
	if e != nil {
		return z, e
	}
	r.SourceDigest = Digest(original)
	return r, nil
}

func (p *preparation) reachableOCI(raw []byte, media string, depth int64, count *int64, seen map[string]bool) error {
	if depth > p.in.Limits.IndexDepth {
		return errors.New("archive index depth exceeded")
	}
	var children []descriptor
	switch media {
	case ociIndex, dockerIndex:
		var idx index
		if e := decode(raw, p.in.Limits, &idx); e != nil {
			return e
		}
		if idx.SchemaVersion != 2 || idx.Subject != nil || idx.ArtifactType != "" {
			return errors.New("unsupported archive index")
		}
		children = idx.Manifests
	case ociManifest, dockerManifest:
		var m manifest
		if e := decode(raw, p.in.Limits, &m); e != nil {
			return e
		}
		if e := checkManifest(m, p.in.Limits); e != nil {
			return e
		}
		children = append([]descriptor{m.Config}, m.Layers...)
	default:
		return errors.New("unsupported archive graph media")
	}
	for _, d := range children {
		*count++
		if *count > p.in.Limits.DescriptorCount {
			return errors.New("archive descriptor count exceeded")
		}
		if e := checkDescriptor(d, p.in.Limits); e != nil {
			return e
		}
		key := "blobs/sha256/" + d.Digest[7:]
		file, ok := p.files[key]
		if !ok {
			return errors.New("archive referenced blob missing")
		}
		p.used[key] = true
		if p.sizes[key] != d.Size {
			return errors.New("archive blob size mismatch")
		}
		if seen[d.Digest] {
			continue
		}
		seen[d.Digest] = true
		f, e := os.Open(file)
		if e != nil {
			return e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		e = errors.Join(e, f.Close())
		if e != nil {
			return e
		}
		if "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest {
			return errors.New("archive blob digest mismatch")
		}
		switch d.MediaType {
		case ociIndex, dockerIndex, ociManifest, dockerManifest:
			b, e := p.read(key)
			if e != nil {
				return e
			}
			if e = p.reachableOCI(b, d.MediaType, depth+1, count, seen); e != nil {
				return e
			}
		case "application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json", "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar", "application/vnd.docker.image.rootfs.diff.tar.gzip":
		default:
			return errors.New("unknown archive blob media")
		}
	}
	return nil
}

func preparerRead(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > max {
		return nil, errors.New("retained metadata exceeds bounds")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("retained metadata exceeds bounds")
	}
	return b, e
}
func (p *preparation) retained(id string) (ImageRecord, error) {
	var r ImageRecord
	b, e := preparerRead(filepath.Join(p.dir, "record.json"), p.in.Limits.JSONBytes*8)
	if e != nil {
		return r, e
	}
	if e = gvxcontract.DecodeStrict(b, int(p.in.Limits.JSONBytes*8), 32, &r); e != nil {
		return r, e
	}
	if r.ID != id {
		return r, errors.New("retained immutable image mismatch")
	}
	if e = ValidateRecord(r, p.in.Limits); e != nil {
		return r, e
	}
	b, e = preparerRead(filepath.Join(p.dir, "source.json"), p.in.Limits.JSONBytes*(p.in.Limits.IndexDepth+2))
	if e != nil {
		return r, e
	}
	metadata, e := ValidateSourceMetadata(b, r, p.in.Limits)
	if e != nil {
		return r, e
	}
	for key, file := range metadata.Members {
		p.files[key] = filepath.Join(p.dir, file)
		st, e := os.Lstat(p.files[key])
		if e != nil {
			return r, e
		}
		if !st.Mode().IsRegular() {
			return r, errors.New("retained source member is not regular")
		}
		p.sizes[key] = st.Size()
	}
	for _, l := range r.Layers {
		key := "blobs/sha256/" + l.Digest[7:]
		if p.sizes[key] != l.Size {
			return r, errors.New("retained layer size mismatch")
		}
		diff, e := p.layer(key, l.MediaType)
		if e != nil {
			return r, e
		}
		if diff != l.DiffID {
			return r, errors.New("retained diffID mismatch")
		}
	}
	return r, nil
}

func RegistryRepository(s string) (string, error) {
	r, e := name.ParseReference(s, name.StrictValidation)
	if e != nil {
		return "", errors.New("invalid registry repository")
	}
	return r.Context().Name(), nil
}

func (p *preparation) dockerAux(layers []string) error {
	if _, ok := p.files["repositories"]; ok {
		raw, e := p.read("repositories")
		if e != nil {
			return e
		}
		var repositories map[string]map[string]string
		if e = decode(raw, p.in.Limits, &repositories); e != nil {
			return e
		}
		for repo, tags := range repositories {
			if repo == "" || strings.ContainsAny(repo, "\x00\r\n") {
				return errors.New("invalid Docker repository metadata")
			}
			for tag, id := range tags {
				if tag == "" || !safeName(id) || strings.Contains(id, "/") {
					return errors.New("invalid Docker tag metadata")
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, layer := range layers {
		dir := path.Dir(layer)
		if dir == "." || seen[dir] {
			continue
		}
		seen[dir] = true
		version := dir + "/VERSION"
		if _, ok := p.files[version]; ok {
			raw, e := p.read(version)
			if e != nil {
				return e
			}
			if strings.TrimSpace(string(raw)) != "1.0" {
				return errors.New("unsupported Docker layer metadata version")
			}
		}
		metadata := dir + "/json"
		if _, ok := p.files[metadata]; ok {
			raw, e := p.read(metadata)
			if e != nil {
				return e
			}
			var legacy map[string]any
			if e = decode(raw, p.in.Limits, &legacy); e != nil {
				return e
			}
			allowed := map[string]bool{"id": true, "parent": true, "created": true, "container": true, "container_config": true, "docker_version": true, "author": true, "config": true, "architecture": true, "os": true, "size": true, "comment": true}
			for key := range legacy {
				if !allowed[key] {
					return errors.New("unknown Docker layer metadata field")
				}
			}
		}
	}
	return nil
}
