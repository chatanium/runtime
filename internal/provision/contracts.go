// Package provision handles untrusted image bytes only inside the bounded preparer.
package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

const ImageManifestLabel = "org.chatanium.flexmodule.manifest.v2"
const PortableResourceLabel = "org.chatanium.flexmodule.resources.v2"
const PortableResourceVersion = "portable-v2"
const ImageRecordVersion uint32 = 1
const RegistryOverride = "https://chatanium.invalid"

type ApprovedImageInput struct {
	JobID            string        `json:"job_id"`
	SourceKind       string        `json:"source_kind"`
	SourceRef        string        `json:"source_ref"`
	ArchiveDigest    string        `json:"archive_digest"`
	CredentialRef    string        `json:"credential_ref"`
	ModuleID         string        `json:"module_id"`
	ConfigRevision   string        `json:"config_revision"`
	ApprovalRevision string        `json:"approval_revision"`
	Platform         string        `json:"platform"`
	Limits           PrepareLimits `json:"limits"`
}
type PrepareLimits struct {
	NanoCPUs        int64         `json:"nano_cpus"`
	MemoryBytes     int64         `json:"memory_bytes"`
	Tasks           int64         `json:"tasks"`
	InputBytes      int64         `json:"input_bytes"`
	ExpandedBytes   int64         `json:"expanded_bytes"`
	OutputBytes     int64         `json:"output_bytes"`
	Inodes          int64         `json:"inodes"`
	JSONBytes       int64         `json:"json_bytes"`
	DescriptorCount int64         `json:"descriptor_count"`
	IndexDepth      int64         `json:"index_depth"`
	Deadline        time.Duration `json:"deadline"`
}

func (l PrepareLimits) Validate() error {
	for _, v := range []int64{l.NanoCPUs, l.MemoryBytes, l.Tasks, l.InputBytes, l.ExpandedBytes, l.OutputBytes, l.Inodes, l.JSONBytes, l.DescriptorCount, l.IndexDepth, int64(l.Deadline)} {
		if v <= 0 {
			return errors.New("positive finite preparation bounds required")
		}
	}
	if l.JSONBytes > 32<<20 || l.IndexDepth > 32 || l.DescriptorCount > 4096 || l.Inodes > 1<<24 || l.JSONBytes > l.MemoryBytes/4 || l.InputBytes > 1<<50 || l.OutputBytes > 1<<50 || l.ExpandedBytes > 1<<50 || l.NanoCPUs%1000 != 0 {
		return errors.New("unsafe preparation bounds")
	}
	return nil
}
func (in ApprovedImageInput) Validate() error {
	if err := in.Limits.Validate(); err != nil {
		return err
	}
	if in.JobID == "" || in.JobID != path.Base(in.JobID) || strings.ContainsAny(in.JobID, ".\\\x00\r\n") || in.ModuleID == "" || in.ConfigRevision == "" || in.ApprovalRevision == "" || in.Platform != "linux/amd64" {
		return errors.New("invalid preparation binding")
	}
	for _, s := range []string{in.JobID, in.ModuleID, in.ConfigRevision, in.ApprovalRevision, in.CredentialRef, in.SourceRef} {
		if len(s) > 4096 || !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n") {
			return errors.New("preparation binding exceeds bounds")
		}
	}
	switch in.SourceKind {
	case "registry":
		if in.SourceRef == "" || in.ArchiveDigest != "" {
			return errors.New("invalid registry source")
		}
	case "oci-archive", "docker-archive":
		if !ValidDigest(in.ArchiveDigest) || in.CredentialRef != "" {
			return errors.New("invalid offline source")
		}
	default:
		return errors.New("unsupported image source")
	}
	return nil
}

type LayerRecord struct {
	Digest    string `json:"digest"`
	DiffID    string `json:"diff_id"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
}
type ImageRecord struct {
	Version                uint32        `json:"version"`
	ID                     string        `json:"id"`
	Revision               string        `json:"revision"`
	SourceKind             string        `json:"source_kind"`
	SourceRef              string        `json:"source_ref"`
	SourceDigest           string        `json:"source_digest"`
	OriginalMediaType      string        `json:"original_media_type"`
	OriginalDigest         string        `json:"original_digest"`
	ManifestDigest         string        `json:"manifest_digest"`
	ConfigDigest           string        `json:"config_digest"`
	DeclarationDigest      string        `json:"declaration_digest"`
	CanonicalArchiveDigest string        `json:"canonical_archive_digest"`
	ExecutionRef           string        `json:"execution_ref"`
	Original               []byte        `json:"original"`
	Manifest               []byte        `json:"manifest"`
	Config                 []byte        `json:"config"`
	Declaration            []byte        `json:"declaration"`
	Layers                 []LayerRecord `json:"layers"`
	ImageEnv               []string      `json:"image_env"`
	Entrypoint             []string      `json:"entrypoint"`
	Cmd                    []string      `json:"cmd"`
	Workdir                string        `json:"workdir"`
}
type FileIntegrity struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

func Digest(raw []byte) string { s := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(s[:]) }
func DomainDigest(domain string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(raw)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func ValidDigest(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
func RecordID(r ImageRecord) string {
	r.ID = ""
	raw, _ := json.Marshal(r)
	return DomainDigest("chatanium-image-record-v1", raw)
}
func Revision(in ApprovedImageInput) string {
	raw, _ := json.Marshal(in)
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&fields)
	canonical, _ := json.Marshal(fields)
	return DomainDigest("chatanium-image-revision-v1", canonical)
}
func ExecutionRef(manifest string) string { return "chatanium.invalid/module-cache@" + manifest }
func Annotation(manifest string) string {
	return "chatanium.invalid/module-cache:sha256-" + strings.TrimPrefix(manifest, "sha256:")
}
func ValidateSelector(s string) error {
	if strings.HasPrefix(s, "record:") {
		if ValidDigest(strings.TrimPrefix(s, "record:")) {
			return nil
		}
	} else if repo, d, ok := strings.Cut(s, "@"); ok && strings.Contains(repo, "/") && !strings.ContainsAny(repo, "\x00\r\n ?#@") && ValidDigest(d) {
		return nil
	}
	return errors.New("exact registry/repository@sha256 or record:sha256 selector required")
}

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	URLs         []string          `json:"urls,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Data         []byte            `json:"data,omitempty"`
	Platform     *platform         `json:"platform,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
}
type platform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Variant      string   `json:"variant,omitempty"`
}
type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
	Subject       *descriptor       `json:"subject,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
}
type index struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Manifests     []descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
	Subject       *descriptor       `json:"subject,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
}
type imageRuntimeConfig struct {
	User         string              `json:"User,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Env          []string            `json:"Env,omitempty"`
	Entrypoint   []string            `json:"Entrypoint,omitempty"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	WorkingDir   string              `json:"WorkingDir,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	StopSignal   string              `json:"StopSignal,omitempty"`
	ArgsEscaped  bool                `json:"ArgsEscaped,omitempty"`
	OnBuild      []string            `json:"OnBuild,omitempty"`
	Shell        []string            `json:"Shell,omitempty"`
	Healthcheck  *struct {
		Test          []string `json:"Test,omitempty"`
		Interval      int64    `json:"Interval,omitempty"`
		Timeout       int64    `json:"Timeout,omitempty"`
		StartPeriod   int64    `json:"StartPeriod,omitempty"`
		StartInterval int64    `json:"StartInterval,omitempty"`
		Retries       int      `json:"Retries,omitempty"`
	} `json:"Healthcheck,omitempty"`
	Hostname        string `json:"Hostname,omitempty"`
	Domainname      string `json:"Domainname,omitempty"`
	AttachStdin     bool   `json:"AttachStdin,omitempty"`
	AttachStdout    bool   `json:"AttachStdout,omitempty"`
	AttachStderr    bool   `json:"AttachStderr,omitempty"`
	Tty             bool   `json:"Tty,omitempty"`
	OpenStdin       bool   `json:"OpenStdin,omitempty"`
	StdinOnce       bool   `json:"StdinOnce,omitempty"`
	Image           string `json:"Image,omitempty"`
	NetworkDisabled bool   `json:"NetworkDisabled,omitempty"`
	MacAddress      string `json:"MacAddress,omitempty"`
	StopTimeout     int    `json:"StopTimeout,omitempty"`
}
type imageConfig struct {
	Created         *string             `json:"created,omitempty"`
	Author          string              `json:"author,omitempty"`
	Architecture    string              `json:"architecture"`
	OS              string              `json:"os"`
	OSVersion       string              `json:"os.version,omitempty"`
	OSFeatures      []string            `json:"os.features,omitempty"`
	Variant         string              `json:"variant,omitempty"`
	Config          imageRuntimeConfig  `json:"config"`
	DockerVersion   string              `json:"docker_version,omitempty"`
	Container       string              `json:"container,omitempty"`
	ContainerConfig *imageRuntimeConfig `json:"container_config,omitempty"`
	RootFS          struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	History []struct {
		Created    *string `json:"created,omitempty"`
		CreatedBy  string  `json:"created_by,omitempty"`
		Author     string  `json:"author,omitempty"`
		Comment    string  `json:"comment,omitempty"`
		EmptyLayer bool    `json:"empty_layer,omitempty"`
	} `json:"history,omitempty"`
}

func decode(raw []byte, l PrepareLimits, out any) error {
	return gvxcontract.DecodeStrict(raw, int(l.JSONBytes), 32, out)
}
func parseConfig(raw []byte, l PrepareLimits, layers int) (imageConfig, []byte, error) {
	return parseImageConfig(raw, l, layers, "amd64", false)
}

func parseImageConfig(raw []byte, l PrepareLimits, layers int, architecture string, portable bool) (imageConfig, []byte, error) {
	var c imageConfig
	if err := decode(raw, l, &c); err != nil {
		return c, nil, err
	}
	if c.OS != "linux" || c.Architecture != architecture || !imageVariant(architecture, c.Variant, portable) || c.RootFS.Type != "layers" || len(c.RootFS.DiffIDs) != layers || len(c.Config.Volumes) != 0 || len(c.Config.OnBuild) != 0 {
		return c, nil, errors.New("unsupported image configuration")
	}
	for _, d := range c.RootFS.DiffIDs {
		if !ValidDigest(d) {
			return c, nil, errors.New("invalid diffID")
		}
	}
	seen := map[string]bool{}
	for _, e := range c.Config.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || seen[k] || strings.ContainsAny(e, "\x00") || strings.HasPrefix(k, "PLUGIN_") || k == "CHATANIUM_GVX_STARTUP_TIMEOUT_NS" {
			return c, nil, errors.New("invalid or reserved image environment")
		}
		for i, ch := range k {
			if !(ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || i > 0 && ch >= '0' && ch <= '9') {
				return c, nil, errors.New("invalid environment name")
			}
		}
		seen[k] = true
	}
	for _, v := range append(append([]string{}, c.Config.Entrypoint...), c.Config.Cmd...) {
		if strings.ContainsRune(v, 0) {
			return c, nil, errors.New("NUL image argument")
		}
	}
	if c.Config.WorkingDir != "" && (path.Clean(c.Config.WorkingDir) != c.Config.WorkingDir || !path.IsAbs(c.Config.WorkingDir) || strings.ContainsRune(c.Config.WorkingDir, 0)) {
		return c, nil, errors.New("invalid image workdir")
	}
	if portable && (c.Config.Labels[PortableResourceLabel] != PortableResourceVersion || c.OSVersion != "" || len(c.OSFeatures) != 0) {
		return c, nil, errors.New("image does not explicitly declare portable-v2 resource semantics")
	}
	declaration := []byte(c.Config.Labels[ImageManifestLabel])
	var anyJSON any
	if err := decode(declaration, l, &anyJSON); err != nil {
		return c, nil, err
	}
	var m wire.ModuleManifest
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: 32}).Unmarshal(declaration, &m); err != nil {
		return c, nil, err
	}
	if m.ProtocolMajor != 2 {
		return c, nil, errors.New("unsupported declaration protocol")
	}
	return c, declaration, nil
}

func imageVariant(arch, variant string, portable bool) bool {
	return variant == "" || portable && arch == "arm64" && variant == "v8"
}
func ValidateRecord(r ImageRecord, l PrepareLimits) error {
	if r.Version != ImageRecordVersion || r.ID != RecordID(r) || !ValidDigest(r.Revision) || !ValidDigest(r.CanonicalArchiveDigest) || Digest(r.Original) != r.OriginalDigest || Digest(r.Manifest) != r.ManifestDigest || Digest(r.Config) != r.ConfigDigest || Digest(r.Declaration) != r.DeclarationDigest || r.ExecutionRef != ExecutionRef(r.ManifestDigest) {
		return errors.New("image record identity mismatch")
	}
	var m manifest
	if err := decode(r.Manifest, l, &m); err != nil {
		return err
	}
	if err := checkManifest(m, l); err != nil {
		return err
	}
	if m.Config.Digest != r.ConfigDigest || m.Config.Size != int64(len(r.Config)) || len(m.Layers) != len(r.Layers) {
		return errors.New("config descriptor mismatch")
	}
	c, d, err := parseConfig(r.Config, l, len(r.Layers))
	if err != nil {
		return err
	}
	if !bytes.Equal(d, r.Declaration) || !reflect.DeepEqual(c.Config.Env, r.ImageEnv) || !reflect.DeepEqual(c.Config.Entrypoint, r.Entrypoint) || !reflect.DeepEqual(c.Config.Cmd, r.Cmd) || c.Config.WorkingDir != r.Workdir {
		return errors.New("derived launch metadata mismatch")
	}
	for i, v := range r.Layers {
		x := m.Layers[i]
		if v.Digest != x.Digest || v.Size != x.Size || v.MediaType != x.MediaType || v.DiffID != c.RootFS.DiffIDs[i] {
			return fmt.Errorf("layer %d identity mismatch", i)
		}
	}
	if r.SourceKind == "docker-archive" {
		var original []struct {
			Config   string   `json:"Config"`
			RepoTags []string `json:"RepoTags"`
			Layers   []string `json:"Layers"`
		}
		if err := decode(r.Original, l, &original); err != nil {
			return err
		}
		if len(original) != 1 || len(original[0].Layers) != len(r.Layers) || path.Base(original[0].Config) != r.ConfigDigest[7:]+".json" && original[0].Config != "blobs/sha256/"+r.ConfigDigest[7:] {
			return errors.New("Docker source/config provenance mismatch")
		}
	}
	switch r.SourceKind {
	case "registry":
		if r.SourceDigest != r.OriginalDigest {
			return errors.New("registry provenance mismatch")
		}
	case "oci-archive":
		if !ValidDigest(r.SourceDigest) {
			return errors.New("archive provenance missing")
		}
	case "docker-archive":
		if !ValidDigest(r.SourceDigest) || r.OriginalMediaType != "application/vnd.chatanium.docker-save.manifest.v1+json" {
			return errors.New("derived Docker provenance mismatch")
		}
	default:
		return errors.New("unknown source kind")
	}
	return nil
}

const ociManifest = "application/vnd.oci.image.manifest.v1+json"
const ociIndex = "application/vnd.oci.image.index.v1+json"
const dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
const dockerIndex = "application/vnd.docker.distribution.manifest.list.v2+json"

func checkDescriptor(d descriptor, l PrepareLimits) error {
	if !ValidDigest(d.Digest) || d.Size < 0 || d.Size > l.InputBytes || len(d.URLs) != 0 || len(d.Data) != 0 || d.ArtifactType != "" {
		return errors.New("unsupported or invalid descriptor")
	}
	return nil
}
func checkManifest(m manifest, l PrepareLimits) error {
	if m.SchemaVersion != 2 || m.MediaType != "" && m.MediaType != ociManifest && m.MediaType != dockerManifest || m.Subject != nil || m.ArtifactType != "" || int64(len(m.Layers)) > l.DescriptorCount {
		return errors.New("unsupported concrete manifest")
	}
	if err := checkDescriptor(m.Config, l); err != nil {
		return err
	}
	if m.Config.Size > l.JSONBytes {
		return errors.New("config descriptor exceeds JSON bound")
	}
	if m.Config.MediaType != "application/vnd.oci.image.config.v1+json" && m.Config.MediaType != "application/vnd.docker.container.image.v1+json" {
		return errors.New("unsupported config media")
	}
	for _, d := range m.Layers {
		if err := checkDescriptor(d, l); err != nil {
			return err
		}
		if !supportedLayerMedia(d.MediaType) {
			return errors.New("unsupported or foreign layer media")
		}
	}
	return nil
}

func supportedLayerMedia(media string) bool {
	switch media {
	case "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar", "application/vnd.docker.image.rootfs.diff.tar.gzip":
		return true
	default:
		return false
	}
}
