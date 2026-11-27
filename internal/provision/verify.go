package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

// SourceMetadata links preserved source members to opaque filenames. The root
// validates this bounded metadata; it never parses an archive or decompresses.
type SourceMetadata struct {
	Chain   [][]byte          `json:"chain"`
	Members map[string]string `json:"members"`
}

func ValidateSourceMetadata(raw []byte, r ImageRecord, l PrepareLimits) (SourceMetadata, error) {
	var m SourceMetadata
	if e := decodeSource(raw, l, &m); e != nil {
		return m, e
	}
	if int64(len(m.Members)) > l.Inodes {
		return m, errors.New("source member bound exceeded")
	}
	for key, file := range m.Members {
		if !safeName(key) || !safeName(file) || strings.Contains(file, "/") || !strings.HasPrefix(file, "blob-") {
			return m, errors.New("invalid source member mapping")
		}
	}
	if r.SourceKind == "docker-archive" {
		if len(m.Chain) != 0 {
			return m, errors.New("Docker source has registry manifest chain")
		}
		return m, nil
	}
	if len(m.Chain) == 0 || !bytes.Equal(m.Chain[0], r.Original) || int64(len(m.Chain)) > l.DescriptorCount*2+2 {
		return m, errors.New("missing source manifest chain")
	}
	byDigest := map[string][]byte{}
	for _, b := range m.Chain {
		if int64(len(b)) > l.JSONBytes {
			return m, errors.New("chain member exceeds bound")
		}
		byDigest[Digest(b)] = b
	}
	p := &preparation{in: ApprovedImageInput{Limits: l}}
	selected, e := p.resolve(r.Original, r.OriginalMediaType, func(d descriptor) ([]byte, error) {
		b, ok := byDigest[d.Digest]
		if !ok {
			return nil, errors.New("source chain missing descriptor")
		}
		return b, nil
	}, 0)
	if e != nil {
		return m, e
	}
	if !bytes.Equal(selected, r.Manifest) {
		return m, errors.New("source selected manifest mismatch")
	}
	if len(p.chain) != len(m.Chain) {
		return m, errors.New("extraneous chain metadata")
	}
	return m, nil
}
func decodeSource(raw []byte, l PrepareLimits, out any) error {
	return decodeWithBound(raw, l.JSONBytes*(l.IndexDepth+2), out)
}
func decodeWithBound(raw []byte, max int64, out any) error {
	return gvxcontract.DecodeStrict(raw, int(max), 32, out)
}

// CacheImageRecord mirrors only the pinned original compiler's on-disk v2
// format. Changing the pinned compiler requires deliberately changing this check.
type CacheImageRecord struct {
	Version          int      `json:"version"`
	BaseURL          string   `json:"baseURL"`
	Repository       string   `json:"repository"`
	Digest           string   `json:"digest"`
	Architecture     string   `json:"architecture"`
	Format           string   `json:"format"`
	Manifests        [][]byte `json:"manifests"`
	Config           []byte   `json:"config"`
	Source           string   `json:"source,omitempty"`
	OriginBaseURL    string   `json:"originBaseURL,omitempty"`
	OriginRepository string   `json:"originRepository,omitempty"`
}
type CacheTagRecord struct {
	Digest       string `json:"digest"`
	Version      int    `json:"version,omitempty"`
	BaseURL      string `json:"baseURL,omitempty"`
	Repository   string `json:"repository,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Tag          string `json:"tag,omitempty"`
}

func CacheKey(format string, parts ...string) string {
	h := sha256.New()
	for _, s := range append([]string{format}, parts...) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}
func ValidateCacheRecord(raw []byte, r ImageRecord, l PrepareLimits) (CacheImageRecord, error) {
	var c CacheImageRecord
	if e := decodeWithBound(raw, l.JSONBytes*8, &c); e != nil {
		return c, e
	}
	if c.Version != 2 || c.BaseURL != RegistryOverride || c.Repository != "module-cache" || c.Digest != r.ManifestDigest || c.Architecture != "amd64" || c.Source != "archive" || c.OriginBaseURL != "" || c.OriginRepository != "" || len(c.Manifests) != 1 || !bytes.Equal(c.Manifests[0], r.Manifest) || !bytes.Equal(c.Config, r.Config) {
		return c, errors.New("compiled cache record source binding mismatch")
	}
	if _, e := CacheBlockSize(c.Format); e != nil {
		return c, e
	}
	return c, nil
}
func CacheBlockSize(format string) (int, error) {
	const prefix = "gvx-erofs-v3-b"
	if !strings.HasPrefix(format, prefix) {
		return 0, errors.New("unsupported pinned cache format")
	}
	n, e := strconv.Atoi(strings.TrimPrefix(format, prefix))
	if e != nil || n < 4096 || n > 65536 || n&(n-1) != 0 {
		return 0, errors.New("invalid cache block size")
	}
	return n, nil
}
func CacheNames(r ImageRecord, format string) (image, tag string) {
	return "image-" + CacheKey(format, RegistryOverride, "module-cache", r.ManifestDigest, "amd64") + ".json", "tag-" + CacheKey(format, RegistryOverride, "module-cache", "sha256-"+r.ManifestDigest[7:], "amd64") + ".json"
}
func ValidateCacheTag(raw []byte, r ImageRecord, l PrepareLimits) error {
	var t CacheTagRecord
	if e := decode(raw, l, &t); e != nil {
		return e
	}
	if t.Version != 2 || t.BaseURL != RegistryOverride || t.Repository != "module-cache" || t.Digest != r.ManifestDigest || t.Architecture != "amd64" || t.Tag != "sha256-"+r.ManifestDigest[7:] {
		return errors.New("compiled cache tag mismatch")
	}
	return nil
}
func ParseLayerSum(raw []byte, format string) (int64, string, error) {
	parts := strings.Fields(string(raw))
	if len(parts) != 3 || parts[0] != format {
		return 0, "", errors.New("cache sidecar format mismatch")
	}
	n, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil || n < 0 || !ValidDigest("sha256:"+parts[2]) {
		return 0, "", errors.New("invalid cache sidecar")
	}
	if string(raw) != fmt.Sprintf("%s %d %s\n", format, n, parts[2]) {
		return 0, "", errors.New("noncanonical cache sidecar")
	}
	return n, "sha256:" + parts[2], nil
}
