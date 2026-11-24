package images

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/provision"
)

func TestCanonicalCacheMetadata(t *testing.T) {
	layers := []provision.LayerRecord{{
		Digest:    provision.Digest([]byte("compressed")),
		DiffID:    provision.Digest([]byte("expanded")),
		MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Size: 17,
	}}
	format := cacheFormat()
	name, ref, raw, err := canonicalMetadata(runtime.GOARCH, format, layers)
	if err != nil {
		t.Fatal(err)
	}
	var rec provision.CacheImageRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Manifests) != 1 || rec.Digest != provision.Digest(rec.Manifests[0]) || ref != provision.ExecutionRef(rec.Digest) || filepath.Base(name) != name || rec.Format != format {
		t.Fatalf("cache key did not bind the generated metadata: %s %s", name, ref)
	}
	if bytes.Contains(rec.Config, []byte(`"config"`)) || bytes.Contains(rec.Manifests[0], []byte("+gzip")) {
		t.Fatal("pre-lockdown cache contained source runtime or descriptor metadata")
	}
}

func TestRegistryAuthoritiesArePlanBound(t *testing.T) {
	base := Source{Kind: "registry", Reference: "https://registry.example.com/a/b", Digest: provision.Digest([]byte("source"))}
	if _, err := parseRepository(base); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"https://registry.example.com/a/%2e%2e", "https://x@registry.example.com/a", "https://registry.example.com/a?foo=bar", "https://registry.example.com:444/a", "https://registry.example.com/a@" + base.Digest} {
		bad := base
		bad.Reference = s
		if _, err := parseRepository(bad); err == nil {
			t.Errorf("accepted repository %q", s)
		}
	}
	bad := base
	bad.RedirectHosts = strings.Fields("first.example.com first.example.com")
	if _, err := parseRepository(bad); err == nil {
		t.Fatal("accepted ambiguous redirect authority")
	}
}
