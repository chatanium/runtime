//go:build linux

package bundle

import (
	"encoding/json"
	"strings"
	"testing"
)

func bundleFixture(t *testing.T) Manifest {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	m := Manifest{Version: 1, Platform: "linux/amd64", CPUBaseline: "amd64-v2", NativeABI: "EL9", FormatVersions: []uint32{1}, SchemaVersions: []uint32{1}, HostfsMetadataVersions: []string{"GVXMETA4"}, SBOMPath: "sbom.json", LicenseDirectory: "licenses"}
	for _, id := range programIDs {
		p := "bin/" + string(id)
		m.Files = append(m.Files, File{Path: p, Digest: digest, Mode: 0555, Size: 1})
		m.Programs = append(m.Programs, Program{ID: id, Path: p})
	}
	m.Files = append(m.Files, File{Path: "sbom.json", Digest: digest, Mode: 0444, Size: 1}, File{Path: "licenses/NOTICE", Digest: digest, Mode: 0444, Size: 1}, File{Path: "lib/loader", Digest: digest, Mode: 0555, Size: 1}, File{Path: "lib/xtables/extension.so", Digest: digest, Mode: 0444, Size: 1})
	m.Provenance = []Provenance{{Source: "source", SourceDigest: "exact-source", ArtifactDigest: digest, Notices: []string{"licenses/NOTICE"}}}
	return m
}
func encodeManifest(t *testing.T, m Manifest) []byte {
	t.Helper()
	m.Digest = ""
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	m.Digest, e = ManifestDigest(raw)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestGvxBundleClosure(t *testing.T) {
	m := bundleFixture(t)
	raw := encodeManifest(t, m)
	if _, e := VerifyManifest(raw); e != nil {
		t.Fatal(e)
	}
	t.Run("archive-integrity", testArchiveIntegrity)
	t.Run("development-worker", testDevelopmentWorkerIntegrity)
	cases := map[string]func(*Manifest){
		"missing-program":             func(m *Manifest) { m.Programs = m.Programs[1:] },
		"unsupported-metadata":        func(m *Manifest) { m.HostfsMetadataVersions = []string{"1"} },
		"missing-loader":              func(m *Manifest) { m.Programs[0].Interpreter = "lib/missing" },
		"writable-program":            func(m *Manifest) { m.Files[0].Mode = 0755 },
		"path-escape":                 func(m *Manifest) { m.Files[0].Path = "../outside" },
		"symlink-mode":                func(m *Manifest) { m.Files[0].Mode = 0120555 },
		"duplicate-file":              func(m *Manifest) { m.Files = append(m.Files, m.Files[0]) },
		"duplicate-program":           func(m *Manifest) { m.Programs = append(m.Programs, m.Programs[0]) },
		"missing-extension-directory": func(m *Manifest) { m.Programs[0].Environment = []string{"XTABLES_LIBDIR=lib/absent"} },
		"ambient-loader":              func(m *Manifest) { m.Programs[0].Environment = []string{"LD_PRELOAD=lib/loader"} },
		"missing-notice":              func(m *Manifest) { m.Provenance[0].Notices = []string{"licenses/missing"} },
		"oversized-closure":           func(m *Manifest) { m.Files[0].Size = MaxBundleBytes + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := bundleFixture(t)
			mutate(&m)
			if _, e := VerifyManifest(encodeManifest(t, m)); e == nil {
				t.Fatal("accepted invalid closure")
			}
		})
	}
	t.Run("tampered-manifest", func(t *testing.T) {
		raw := strings.Replace(string(raw), "exact-source", "other-source", 1)
		if _, e := VerifyManifest([]byte(raw)); e == nil {
			t.Fatal("accepted tampered manifest")
		}
	})
	t.Run("duplicate-keys", func(t *testing.T) {
		bad := strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)
		if _, e := VerifyManifest([]byte(bad)); e == nil {
			t.Fatal("accepted duplicate JSON key")
		}
	})
}
