//go:build linux

package bundle

import (
	"encoding/json"
	"strings"
	"testing"
)

func encodeDevelopment(t *testing.T, manifest DevelopmentWorkerManifest) []byte {
	t.Helper()
	manifest.Digest = ""
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Digest, err = canonicalDigest(raw, "chatanium-development-worker-v1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testDevelopmentWorkerIntegrity(t *testing.T) {
	base, err := VerifyManifest(encodeManifest(t, bundleFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	fixture := func() DevelopmentWorkerManifest {
		return DevelopmentWorkerManifest{
			Version: 1, BaseBundleDigest: base.Digest, Platform: "linux/amd64", CPUBaseline: "amd64-v2", NativeABI: "EL9",
			WorkerControlVersion: 1, RuntimeControlVersion: 2, RuntimeConfigVersion: 2,
			Files: []File{{Path: "bin/chatanium-worker", Digest: "sha256:" + strings.Repeat("a", 64), Size: 1, Mode: 0555}},
		}
	}
	if _, err := VerifyDevelopmentWorkerManifest(encodeDevelopment(t, fixture()), base); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*DevelopmentWorkerManifest){
		"replace-root-stage":              func(m *DevelopmentWorkerManifest) { m.Files[0].Path = "bin/gvx-stage" },
		"replace-base-loader":             func(m *DevelopmentWorkerManifest) { m.Files[0].Path = "lib/ld-linux-x86-64.so.2" },
		"unknown-base":                    func(m *DevelopmentWorkerManifest) { m.BaseBundleDigest = "sha256:" + strings.Repeat("b", 64) },
		"control-mismatch":                func(m *DevelopmentWorkerManifest) { m.RuntimeControlVersion = 1 },
		"writable-worker":                 func(m *DevelopmentWorkerManifest) { m.Files[0].Mode = 0755 },
		"duplicate-member":                func(m *DevelopmentWorkerManifest) { m.Files = append(m.Files, m.Files[0]) },
		"unsigned-native-without-closure": func(m *DevelopmentWorkerManifest) { m.Voice = true },
		"static-worker-extra-native": func(m *DevelopmentWorkerManifest) {
			m.Files = append(m.Files, File{Path: "bin/voice-runtime/lib/libextra.so", Digest: m.Files[0].Digest, Size: 1, Mode: 0555})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			mutate(&m)
			if _, err := VerifyDevelopmentWorkerManifest(encodeDevelopment(t, m), base); err == nil {
				t.Fatal("accepted invalid development privilege/closure boundary")
			}
		})
	}
}
