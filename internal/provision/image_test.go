package provision

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testLimits() PrepareLimits {
	return PrepareLimits{NanoCPUs: 1e9, MemoryBytes: 64 << 20, Tasks: 16, InputBytes: 4 << 20, ExpandedBytes: 4 << 20, OutputBytes: 4 << 20, Inodes: 256, JSONBytes: 1 << 20, DescriptorCount: 32, IndexDepth: 8, Deadline: time.Second * 5}
}
func tarBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if e := tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write(files[n]); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func fixture(t *testing.T, kind string) ([]byte, []byte) {
	t.Helper()
	layer := tarBytes(t, map[string][]byte{"module": []byte("module bytes")})
	cfg := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["LANG=C"],"Entrypoint":["/module"],"WorkingDir":"/","Labels":{"org.chatanium.flexmodule.manifest.v2":"{\"protocolMajor\":2}"}},"rootfs":{"type":"layers","diff_ids":["` + Digest(layer) + `"]}}`)
	cfgID := Digest(cfg)
	if kind == "docker-archive" {
		manifest, _ := json.Marshal([]any{map[string]any{"Config": cfgID[7:] + ".json", "RepoTags": []string{"local/module:built"}, "Layers": []string{"layer/layer.tar"}}})
		return tarBytes(t, map[string][]byte{"manifest.json": manifest, cfgID[7:] + ".json": cfg, "layer/layer.tar": layer}), cfg
	}
	m := manifest{SchemaVersion: 2, MediaType: ociManifest, Config: descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: cfgID, Size: int64(len(cfg))}, Layers: []descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: Digest(layer), Size: int64(len(layer))}}}
	raw, _ := json.Marshal(m)
	idx, _ := json.Marshal(index{SchemaVersion: 2, MediaType: ociIndex, Manifests: []descriptor{{MediaType: ociManifest, Digest: Digest(raw), Size: int64(len(raw)), Platform: &platform{OS: "linux", Architecture: "amd64"}}}})
	return tarBytes(t, map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": idx, "blobs/sha256/" + Digest(raw)[7:]: raw, "blobs/sha256/" + cfgID[7:]: cfg, "blobs/sha256/" + Digest(layer)[7:]: layer}), cfg
}
func prepareFixture(t *testing.T, kind string, archive []byte) (ImageRecord, string, error) {
	t.Helper()
	dir := t.TempDir()
	work := t.TempDir()
	input := ApprovedImageInput{JobID: "fixture", SourceKind: kind, SourceRef: "approved-offline-input", ArchiveDigest: Digest(archive), ModuleID: "module", ConfigRevision: "config", ApprovalRevision: "approval", Platform: "linux/amd64", Limits: testLimits()}
	var task bytes.Buffer
	if e := WriteTask(&task, Task{Input: input, Directory: dir, CanonicalDirectory: work}); e != nil {
		t.Fatal(e)
	}
	task.Write(archive)
	var out bytes.Buffer
	e := RunPreparer(context.Background(), &task, &out, io.Discard)
	var record ImageRecord
	if e == nil {
		e = json.Unmarshal(out.Bytes(), &record)
	}
	return record, work, e
}
func TestGvxCanonicalImageIdentity(t *testing.T) {
	for _, kind := range []string{"oci-archive", "docker-archive"} {
		t.Run(kind, func(t *testing.T) {
			archive, cfg := fixture(t, kind)
			record, dir, e := prepareFixture(t, kind, archive)
			if e != nil {
				t.Fatal(e)
			}
			if e = ValidateRecord(record, testLimits()); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(record.Config, cfg) || record.SourceDigest != Digest(archive) || record.ConfigDigest != Digest(cfg) {
				t.Fatal("exact source/config identity not preserved")
			}
			canonical, e := os.ReadFile(filepath.Join(dir, "canonical.tar"))
			if e != nil {
				t.Fatal(e)
			}
			if Digest(canonical) != record.CanonicalArchiveDigest {
				t.Fatal("canonical archive identity mismatch")
			}
			tr := tar.NewReader(bytes.NewReader(canonical))
			seen := map[string]bool{}
			for {
				h, e := tr.Next()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				if seen[h.Name] || !safeName(h.Name) || h.Typeflag != tar.TypeReg {
					t.Fatal("unsafe canonical member")
				}
				seen[h.Name] = true
				b, e := io.ReadAll(tr)
				if e != nil {
					t.Fatal(e)
				}
				if h.Name == "index.json" {
					var idx index
					if e = decode(b, testLimits(), &idx); e != nil {
						t.Fatal(e)
					}
					if len(idx.Manifests) != 1 || idx.Manifests[0].Annotations["io.containerd.image.name"] != Annotation(record.ManifestDigest) {
						t.Fatal("canonical execution annotation mismatch")
					}
				}
			}
			tampered := record
			tampered.Workdir = "/different"
			tampered.ID = RecordID(tampered)
			if ValidateRecord(tampered, testLimits()) == nil {
				t.Fatal("self-consistent record digest accepted forged config-derived workdir")
			}
			if kind == "docker-archive" && record.OriginalDigest == record.ManifestDigest {
				t.Fatal("derived Docker manifest confused with source provenance")
			}
		})
	}
	t.Run("reject traversal", func(t *testing.T) {
		archive := tarBytes(t, map[string][]byte{"../escape": []byte("x")})
		if _, _, e := prepareFixture(t, "oci-archive", archive); e == nil {
			t.Fatal("traversal archive accepted")
		}
	})
	t.Run("reject undeclared member", func(t *testing.T) {
		archive, _ := fixture(t, "oci-archive")
		var b bytes.Buffer
		b.Write(archive[:len(archive)-1024])
		tw := tar.NewWriter(&b)
		tw.WriteHeader(&tar.Header{Name: "extra", Typeflag: tar.TypeReg, Mode: 0600, Size: 1})
		tw.Write([]byte("x"))
		tw.Close()
		if _, _, e := prepareFixture(t, "oci-archive", b.Bytes()); e == nil {
			t.Fatal("unknown archive entry accepted")
		}
	})
	t.Run("retained canonical source", func(t *testing.T) {
		archive, _ := fixture(t, "oci-archive")
		source := t.TempDir()
		first := t.TempDir()
		input := ApprovedImageInput{JobID: "original", SourceKind: "oci-archive", SourceRef: "approved-offline-input", ArchiveDigest: Digest(archive), ModuleID: "module", ConfigRevision: "config", ApprovalRevision: "approval", Platform: "linux/amd64", Limits: testLimits()}
		var packet, out bytes.Buffer
		WriteTask(&packet, Task{Input: input, Directory: source, CanonicalDirectory: first})
		packet.Write(archive)
		if e := RunPreparer(context.Background(), &packet, &out, io.Discard); e != nil {
			t.Fatal(e)
		}
		var record ImageRecord
		if e := json.Unmarshal(out.Bytes(), &record); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(source, "record.json"), out.Bytes(), 0600); e != nil {
			t.Fatal(e)
		}
		second := t.TempDir()
		input.JobID = "rebuild"
		packet.Reset()
		out.Reset()
		WriteTask(&packet, Task{Input: input, Directory: source, CanonicalDirectory: second, RebuildRecordID: record.ID})
		if e := RunPreparer(context.Background(), &packet, &out, io.Discard); e != nil {
			t.Fatal(e)
		}
		a, e := os.ReadFile(filepath.Join(first, "canonical.tar"))
		if e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(filepath.Join(second, "canonical.tar"))
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(a, b) {
			t.Fatal("retained-source rebuild changed canonical archive")
		}
		raw, e := os.ReadFile(filepath.Join(source, "source.json"))
		if e != nil {
			t.Fatal(e)
		}
		metadata, e := ValidateSourceMetadata(raw, record, testLimits())
		if e != nil {
			t.Fatal(e)
		}
		layer := metadata.Members["blobs/sha256/"+record.Layers[0].Digest[7:]]
		if e = os.WriteFile(filepath.Join(source, layer), []byte("corrupt"), 0600); e != nil {
			t.Fatal(e)
		}
		packet.Reset()
		WriteTask(&packet, Task{Input: input, Directory: source, CanonicalDirectory: t.TempDir(), RebuildRecordID: record.ID})
		if RunPreparer(context.Background(), &packet, io.Discard, io.Discard) == nil {
			t.Fatal("retained source corruption accepted")
		}
	})
	t.Run("registry resolves tag once", func(t *testing.T) {
		archive, cfg := fixture(t, "oci-archive")
		files := map[string][]byte{}
		tr := tar.NewReader(bytes.NewReader(archive))
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(tr)
			if e != nil {
				t.Fatal(e)
			}
			files[h.Name] = b
		}
		var idx index
		if e := decode(files["index.json"], testLimits(), &idx); e != nil {
			t.Fatal(e)
		}
		var tags atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v2/" {
				w.WriteHeader(200)
				return
			}
			var body []byte
			switch {
			case r.URL.Path == "/v2/module/manifests/test":
				tags.Add(1)
				body = files["index.json"]
				w.Header().Set("Content-Type", ociIndex)
			case strings.HasPrefix(r.URL.Path, "/v2/module/manifests/"):
				key := strings.TrimPrefix(r.URL.Path, "/v2/module/manifests/")
				body = files["blobs/sha256/"+strings.TrimPrefix(key, "sha256:")]
				w.Header().Set("Content-Type", ociManifest)
			case strings.HasPrefix(r.URL.Path, "/v2/module/blobs/"):
				key := strings.TrimPrefix(r.URL.Path, "/v2/module/blobs/")
				body = files["blobs/sha256/"+strings.TrimPrefix(key, "sha256:")]
				w.Header().Set("Content-Type", "application/octet-stream")
			}
			if body == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Docker-Content-Digest", Digest(body))
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			if r.Method != "HEAD" {
				w.Write(body)
			}
		}))
		defer server.Close()
		input := ApprovedImageInput{JobID: "online", SourceKind: "registry", SourceRef: strings.TrimPrefix(server.URL, "http://") + "/module:test", ModuleID: "module", ConfigRevision: "config", ApprovalRevision: "approval", Platform: "linux/amd64", Limits: testLimits()}
		var packet, out bytes.Buffer
		WriteTask(&packet, Task{Input: input, Directory: t.TempDir(), CanonicalDirectory: t.TempDir()})
		if e := RunPreparer(context.Background(), &packet, &out, io.Discard); e != nil {
			t.Fatal(e)
		}
		var record ImageRecord
		if e := json.Unmarshal(out.Bytes(), &record); e != nil {
			t.Fatal(e)
		}
		if tags.Load() != 1 {
			t.Fatalf("tag resolved %d times", tags.Load())
		}
		if record.SourceDigest != Digest(files["index.json"]) || record.ManifestDigest != idx.Manifests[0].Digest || !bytes.Equal(record.Config, cfg) {
			t.Fatal("online original/selected/config identity changed")
		}
	})
	t.Run("reject source digest mismatch", func(t *testing.T) {
		a, _ := fixture(t, "oci-archive")
		dir := t.TempDir()
		work := t.TempDir()
		input := ApprovedImageInput{JobID: "fixture", SourceKind: "oci-archive", ArchiveDigest: "sha256:" + strings.Repeat("0", 64), ModuleID: "m", ConfigRevision: "c", ApprovalRevision: "a", Platform: "linux/amd64", Limits: testLimits()}
		var b bytes.Buffer
		WriteTask(&b, Task{Input: input, Directory: dir, CanonicalDirectory: work})
		b.Write(a)
		if RunPreparer(context.Background(), &b, io.Discard, io.Discard) == nil {
			t.Fatal("archive digest mismatch accepted")
		}
	})
	t.Run("development-worker", testDevelopmentWorkerPreparation)
	t.Run("preparation revision binds acquisition policy", func(t *testing.T) {
		approved := ApprovedImageInput{JobID: "retry", SourceKind: "registry", SourceRef: "example.invalid/module:approved", CredentialRef: "approved-credential", ModuleID: "module", ConfigRevision: "config", ApprovalRevision: "approval", Platform: "linux/amd64", Limits: testLimits()}
		want := Revision(approved)
		for _, mutate := range []func(*ApprovedImageInput){
			func(in *ApprovedImageInput) { in.SourceRef = "example.invalid/module:other" },
			func(in *ApprovedImageInput) { in.CredentialRef = "other-credential" },
			func(in *ApprovedImageInput) { in.Limits.InputBytes++ },
			func(in *ApprovedImageInput) { in.Limits.Deadline++ },
		} {
			changed := approved
			mutate(&changed)
			if Revision(changed) == want {
				t.Fatal("distinct approved acquisition policy reused the committed preparation identity")
			}
		}
		raw, err := json.Marshal(approved)
		if err != nil {
			t.Fatal(err)
		}
		var restored ApprovedImageInput
		if err = json.Unmarshal(raw, &restored); err != nil {
			t.Fatal(err)
		}
		if Revision(restored) != want {
			t.Fatal("durable exact planned input changed preparation identity on resume")
		}
	})
}
