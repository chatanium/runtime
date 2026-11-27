package provision

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/bundle"
)

func testDevelopmentWorkerPreparation(t *testing.T) {
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	worker, e := os.ReadFile(executable)
	if e != nil {
		t.Fatal(e)
	}
	base := bundle.Manifest{Version: 1, Platform: "linux/amd64", CPUBaseline: "amd64-v2", NativeABI: "EL9", FormatVersions: []uint32{1}, SchemaVersions: []uint32{1}, HostfsMetadataVersions: []string{bundle.HostfsMetadataVersion}, SBOMPath: "sbom.json", LicenseDirectory: "licenses"}
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, id := range []bundle.ProgramID{bundle.Worker, bundle.Stage, bundle.GuestBridge, bundle.Preparer, bundle.Rungv, bundle.MkfsXFS, bundle.XFSQuota, bundle.IP, bundle.IPTables, bundle.IP6Tables, bundle.Conntrack, bundle.UserAdd, bundle.GroupAdd, bundle.UserDel, bundle.GroupDel} {
		file := "bin/" + string(id)
		base.Files = append(base.Files, bundle.File{Path: file, Digest: digest, Mode: 0555, Size: 1})
		base.Programs = append(base.Programs, bundle.Program{ID: id, Path: file})
	}
	base.Files = append(base.Files, bundle.File{Path: "sbom.json", Digest: digest, Mode: 0444, Size: 1}, bundle.File{Path: "licenses/NOTICE", Digest: digest, Mode: 0444, Size: 1})
	base.Provenance = []bundle.Provenance{{Source: "test-source", SourceDigest: "test-source-pin", ArtifactDigest: digest, Notices: []string{"licenses/NOTICE"}}}
	raw, e := json.Marshal(base)
	if e != nil {
		t.Fatal(e)
	}
	base.Digest, e = bundle.ManifestDigest(raw)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = json.Marshal(base)
	if e != nil {
		t.Fatal(e)
	}
	baseRoot := t.TempDir()
	if e = os.WriteFile(filepath.Join(baseRoot, "manifest.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	manifest := bundle.DevelopmentWorkerManifest{Version: 1, BaseBundleDigest: base.Digest, Platform: "linux/amd64", CPUBaseline: "amd64-v2", NativeABI: "EL9", WorkerControlVersion: 1, RuntimeControlVersion: 2, RuntimeConfigVersion: 2, Files: []bundle.File{{Path: "bin/chatanium-worker", Digest: Digest(worker), Size: int64(len(worker)), Mode: 0555}}}
	raw, e = json.Marshal(manifest)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if e = decoder.Decode(&fields); e != nil {
		t.Fatal(e)
	}
	delete(fields, "digest")
	canonical, e := json.Marshal(fields)
	if e != nil {
		t.Fatal(e)
	}
	manifest.Digest = DomainDigest("chatanium-development-worker-v1", canonical)
	raw, e = json.Marshal(manifest)
	if e != nil {
		t.Fatal(e)
	}
	archive := func(mode byte, extra bool) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		if e := tw.WriteHeader(&tar.Header{Name: "worker-manifest.json", Mode: 0444, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
			t.Fatal(e)
		}
		tw.Write(raw)
		header := &tar.Header{Name: "bin/chatanium-worker", Mode: 0555, Size: int64(len(worker)), Typeflag: mode, Format: tar.FormatUSTAR}
		if mode != tar.TypeReg {
			header.Size = 0
			header.Linkname = "/host/executable"
		}
		if e := tw.WriteHeader(header); e != nil {
			t.Fatal(e)
		}
		if mode == tar.TypeReg {
			tw.Write(worker)
		}
		if extra {
			tw.WriteHeader(&tar.Header{Name: "bin/gvx-stage", Mode: 0555, Size: 1, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR})
			tw.Write([]byte("x"))
		}
		if e := tw.Close(); e != nil {
			t.Fatal(e)
		}
		if remainder := b.Len() % 4096; remainder != 0 {
			b.Write(make([]byte, 4096-remainder))
		}
		return b.Bytes()
	}
	run := func(data []byte, extraBytes int64, mixed bool) ([]byte, string, error) {
		input := bundle.DevelopmentWorkerInput{ArchiveDigest: Digest(data), ArchiveBytes: int64(len(data)) + extraBytes}
		limits := testLimits()
		limits.MemoryBytes = 256 << 20
		limits.InputBytes = input.ArchiveBytes
		limits.ExpandedBytes = input.ArchiveBytes
		limits.OutputBytes = input.ArchiveBytes
		directory := t.TempDir()
		task := Task{DevelopmentWorker: &DevelopmentWorkerTask{Input: input, Directory: directory, BaseRoot: baseRoot, Limits: limits}}
		if mixed {
			task.Input.JobID = "mixed"
		}
		var packet, out bytes.Buffer
		WriteTask(&packet, task)
		packet.Write(data)
		e := RunPreparer(context.Background(), &packet, &out, io.Discard)
		return out.Bytes(), directory, e
	}
	t.Run("bounded static worker", func(t *testing.T) {
		out, directory, e := run(archive(tar.TypeReg, false), 0, false)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := bundle.VerifyDevelopmentWorkerManifest(out, base)
		if e != nil {
			t.Fatal(e)
		}
		if parsed.Digest != manifest.Digest {
			t.Fatal("development manifest identity changed")
		}
		data, e := os.ReadFile(filepath.Join(directory, "bin/chatanium-worker"))
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(data, worker) {
			t.Fatal("development ELF was altered")
		}
	})
	t.Run("reject archive link", func(t *testing.T) {
		if _, _, e := run(archive(tar.TypeSymlink, false), 0, false); e == nil {
			t.Fatal("development executable symlink accepted")
		}
	})
	t.Run("reject privileged extra member", func(t *testing.T) {
		if _, _, e := run(archive(tar.TypeReg, true), 0, false); e == nil {
			t.Fatal("privileged base replacement accepted")
		}
	})
	t.Run("reject truncated declared input", func(t *testing.T) {
		if _, _, e := run(archive(tar.TypeReg, false), 4096, false); e == nil {
			t.Fatal("wrong exact development input size accepted")
		}
	})
	t.Run("reject mixed image worker task", func(t *testing.T) {
		if _, _, e := run(archive(tar.TypeReg, false), 0, true); e == nil {
			t.Fatal("mixed root preparation authority accepted")
		}
	})
}
