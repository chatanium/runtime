//go:build linux

package host

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

func TestGvxBackingBudgetReservesEveryPoolAndHeadroom(t *testing.T) {
	m := InstallationManifest{Backing: BackingIdentity{SizeBytes: 5 * 4096}, Budget: StorageBudget{
		DataBytes: 4096, DataInodes: 8, AppBytes: 4096, AppInodes: 4, SourceBytes: 4096, SourceInodes: 1,
		CacheBytes: 4096, CacheInodes: 1, PreparationBytes: 4096, PreparationInodes: 1,
		MetadataHeadroomBytes: 4096, MetadataHeadroomInodes: 1,
	}}
	if err := validateBackingBudget(m); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*InstallationManifest){
		func(m *InstallationManifest) { m.Backing.SizeBytes -= 4096 },
		func(m *InstallationManifest) { m.Budget.MetadataHeadroomBytes = 0 },
		func(m *InstallationManifest) { m.Budget.MetadataHeadroomInodes = 0 },
		func(m *InstallationManifest) { m.Budget.DataBytes = math.MaxInt64 },
		func(m *InstallationManifest) { m.Budget.DataInodes = math.MaxInt64 },
		func(m *InstallationManifest) { m.Budget.AppBytes = 0 },
		func(m *InstallationManifest) { m.Budget.AppBytes = m.Budget.DataBytes + 4096 },
		func(m *InstallationManifest) { m.Budget.AppInodes = 3 },
		func(m *InstallationManifest) { m.Budget.AppInodes = m.Budget.DataInodes + 1 },
	} {
		bad := m
		change(&bad)
		if err := validateBackingBudget(bad); err == nil {
			t.Fatalf("unsafe budget accepted: %+v", bad)
		}
	}
}

func TestGvxImagePeakOverflowRejectedBeforeHostAccess(t *testing.T) {
	for _, limits := range []provision.PrepareLimits{
		{InputBytes: math.MaxInt64, OutputBytes: 4096, ExpandedBytes: 4096, Inodes: 2},
		{InputBytes: 4096, OutputBytes: 4096, ExpandedBytes: math.MaxInt64, Inodes: 2},
		{InputBytes: 4096, OutputBytes: 4096, ExpandedBytes: 4096, Inodes: 0},
		{InputBytes: 4096, OutputBytes: 4096, ExpandedBytes: 4096, Inodes: 1},
	} {
		// A nil receiver makes accidental host access or claim mutation observable.
		var storage *Storage
		if _, err := storage.PrepareImageSpace(context.Background(), strings.Repeat("a", 32), limits); err == nil {
			t.Fatalf("invalid peak accepted: %+v", limits)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var storage *Storage
	if _, err := storage.PrepareImageSpace(ctx, strings.Repeat("a", 32), provision.PrepareLimits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost original cancellation: %v", err)
	}
}

func TestGvxStorageReclaimRequiresEveryWriterBarrier(t *testing.T) {
	evidence := CleanupEvidence{BootID: "boot", JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, OpenReferencesAbsent: true}
	if err := validateStorageWriters(evidence); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*CleanupEvidence){
		func(e *CleanupEvidence) { e.BootID = "" }, func(e *CleanupEvidence) { e.JobsAbsent = false },
		func(e *CleanupEvidence) { e.ProcessesAbsent = false }, func(e *CleanupEvidence) { e.TransportsClosed = false },
		func(e *CleanupEvidence) { e.OpenReferencesAbsent = false },
	} {
		bad := evidence
		change(&bad)
		if err := validateStorageWriters(bad); !errors.Is(err, sharedhost.ErrCleanupIncomplete) {
			t.Fatalf("incomplete writer barrier accepted: %+v: %v", bad, err)
		}
	}
}

func TestGvxImageCleanupNeverPromotesUnknownNamespace(t *testing.T) {
	job := strings.Repeat("a", 32)
	space := ImageSpace{JobID: job, ProvisionID: strings.Repeat("b", 32), Source: "/owned/images/" + job, Cache: "/owned/prepared/" + job, Work: "/owned/preparation/" + job}
	storage := Storage{config: SupervisorConfig{StorageRoot: "/owned"}}
	proof := CleanupEvidence{BootID: "unused-before-private-namespace-proof", JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, OpenReferencesAbsent: true, QuotaReclaimed: true}
	// No Store, quota descriptor or host namespace is needed: an unknown
	// helper namespace must fail before any native absence observation.
	observed, err := storage.VerifyImageSpaceDetached(context.Background(), space, proof)
	if !errors.Is(err, sharedhost.ErrCleanupIncomplete) || observed.MountsAbsent || observed.QuotaReclaimed {
		t.Fatalf("unknown private namespace or unrelated quota proof was promoted: %+v: %v", observed, err)
	}
}

func TestGvxCleanupStorageRejectsAdmission(t *testing.T) {
	storage := Storage{cleanupOnly: true}
	ctx := context.Background()
	limits := provision.PrepareLimits{InputBytes: 4096, OutputBytes: 4096, ExpandedBytes: 4096, Inodes: 4}
	job := strings.Repeat("a", 32)
	checks := []func() error{
		func() error { return storage.Prepare(ctx, sharedhost.Lease{}) },
		func() error { return storage.PrepareApp(ctx) },
		func() error { _, err := storage.PrepareRoots(ctx, sharedhost.Lease{}); return err },
		func() error { return storage.ConfirmRoots(ctx, sharedhost.Lease{}, gvxcontract.RootInitResult{}) },
		func() error { _, _, _, err := storage.CreateEndpoint(ctx, sharedhost.Lease{}); return err },
		func() error { _, err := storage.PrepareImageSpace(ctx, job, limits); return err },
		func() error { _, err := storage.PrepareCacheSpace(ctx, job, ImageSpace{}, limits); return err },
		func() error { _, err := storage.PreparationLayout(ctx, ImageSpace{}); return err },
	}
	for _, check := range checks {
		if err := check(); err == nil || !strings.Contains(err.Error(), "cleanup-only") {
			t.Fatalf("cleanup backend admitted resource preparation: %v", err)
		}
	}
}

func TestGvxAppAllowanceRejectsInfeasibleConsumerBudget(t *testing.T) {
	budget := StorageBudget{DataBytes: 16 << 30, DataInodes: 1 << 20, AppBytes: 10 << 30, AppInodes: 65536}
	if err := ValidateAppAllowance(budget, 8<<30, 256); err != nil {
		t.Fatal(err)
	}
	for _, required := range []struct{ bytes, inodes int64 }{{11 << 30, 256}, {8 << 30, 65537}, {-1, 4}, {0, -1}} {
		if err := ValidateAppAllowance(budget, required.bytes, required.inodes); err == nil {
			t.Fatalf("infeasible app aggregate accepted: %+v", required)
		}
	}
}

func TestGvxCacheEnvelopeExposureRequiresScopedJournalPhase(t *testing.T) {
	// Runtime may also be the preparer's primary/supplementary group. A
	// traversal-only runtime parent must never stand in for the birth barrier.
	const runtimeGID = 9001
	for _, test := range []struct {
		name                      string
		uid, gid, mode            uint32
		intent, observed, allowed bool
	}{
		{"private birth", 0, 0, 0700, false, false, true},
		{"preparer owned", 9001, runtimeGID, 0700, false, false, false},
		{"changed group before intent", 0, runtimeGID, 0700, false, false, false},
		{"traversable before intent", 0, runtimeGID, 0710, false, false, false},
		{"readonly legacy wrapper", 0, runtimeGID, 0550, false, false, false},
		{"journaled private", 0, 0, 0700, true, false, true},
		{"journaled chown", 0, runtimeGID, 0700, true, false, true},
		{"journaled chmod", 0, runtimeGID, 0710, true, false, true},
		{"observed exposure", 0, runtimeGID, 0710, true, true, true},
		{"observation without intent", 0, runtimeGID, 0710, false, true, false},
		{"observed but reverted group", 0, 0, 0700, true, true, false},
		{"observed but reverted mode", 0, runtimeGID, 0700, true, true, false},
		{"widened permissions", 0, runtimeGID, 0750, true, false, false},
		{"foreign group", 0, 9002, 0710, true, false, false},
		{"foreign owner after intent", 9001, runtimeGID, 0710, true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := NativeRootIdentity{UID: test.uid, GID: test.gid, Mode: test.mode}
			if err := validateCacheExposure(root, runtimeGID, test.intent, test.observed); (err == nil) != test.allowed {
				t.Fatalf("unexpected exposure decision: %+v: %v", test, err)
			}
		})
	}
	if err := validateCacheExposure(NativeRootIdentity{UID: 0, GID: 0, Mode: 0700}, 0, false, false); err == nil {
		t.Fatal("root runtime identity accepted")
	}
}

func TestGvxPreparationDataDistinguishesReadOnlySource(t *testing.T) {
	const uid, gid = 9001, 9002
	for _, test := range []struct {
		name                             string
		root                             NativeRootIdentity
		allowReadOnly, readOnly, allowed bool
	}{
		{"native writable data", NativeRootIdentity{UID: uid, GID: gid, Mode: 0700}, false, false, true},
		{"sealed source", NativeRootIdentity{UID: 0, GID: gid, Mode: 0550}, true, true, true},
		{"sealed cache cannot start another writer", NativeRootIdentity{UID: 0, GID: gid, Mode: 0550}, false, false, false},
		{"preparer can restore writes", NativeRootIdentity{UID: uid, GID: gid, Mode: 0550}, true, false, false},
		{"root source still writable", NativeRootIdentity{UID: 0, GID: gid, Mode: 0750}, true, false, false},
		{"unapproved source reader", NativeRootIdentity{UID: 0, GID: gid + 1, Mode: 0550}, true, false, false},
		{"unexpected source permissions", NativeRootIdentity{UID: 0, GID: gid, Mode: 0555}, true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			readOnly, err := preparationDataReadOnly(test.root, uid, gid, test.allowReadOnly)
			if (err == nil) != test.allowed || err == nil && readOnly != test.readOnly {
				t.Fatalf("unexpected native data access: %+v: readonly=%t: %v", test, readOnly, err)
			}
		})
	}
	if _, err := preparationDataReadOnly(NativeRootIdentity{UID: 0, GID: 0, Mode: 0550}, 0, 0, true); err == nil {
		t.Fatal("root preparer identity accepted")
	}
}

func TestGvxCommittedImageRejectsLatentSharedWrite(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "latent-shared-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	page := os.Getpagesize()
	if err = file.Truncate(int64(page)); err != nil {
		t.Fatal(err)
	}
	mapped, err := unix.Mmap(int(file.Fd()), 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mapped)
	mapped[0] = 0x41
	if err = unix.Mprotect(mapped, unix.PROT_READ); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(file.Name(), 0400); err != nil {
		t.Fatal(err)
	}
	mapping := testNativeFileMapping(t, mapped, file.Name())
	if mapping.Permissions != "r--s" {
		t.Fatalf("expected downgraded shared mapping, got %q", mapping.Permissions)
	}
	err = verifySharedMappingsReadOnly(context.Background(), "/proc/self/smaps", []nativeMappingIdentity{mapping})
	if !errors.Is(err, sharedhost.ErrCleanupIncomplete) || !errors.Is(err, errSharedMappingWritable) {
		t.Fatalf("latent shared writer was not rejected through VmFlags: %v", err)
	}
	// Prove that the rejected mapping really retains write authority despite
	// its current r--s header, closed writable FD and readonly file mode.
	if err = unix.Mprotect(mapped, unix.PROT_READ|unix.PROT_WRITE); err != nil {
		t.Fatal(err)
	}
	mapped[0] = 0x42
	if err = unix.Msync(mapped, unix.MS_SYNC); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 0x42 {
		t.Fatal("restored shared mapping did not change backing file")
	}
}

func TestGvxCommittedImageAcceptsReadOnlySharedMapping(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "readonly-shared-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = file.Truncate(int64(os.Getpagesize())); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(file.Name(), 0400); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	mapped, err := unix.Mmap(int(reader.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mapped)
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	mapping := testNativeFileMapping(t, mapped, file.Name())
	if err = verifySharedMappingsReadOnly(context.Background(), "/proc/self/smaps", []nativeMappingIdentity{mapping}); err != nil {
		t.Fatalf("genuine readonly shared mapping rejected: %v", err)
	}
	for _, change := range []func(*nativeMappingIdentity){func(m *nativeMappingIdentity) { m.Inode++ }, func(m *nativeMappingIdentity) { m.Offset += uint64(os.Getpagesize()) }} {
		mismatch := mapping
		change(&mismatch)
		if err = verifySharedMappingsReadOnly(context.Background(), "/proc/self/smaps", []nativeMappingIdentity{mismatch}); !errors.Is(err, sharedhost.ErrCleanupIncomplete) {
			t.Fatalf("unbound shared mapping identity accepted: %v", err)
		}
	}
	if err = verifySharedMappingsReadOnly(context.Background(), "/proc/self/smaps", []nativeMappingIdentity{mapping, mapping}); !errors.Is(err, sharedhost.ErrCleanupIncomplete) {
		t.Fatalf("ambiguous mapping inventory accepted: %v", err)
	}
	if err = verifySharedMappingsReadOnly(context.Background(), file.Name()+".missing", []nativeMappingIdentity{mapping}); !errors.Is(err, sharedhost.ErrCleanupIncomplete) {
		t.Fatalf("unavailable VmFlags accepted: %v", err)
	}
}

func testNativeFileMapping(t *testing.T, mapped []byte, path string) nativeMappingIdentity {
	t.Helper()
	address := uint64(uintptr(unsafe.Pointer(&mapped[0])))
	var native unix.Stat_t
	if err := unix.Stat(path, &native); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		mapping, err := parseNativeMappingHeader(line)
		if err != nil {
			t.Fatal(err)
		}
		if mapping.Start != address || mapping.End != address+uint64(len(mapped)) {
			continue
		}
		if mapping.Inode != native.Ino || mapping.Major != unix.Major(native.Dev) || mapping.Minor != unix.Minor(native.Dev) {
			t.Fatal("native mapping identity differs from actual temporary file")
		}
		return mapping
	}
	t.Fatal("exact native temporary-file mapping is unavailable")
	return nativeMappingIdentity{}
}

func TestGvxCommittedImageCapturedDescriptorSurvivesSlotReuse(t *testing.T) {
	for _, sameInode := range []bool{false, true} {
		name := "unrelated-readonly"
		if sameInode {
			name = "same-inode-readonly"
		}
		t.Run(name, func(t *testing.T) {
			original, err := os.CreateTemp(t.TempDir(), "original-writer-")
			if err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			replacementPath := original.Name()
			if !sameInode {
				other, err := os.CreateTemp(t.TempDir(), "replacement-")
				if err != nil {
					t.Fatal(err)
				}
				replacementPath = other.Name()
				if err = other.Close(); err != nil {
					t.Fatal(err)
				}
			}
			reader, err := os.Open(replacementPath)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			held, err := captureProcessDescriptor(os.Getpid(), -1, int(original.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			var before unix.Stat_t
			if err = unix.Fstat(int(held.Fd()), &before); err != nil {
				t.Fatal(err)
			}
			if err = unix.Dup3(int(reader.Fd()), int(original.Fd()), unix.O_CLOEXEC); err != nil {
				t.Fatal(err)
			}
			var after unix.Stat_t
			if err = unix.Fstat(int(original.Fd()), &after); err != nil {
				t.Fatal(err)
			}
			if (before.Dev == after.Dev && before.Ino == after.Ino) != sameInode {
				t.Fatal("replacement did not exercise requested inode identity")
			}
			_, slotWritable, err := capturedDescriptorAccess(original)
			if err != nil || slotWritable {
				t.Fatalf("reused numeric slot is not readonly: %v", err)
			}
			_, heldWritable, err := capturedDescriptorAccess(held)
			if err != nil || !heldWritable {
				t.Fatalf("held original writer was hidden by FD reuse: %v", err)
			}
			var retained unix.Stat_t
			if err = unix.Fstat(int(held.Fd()), &retained); err != nil {
				t.Fatal(err)
			}
			if retained.Dev != before.Dev || retained.Ino != before.Ino {
				t.Fatal("held capture no longer identifies the original inode")
			}
			flags, err := unix.FcntlInt(held.Fd(), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatalf("capture lacks atomic close-on-exec: %v", err)
			}
			if wrong, err := captureProcessDescriptor(os.Getpid()+1, -1, int(original.Fd())); err == nil {
				wrong.Close()
				t.Fatal("foreign PID used self-duplicate bypass")
			}
		})
	}
}

func TestGvxCommittedImageRetainsCapturedOPathConsumer(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "readonly-path-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(file.Name(), 0400); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(file.Name(), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	held, err := captureProcessDescriptor(os.Getpid(), -1, fd)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var identity unix.Stat_t
	if err = unix.Fstat(int(held.Fd()), &identity); err != nil {
		t.Fatal(err)
	}
	flags, writable, err := capturedDescriptorAccess(held)
	if err != nil || writable || flags&unix.O_PATH == 0 {
		t.Fatalf("actual O_PATH capability misclassified: %v", err)
	}
	storage := Storage{}
	if err = storage.checkCapturedProjectDescriptor(held, identity, []uint32{1}, true); err != nil {
		t.Fatalf("non-writing O_PATH consumer required a reopened description: %v", err)
	}
}
