package upload

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	config := Config{ManagementDirectory: t.TempDir(), ModuleMountRoots: []string{t.TempDir()}, Limits: runtime.Limits{UploadRecordsPerInstance: 4, UploadRecordsPerHost: 8, UploadFileNameMaxBytes: 128, UploadContentTypeMaxBytes: 128, UploadDeadline: runtime.Duration(time.Minute)}}
	// testing.TempDir creates its numbered child with mode 0777 subject to
	// umask, not 0700. Provision this owned fixture like the supervisor does;
	// production must continue rejecting a public management parent.
	if err := os.Chmod(config.ManagementDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(config.ManagementDirectory, "uploads"), 0700); err != nil {
		t.Fatal(err)
	}
	return config
}

func testStore(t *testing.T, config Config) (*UploadStore, runtime.InstancePrincipal) {
	t.Helper()
	s, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	p := runtime.InstancePrincipal{ModuleID: "module", InstanceID: "instance"}
	s.instances[p.InstanceID] = &instance{principal: p}
	return s, p
}

// Internal fixtures exercise accounting transitions directly; no production
// authority bypass is exported and RPC/read admission still requires runtime.
func reserveTest(t *testing.T, s *UploadStore, p runtime.InstancePrincipal, size uint64) *record {
	t.Helper()
	r, _, err := s.reserve(context.Background(), p, &wire.UploadMetadata{FileName: "../display-name", ContentType: "application/octet-stream", DeclaredSizeBytes: size})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func commitTest(t *testing.T, s *UploadStore, r *record) {
	t.Helper()
	file, err := s.spool.create(r.name)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(r.size)); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0400); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	r.storage = true
	r.committed = true
	r.writing = false
	r.expires = time.Now().Add(CompletionTTL)
	close(r.writerDone)
	s.releaseSlotLocked(r)
	s.mu.Unlock()
}

func TestZeroByteTombstoneOccupiesEntryUntilOriginalExpiry(t *testing.T) {
	config := testConfig(t)
	config.Limits.UploadRecordsPerInstance = 1
	s, p := testStore(t, config)
	r := reserveTest(t, s, p, 0)
	commitTest(t, s, r)
	expires := r.expires
	r.deleted = true
	r.retiring = true
	if err := s.reclaimLocked(r, expires.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if s.usage.bytes != 0 || s.usage.active != 0 || s.usage.records != 1 || r.storage {
		t.Fatalf("wrong tombstone accounting: %+v", s.usage)
	}
	for range 2 {
		if _, err := s.lookupLocked(p, reference(r), expires.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := s.reclaimLocked(r, expires.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if !r.expires.Equal(expires) {
		t.Fatal("repeat delete extended TTL")
	}
	before := s.usage
	_, _, err := s.reserve(context.Background(), p, &wire.UploadMetadata{FileName: "empty", ContentType: "text/plain"})
	if status.Code(err) != codes.ResourceExhausted || s.usage != before {
		t.Fatalf("tombstone did not atomically deny admission: %v %+v", err, s.usage)
	}
	if err := s.reclaimLocked(r, expires); err != nil {
		t.Fatal(err)
	}
	if s.usage != (accounting{}) || len(s.records) != 0 {
		t.Fatalf("expired tombstone retained: %+v", s.usage)
	}
	if err := s.reclaimLocked(r, expires); err != nil {
		t.Fatal(err)
	}
	if s.usage != (accounting{}) {
		t.Fatal("double decrement")
	}
}

func TestReservationFailureLeavesHostAndInstanceUntouched(t *testing.T) {
	for _, constraint := range []string{"host bytes", "instance bytes", "host slots", "instance slots", "host records", "instance records"} {
		t.Run(constraint, func(t *testing.T) {
			s, p := testStore(t, testConfig(t))
			i := s.instances[p.InstanceID]
			switch constraint {
			case "host bytes":
				s.usage.bytes = BytesPerHost
			case "instance bytes":
				i.usage.bytes = BytesPerInstance
			case "host slots":
				s.usage.active = ActiveUploadsPerHost
			case "instance slots":
				i.usage.active = ActiveUploadsPerInstance
			case "host records":
				s.usage.records = s.config.Limits.UploadRecordsPerHost
			case "instance records":
				i.usage.records = s.config.Limits.UploadRecordsPerInstance
			}
			hostBefore, instanceBefore := s.usage, i.usage
			_, _, err := s.reserve(context.Background(), p, &wire.UploadMetadata{FileName: "file", ContentType: "text/plain", DeclaredSizeBytes: 1})
			if status.Code(err) != codes.ResourceExhausted || s.usage != hostBefore || i.usage != instanceBefore || len(s.records) != 0 {
				t.Fatalf("partial reservation: %v host=%+v instance=%+v", err, s.usage, i.usage)
			}
			// Synthetic boundary counters are not live resources.
			s.usage = accounting{}
			i.usage = accounting{}
		})
	}
}

func TestUnlinkFailureRetainsAllChargesAndCanRetry(t *testing.T) {
	s, p := testStore(t, testConfig(t))
	r := reserveTest(t, s, p, 1)
	commitTest(t, s, r)
	if err := s.spool.remove(r.name); err != nil {
		t.Fatal(err)
	}
	fd := int(s.spool.directory.Fd())
	if err := unix.Mkdirat(fd, r.name, 0700); err != nil {
		t.Fatal(err)
	}
	r.retiring = true
	before := s.usage
	if err := s.reclaimLocked(r, time.Now()); status.Code(err) != codes.Internal {
		t.Fatalf("unlink failure not reported: %v", err)
	}
	if s.usage != before || !r.storage || !r.charged || s.LastCleanupError() == nil {
		t.Fatal("failed unlink released accounting")
	}
	if err := unix.Unlinkat(fd, r.name, unix.AT_REMOVEDIR); err != nil {
		t.Fatal(err)
	}
	if err := s.reclaimLocked(r, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.usage != (accounting{}) {
		t.Fatalf("retry leaked accounting: %+v", s.usage)
	}
}

func TestExclusiveSpoolOwnershipAndOrphanReclaim(t *testing.T) {
	config := testConfig(t)
	first, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close(context.Background()) })
	name := "file-00000000000000000000000000000000"
	writer, err := first.spool.create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if second, err := New(context.Background(), config); err == nil {
		_ = second.Close(context.Background())
		t.Fatal("second store acquired active spool")
	}
	if _, err := os.Stat(filepath.Join(config.ManagementDirectory, "uploads", name)); err != nil {
		t.Fatal("second store removed active file")
	}
	// Simulate an old runtime epoch without an in-memory ref registry.
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	if _, err := os.Stat(filepath.Join(config.ManagementDirectory, "uploads", name)); !os.IsNotExist(err) {
		t.Fatalf("orphan survived: %v", err)
	}
	if len(second.records) != 0 {
		t.Fatal("orphan reference revived")
	}
}

func TestReaderReleaseWaitsAndIsIdempotent(t *testing.T) {
	s, p := testStore(t, testConfig(t))
	r := reserveTest(t, s, p, 0)
	commitTest(t, s, r)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	lease := &UploadReadLease{store: s, record: r, ctx: ctx, cancel: cancel, readers: make(map[*leaseReader]struct{}), done: make(chan struct{}), stopAdmission: func() bool { return true }, stopCancellation: func() bool { return true }}
	lease.condition = sync.NewCond(&lease.mu)
	r.leases[lease] = struct{}{}
	reader, err := lease.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	r.retiring = true
	r.deleted = true
	if err := s.reclaimLocked(r, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !r.storage {
		t.Fatal("retirement reclaimed a pinned reader")
	}
	var byte [1]byte
	if _, err := reader.Read(byte[:]); err != io.EOF {
		t.Fatalf("zero-byte reader: %v", err)
	}
	// Linearize Release's admission closure without sleeps or scheduler timing.
	lease.mu.Lock()
	lease.releasing = true
	lease.mu.Unlock()
	released := make(chan error, 1)
	go func() { released <- lease.Release() }()
	select {
	case <-lease.done:
		t.Fatal("release completed before reader close")
	default:
	}
	if _, err := lease.Open(ctx); err == nil {
		t.Fatal("released lease admitted another reader")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if r.storage || s.usage.records != 1 || s.usage.bytes != 0 {
		t.Fatalf("wrong post-release tombstone: %+v", s.usage)
	}
}
