package upload

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

// UploadReadLease pins one immutable upload for a single admitted outbound
// operation. Deletion/expiry prevent new leases but do not cancel this lease.
// Cancellation closes readers; the owning backend joins its multipart/HTTP
// workers before calling Release. Instance cleanup joins forced releases.
type UploadReadLease struct {
	store            *UploadStore
	record           *record
	ctx              context.Context
	cancel           context.CancelFunc
	stopAdmission    func() bool
	stopCancellation func() bool
	mu               sync.Mutex
	condition        *sync.Cond
	readers          map[*leaseReader]struct{}
	releasing        bool
	once             sync.Once
	stopRelease      sync.Once
	done             chan struct{}
	result           error
}

// AcquireReadLease requires an actual runtime operation admission in ctx and a
// finite outbound-operation deadline. Metadata is checked against the stored
// owner, exact size/name/MIME and original expiry; none is used as authority.
func (s *UploadStore) AcquireReadLease(ctx context.Context, principal runtime.InstancePrincipal, ref *wire.UploadedFileRef) (*UploadReadLease, error) {
	work, err := admitted(ctx, principal)
	if err != nil {
		return nil, err
	}
	admission, err := runtime.AdmissionFromContext(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if work.Err() != nil {
		return nil, contextFailure(work)
	}
	if admission.Context().Err() != nil {
		return nil, contextFailure(admission.Context())
	}
	r, err := s.lookupLocked(principal, ref, time.Now())
	if err != nil {
		return nil, err
	}
	if r.retiring || !r.storage {
		return nil, notFound()
	}
	bounded, cancel := context.WithCancel(work)
	lease := &UploadReadLease{store: s, record: r, ctx: bounded, cancel: cancel, readers: make(map[*leaseReader]struct{}), done: make(chan struct{})}
	lease.condition = sync.NewCond(&lease.mu)
	r.leases[lease] = struct{}{}
	lease.stopAdmission = context.AfterFunc(admission.Context(), cancel)
	lease.stopCancellation = context.AfterFunc(bounded, func() {
		lease.mu.Lock()
		readers := make([]*leaseReader, 0, len(lease.readers))
		for reader := range lease.readers {
			readers = append(readers, reader)
		}
		lease.releasing = true
		lease.mu.Unlock()
		for _, reader := range readers {
			_ = reader.Close()
		}
	})
	return lease, nil
}

// Reference returns a fresh validated metadata copy, never a filesystem path.
func (l *UploadReadLease) Reference() *wire.UploadedFileRef { return reference(l.record) }

// Context is bounded by both the actual admission and outbound operation. Use it
// for HTTP and multipart workers so instance stop cancels the complete operation.
func (l *UploadReadLease) Context() context.Context { return l.ctx }

// Open returns a fresh offset-zero reader. Every reader must be closed before
// Release can complete. A shorter per-attempt context also cancels that reader.
func (l *UploadReadLease) Open(ctx context.Context) (io.ReadCloser, error) {
	if ctx == nil {
		return nil, invalid()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.releasing {
		return nil, notFound()
	}
	if l.ctx.Err() != nil {
		return nil, contextFailure(l.ctx)
	}
	if ctx.Err() != nil {
		return nil, contextFailure(ctx)
	}
	file, err := l.store.spool.open(l.record.name)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil || stat.Size() < 0 || uint64(stat.Size()) != l.record.size {
		_ = file.Close()
		return nil, internal()
	}
	reader := &leaseReader{file: file, lease: l, ctx: ctx}
	l.readers[reader] = struct{}{}
	reader.stop = context.AfterFunc(ctx, func() { _ = reader.Close() })
	return reader, nil
}

// Release prevents further Open calls, waits for all owned readers to close,
// and drops the storage pin exactly once. It does not cancel admitted readers.
// Cancellation/stop instead close readers through the lease's context callback.
func (l *UploadReadLease) Release() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.releasing = true
		for len(l.readers) != 0 {
			l.condition.Wait()
		}
		l.mu.Unlock()
		l.store.mu.Lock()
		delete(l.record.leases, l)
		l.result = l.store.reclaimLocked(l.record, time.Now())
		l.store.mu.Unlock()
		l.stopAdmission()
		l.stopCancellation()
		l.cancel()
		close(l.done)
	})
	return l.result
}

type leaseReader struct {
	file   *os.File
	lease  *UploadReadLease
	ctx    context.Context
	stop   func() bool
	once   sync.Once
	result error
}

func (r *leaseReader) Read(bytes []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, contextFailure(r.ctx)
	}
	if r.lease.ctx.Err() != nil {
		return 0, contextFailure(r.lease.ctx)
	}
	n, err := r.file.Read(bytes)
	if err != nil && err != io.EOF {
		return n, internal()
	}
	return n, err
}

func (r *leaseReader) Close() error {
	r.once.Do(func() {
		if err := r.file.Close(); err != nil {
			r.result = internal()
		}
		// Open publishes stop under this mutex before cancellation may use it.
		r.lease.mu.Lock()
		stop := r.stop
		r.lease.mu.Unlock()
		stop()
		r.lease.mu.Lock()
		delete(r.lease.readers, r)
		r.lease.condition.Broadcast()
		r.lease.mu.Unlock()
	})
	return r.result
}
