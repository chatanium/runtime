package upload

import (
	"context"
	"mime"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	MaxChunkBytes                   = 256 << 10
	MaxFileBytes             uint64 = 500 << 20
	ActiveUploadsPerInstance        = 2
	ActiveUploadsPerHost            = 8
	BytesPerInstance         uint64 = 2 << 30
	BytesPerHost             uint64 = 8 << 30
	CompletionTTL                   = 30 * time.Minute
)

// Config has required upload limits. The supervisor provisions
// ManagementDirectory/uploads as private runtime storage outside every module mount.
type Config struct {
	ManagementDirectory string
	Limits              runtime.Limits
	// Portable requires installation-owned private storage. No host directory is
	// bound into the guest, so a module mount root inventory is not required.
	Portable bool
	// ModuleMountRoots lists every trusted host subtree exposed to modules.
	// Roots must already exist; lexical and resolved overlap both fail closed.
	ModuleMountRoots []string
}

type accounting struct {
	bytes           uint64
	active, records int
}
type instance struct {
	principal runtime.InstancePrincipal
	stopped   bool
	usage     accounting
}
type record struct {
	id, name, fileName, contentType                      string
	owner                                                *instance
	size                                                 uint64
	expires                                              time.Time
	committed, retiring, deleted, storage, charged, slot bool
	writing                                              bool
	writerDone                                           chan struct{}
	cancel                                               context.CancelFunc
	leases                                               map[*UploadReadLease]struct{}
	timer                                                *time.Timer
}

// UploadStore owns all reservation and retirement state under a single lock.
// Byte charges and record entries are released independently, only after actual
// unlink and, for entries, the original deletion retention window have ended.
type UploadStore struct {
	mu               sync.Mutex
	config           Config
	spool            *spool
	instances        map[runtime.InstanceID]*instance
	records          map[string]*record
	usage            accounting
	closing, closed  bool
	lastCleanupError error
}

// New verifies and exclusively claims the existing supervisor-provisioned
// ManagementDirectory/uploads child, then reclaims its old internal spool
// files. It never recovers references from an earlier runtime.
func New(ctx context.Context, config Config) (*UploadStore, error) {
	l := config.Limits
	if l.UploadRecordsPerInstance <= 0 || l.UploadRecordsPerHost <= 0 || l.UploadFileNameMaxBytes <= 0 || l.UploadContentTypeMaxBytes <= 0 || l.UploadDeadline <= 0 {
		return nil, invalid()
	}
	if config.Portable && (l.UploadRecordsPerInstance != 1 || l.UploadRecordsPerHost != 1) {
		return nil, invalid()
	}
	if err := validateIsolation(config); err != nil {
		return nil, err
	}
	spool, err := openSpool(ctx, config.ManagementDirectory, config.Portable)
	if err != nil {
		return nil, err
	}
	return &UploadStore{config: config, spool: spool, instances: make(map[runtime.InstanceID]*instance), records: make(map[string]*record)}, nil
}

func validateIsolation(config Config) error {
	if !filepath.IsAbs(config.ManagementDirectory) || filepath.Clean(config.ManagementDirectory) != config.ManagementDirectory || !config.Portable && len(config.ModuleMountRoots) == 0 {
		return invalid()
	}
	management, err := filepath.EvalSymlinks(config.ManagementDirectory)
	if err != nil {
		return internal()
	}
	spool := filepath.Join(management, "uploads")
	for _, root := range config.ModuleMountRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return invalid()
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return internal()
		}
		for _, pair := range [][2]string{{root, filepath.Join(config.ManagementDirectory, "uploads")}, {resolved, spool}} {
			if within(pair[0], pair[1]) || within(pair[1], pair[0]) {
				return invalid()
			}
		}
	}
	return nil
}

func within(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func invalid() error  { return core.NewError(codes.InvalidArgument, core.ReasonInvalidArgument) }
func internal() error { return core.NewError(codes.Internal, core.ReasonInternal) }
func unavailable() error {
	return core.NewError(codes.FailedPrecondition, core.ReasonInstanceNotRunning)
}
func notFound() error { return core.NewError(codes.NotFound, core.ReasonRefNotFound) }
func contextFailure(ctx context.Context) error {
	if ctx.Err() == context.DeadlineExceeded {
		return core.NewError(codes.DeadlineExceeded, core.ReasonDeadlineExceeded)
	}
	return core.NewError(codes.Canceled, core.ReasonCanceled)
}

func (s *UploadStore) validateMetadata(m *wire.UploadMetadata) error {
	if m == nil {
		return core.NewError(codes.InvalidArgument, core.ReasonUploadSequence)
	}
	if m.DeclaredSizeBytes > MaxFileBytes {
		return core.NewError(codes.OutOfRange, core.ReasonUploadTooLarge)
	}
	if m.FileName == "" || len(m.FileName) > s.config.Limits.UploadFileNameMaxBytes || !utf8.ValidString(m.FileName) || strings.ContainsAny(m.FileName, "\r\n\x00") || m.ContentType == "" || len(m.ContentType) > s.config.Limits.UploadContentTypeMaxBytes || !utf8.ValidString(m.ContentType) || strings.ContainsAny(m.ContentType, "\r\n\x00") {
		return invalid()
	}
	media, _, err := mime.ParseMediaType(m.ContentType)
	if err != nil || !strings.Contains(media, "/") {
		return invalid()
	}
	return nil
}

func (s *UploadStore) reserve(ctx context.Context, p runtime.InstancePrincipal, m *wire.UploadMetadata) (*record, context.Context, error) {
	if err := s.validateMetadata(m); err != nil {
		return nil, nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return nil, nil, contextFailure(ctx)
	}
	i := s.instances[p.InstanceID]
	if s.closing || i == nil || i.stopped || i.principal != p {
		return nil, nil, unavailable()
	}
	if _, exists := s.records[id]; exists {
		return nil, nil, internal()
	}
	if s.usage.active >= ActiveUploadsPerHost || i.usage.active >= ActiveUploadsPerInstance || s.usage.records >= s.config.Limits.UploadRecordsPerHost || i.usage.records >= s.config.Limits.UploadRecordsPerInstance || m.DeclaredSizeBytes > BytesPerHost-s.usage.bytes || m.DeclaredSizeBytes > BytesPerInstance-i.usage.bytes {
		return nil, nil, core.NewError(codes.ResourceExhausted, core.ReasonQuotaExceeded)
	}
	work, cancel := context.WithCancel(ctx)
	r := &record{id: id, name: "file-" + id, fileName: m.FileName, contentType: m.ContentType, owner: i, size: m.DeclaredSizeBytes, charged: true, slot: true, writing: true, writerDone: make(chan struct{}), cancel: cancel, leases: make(map[*UploadReadLease]struct{})}
	s.records[id] = r
	s.usage.bytes += r.size
	i.usage.bytes += r.size
	s.usage.active++
	i.usage.active++
	s.usage.records++
	i.usage.records++
	return r, work, nil
}

func (s *UploadStore) releaseSlotLocked(r *record) {
	if r.slot {
		r.slot = false
		s.usage.active--
		r.owner.usage.active--
	}
}

// reclaimLocked cannot release a byte charge while any writer or lease owns the
// file. A failed unlink leaves every charge and the cleanup record in place.
func (s *UploadStore) reclaimLocked(r *record, now time.Time) error {
	if !r.retiring || r.writing || len(r.leases) != 0 {
		return nil
	}
	if r.storage {
		if err := s.spool.remove(r.name); err != nil {
			s.lastCleanupError = err
			return err
		}
		r.storage = false
	}
	if r.charged {
		r.charged = false
		s.usage.bytes -= r.size
		r.owner.usage.bytes -= r.size
	}
	s.releaseSlotLocked(r)
	if r.deleted && !r.owner.stopped && !s.closing && now.Before(r.expires) {
		return nil
	}
	if s.records[r.id] == r {
		delete(s.records, r.id)
		s.usage.records--
		r.owner.usage.records--
		if r.timer != nil {
			r.timer.Stop()
		}
	}
	return nil
}

func (s *UploadStore) expire(r *record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.records[r.id] != r {
		return
	}
	r.retiring = true
	_ = s.reclaimLocked(r, time.Now())
}

func reference(r *record) *wire.UploadedFileRef {
	return &wire.UploadedFileRef{OpaqueId: r.id, FileName: r.fileName, ContentType: r.contentType, SizeBytes: r.size, ExpiresAt: timestamppb.New(r.expires)}
}

func (s *UploadStore) lookupLocked(p runtime.InstancePrincipal, ref *wire.UploadedFileRef, now time.Time) (*record, error) {
	if s.closing {
		return nil, unavailable()
	}
	i := s.instances[p.InstanceID]
	if i == nil || i.stopped || i.principal != p {
		return nil, unavailable()
	}
	if ref == nil {
		return nil, invalid()
	}
	r := s.records[ref.OpaqueId]
	if r == nil {
		return nil, notFound()
	}
	if r.owner != i {
		return nil, core.NewError(codes.PermissionDenied, core.ReasonScopeDenied)
	}
	if !r.committed {
		return nil, notFound()
	}
	if !now.Before(r.expires) {
		r.retiring = true
		_ = s.reclaimLocked(r, now) // Cleanup failures remain observable, not usable refs.
		return nil, core.NewError(codes.NotFound, core.ReasonRefExpired)
	}
	// These are display copies, not authority. Altering any field is rejected;
	// expiration and accounting always use the immutable server-side record.
	if ref.FileName != r.fileName || ref.ContentType != r.contentType || ref.SizeBytes != r.size || ref.ExpiresAt == nil || ref.ExpiresAt.CheckValid() != nil || !ref.ExpiresAt.AsTime().Equal(r.expires) {
		return nil, invalid()
	}
	return r, nil
}

// admitted proves the supplied principal belongs to the actual authorized RPC,
// not metadata or a manufactured owner value. All file uses have finite bounds.
func admitted(ctx context.Context, p runtime.InstancePrincipal) (context.Context, error) {
	if ctx == nil {
		return nil, invalid()
	}
	a, err := runtime.AdmissionFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if a.Principal() != p {
		return nil, core.NewError(codes.PermissionDenied, core.ReasonScopeDenied)
	}
	if a.Context().Err() != nil {
		return nil, contextFailure(a.Context())
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, invalid()
	}
	if ctx.Err() != nil {
		return nil, contextFailure(ctx)
	}
	return ctx, nil
}

// Delete prevents new reads. Already admitted leases remain usable until their
// own operation deadline. A successful unlink retains an owner-checked tombstone
// until the original expiration, even for zero-byte files.
func (s *UploadStore) Delete(ctx context.Context, p runtime.InstancePrincipal, ref *wire.UploadedFileRef) error {
	if _, err := admitted(ctx, p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.lookupLocked(p, ref, time.Now())
	if err != nil {
		return err
	}
	if r.retiring && !r.deleted {
		return notFound()
	}
	r.deleted = true
	r.retiring = true
	return s.reclaimLocked(r, time.Now())
}

// Sweep reattempts failed cleanup and expires records without extending any TTL.
// Timer cleanup failures are also available through LastCleanupError.
func (s *UploadStore) Sweep(ctx context.Context) error {
	if ctx == nil {
		return invalid()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var result error
	now := time.Now()
	for _, r := range s.records {
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		if r.committed && !now.Before(r.expires) {
			r.retiring = true
		}
		if err := s.reclaimLocked(r, now); err != nil {
			result = err
		}
	}
	return result
}

// LastCleanupError returns a fixed, structured diagnostic, never a filesystem
// path or underlying OS error. A failure remains observable after later retries.
func (s *UploadStore) LastCleanupError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCleanupError
}

// CleanupInstance is runtime.ManagerOptions.FileCleanup. It denies new work,
// cancels and joins writers/readers, drops retention, and reclaims actual bytes.
// A deadline or unlink failure keeps the ownership lock and all remaining charges
// so the manager can fail closed and retry rather than declaring reclamation.
func (s *UploadStore) CleanupInstance(ctx context.Context, p runtime.InstancePrincipal) error {
	if ctx == nil {
		return invalid()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	i := s.instances[p.InstanceID]
	if i == nil {
		s.mu.Unlock()
		return nil
	}
	if i.principal != p {
		s.mu.Unlock()
		return core.NewError(codes.PermissionDenied, core.ReasonScopeDenied)
	}
	i.stopped = true
	var writers []<-chan struct{}
	var leases []*UploadReadLease
	for _, r := range s.records {
		if r.owner != i {
			continue
		}
		r.retiring = true
		r.deleted = false
		r.cancel()
		if r.writing {
			writers = append(writers, r.writerDone)
		}
		for lease := range r.leases {
			leases = append(leases, lease)
		}
	}
	s.mu.Unlock()
	for _, lease := range leases {
		lease.cancel()
		// Backend Cleanup has already joined outbound workers before this
		// callback. Start at most one forced release even across retries.
		lease.stopRelease.Do(func() { go func() { _ = lease.Release() }() })
	}
	for _, done := range writers {
		select {
		case <-done:
		case <-ctx.Done():
			return contextFailure(ctx)
		}
	}
	for _, lease := range leases {
		select {
		case <-lease.done:
		case <-ctx.Done():
			return contextFailure(ctx)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var result error
	for _, r := range s.records {
		if r.owner == i {
			if err := s.reclaimLocked(r, time.Now()); err != nil {
				result = err
			}
		}
	}
	if result == nil && i.usage.records == 0 {
		delete(s.instances, p.InstanceID)
	}
	return result
}

// Close cancels all instances and releases exclusive directory ownership only
// after every worker and actual spool file has been reclaimed. Retry on failure.
// The composition must stop/join backend operations before closing the store.
func (s *UploadStore) Close(ctx context.Context) error {
	if ctx == nil {
		return invalid()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	principals := make([]runtime.InstancePrincipal, 0, len(s.instances))
	for _, i := range s.instances {
		principals = append(principals, i.principal)
	}
	s.mu.Unlock()
	for _, p := range principals {
		if err := s.CleanupInstance(ctx, p); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if len(s.records) != 0 {
		return internal()
	}
	s.closed = true
	return s.spool.close()
}

func sameManagement(a, b string) bool { return filepath.Clean(a) == filepath.Clean(b) }
