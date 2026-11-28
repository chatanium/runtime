//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

// developmentInput owns the supplied stream across transport and preparation.
// Both cancellation paths may close it; the underlying stream is closed once.
// The extra byte lets the preparer reject an oversized archive without pumping
// an unbounded caller stream into the management transport.
type developmentInput struct {
	io.Reader
	input io.ReadCloser
	once  sync.Once
	err   error
}

func (in *developmentInput) Close() error {
	in.once.Do(func() { in.err = in.input.Close() })
	return in.err
}

func validateDevelopmentStream(data io.ReadCloser) error {
	if data == nil {
		return errors.New("development artifact stream required")
	}
	if file, ok := data.(*os.File); ok {
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
			return err
		}
		kind := stat.Mode & unix.S_IFMT
		if kind != unix.S_IFREG && kind != unix.S_IFIFO {
			return errors.New("development artifact requires a read-only regular file or pipe")
		}
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		if err != nil {
			return err
		}
		if flags&unix.O_ACCMODE != unix.O_RDONLY {
			return errors.New("development artifact descriptor is writable")
		}
	}
	return nil
}

// PrepareDevelopmentWorker publishes a retained development candidate, never a
// release or pending release. Ownership of data is transferred on every path.
func PrepareDevelopmentWorker(ctx context.Context, id RuntimeInstallationID, input bundle.DevelopmentWorkerInput, data io.ReadCloser) (revision legacyhost.RevisionRecord, retErr error) {
	if data == nil {
		return revision, errors.New("development artifact stream required")
	}
	stream := &developmentInput{Reader: data, input: data}
	defer stream.Close()
	stopClose := context.AfterFunc(ctx, func() { stream.Close() })
	defer stopClose()
	if err := rootRequired(); err != nil {
		return revision, err
	}
	if err := provision.ValidateDevelopmentInput(input); err != nil {
		return revision, err
	}
	if err := validateDevelopmentStream(data); err != nil {
		return revision, err
	}
	stream.Reader = io.LimitReader(data, input.ArchiveBytes+1)
	response, live, err := contactOwner(ctx, id, managementRequest{Operation: "prepare_dev_worker", WorkerInput: &input}, &taskInputs{archive: stream})
	if live {
		if err != nil {
			return revision, err
		}
		if !validID(response.RevisionID) {
			return revision, errors.New("missing prepared development revision result")
		}
		store, _, err := openInstallation(ctx, id)
		if err != nil {
			return revision, err
		}
		defer store.Close()
		revision, err = store.Revision(ctx, response.RevisionID)
		if err == nil && revision.DevelopmentWorker == nil {
			err = errors.New("management returned a non-development revision")
		}
		return revision, err
	}
	if err != nil {
		return revision, err
	}
	if err = verifyDevelopmentInstallation(ctx, id); err != nil {
		return revision, err
	}
	session, err := acquireSession(ctx, id, Foreground)
	if err != nil {
		return revision, err
	}
	defer func() { retErr = errors.Join(retErr, closeDevelopmentSession(session)) }()
	return session.prepareDevelopmentWorker(ctx, input, stream)
}

// DiscardDevelopmentRevision retires only the selected owned generation. A
// successful command is evidence of native cleanup, not merely a dropped ref.
func DiscardDevelopmentRevision(ctx context.Context, id RuntimeInstallationID, revision string) (report CleanupReport, retErr error) {
	report.InstallationID = id
	if err := rootRequired(); err != nil {
		return report, err
	}
	if !validID(revision) {
		return report, errors.New("invalid development revision ID")
	}
	response, live, err := contactOwner(ctx, id, managementRequest{Operation: "discard_dev_revision", Revision: revision}, nil)
	if live {
		if response.Report != nil {
			return *response.Report, err
		}
		return report, errors.Join(err, errors.New("missing development discard report"))
	}
	if err != nil {
		return report, err
	}
	if err = verifyDevelopmentInstallation(ctx, id); err != nil {
		return report, err
	}
	session, err := acquireSession(ctx, id, Foreground)
	if err != nil {
		return report, err
	}
	defer func() {
		cleanup := closeDevelopmentSession(session)
		if cleanup != nil {
			report.Complete = false
			report.Failures = append(report.Failures, OperationFailure{Phase: "cleanup", Code: "CLEANUP_INCOMPLETE", Message: cleanup.Error()})
		}
		retErr = errors.Join(retErr, cleanup)
	}()
	return session.discardDevelopmentRevision(ctx, revision)
}

// Do not let stopped development management invoke release bundle recovery:
// admission requires the already installed launcher and complete immutable base.
func verifyDevelopmentInstallation(ctx context.Context, id RuntimeInstallationID) error {
	store, manifest, err := openInstallation(ctx, id)
	if err != nil {
		return err
	}
	defer store.Close()
	return verifyInstalledLauncher(ctx, &ownedSession{id: id, store: store, manifest: manifest})
}

func closeDevelopmentSession(session *ownedSession) error {
	_, drain := DrainOwnedSession(context.Background(), OwnedSession{session})
	return errors.Join(drain, closeMaintenance(session))
}

// beginDevelopmentTask shares admission and drain accounting with image tasks.
// It does not route through management: the authenticated owner calls it directly.
func (s *ownedSession) beginDevelopmentTask(ctx context.Context) (context.Context, func(), error) {
	if err := rootRequired(); err != nil {
		return nil, nil, err
	}
	taskCtx, cancel := context.WithTimeout(ctx, imageConfig(s.manifest, bundle.Verified{}, s.owner, nil).Limits.Deadline)
	id := newID()
	if !validID(id) {
		cancel()
		return nil, nil, errors.New("cannot allocate development task identity")
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		cancel()
		return nil, nil, errors.New("owner is draining")
	}
	if s.taskCancel == nil {
		s.taskCancel = make(map[string]context.CancelFunc)
	}
	s.taskCancel[id] = cancel
	s.preparing.Add(1)
	s.mu.Unlock()
	return taskCtx, func() {
		cancel()
		s.mu.Lock()
		delete(s.taskCancel, id)
		s.mu.Unlock()
		s.preparing.Done()
	}, nil
}

func (s *ownedSession) recoverDevelopmentFailure(cause error) error {
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := s.images.Recover(cleanup)
	if err != nil {
		err = errors.Join(err, s.store.RequireRecovery(cleanup, "development preparation cleanup incomplete"))
	}
	return errors.Join(cause, err)
}

func (s *ownedSession) prepareDevelopmentWorker(ctx context.Context, input bundle.DevelopmentWorkerInput, data io.ReadCloser) (legacyhost.RevisionRecord, error) {
	var zero legacyhost.RevisionRecord
	if data == nil {
		return zero, errors.New("development artifact stream required")
	}
	defer data.Close()
	stopClose := context.AfterFunc(ctx, func() { data.Close() })
	defer stopClose()
	if err := provision.ValidateDevelopmentInput(input); err != nil {
		return zero, err
	}
	if err := validateDevelopmentStream(data); err != nil {
		return zero, err
	}
	taskCtx, finish, err := s.beginDevelopmentTask(ctx)
	if err != nil {
		return zero, err
	}
	defer finish()
	stopTaskClose := context.AfterFunc(taskCtx, func() { data.Close() })
	defer stopTaskClose()
	if err = verifyInstalledLauncher(taskCtx, s); err != nil {
		return zero, err
	}
	manifest, err := s.store.Installation(taskCtx)
	if err != nil {
		return zero, err
	}
	if manifest.State != "READY" || manifest.ActiveRevision == "" || manifest.BundleDigest != s.manifest.BundleDigest {
		return zero, errors.New("development preparation requires the active READY installed base")
	}
	revision, err := s.store.Revision(taskCtx, manifest.ActiveRevision)
	if err != nil {
		return zero, err
	}
	if revision.DevelopmentWorker != nil || revision.BundleDigest != manifest.BundleDigest {
		return zero, errors.New("development worker base must be the active release")
	}
	worker, err := s.images.PrepareDevelopmentWorker(taskCtx, input, data)
	if err != nil {
		return zero, s.recoverDevelopmentFailure(err)
	}
	baseID := revision.ID
	revision.ID = newID()
	revision.DevelopmentWorker = &legacyhost.DevelopmentWorkerBinding{BaseRevision: baseID, ArtifactDigest: worker.Digest, JobID: worker.JobID}
	// Copying the entire release record preserves LaunchPolicies and future
	// release fields as well as config, images, bundle and public network policy.
	// The Store atomically transfers the upload reference with this insertion.
	if err = s.store.PutDevelopmentRevision(taskCtx, revision); err != nil {
		return zero, s.recoverDevelopmentFailure(err)
	}
	return revision, nil
}

func (s *ownedSession) discardDevelopmentRevision(ctx context.Context, revisionID string) (CleanupReport, error) {
	report := CleanupReport{InstallationID: s.id, ObservedState: "unknown"}
	object := ObjectResult{Kind: "development-revision", Identity: revisionID, State: "pending"}
	fail := func(cause error) (CleanupReport, error) {
		failure := OperationFailure{Phase: "development-discard", Code: "CLEANUP_INCOMPLETE", Message: cause.Error()}
		object.Failures = append(object.Failures, failure)
		report.Pending = append(report.Pending, object)
		report.Failures = append(report.Failures, failure)
		return report, cause
	}
	if !validID(revisionID) {
		return fail(errors.New("invalid development revision ID"))
	}
	taskCtx, finish, err := s.beginDevelopmentTask(ctx)
	if err != nil {
		return fail(err)
	}
	defer finish()
	if err = verifyInstalledLauncher(taskCtx, s); err != nil {
		return fail(err)
	}
	manifest, err := s.store.Installation(taskCtx)
	if err != nil {
		return fail(err)
	}
	report.DesiredRunState = manifest.DesiredRunState
	if revisionID == manifest.ActiveRevision || revisionID == manifest.PendingRevision {
		return fail(errors.New("cannot discard an active or pending release"))
	}
	revision, err := s.store.Revision(taskCtx, revisionID)
	if err != nil {
		return fail(err)
	}
	if revision.DevelopmentWorker == nil {
		return fail(errors.New("only an owned development revision may be discarded"))
	}
	proof, err := s.images.DiscardDevelopmentWorker(taskCtx, revisionID)
	if err != nil {
		return fail(err)
	}
	if !proof.JobsAbsent || !proof.ProcessesAbsent || !proof.TransportsClosed || !proof.MountsAbsent || !proof.OpenReferencesAbsent || !proof.QuotaReclaimed {
		return fail(host.ErrCleanupIncomplete)
	}
	object.State = "removed"
	report.Removed = append(report.Removed, object)
	report.Complete = true
	if s.worker.Name != "" {
		report.ObservedState = "running"
	} else {
		report.ObservedState = "stopped"
	}
	return report, nil
}

// purgeDevelopment runs while the owner's quota filesystem is mounted. All
// scope and retention checks precede mutation; an upload whose publication
// response was lost remains owned and cannot be silently converted or deleted.
func (s *ownedSession) purgeDevelopment(ctx context.Context, scope []ApprovedObject) ([]ObjectResult, []ApprovedObject, error) {
	records, err := s.store.PendingProvisions(ctx)
	if err != nil {
		return nil, scope, err
	}
	refs, err := s.store.GenerationReferences(ctx)
	if err != nil {
		return nil, scope, err
	}
	wholeVolume := false
	for _, object := range scope {
		if object.Kind != "backing" || object.Identity != s.manifest.Paths.BackingFile {
			continue
		}
		backing, err := ownedRecord(ctx, s.store, object.Kind, object.Identity)
		if err != nil {
			return nil, scope, err
		}
		if err = authorizeRemoval(backing, object); err != nil {
			return nil, scope, err
		}
		wholeVolume = true
	}
	approved := make(map[string]ApprovedObject)
	for _, object := range scope {
		if object.Kind == "development-worker" {
			if _, exists := approved[object.Identity]; exists {
				return nil, scope, errors.New("duplicate development purge scope")
			}
			approved[object.Identity] = object
		}
	}
	volumeUploads := make(map[string]bool)
	seenReferences := make(map[string]bool)
	for _, ref := range refs {
		if !strings.HasPrefix(ref.ID, "development-worker:") {
			continue
		}
		if seenReferences[ref.ID] {
			return nil, scope, errors.New("development purge generation has conflicting retention references")
		}
		seenReferences[ref.ID] = true
		job := strings.TrimPrefix(ref.ID, "development-worker:")
		if ref.Kind != "preparation" {
			return nil, scope, errors.New("live or recovery development reference blocks purge")
		}
		if wholeVolume && ref.Claim == "dev-upload:"+job {
			if err = s.validateDevelopmentVolumeUpload(records, job); err != nil {
				return nil, scope, err
			}
			volumeUploads[job] = true
			continue
		}
		if _, ok := approved[job]; !ok {
			return nil, scope, errors.New("retained development generation is outside purge approval")
		}
	}
	type selection struct {
		job      string
		revision string
	}
	var selected []selection
	seen := make(map[string]bool)
	for _, record := range records {
		approval, ok := approved[record.Identity]
		if record.Kind != "development-worker" || !ok {
			continue
		}
		if seen[record.Identity] {
			return nil, scope, errors.New("ambiguous development purge ledger")
		}
		seen[record.Identity] = true
		if err = authorizeRemoval(record, approval); err != nil {
			return nil, scope, err
		}
		if volumeUploads[record.Identity] {
			// The exact backing approval, not a synthetic revision, authorizes
			// eventual contained-volume destruction. Keep this scope entry.
			continue
		}
		revisionID := ""
		for _, ref := range refs {
			if ref.ID != "development-worker:"+record.Identity {
				continue
			}
			if ref.Kind != "preparation" || !strings.HasPrefix(ref.Claim, "dev-revision:") || revisionID != "" {
				return nil, scope, errors.New("development purge requires exactly one unreferenced owned revision")
			}
			revisionID = strings.TrimPrefix(ref.Claim, "dev-revision:")
		}
		if !validID(revisionID) {
			return nil, scope, errors.New("development purge cannot discard an uncertain upload or retired generation")
		}
		revision, err := s.store.Revision(ctx, revisionID)
		if err != nil {
			return nil, scope, err
		}
		if revision.DevelopmentWorker == nil || revision.DevelopmentWorker.JobID != record.Identity {
			return nil, scope, errors.New("development purge revision binding mismatch")
		}
		selected = append(selected, selection{job: record.Identity, revision: revisionID})
	}
	if len(seen) != len(approved) {
		return nil, scope, errors.New("development purge scope lacks proven ownership")
	}
	remaining := append([]ApprovedObject(nil), scope...)
	var removed []ObjectResult
	for _, candidate := range selected {
		report, err := s.discardDevelopmentRevision(ctx, candidate.revision)
		if err != nil || !report.Complete {
			return removed, remaining, errors.Join(err, host.ErrCleanupIncomplete)
		}
		removed = append(removed, ObjectResult{Kind: "development-worker", Identity: candidate.job, State: "removed"})
		for index, object := range remaining {
			if object.Kind == "development-worker" && object.Identity == candidate.job {
				remaining = append(remaining[:index], remaining[index+1:]...)
				break
			}
		}
	}
	return removed, remaining, nil
}

func (s *ownedSession) validateDevelopmentVolumeUpload(records []legacyhost.ProvisionRecord, job string) error {
	if !validID(job) {
		return errors.New("invalid retained development upload identity")
	}
	found := false
	for _, record := range records {
		if record.Kind != "development-worker" || record.Identity != job {
			continue
		}
		if found || !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
			return errors.New("whole-volume development upload lacks unique observed ownership")
		}
		var properties legacyhost.ProvisionProperties
		if err := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &properties); err != nil {
			return err
		}
		space := properties.ImageSpace
		if space == nil || space.JobID != job || space.ReusedSource ||
			space.Source != filepath.Join(s.manifest.Paths.StorageRoot, "images", job) ||
			space.Cache != filepath.Join(s.manifest.Paths.StorageRoot, "prepared", job) ||
			space.Work != filepath.Join(s.manifest.Paths.StorageRoot, "preparation", job) ||
			space.SourceProject == 0 || space.CacheProject == 0 || space.WorkProject == 0 ||
			properties.Path != space.Source || properties.Source != space.Work || properties.Target != space.Cache ||
			!provision.ValidDigest(properties.Digest) {
			return errors.New("development upload is outside the exact owned quota volume")
		}
		found = true
	}
	if !found {
		return errors.New("retained development upload lacks an owned ledger generation")
	}
	return nil
}
