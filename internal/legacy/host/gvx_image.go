//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

const ImageManifestLabel = provision.ImageManifestLabel

const preparationSource = "/chatanium/source"
const preparationCache = "/chatanium/cache"
const preparationWork = "/chatanium/work"
const preparationBase = "/chatanium/base"

type ImageManagerConfig struct {
	Owner     sharedhost.UnitIdentity
	Bundle    bundle.Verified
	Preparer  NumericIdentity
	Limits    provision.PrepareLimits
	TaskInput func(context.Context, provision.ApprovedImageInput) (archive, credential io.ReadCloser, err error)
}
type ImageManager struct {
	cfg     ImageManagerConfig
	store   *Store
	systemd *Systemd
	storage *Storage
	mu      sync.Mutex
}

func NewImageManager(c ImageManagerConfig, s *Store, d *Systemd, storage *Storage) (*ImageManager, error) {
	if s == nil || d == nil || storage == nil || c.Owner.Name == "" || c.Bundle.Digest == "" || c.Preparer.UID == 0 || c.Preparer.GID == 0 {
		return nil, errors.New("image manager requires installed bounded owner")
	}
	if e := c.Limits.Validate(); e != nil {
		return nil, e
	}
	if e := s.requireLease(); e != nil {
		return nil, e
	}
	if e := d.BindStore(s); e != nil {
		return nil, e
	}
	return &ImageManager{cfg: c, store: s, systemd: d, storage: storage}, nil
}
func withinImageLimits(a, b provision.PrepareLimits) bool {
	av := []int64{a.NanoCPUs, a.MemoryBytes, a.Tasks, a.InputBytes, a.ExpandedBytes, a.OutputBytes, a.Inodes, a.JSONBytes, a.DescriptorCount, a.IndexDepth, int64(a.Deadline)}
	bv := []int64{b.NanoCPUs, b.MemoryBytes, b.Tasks, b.InputBytes, b.ExpandedBytes, b.OutputBytes, b.Inodes, b.JSONBytes, b.DescriptorCount, b.IndexDepth, int64(b.Deadline)}
	for i, v := range av {
		if v > bv[i] {
			return false
		}
	}
	return true
}
func (m *ImageManager) PrepareImage(ctx context.Context, in provision.ApprovedImageInput) (provision.ImageRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var zero provision.ImageRecord
	if e := in.Validate(); e != nil {
		return zero, e
	}
	if !withinImageLimits(in.Limits, m.cfg.Limits) {
		return zero, errors.New("preparation exceeds installed ceiling")
	}
	if e := m.recover(ctx); e != nil {
		return zero, e
	}
	if committed, _, found, err := m.preparedImage(ctx, in); err != nil {
		return zero, err
	} else if found {
		return committed, nil
	}
	ctx, cancel := context.WithTimeout(ctx, in.Limits.Deadline)
	defer cancel()
	// Reservation itself journals before every quota/filesystem mutation.
	space, e := m.storage.PrepareImageSpace(ctx, in.JobID, in.Limits)
	if e != nil {
		return zero, e
	}
	jobProps := ProvisionProperties{Name: in.JobID, Path: space.Source, Target: space.Cache, Source: space.Work, Revision: m.cfg.Bundle.Digest, ImageSpace: &space, PrepareLimits: &in.Limits, ApprovedImageInput: &in, ProductCreated: true}
	jobRaw, _ := json.Marshal(jobProps)
	jobID := newID()
	if e = m.store.BeginProvision(ctx, ProvisionIntent{ID: jobID, Kind: "image", Identity: in.JobID, ProductCreated: true, Desired: jobRaw}); e != nil {
		return zero, e
	}
	if e = m.store.RetainGeneration(ctx, "preparation", "image-preparation:"+space.JobID, space.JobID); e != nil {
		return zero, e
	}
	var archive, credential io.ReadCloser
	if m.cfg.TaskInput != nil {
		archive, credential, e = m.cfg.TaskInput(ctx, in)
	}
	if archive != nil {
		defer archive.Close()
	}
	if credential != nil {
		defer credential.Close()
	}
	stopInputs := context.AfterFunc(ctx, func() {
		if archive != nil {
			archive.Close()
		}
		if credential != nil {
			credential.Close()
		}
	})
	defer stopInputs()
	if e != nil {
		return zero, e
	}
	if in.SourceKind != "registry" && archive == nil || in.CredentialRef != "" && credential == nil {
		return zero, errors.New("approved private task input unavailable")
	}
	if in.SourceKind == "registry" && archive != nil || in.CredentialRef == "" && credential != nil {
		return zero, errors.New("unexpected private task input")
	}
	var credentials []byte
	if credential != nil {
		credentials, e = io.ReadAll(io.LimitReader(credential, 64<<10+1))
		if e != nil || len(credentials) > 64<<10 {
			return zero, errors.New("private credential bound exceeded")
		}
		defer func() {
			for i := range credentials {
				credentials[i] = 0
			}
		}()
	}
	task := provision.Task{Input: in, Directory: preparationSource, CanonicalDirectory: preparationWork, Credential: credentials}
	var privateEnvelope bytes.Buffer
	if e = provision.WriteTask(&privateEnvelope, task); e != nil {
		return zero, e
	}
	defer func() {
		for i := range privateEnvelope.Bytes() {
			privateEnvelope.Bytes()[i] = 0
		}
	}()
	send := func(w io.Writer) error {
		if _, e := w.Write(privateEnvelope.Bytes()); e != nil {
			return e
		}
		if archive != nil {
			n, e := io.Copy(w, io.LimitReader(archive, in.Limits.InputBytes+1))
			if e != nil {
				return e
			}
			if n > in.Limits.InputBytes {
				return errors.New("archive exceeds approved task bound")
			}
		}
		return nil
	}
	output, evidence, e := m.runImageService(ctx, in.JobID, bundle.Preparer, []string{"gvx-preparer"}, space, in.Limits, send, func() {
		if archive != nil {
			archive.Close()
		}
	}, in.Limits.JSONBytes*8, false)
	if e != nil {
		return zero, e
	}
	var record provision.ImageRecord
	if e = gvxcontract.DecodeStrict(output, int(in.Limits.JSONBytes*8), 32, &record); e != nil {
		return zero, e
	}
	if e = provision.ValidateRecord(record, in.Limits); e != nil {
		return zero, e
	}
	if record.Revision != provision.Revision(in) || record.SourceKind != in.SourceKind || record.SourceRef != in.SourceRef || in.SourceKind != "registry" && record.SourceDigest != in.ArchiveDigest {
		return zero, errors.New("preparer response approval binding mismatch")
	}
	if e = writeImageFile(filepath.Join(space.Source, "record.json"), output, 0600); e != nil {
		return zero, e
	}
	if e = m.verifySource(space, record, in.Limits); e != nil {
		return zero, e
	}
	canonical := filepath.Join(space.Work, "canonical.tar")
	if e = verifyImageHash(canonical, record.CanonicalArchiveDigest, in.Limits.OutputBytes); e != nil {
		return zero, e
	}
	// Freeze the source before giving only the original compiler write access to a
	// separate cache generation. It has no credentials and cannot fetch.
	if _, e = freezeImageDirectory(space.Source, m.cfg.Preparer.GID, in.Limits.InputBytes*2, in.Limits.Inodes); e != nil {
		return zero, e
	}
	_, loadEvidence, e := m.runImageService(ctx, in.JobID, bundle.Rungv, []string{"rungv", "load", "--arch=amd64", "--cache-dir=" + preparationCache, "--input=" + preparationWork + "/canonical.tar"}, space, in.Limits, nil, nil, 64<<10, false)
	if e != nil {
		return zero, e
	}
	evidence = mergeImageEvidence(evidence, loadEvidence)
	if e = verifyImageHash(canonical, record.CanonicalArchiveDigest, in.Limits.OutputBytes); e != nil {
		return zero, e
	}
	cache, e := m.publish(ctx, space, record, in.Limits)
	if e != nil {
		return zero, e
	}
	jobProps.Digest = record.ID
	jobProps.Revision = cache.ID
	jobRaw, _ = json.Marshal(jobProps)
	if e = m.store.ObserveProvision(ctx, jobID, ObjectObservation{Identity: in.JobID, Attributes: jobRaw}); e != nil {
		return zero, e
	}
	evidence, e = m.releasePreparation(ctx, space, evidence)
	if e != nil {
		return zero, e
	}
	if e = m.storage.CommitImageSpace(ctx, space, evidence); e != nil {
		return zero, e
	}
	if e = m.completeCommittedPreparationUnits(ctx, space); e != nil {
		return zero, e
	}
	return record, nil
}
func mergeImageEvidence(a, b CleanupEvidence) CleanupEvidence {
	a.Units = append(a.Units, b.Units...)
	a.JobsAbsent = a.JobsAbsent && b.JobsAbsent
	a.ProcessesAbsent = a.ProcessesAbsent && b.ProcessesAbsent
	a.TransportsClosed = a.TransportsClosed && b.TransportsClosed
	a.MountsAbsent = a.MountsAbsent && b.MountsAbsent
	a.OpenReferencesAbsent = a.OpenReferencesAbsent && b.OpenReferencesAbsent
	return a
}
func (m *ImageManager) runImageService(ctx context.Context, job string, program bundle.ProgramID, argv []string, space ImageSpace, l provision.PrepareLimits, send func(io.Writer) error, closeInput func(), maxOutput int64, offline bool) ([]byte, CleanupEvidence, error) {
	var proof CleanupEvidence
	generation := newID()
	name := "chatanium-image-" + string(program) + "-" + generation + ".service"
	limits := sharedhost.ResourceLimits{NanoCPUs: l.NanoCPUs, MemoryBytes: l.MemoryBytes, Pids: l.Tasks}
	proposed := sharedhost.UnitIdentity{Name: name, Generation: generation, BootID: m.cfg.Owner.BootID}
	properties := ProvisionProperties{Name: name, Source: job, Unit: &proposed, Limits: &limits, ProductCreated: true}
	raw, _ := json.Marshal(properties)
	ledger := newID()
	if e := m.store.BeginProvision(ctx, ProvisionIntent{ID: ledger, Kind: "unit", Identity: name, ProductCreated: true, Desired: raw}); e != nil {
		return nil, proof, e
	}
	inR, inW, e := os.Pipe()
	if e != nil {
		return nil, proof, e
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, e := os.Pipe()
	if e != nil {
		return nil, proof, e
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, e := os.Pipe()
	if e != nil {
		return nil, proof, e
	}
	defer errR.Close()
	defer errW.Close()
	service := OwnedService{Owner: m.cfg.Owner, Name: name, Generation: generation, Program: program, Argv: argv, Env: []string{"TMPDIR=" + preparationWork}, Identity: m.cfg.Preparer, Limits: sharedhost.ResourceLimits{NanoCPUs: l.NanoCPUs, MemoryBytes: l.MemoryBytes, Pids: l.Tasks}, WorkingDirectory: preparationWork, Mounts: []OwnedMount{{Source: space.Source, Target: preparationSource, ReadOnly: program == bundle.Rungv || space.ReusedSource}, {Source: space.Work, Target: preparationWork}, {Source: filepath.Join(space.Cache, "generation"), Target: preparationCache}, {Source: m.cfg.Bundle.Root, Target: preparationBase, ReadOnly: true}}, TimeoutStop: 5 * time.Second, OfflinePreparation: offline}
	v, e := m.systemd.StartPreparation(ctx, service, StandardFiles{Stdin: inR, Stdout: outW, Stderr: errW}, m.storage, space)
	if e != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if rejected := systemdRejection(e); rejected != "" {
			properties.Unit = nil
			properties.Rejection = rejected
			raw, _ = json.Marshal(properties)
			journalErr := m.store.ObserveProvision(cleanup, ledger, ObjectObservation{Identity: name, Attributes: raw})
			return nil, proof, errors.Join(e, journalErr)
		}
		journalErr := m.store.RequireRecovery(cleanup, "uncertain image service submission")
		return nil, proof, errors.Join(e, journalErr)
	}
	inR.Close()
	outW.Close()
	errW.Close()
	properties.Unit = &v.Unit
	properties.Writer = v.Writer
	if e = m.capturePreparationNative(ctx, v.Unit, &properties, false); e != nil {
		return nil, proof, e
	}
	raw, _ = json.Marshal(properties)
	if e = m.store.ObserveProvision(ctx, ledger, ObjectObservation{Identity: name, Attributes: raw}); e != nil {
		return nil, proof, e
	}
	sendDone := make(chan error, 1)
	go func() {
		var e error
		if send != nil {
			e = send(inW)
		}
		e = errors.Join(e, inW.Close())
		sendDone <- e
	}()
	type outputResult struct {
		b []byte
		e error
	}
	outputDone := make(chan outputResult, 1)
	go func() {
		b, e := io.ReadAll(io.LimitReader(outR, maxOutput+1))
		if int64(len(b)) > maxOutput {
			e = errors.New("bounded helper output exceeded")
			outR.Close()
		}
		outputDone <- outputResult{b, e}
	}()
	diagnosticsDone := make(chan error, 1)
	go func() { _, e := io.Copy(io.Discard, errR); diagnosticsDone <- e }()
	stopIO := context.AfterFunc(ctx, func() { inW.Close(); outR.Close(); errR.Close() })
	defer stopIO()
	joined := false
	defer func() {
		inW.Close()
		outR.Close()
		errR.Close()
		if closeInput != nil {
			closeInput()
		}
		if !joined {
			<-sendDone
			<-outputDone
			<-diagnosticsDone
		}
	}()
	exit, e := m.systemd.Wait(ctx, v.Unit)
	if e != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		stopErr := m.systemd.Stop(cleanup, v.Unit)
		if stopErr == nil {
			exit, stopErr = m.systemd.Wait(cleanup, v.Unit)
		}
		if stopErr != nil {
			return nil, proof, errors.Join(e, stopErr)
		}
	}
	terminal := properties
	terminal.Exit = &exit
	raw, _ = json.Marshal(terminal)
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if journalErr := m.store.ObserveProvision(settleCtx, ledger, ObjectObservation{Identity: name, Attributes: raw}); journalErr != nil {
		return nil, proof, errors.Join(e, journalErr)
	}
	if releaseErr := m.systemd.ReleaseReference(settleCtx, v.Unit); releaseErr != nil {
		return nil, proof, errors.Join(e, releaseErr)
	}
	inW.Close()
	sent := <-sendDone
	result := <-outputDone
	diagnosticErr := <-diagnosticsDone
	joined = true
	outR.Close()
	errR.Close()
	proof, settleErr := m.systemd.Settle(settleCtx, v.Unit)
	if settleErr != nil {
		return nil, proof, errors.Join(e, settleErr)
	}
	if scopeErr := validateScopedCleanup(proof, true, false); scopeErr != nil {
		return nil, proof, errors.Join(e, scopeErr)
	}
	// Persist actual native writer settlement before asking storage to validate
	// the data barriers. Helper COMPLETE follows physical publication instead.
	terminal.Absence = &proof
	terminal.CgroupEmpty = true
	raw, _ = json.Marshal(terminal)
	if journalErr := m.store.ObserveProvision(settleCtx, ledger, ObjectObservation{Identity: name, Attributes: raw}); journalErr != nil {
		return nil, proof, journalErr
	}
	proof, settleErr = m.storage.VerifyImageSpaceDetached(settleCtx, space, proof)
	if settleErr != nil {
		return nil, proof, errors.Join(e, settleErr)
	}
	if exit.Kind != "exit" || exit.Value != 0 || exit.OOMKilled {
		return nil, proof, errors.New("bounded image helper failed")
	}
	return result.b, proof, errors.Join(e, sent, result.e, diagnosticErr)
}
func openImageFile(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("nonregular image file")
	}
	var native unix.Stat_t
	if e = unix.Fstat(fd, &native); e != nil || native.Nlink != 1 {
		f.Close()
		return nil, errors.New("linked image file")
	}
	return f, nil
}
func readImageFile(path string, max int64) ([]byte, error) {
	f, e := openImageFile(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if st.Size() < 0 || st.Size() > max {
		return nil, errors.New("image metadata bound exceeded")
	}
	return io.ReadAll(io.LimitReader(f, max+1))
}
func verifyImageHash(path, digest string, max int64) error {
	f, e := openImageFile(path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, max+1))
	if e != nil {
		return e
	}
	if n > max || "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("image file integrity mismatch")
	}
	return nil
}
func writeImageFile(path string, raw []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	return errors.Join(e, f.Sync(), f.Close())
}
func (m *ImageManager) verifySource(space ImageSpace, r provision.ImageRecord, l provision.PrepareLimits) error {
	raw, e := readImageFile(filepath.Join(space.Source, "source.json"), l.JSONBytes*(l.IndexDepth+2))
	if e != nil {
		return e
	}
	metadata, e := provision.ValidateSourceMetadata(raw, r, l)
	if e != nil {
		return e
	}
	expected := map[string]bool{"record.json": true, "source.json": true}
	for key, file := range metadata.Members {
		expected[file] = true
		if strings.HasPrefix(key, "blobs/sha256/") {
			digest := "sha256:" + strings.TrimPrefix(key, "blobs/sha256/")
			if !provision.ValidDigest(digest) {
				return errors.New("invalid source blob key")
			}
			if e = verifyImageHash(filepath.Join(space.Source, file), digest, l.InputBytes); e != nil {
				return e
			}
		}
	}
	for _, layer := range r.Layers {
		file, ok := metadata.Members["blobs/sha256/"+layer.Digest[7:]]
		if !ok {
			return errors.New("source layer identity absent")
		}
		if e = verifyExactImageFile(filepath.Join(space.Source, file), layer.Digest, layer.Size); e != nil {
			return e
		}
	}
	if r.SourceKind != "registry" {
		expected["source.tar"] = true
		if e = verifyImageHash(filepath.Join(space.Source, "source.tar"), r.SourceDigest, l.InputBytes); e != nil {
			return e
		}
	}
	if r.SourceKind == "oci-archive" {
		file, ok := metadata.Members["index.json"]
		if !ok {
			return errors.New("original source index absent")
		}
		if e = verifyImageHash(filepath.Join(space.Source, file), r.OriginalDigest, l.JSONBytes); e != nil {
			return e
		}
	}
	if r.SourceKind == "docker-archive" {
		var original []struct {
			Config   string   `json:"Config"`
			RepoTags []string `json:"RepoTags"`
			Layers   []string `json:"Layers"`
		}
		if e = gvxcontract.DecodeStrict(r.Original, int(l.JSONBytes), 32, &original); e != nil || len(original) != 1 {
			return errors.New("invalid original Docker source manifest")
		}
		file, ok := metadata.Members[original[0].Config]
		if !ok {
			return errors.New("Docker original config missing")
		}
		if e = verifyImageHash(filepath.Join(space.Source, file), r.ConfigDigest, l.JSONBytes); e != nil {
			return e
		}
	}
	entries, e := os.ReadDir(space.Source)
	if e != nil {
		return e
	}
	if len(entries) != len(expected) {
		return errors.New("source generation has unknown or missing files")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return errors.New("source generation contains undeclared files")
		}
	}
	return nil
}
func imageOpenReferences(roots ...string) error {
	references := func(target string) bool {
		target = strings.TrimSuffix(target, " (deleted)")
		for _, root := range roots {
			if target == root || strings.HasPrefix(target, root+"/") {
				return true
			}
		}
		return false
	}
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "" || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		fds, e := os.ReadDir(filepath.Join(base, "fd"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		for _, fd := range fds {
			target, e := os.Readlink(filepath.Join(base, "fd", fd.Name()))
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return e
			}
			if references(target) {
				return fmt.Errorf("image generation has process %s open references", entry.Name())
			}
		}
		for _, kind := range []string{"cwd", "root"} {
			target, e := os.Readlink(filepath.Join(base, kind))
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return e
			}
			if references(target) {
				return errors.New("image generation remains a process directory")
			}
		}
		maps, e := os.Open(filepath.Join(base, "maps"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(maps, 16<<20+1))
		e = errors.Join(e, maps.Close())
		if e != nil {
			return e
		}
		if len(raw) > 16<<20 {
			return errors.New("process mapping evidence exceeds bound")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 6 && references(strings.Join(fields[5:], " ")) {
				return errors.New("image generation retains mapped files")
			}
		}
	}
	return nil
}
func freezeImageDirectory(dir string, gid uint32, maxBytes, maxInodes int64) ([]provision.FileIntegrity, error) {
	if e := checkImageDirectory(dir); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	if int64(len(entries))+1 > maxInodes {
		return nil, errors.New("image generation inode bound exceeded")
	}
	var files []provision.FileIntegrity
	var total int64
	for _, entry := range entries {
		p := filepath.Join(dir, entry.Name())
		f, e := openImageFile(p)
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return nil, e
		}
		total += st.Size()
		if total > maxBytes {
			f.Close()
			return nil, errors.New("image generation byte bound exceeded")
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		if e == nil {
			e = unix.Fchown(int(f.Fd()), 0, int(gid))
		}
		if e == nil {
			e = unix.Fchmod(int(f.Fd()), 0440)
		}
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil {
			return nil, e
		}
		files = append(files, provision.FileIntegrity{Path: entry.Name(), Digest: "sha256:" + hex.EncodeToString(h.Sum(nil)), Size: st.Size(), Mode: 0440})
	}
	if e = os.Chown(dir, 0, int(gid)); e != nil {
		return nil, e
	}
	if e = os.Chmod(dir, 0550); e != nil {
		return nil, e
	}
	f, e := os.Open(dir)
	if e != nil {
		return nil, e
	}
	e = errors.Join(f.Sync(), f.Close())
	return files, e
}

func (m *ImageManager) validateCache(dir string, r provision.ImageRecord, l provision.PrepareLimits) ([]provision.FileIntegrity, error) {
	if e := checkImageDirectory(dir); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	if int64(len(entries)) > l.Inodes {
		return nil, errors.New("cache inode bound exceeded")
	}
	var recordName string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "image-") && strings.HasSuffix(entry.Name(), ".json") {
			if recordName != "" {
				return nil, errors.New("multiple cache image records")
			}
			recordName = entry.Name()
		}
	}
	if recordName == "" {
		return nil, errors.New("missing cache image record")
	}
	raw, e := readImageFile(filepath.Join(dir, recordName), l.JSONBytes*8)
	if e != nil {
		return nil, e
	}
	c, e := provision.ValidateCacheRecord(raw, r, l)
	if e != nil {
		return nil, e
	}
	expectedRecord, tag := provision.CacheNames(r, c.Format)
	if recordName != expectedRecord {
		return nil, errors.New("cache key does not bind execution reference")
	}
	raw, e = readImageFile(filepath.Join(dir, tag), l.JSONBytes)
	if e != nil {
		return nil, e
	}
	if e = provision.ValidateCacheTag(raw, r, l); e != nil {
		return nil, e
	}
	expected := map[string]bool{recordName: true, tag: true}
	for _, layer := range r.Layers {
		image := layer.Digest[7:] + "." + c.Format + ".erofs"
		sidecar := image + ".sum"
		if expected[image] {
			continue
		}
		expected[image] = true
		expected[sidecar] = true
		sum, e := readImageFile(filepath.Join(dir, sidecar), 512)
		if e != nil {
			return nil, e
		}
		size, digest, e := provision.ParseLayerSum(sum, c.Format)
		if e != nil {
			return nil, e
		}
		block, e := provision.CacheBlockSize(c.Format)
		if e != nil || size < int64(block) || size > l.OutputBytes {
			return nil, errors.New("invalid compiled layer size")
		}
		if e = verifyExactImageFile(filepath.Join(dir, image), digest, size); e != nil {
			return nil, e
		}
	}
	if len(entries) != len(expected) {
		return nil, errors.New("cache has missing or unknown files")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return nil, errors.New("unrecognized compiler output")
		}
	}
	return freezeImageDirectory(dir, m.storage.installation.Identities.Sandbox.GID, l.OutputBytes, l.Inodes)
}
func (m *ImageManager) publish(ctx context.Context, space ImageSpace, r provision.ImageRecord, l provision.PrepareLimits) (CacheGeneration, error) {
	if space.ReusedSource && space.SourceGenerationID != r.ID {
		return CacheGeneration{}, errors.New("reused OCI source generation differs from image record")
	}
	var zero CacheGeneration
	if e := m.requirePreparationUse(ctx, "image", space); e != nil {
		return zero, e
	}
	if e := provision.ValidateRecord(r, l); e != nil {
		return zero, e
	}
	if e := m.verifySource(space, r, l); e != nil {
		return zero, e
	}
	directory := filepath.Join(space.Cache, "generation")
	files, e := m.validateCache(directory, r, l)
	if e != nil {
		return zero, e
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	inventory, _ := json.Marshal(files)
	inventoryDigest := provision.DomainDigest("chatanium-cache-inventory-v1", inventory)
	identity, _ := json.Marshal([]string{m.cfg.Bundle.Digest, r.ID, inventoryDigest})
	id := provision.DomainDigest("chatanium-cache-generation-v1", identity)
	if !space.ReusedSource {
		if e = m.store.BindStorageGeneration(ctx, space.JobID+":source", r.ID); e != nil {
			return zero, e
		}
	}
	if e = m.store.BindStorageGeneration(ctx, space.JobID+":cache", id); e != nil {
		return zero, e
	}
	if e = m.store.StoreImage(ctx, r); e != nil {
		return zero, e
	}
	generation := CacheGeneration{ID: id, BundleDigest: m.cfg.Bundle.Digest, ImageRecordID: r.ID, CanonicalArchiveDigest: r.CanonicalArchiveDigest, ManifestDigest: r.ManifestDigest, Directory: directory, InventoryDigest: inventoryDigest, State: "READY", Files: files}
	if e = m.store.PublishCache(ctx, generation); e != nil {
		return zero, e
	}
	return generation, nil
}
func (m *ImageManager) ImageManifest(ctx context.Context, selector string, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, invalid("finite declaration bound required")
	}
	r, _, e := m.committed(ctx, selector)
	if e != nil {
		return nil, e
	}
	if int64(len(r.Declaration)) > max {
		return nil, errors.New("prepared declaration exceeds bound")
	}
	return bytes.Clone(r.Declaration), nil
}
func (m *ImageManager) InspectPreparedImage(ctx context.Context, selector string) (provision.ImageRecord, error) {
	r, _, e := m.committed(ctx, selector)
	return r, e
}
func (m *ImageManager) committed(ctx context.Context, selector string) (provision.ImageRecord, CacheGeneration, error) {
	var zero provision.ImageRecord
	var empty CacheGeneration
	r, e := m.store.ResolveApprovedImage(ctx, selector)
	if e != nil {
		return zero, empty, e
	}
	if e = provision.ValidateRecord(r, m.cfg.Limits); e != nil {
		return zero, empty, e
	}
	if e = verifyImageSelectorBinding(selector, r); e != nil {
		return zero, empty, e
	}
	cache, e := m.store.CacheForImage(ctx, r.ID, m.cfg.Bundle.Digest)
	if e != nil {
		return zero, empty, e
	}
	if e = m.verifyCommittedImageCache(ctx, r, cache); e != nil {
		return zero, empty, e
	}
	return r, cache, nil
}

func verifyImageSelectorBinding(selector string, record provision.ImageRecord) error {
	if e := validateImageDigest(selector); e != nil {
		return e
	}
	if strings.HasPrefix(selector, "record:") {
		if strings.TrimPrefix(selector, "record:") != record.ID {
			return errors.New("immutable record selector mismatch")
		}
		return nil
	}
	_, digest, _ := strings.Cut(selector, "@")
	if record.SourceKind != "registry" || digest != record.SourceDigest {
		return errors.New("registry selector provenance mismatch")
	}
	sourceRepository, e := provision.RegistryRepository(record.SourceRef)
	if e != nil {
		return e
	}
	selectorRepository, e := provision.RegistryRepository(selector)
	if e != nil || sourceRepository != selectorRepository {
		return errors.New("registry repository approval mismatch")
	}
	return nil
}

// VerifyReleaseCaches checks an already-approved root-management revision. It
// never recovers, reserves, fetches, compiles, publishes, or changes references.
func (m *ImageManager) VerifyReleaseCaches(ctx context.Context, revision RevisionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if revision.ID == "" || revision.BundleDigest != m.cfg.Bundle.Digest || revision.DevelopmentWorker != nil || len(revision.Config) == 0 || provision.Digest(revision.Config) != revision.ConfigDigest || len(revision.Images) != len(revision.LaunchPolicies) {
		return errors.New("release cache verification revision binding mismatch")
	}
	policies := make(map[string]sharedhost.LaunchSpec, len(revision.LaunchPolicies))
	for _, policy := range revision.LaunchPolicies {
		if policy.ModuleID == "" || policy.ConfigRevision == "" || policy.ApprovalRevision == "" {
			return errors.New("release launch approval binding is incomplete")
		}
		if _, exists := policies[policy.ModuleID]; exists {
			return errors.New("duplicate release launch policy")
		}
		policies[policy.ModuleID] = policy
	}
	verified := make(map[string]bool, len(revision.Images))
	for _, binding := range revision.Images {
		policy, exists := policies[binding.ModuleID]
		if !exists || policy.ImageDigest != binding.ImageSelector || policy.ConfigRevision != binding.ConfigRevision || policy.ApprovalRevision != binding.ApprovalRevision {
			return errors.New("release image differs from its exact launch approval")
		}
		delete(policies, binding.ModuleID)
		record, e := m.store.Image(ctx, binding.ImageRecordID)
		if e != nil {
			return e
		}
		if record.ID != binding.ImageRecordID {
			return errors.New("release image record key differs from its immutable identity")
		}
		if e = verifyImageSelectorBinding(binding.ImageSelector, record); e != nil {
			return e
		}
		if verified[record.ID] {
			continue
		}
		if e = provision.ValidateRecord(record, m.cfg.Limits); e != nil {
			return e
		}
		cache, e := m.store.CacheForImage(ctx, record.ID, revision.BundleDigest)
		if e != nil {
			return e
		}
		if e = m.verifyCommittedImageCache(ctx, record, cache); e != nil {
			return e
		}
		verified[record.ID] = true
	}
	return nil
}

func (m *ImageManager) verifyCommittedImageCache(ctx context.Context, record provision.ImageRecord, cache CacheGeneration) error {
	if cache.BundleDigest != m.cfg.Bundle.Digest || cache.ImageRecordID != record.ID || cache.State != "READY" {
		return errors.New("image cache is not a compatible committed generation")
	}
	entries, e := m.store.PendingProvisions(ctx)
	if e != nil {
		return e
	}
	var space ImageSpace
	found := false
	for _, entry := range entries {
		if entry.Kind != "image" || entry.State != "OBSERVED" || strings.HasPrefix(entry.Identity, "image-space:") {
			continue
		}
		var published, desired ProvisionProperties
		if e = gvxcontract.DecodeStrict(entry.Observed.Attributes, 64<<10, 16, &published); e != nil {
			return e
		}
		if published.Digest != record.ID || published.Revision != cache.ID {
			continue
		}
		if e = gvxcontract.DecodeStrict(entry.Desired, 64<<10, 16, &desired); e != nil {
			return e
		}
		if found || published.ImageSpace == nil || desired.Revision != cache.BundleDigest {
			return errors.New("image cache publication is missing or ambiguous")
		}
		space = *published.ImageSpace
		sourceJob := filepath.Base(space.Source)
		if !safeID(space.JobID) || !safeID(sourceJob) || !safeID(space.ProvisionID) || entry.Identity != space.JobID || space.Source != filepath.Join(m.storage.config.StorageRoot, "images", sourceJob) || space.Cache != filepath.Join(m.storage.config.StorageRoot, "prepared", space.JobID) || space.Work != filepath.Join(m.storage.config.StorageRoot, "preparation", space.JobID) || cache.Directory != filepath.Join(space.Cache, "generation") || !space.ReusedSource && sourceJob != space.JobID || space.ReusedSource && space.SourceGenerationID != record.ID {
			return errors.New("image cache publication paths or source binding changed")
		}
		if e = verifyPreparationRecordBinding(desired, record); e != nil {
			return e
		}
		committed, e := committedImageSpace(entries, space)
		if e != nil {
			return e
		}
		if !committed {
			return errors.New("image cache has not completed its physical publication barriers")
		}
		sourceGeneration, e := m.store.StorageGeneration(ctx, sourceJob+":source")
		if e != nil {
			return e
		}
		cacheGeneration, e := m.store.StorageGeneration(ctx, space.JobID+":cache")
		if e != nil {
			return e
		}
		if sourceGeneration != record.ID || cacheGeneration != cache.ID {
			return errors.New("image source or cache storage is retired or rebound")
		}
		found = true
	}
	if !found {
		return errors.New("image cache lacks its committed publication")
	}
	if e = m.requirePreparationUse(ctx, "image", space); e != nil {
		return e
	}
	if e = m.verifySource(space, record, m.cfg.Limits); e != nil {
		return e
	}
	return m.verifyPublished(cache, record)
}
func (m *ImageManager) verifyPublished(c CacheGeneration, r provision.ImageRecord) error {
	if e := checkImageDirectory(c.Directory); e != nil {
		return e
	}
	if c.ImageRecordID != r.ID || c.ManifestDigest != r.ManifestDigest || c.CanonicalArchiveDigest != r.CanonicalArchiveDigest || !provision.ValidDigest(c.BundleDigest) || c.State != "READY" {
		return errors.New("cache declaration binding mismatch")
	}
	inventory, _ := json.Marshal(c.Files)
	if c.InventoryDigest != provision.DomainDigest("chatanium-cache-inventory-v1", inventory) {
		return errors.New("cache inventory identity mismatch")
	}
	identity, _ := json.Marshal([]string{c.BundleDigest, r.ID, c.InventoryDigest})
	if c.ID != provision.DomainDigest("chatanium-cache-generation-v1", identity) {
		return errors.New("cache generation identity mismatch")
	}
	expected := map[string]bool{}
	for _, file := range c.Files {
		if file.Path != filepath.Base(file.Path) || file.Mode != 0440 || !provision.ValidDigest(file.Digest) || file.Size < 0 || expected[file.Path] {
			return errors.New("invalid published inventory")
		}
		expected[file.Path] = true
		path := filepath.Join(c.Directory, file.Path)
		f, e := openImageFile(path)
		if e != nil {
			return e
		}
		var st unix.Stat_t
		e = unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if e != nil {
			return e
		}
		if st.Uid != 0 || st.Gid != m.storage.installation.Identities.Sandbox.GID || st.Mode&07777 != 0440 || st.Size != file.Size {
			return errors.New("published generation native ownership changed")
		}
		if e = verifyImageHash(path, file.Digest, file.Size); e != nil {
			return e
		}
	}
	entries, e := os.ReadDir(c.Directory)
	if e != nil {
		return e
	}
	if len(entries) != len(expected) {
		return errors.New("published generation inventory changed")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return errors.New("published cache foreign member")
		}
	}
	return nil
}
func imageViewPath(l sharedhost.Lease) string { return filepath.Join(filepath.Dir(l.ScratchPath), "image-view") }
func (m *ImageManager) InstanceView(ctx context.Context, l sharedhost.Lease) (string, error) {
	if e := m.storage.validateLease(l); e != nil {
		return "", e
	}
	r, e := m.store.Image(ctx, l.ImageRecordID)
	if e != nil {
		return "", e
	}
	c, e := m.store.Cache(ctx, l.CacheGenerationID)
	if e != nil {
		return "", e
	}
	if c.BundleDigest != m.cfg.Bundle.Digest {
		return "", errors.New("instance cache bundle mismatch")
	}
	if e = provision.ValidateRecord(r, m.cfg.Limits); e != nil {
		return "", e
	}
	if e = m.verifyCommittedImageCache(ctx, r, c); e != nil {
		return "", e
	}
	view := imageViewPath(l)
	if e = os.Mkdir(view, 0550); e != nil {
		return "", e
	}
	if e = os.Chown(view, 0, int(l.SandboxGID)); e != nil {
		return "", e
	}
	if e = unix.Mount(c.Directory, view, "", unix.MS_BIND, ""); e != nil {
		return "", e
	}
	if e = unix.Mount("", view, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, ""); e != nil {
		return "", errors.Join(e, unix.Unmount(view, 0))
	}
	if e = m.store.RetainGeneration(ctx, "live", c.ID, l.Spec.InstanceID); e != nil {
		return "", errors.Join(e, unix.Unmount(view, 0))
	}
	return view, nil
}
func (m *ImageManager) Release(ctx context.Context, l sharedhost.Lease, e CleanupEvidence) error {
	if e.BootID == "" || !e.JobsAbsent || !e.ProcessesAbsent || !e.TransportsClosed {
		return sharedhost.ErrCleanupIncomplete
	}
	if err := m.storage.validateLease(l); err != nil {
		return err
	}
	view := imageViewPath(l)
	mounts, err := storageMounts()
	if err != nil {
		return err
	}
	for _, mount := range mounts {
		if mount.target == view {
			if err = unix.Unmount(view, 0); err != nil {
				return err
			}
		}
	}
	if err = requireNoMounts(view); err != nil {
		return err
	}
	if err = imageOpenReferences(view); err != nil {
		return err
	}
	if err = os.Remove(view); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Recover settles only journaled preparation invocations. It never re-executes
// a tag resolution or compiler and never turns an uncertain submission absent.
func (m *ImageManager) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recover(ctx)
}
func (m *ImageManager) recover(ctx context.Context) error {
	records, e := m.store.PendingProvisions(ctx)
	if e != nil {
		return e
	}
	for _, job := range records {
		if job.Kind != "image" || strings.HasPrefix(job.Identity, "image-space:") {
			continue
		}
		var desired ProvisionProperties
		if e = gvxcontract.DecodeStrict(job.Desired, 64<<10, 16, &desired); e != nil {
			return e
		}
		if desired.ImageSpace == nil || desired.PrepareLimits == nil {
			return errors.New("preparation recovery identity missing")
		}
		space := *desired.ImageSpace
		limits := *desired.PrepareLimits
		if e = limits.Validate(); e != nil {
			return e
		}
		if !withinImageLimits(limits, m.cfg.Limits) {
			return errors.New("recovery preparation bounds incompatible")
		}
		validSource := space.Source == filepath.Join(m.storage.config.StorageRoot, "images", space.JobID)
		if space.ReusedSource {
			validSource = filepath.Dir(space.Source) == filepath.Join(m.storage.config.StorageRoot, "images") && safeID(filepath.Base(space.Source))
		}
		if space.JobID != job.Identity || !validSource || space.Cache != filepath.Join(m.storage.config.StorageRoot, "prepared", space.JobID) || space.Work != filepath.Join(m.storage.config.StorageRoot, "preparation", space.JobID) {
			return errors.New("recovery image space identity mismatch")
		}
		committed, e := committedImageSpace(records, space)
		if e != nil {
			return e
		}
		quarantined, e := m.preparationQuarantined(ctx, "image", space)
		if e != nil {
			return e
		}
		if quarantined && committed && job.State == "OBSERVED" {
			continue
		}
		if committed && job.State == "OBSERVED" {
			var published ProvisionProperties
			if e = gvxcontract.DecodeStrict(job.Observed.Attributes, 64<<10, 16, &published); e != nil {
				return e
			}
			record, e := m.store.Image(ctx, published.Digest)
			if e != nil {
				return e
			}
			cache, e := m.store.Cache(ctx, published.Revision)
			if e != nil {
				return e
			}
			if e = provision.ValidateRecord(record, limits); e != nil {
				return e
			}
			if e = verifyPreparationRecordBinding(desired, record); e != nil {
				return e
			}
			if e = m.verifyPublished(cache, record); e != nil {
				return e
			}
			if e = m.verifySource(space, record, limits); e != nil {
				return e
			}
			if e = m.completeCommittedPreparationUnits(ctx, space); e != nil {
				return e
			}
			continue
		}
		settled, e := m.settlePreparationUnits(ctx, space)
		if e != nil {
			return e
		}
		proof := settled.Evidence
		successfulCompiler := settled.Succeeded[bundle.Rungv]
		if e = imageOpenReferences(space.Source, space.Cache, space.Work); e != nil {
			return e
		}
		proof, e = m.releasePreparation(ctx, space, proof)
		if e != nil {
			return e
		}
		var observed ProvisionProperties
		if job.State == "OBSERVED" {
			if e = gvxcontract.DecodeStrict(job.Observed.Attributes, 64<<10, 16, &observed); e != nil {
				return e
			}
			if observed.Digest != "" {
				record, e := m.store.Image(ctx, observed.Digest)
				if e != nil {
					return e
				}
				cache, e := m.store.Cache(ctx, observed.Revision)
				if e != nil {
					return e
				}
				if e = provision.ValidateRecord(record, limits); e != nil {
					return e
				}
				if e = verifyPreparationRecordBinding(desired, record); e != nil {
					return e
				}
				if e = m.verifyPublished(cache, record); e != nil {
					return e
				}
				if e = m.verifySource(space, record, limits); e != nil {
					return e
				}
				if e = m.storage.CommitImageSpace(ctx, space, proof); e != nil {
					return e
				}
				if e = m.completePreparationUnitLedgers(ctx, settled.Ledgers, proof); e != nil {
					return e
				}
				continue
			}
		}
		// A successful compiler may have completed just before the durable READY
		// commit. Resume publication from exact protected source/config bytes only.
		if successfulCompiler && desired.Revision == m.cfg.Bundle.Digest {
			raw, e := readImageFile(filepath.Join(space.Source, "record.json"), limits.JSONBytes*8)
			if e != nil {
				return e
			}
			var record provision.ImageRecord
			if e = gvxcontract.DecodeStrict(raw, int(limits.JSONBytes*8), 32, &record); e != nil {
				return e
			}
			if e = provision.ValidateRecord(record, limits); e != nil {
				return e
			}
			if e = verifyPreparationRecordBinding(desired, record); e != nil {
				return e
			}
			if e = verifyImageHash(filepath.Join(space.Work, "canonical.tar"), record.CanonicalArchiveDigest, limits.OutputBytes); e != nil {
				return e
			}
			cache, e := m.publish(ctx, space, record, limits)
			if e != nil {
				return e
			}
			desired.Digest = record.ID
			desired.Revision = cache.ID
			raw, _ = json.Marshal(desired)
			if e = m.store.ObserveProvision(ctx, job.ID, ObjectObservation{Identity: job.Identity, Attributes: raw}); e != nil {
				return e
			}
			if e = m.storage.CommitImageSpace(ctx, space, proof); e != nil {
				return e
			}
			if e = m.completePreparationUnitLedgers(ctx, settled.Ledgers, proof); e != nil {
				return e
			}
			continue
		}
		// Failed/interrupted preparations cannot become launchable. Reclaim source,
		// cache and peak only after exact unit and all external-reference barriers.
		proof, e = m.storage.ReleaseImageSpaceEvidence(ctx, space, proof)
		if e != nil {
			return e
		}
		if e = m.completePreparationUnitLedgers(ctx, settled.Ledgers, proof); e != nil {
			return e
		}
		if e = m.store.CompleteProvisionCleanup(ctx, job.ID, proof); e != nil {
			return e
		}
	}
	if e = m.recoverDevelopmentWorkers(ctx, records); e != nil {
		return e
	}
	return m.storage.RecoverUnsubmittedImageSpaces(ctx)
}

func (m *ImageManager) releasePreparation(ctx context.Context, space ImageSpace, e CleanupEvidence) (CleanupEvidence, error) {
	if err := validateScopedCleanup(e, true, false); err != nil {
		return e, err
	}
	var err error
	e, err = m.storage.VerifyImageSpaceDetached(ctx, space, e)
	if err != nil {
		return e, err
	}
	if err := m.store.ReleaseGeneration(ctx, "preparation", "image-preparation:"+space.JobID, space.JobID, e); err != nil {
		return e, err
	}
	if space.ReusedSource {
		if !provision.ValidDigest(space.SourceGenerationID) {
			return e, errors.New("rebuild source generation absent")
		}
		if err := m.store.ReleaseGeneration(ctx, "preparation", space.SourceGenerationID, space.JobID, e); err != nil {
			return e, err
		}
	}
	return e, nil
}

// RebuildCache is maintenance-only: the existing immutable OCI source stays
// authoritative while a new compiler bundle receives its own cache generation.
func (m *ImageManager) RebuildCache(ctx context.Context, recordID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !provision.ValidDigest(recordID) {
		return errors.New("invalid rebuild record")
	}
	if e := m.recover(ctx); e != nil {
		return e
	}
	record, e := m.store.Image(ctx, recordID)
	if e != nil {
		return e
	}
	limits := m.cfg.Limits
	if e = provision.ValidateRecord(record, limits); e != nil {
		return e
	}
	existingCache, e := m.store.CacheForImage(ctx, recordID, m.cfg.Bundle.Digest)
	if e == nil {
		return m.verifyCommittedImageCache(ctx, record, existingCache)
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	entries, e := m.store.PendingProvisions(ctx)
	if e != nil {
		return e
	}
	var source ImageSpace
	for _, entry := range entries {
		if entry.Kind != "image" || entry.State != "OBSERVED" || strings.HasPrefix(entry.Identity, "image-space:") {
			continue
		}
		var p ProvisionProperties
		if e = gvxcontract.DecodeStrict(entry.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return e
		}
		if p.Digest != recordID || p.ImageSpace == nil {
			continue
		}
		if !p.ImageSpace.ReusedSource {
			source = *p.ImageSpace
		}
	}
	if source.Source == "" {
		return errors.New("immutable retained OCI source unavailable")
	}
	committed, e := committedImageSpace(entries, source)
	if e != nil {
		return e
	}
	if !committed {
		return errors.New("retained OCI source lacks its original committed acquisition")
	}
	if e = m.requirePreparationUse(ctx, "image", source); e != nil {
		return e
	}
	if e = m.verifySource(source, record, limits); e != nil {
		return e
	}
	cacheBytes, cacheInodes, e := m.store.AvailableStorage(ctx, "cache")
	if e != nil {
		return e
	}
	workBytes, workInodes, e := m.store.AvailableStorage(ctx, "preparation")
	if e != nil {
		return e
	}
	limits.OutputBytes = min(limits.OutputBytes, cacheBytes, workBytes/2) / 1024 * 1024
	limits.ExpandedBytes = min(limits.ExpandedBytes, workBytes-limits.OutputBytes) / 1024 * 1024
	limits.Inodes = min(limits.Inodes, cacheInodes, workInodes)
	if e = limits.Validate(); e != nil {
		return errors.New("insufficient bounded capacity for retained cache rebuild")
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Deadline)
	defer cancel()
	jobID := newID()
	space, e := m.storage.PrepareCacheSpace(ctx, jobID, source, limits)
	if e != nil {
		return e
	}
	properties := ProvisionProperties{Name: jobID, Path: space.Source, Source: space.Work, Target: space.Cache, Digest: recordID, Revision: m.cfg.Bundle.Digest, ImageSpace: &space, PrepareLimits: &limits, ProductCreated: true}
	raw, _ := json.Marshal(properties)
	ledger := newID()
	if e = m.store.BeginProvision(ctx, ProvisionIntent{ID: ledger, Kind: "image", Identity: jobID, ProductCreated: true, Desired: raw}); e != nil {
		return e
	}
	if e = m.store.RetainGeneration(ctx, "preparation", "image-preparation:"+jobID, jobID); e != nil {
		return e
	}
	input := provision.ApprovedImageInput{JobID: jobID, SourceKind: record.SourceKind, SourceRef: record.SourceRef, ModuleID: "cache-rebuild", ConfigRevision: record.Revision, ApprovalRevision: record.Revision, Platform: "linux/amd64", Limits: limits}
	if record.SourceKind != "registry" {
		input.ArchiveDigest = record.SourceDigest
	}
	task := provision.Task{Input: input, Directory: preparationSource, CanonicalDirectory: preparationWork, RebuildRecordID: recordID}
	var envelope bytes.Buffer
	if e = provision.WriteTask(&envelope, task); e != nil {
		return e
	}
	output, proof, e := m.runImageService(ctx, jobID, bundle.Preparer, []string{"gvx-preparer"}, space, limits, func(w io.Writer) error { _, e := w.Write(envelope.Bytes()); return e }, nil, limits.JSONBytes*8, false)
	if e != nil {
		return e
	}
	var rebuilt provision.ImageRecord
	if e = gvxcontract.DecodeStrict(output, int(limits.JSONBytes*8), 32, &rebuilt); e != nil {
		return e
	}
	if e = provision.ValidateRecord(rebuilt, limits); e != nil {
		return e
	}
	if rebuilt.ID != recordID {
		return errors.New("rebuild changed immutable source record")
	}
	canonical := filepath.Join(space.Work, "canonical.tar")
	if e = verifyImageHash(canonical, record.CanonicalArchiveDigest, limits.OutputBytes); e != nil {
		return e
	}
	_, loadProof, e := m.runImageService(ctx, jobID, bundle.Rungv, []string{"rungv", "load", "--arch=amd64", "--cache-dir=" + preparationCache, "--input=" + preparationWork + "/canonical.tar"}, space, limits, nil, nil, 64<<10, false)
	if e != nil {
		return e
	}
	proof = mergeImageEvidence(proof, loadProof)
	if e = verifyImageHash(canonical, record.CanonicalArchiveDigest, limits.OutputBytes); e != nil {
		return e
	}
	cache, e := m.publish(ctx, space, record, limits)
	if e != nil {
		return e
	}
	properties.Revision = cache.ID
	raw, _ = json.Marshal(properties)
	if e = m.store.ObserveProvision(ctx, ledger, ObjectObservation{Identity: jobID, Attributes: raw}); e != nil {
		return e
	}
	proof, e = m.releasePreparation(ctx, space, proof)
	if e != nil {
		return e
	}
	if e = m.storage.CommitImageSpace(ctx, space, proof); e != nil {
		return e
	}
	return m.completeCommittedPreparationUnits(ctx, space)
}

func checkImageDirectory(path string) error {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	return unix.Close(fd)
}

func verifyExactImageFile(path, digest string, size int64) error {
	f, e := openImageFile(path)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if st.Size() != size {
		return errors.New("image descriptor file size mismatch")
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return e
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("image descriptor file digest mismatch")
	}
	return nil
}

// PreparationNoSubmissionDetails is causal evidence scoped to one reserved
// job: the complete durable unit history proves no helper was dispatched.
type PreparationNoSubmissionDetails struct {
	JobID              string `json:"job_id"`
	ProvisionID        string `json:"provision_id"`
	NoHelperSubmission bool   `json:"no_helper_submission"`
}

type preparationUnits struct {
	Evidence  CleanupEvidence
	Ledgers   []string
	Succeeded map[bundle.ProgramID]bool
}

func (m *ImageManager) settlePreparationUnits(ctx context.Context, space ImageSpace) (preparationUnits, error) {
	history, err := m.store.PreparationUnitProvisions(ctx, space.JobID)
	if err != nil {
		return preparationUnits{}, err
	}
	return m.settlePreparationUnitHistory(ctx, space, history)
}

func (m *ImageManager) settlePreparationUnitHistory(ctx context.Context, space ImageSpace, history []ProvisionRecord) (preparationUnits, error) {
	result := preparationUnits{Succeeded: map[bundle.ProgramID]bool{}}
	if len(history) == 0 {
		if !safeID(space.JobID) || !safeID(space.ProvisionID) || m.cfg.Owner.BootID == "" {
			return result, sharedhost.ErrCleanupIncomplete
		}
		details, err := json.Marshal(PreparationNoSubmissionDetails{JobID: space.JobID, ProvisionID: space.ProvisionID, NoHelperSubmission: true})
		if err != nil {
			return result, err
		}
		result.Evidence = CleanupEvidence{BootID: m.cfg.Owner.BootID, JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, Details: details}
		return result, nil
	}
	proofs := 0
	absorb := func(proof CleanupEvidence) error {
		if err := validateScopedCleanup(proof, true, false); err != nil {
			return err
		}
		if proofs == 0 {
			result.Evidence = proof
		} else {
			result.Evidence = mergeImageEvidence(result.Evidence, proof)
		}
		proofs++
		return nil
	}
	for _, entry := range history {
		var desired ProvisionProperties
		if err := gvxcontract.DecodeStrict(entry.Desired, 64<<10, 16, &desired); err != nil {
			return result, err
		}
		if entry.Kind != "unit" || desired.Source != space.JobID || desired.Unit == nil || desired.Limits == nil {
			return result, errors.New("helper recovery intent lacks exact job/native binding")
		}
		completed := entry.CleanupState == "COMPLETE"
		result.Ledgers = append(result.Ledgers, entry.ID)
		u := *desired.Unit
		program := bundle.Preparer
		if strings.HasPrefix(desired.Name, "chatanium-image-rungv-") {
			program = bundle.Rungv
		} else if !strings.HasPrefix(desired.Name, "chatanium-image-preparer-") {
			return result, errors.New("invalid preparation service purpose")
		}
		observed := desired
		frozen := completed
		persist := func() error {
			if frozen {
				return nil
			}
			raw, err := json.Marshal(observed)
			if err != nil {
				return err
			}
			return m.store.ObserveProvision(ctx, entry.ID, ObjectObservation{Identity: desired.Name, Attributes: raw})
		}
		if entry.State == "INTENT" {
			internal, err := m.store.UnitProvisions(ctx, desired.Name)
			if err != nil {
				return result, err
			}
			submitted, rejection := false, ""
			for _, row := range internal {
				if !strings.HasPrefix(row.ID, "systemd-") {
					continue
				}
				submitted = true
				var dispatch, actual ProvisionProperties
				if err = gvxcontract.DecodeStrict(row.Desired, 64<<10, 16, &dispatch); err != nil {
					return result, err
				}
				if dispatch.Unit == nil || dispatch.Unit.Generation != u.Generation || dispatch.Unit.Name != desired.Name || dispatch.Source != string(program) || dispatch.Limits == nil || *dispatch.Limits != *desired.Limits {
					return result, errors.New("preparation dispatch history differs from its outer intent")
				}
				if row.State == "OBSERVED" {
					if err = gvxcontract.DecodeStrict(row.Observed.Attributes, 64<<10, 16, &actual); err != nil {
						return result, err
					}
					rejection = actual.Rejection
				}
			}
			if completed && submitted {
				return result, errors.New("completed unsubmitted helper acquired native submission history")
			}
			if !submitted {
				proof, err := m.systemd.ProveUnsubmittedPreparation(ctx, desired.Name, u.Generation, program, *desired.Limits)
				if err != nil {
					return result, err
				}
				if err = absorb(proof); err != nil {
					return result, err
				}
				continue
			}
			if rejection != "" {
				observed.Unit = nil
				observed.Rejection = rejection
				if err = persist(); err != nil {
					return result, err
				}
			}
		} else if entry.State == "OBSERVED" {
			if err := gvxcontract.DecodeStrict(entry.Observed.Attributes, 64<<10, 16, &observed); err != nil {
				return result, err
			}
			frozen = completed || observed.Absence != nil
		} else {
			return result, errors.New("invalid helper journal state")
		}
		if observed.Rejection != "" {
			internal, err := m.store.UnitProvisions(ctx, desired.Name)
			if err != nil {
				return result, err
			}
			var proof CleanupEvidence
			if len(internal) == 0 {
				proof, err = m.systemd.ProveUnsubmittedPreparation(ctx, desired.Name, u.Generation, program, *desired.Limits)
			} else {
				var native UnitObservation
				native, err = m.systemd.RecoverOwnedUnit(ctx, desired.Name, u.Generation, program, *desired.Limits)
				if err == nil {
					proof, err = m.systemd.Settle(ctx, native.Unit)
				}
			}
			if err != nil {
				return result, err
			}
			if err = absorb(proof); err != nil {
				return result, err
			}
			continue
		}
		if entry.State == "OBSERVED" {
			if observed.Unit == nil || observed.Unit.Name != u.Name || observed.Unit.Generation != u.Generation || observed.Unit.BootID != u.BootID {
				return result, errors.New("observed preparation invocation rebound")
			}
			u = *observed.Unit
		}
		success := func() {
			if observed.Writer != nil && validatePreparationWriter(*observed.Writer) == nil && observed.Writer.StartIntent && !observed.Writer.StartForbidden && observed.Writer.Evidence != nil && observed.Exit != nil && observed.Exit.Kind == "exit" && observed.Exit.Value == 0 && !observed.Exit.OOMKilled {
				result.Succeeded[program] = true
			}
		}
		// Stored absence is historical, including its boot. Never reuse it as
		// current proof or rewrite it merely to refresh its physical observation.
		if observed.Absence != nil && (len(observed.Absence.Units) != 1 || observed.Absence.Units[0] != u) {
			return result, errors.New("historical helper absence identifies a different invocation")
		}
		// B must classify exact COMPLETE historical receipts before native
		// cleanup; E grants neither a no-START exception nor publication success.
		legacyCleanup := completed && (observed.Writer == nil || validatePreparationWriter(*observed.Writer) != nil)
		if !legacyCleanup {
			writer, err := m.store.PreparationWriter(ctx, "systemd-"+u.Generation)
			if err != nil {
				return result, err
			}
			if writer.Birth != nil && !writer.StartIntent && !writer.StartForbidden {
				if err = m.store.ForbidPreparationWriterStart(ctx, "systemd-"+u.Generation, *writer.Birth); err != nil {
					return result, err
				}
			}
		}
		native, err := m.systemd.RecoverOwnedUnit(ctx, desired.Name, u.Generation, program, *desired.Limits)
		if err != nil {
			return result, err
		}
		if entry.State == "OBSERVED" && native.Unit != u {
			return result, errors.New("recovered helper changed its observed invocation")
		}
		previous := observed
		u = native.Unit
		observed.Unit = &u
		if err = m.capturePreparationNative(ctx, u, &observed, legacyCleanup); err != nil {
			return result, err
		}
		if native.Exit != nil && observed.Exit == nil && !frozen {
			observed.Exit = native.Exit
		}
		if frozen && (previous.Unit == nil || *previous.Unit != u || previous.JobPath != observed.JobPath || !slices.Equal(previous.TransportPipes, observed.TransportPipes) || previous.MountNamespace == nil || observed.MountNamespace == nil || *previous.MountNamespace != *observed.MountNamespace || previous.MountNamespaceDisposition != observed.MountNamespaceDisposition || !samePreparationWriter(previous.Writer, observed.Writer)) {
			return result, errors.New("completed helper capture changed or was missing")
		}
		if err = persist(); err != nil {
			return result, err
		}
		if native.Absence != nil {
			if err = validateUnitAbsenceEvidence(u, observed.TransportPipes, observed.MountNamespace, observed.MountNamespaceDisposition, *native.Absence); err != nil {
				return result, err
			}
			if observed.Absence == nil && !frozen {
				observed.Absence = native.Absence
				observed.CgroupEmpty = true
				if err = persist(); err != nil {
					return result, err
				}
			}
			if err = m.systemd.ReleaseReference(ctx, u); err != nil {
				return result, err
			}
			proof, err := m.systemd.Settle(ctx, u)
			if err != nil {
				return result, err
			}
			if err = absorb(proof); err != nil {
				return result, err
			}
			success()
			continue
		}
		if observed.Absence != nil {
			return result, errors.New("helper with recorded absence reappeared")
		}
		if native.Exit == nil {
			if completed {
				return result, errors.New("completed helper reappeared without its terminal result")
			}
			if err = m.systemd.Stop(ctx, u); err != nil {
				return result, err
			}
			exit, err := m.systemd.Wait(ctx, u)
			if err != nil {
				return result, err
			}
			native.Exit = &exit
		}
		if observed.Exit != nil && *observed.Exit != *native.Exit || completed && observed.Exit == nil {
			return result, errors.New("helper changed or lost its recorded terminal result")
		}
		observed.Exit = native.Exit
		if err = persist(); err != nil {
			return result, err
		}
		if err = m.systemd.ReleaseReference(ctx, u); err != nil {
			return result, err
		}
		proof, err := m.systemd.Settle(ctx, u)
		if err != nil {
			return result, err
		}
		if err = absorb(proof); err != nil {
			return result, err
		}
		observed.CgroupEmpty = true
		observed.Absence = &proof
		if err = persist(); err != nil {
			return result, err
		}
		success()
	}
	if proofs != len(history) {
		return result, sharedhost.ErrCleanupIncomplete
	}
	return result, nil
}

func committedImageSpace(records []ProvisionRecord, space ImageSpace) (bool, error) {
	for _, record := range records {
		if record.ID != space.ProvisionID {
			continue
		}
		if record.Kind != "image" || record.Identity != "image-space:"+space.JobID || record.State != "OBSERVED" {
			return false, nil
		}
		var p ProvisionProperties
		if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return false, e
		}
		if p.ImageSpace == nil || p.ImageSpace.ProvisionID != space.ProvisionID || p.ImageSpace.JobID != space.JobID || p.ImageSpace.ReusedSource != space.ReusedSource || p.ImageSpace.SourceGenerationID != space.SourceGenerationID || p.ImageSpace.Source != space.Source || p.ImageSpace.Cache != space.Cache || p.ImageSpace.Work != space.Work || p.ImageSpace.SourceProject != space.SourceProject || p.ImageSpace.CacheProject != space.CacheProject || p.ImageSpace.WorkProject != space.WorkProject {
			return false, errors.New("committed image-space identity changed")
		}
		return p.ImageSpace.Committed, nil
	}
	return false, nil
}

// legacyCleanup permits only immutable COMPLETE native identity capture. The
// caller still needs actual native settlement and the full storage barriers.
func (m *ImageManager) capturePreparationNative(ctx context.Context, unit sharedhost.UnitIdentity, outer *ProvisionProperties, legacyCleanup bool) error {
	records, e := m.store.UnitProvisions(ctx, unit.Name)
	if e != nil {
		return e
	}
	for _, record := range records {
		if !strings.HasPrefix(record.ID, "systemd-") || record.State != "OBSERVED" {
			continue
		}
		var captured ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &captured); e != nil {
			return e
		}
		if captured.Unit == nil || *captured.Unit != unit {
			continue
		}
		legacy := legacyCleanup && record.CleanupState == "COMPLETE" && samePreparationWriter(outer.Writer, captured.Writer) && (captured.Writer == nil || validatePreparationWriter(*captured.Writer) != nil)
		var writer PreparationWriterRecord
		if !legacy {
			var err error
			writer, err = m.store.PreparationWriter(ctx, record.ID)
			if err != nil {
				return err
			}
			if writer.Launch.JobID != outer.Source || writer.Launch.Generation != unit.Generation || writer.Launch.UnitName != unit.Name || writer.Birth == nil || writer.Birth.Unit != unit || captured.Writer == nil || !samePreparationWriter(captured.Writer, &writer) {
				return errors.New("preparation writer evidence differs from its original native invocation")
			}
			if outer.Writer != nil && (outer.Writer.Launch != writer.Launch || outer.Writer.Birth != nil && (writer.Birth == nil || *outer.Writer.Birth != *writer.Birth) || outer.Writer.Evidence != nil && (writer.Evidence == nil || *outer.Writer.Evidence != *writer.Evidence) || outer.Writer.StartIntent && !writer.StartIntent || outer.Writer.StartForbidden && !writer.StartForbidden) {
				return errors.New("preparation writer evidence changed its immutable prefix")
			}
		}
		if e = validateNativePipeIdentities(captured.TransportPipes); e != nil {
			return e
		}
		if len(captured.TransportPipes) == 0 {
			return errors.New("preparation invocation lacks original transport identities")
		}
		if len(outer.TransportPipes) != 0 && !slices.Equal(outer.TransportPipes, captured.TransportPipes) {
			return errors.New("preparation transport identity changed")
		}
		if e = validateNamespaceTransition(outer.MountNamespace, outer.MountNamespaceDisposition, captured.MountNamespace, captured.MountNamespaceDisposition); e != nil {
			return e
		}
		if outer.JobPath != "" && outer.JobPath != captured.JobPath {
			return errors.New("preparation job identity changed")
		}
		outer.JobPath = captured.JobPath
		outer.TransportPipes = captured.TransportPipes
		outer.MountNamespace = captured.MountNamespace
		outer.MountNamespaceDisposition = captured.MountNamespaceDisposition
		if !legacy {
			outer.Writer = &writer
		}
		return nil
	}
	return errors.New("preparation invocation lacks original native observation")
}

func (m *ImageManager) preparationQuarantined(ctx context.Context, kind string, space ImageSpace) (bool, error) {
	receipt, quarantined, err := m.store.LegacyAcquisitionQuarantine(ctx, kind, space.JobID)
	if err != nil || !quarantined {
		return false, err
	}
	lineage := receipt.Lineage
	if lineage.Kind != kind {
		return false, errors.New("quarantine receipt changed its acquisition kind")
	}
	if lineage.JobID == space.JobID && lineage.ProvisionID == space.ProvisionID {
		return true, nil
	}
	for index, job := range lineage.DerivedJobIDs {
		if job == space.JobID && index < len(lineage.DerivedProvisionIDs) && lineage.DerivedProvisionIDs[index] == space.ProvisionID {
			return true, nil
		}
	}
	return false, errors.New("quarantine receipt differs from the exact acquisition space")
}

func (m *ImageManager) requirePreparationUse(ctx context.Context, kind string, space ImageSpace) error {
	quarantined, err := m.preparationQuarantined(ctx, kind, space)
	if err != nil {
		return err
	}
	if quarantined {
		return errors.New("quarantined acquisition cannot be published, replayed or reused")
	}
	return m.store.RequirePreparationWriterDomain(ctx, space)
}

func samePreparationWriter(a, b *PreparationWriterRecord) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Launch != b.Launch || a.StartIntent != b.StartIntent || a.StartForbidden != b.StartForbidden {
		return false
	}
	if a.Birth == nil || b.Birth == nil {
		if a.Birth != nil || b.Birth != nil {
			return false
		}
	} else if *a.Birth != *b.Birth {
		return false
	}
	if a.Evidence == nil || b.Evidence == nil {
		return a.Evidence == nil && b.Evidence == nil
	}
	return *a.Evidence == *b.Evidence
}

// preparedImage resumes a completed preparation identity without reopening its
// private inputs or resolving a mutable registry tag a second time.
func (m *ImageManager) preparedImage(ctx context.Context, in provision.ApprovedImageInput) (provision.ImageRecord, CacheGeneration, bool, error) {
	var zero provision.ImageRecord
	var empty CacheGeneration
	history, err := m.store.ObjectProvisions(ctx, "image", in.JobID)
	if err != nil {
		return zero, empty, false, err
	}
	if len(history) == 0 {
		spaces, err := m.store.ObjectProvisions(ctx, "image", "image-space:"+in.JobID)
		if err != nil {
			return zero, empty, false, err
		}
		if len(spaces) != 0 {
			return zero, empty, false, errors.New("preparation identity has orphaned or retired storage history; resubmission is forbidden")
		}
		for _, kind := range []string{"source", "cache", "preparation"} {
			_, exists, err := m.store.StorageProject(ctx, in.JobID+":"+kind)
			if err != nil {
				return zero, empty, false, err
			}
			if exists {
				return zero, empty, false, errors.New("preparation identity has orphaned or retired quota ownership; resubmission is forbidden")
			}
		}
		return zero, empty, false, nil
	}
	if len(history) != 1 || history[0].State != "OBSERVED" || history[0].CleanupState == "COMPLETE" {
		return zero, empty, false, errors.New("preparation identity is unresolved or retired; resubmission is forbidden")
	}
	var desired, published ProvisionProperties
	if err = gvxcontract.DecodeStrict(history[0].Desired, 64<<10, 16, &desired); err != nil {
		return zero, empty, false, err
	}
	if err = gvxcontract.DecodeStrict(history[0].Observed.Attributes, 64<<10, 16, &published); err != nil {
		return zero, empty, false, err
	}
	if desired.ApprovedImageInput == nil || *desired.ApprovedImageInput != in || desired.Revision != m.cfg.Bundle.Digest || desired.PrepareLimits == nil || *desired.PrepareLimits != in.Limits || published.ImageSpace == nil {
		return zero, empty, false, errors.New("committed preparation input or compiler binding differs")
	}
	space := *published.ImageSpace
	if space.JobID != in.JobID || space.ReusedSource || space.Source != filepath.Join(m.storage.config.StorageRoot, "images", in.JobID) || space.Cache != filepath.Join(m.storage.config.StorageRoot, "prepared", in.JobID) || space.Work != filepath.Join(m.storage.config.StorageRoot, "preparation", in.JobID) {
		return zero, empty, false, errors.New("committed preparation does not own the original job paths")
	}
	spaces, err := m.store.ObjectProvisions(ctx, "image", "image-space:"+in.JobID)
	if err != nil {
		return zero, empty, false, err
	}
	committed, err := committedImageSpace(spaces, space)
	if err != nil {
		return zero, empty, false, err
	}
	if !committed {
		return zero, empty, false, errors.New("preparation has not completed its physical writer/workspace barriers")
	}
	if err = m.requirePreparationUse(ctx, "image", space); err != nil {
		return zero, empty, false, err
	}
	record, err := m.store.Image(ctx, published.Digest)
	if err != nil {
		return zero, empty, false, err
	}
	if err = provision.ValidateRecord(record, in.Limits); err != nil {
		return zero, empty, false, err
	}
	if record.ID != published.Digest || record.Revision != provision.Revision(in) || record.SourceKind != in.SourceKind || record.SourceRef != in.SourceRef || in.SourceKind != "registry" && record.SourceDigest != in.ArchiveDigest {
		return zero, empty, false, errors.New("committed preparation approval/input identity differs")
	}
	cache, err := m.store.CacheForImage(ctx, record.ID, m.cfg.Bundle.Digest)
	if err != nil {
		return zero, empty, false, err
	}
	if cache.ID != published.Revision || cache.Directory != filepath.Join(space.Cache, "generation") {
		return zero, empty, false, errors.New("committed preparation cache belongs to another generation")
	}
	sourceGeneration, err := m.store.StorageGeneration(ctx, in.JobID+":source")
	if err != nil {
		return zero, empty, false, err
	}
	cacheGeneration, err := m.store.StorageGeneration(ctx, in.JobID+":cache")
	if err != nil {
		return zero, empty, false, err
	}
	if sourceGeneration != record.ID || cacheGeneration != cache.ID {
		return zero, empty, false, errors.New("committed preparation storage is retired or rebound")
	}
	if err = m.verifySource(space, record, in.Limits); err != nil {
		return zero, empty, false, err
	}
	if err = m.verifyPublished(cache, record); err != nil {
		return zero, empty, false, err
	}
	return record, cache, true, nil
}

// LookupPreparedImage verifies only a complete original acquisition. Missing
// history is reported separately; partial or retired jobs are never replayable.
func (m *ImageManager) LookupPreparedImage(ctx context.Context, in provision.ApprovedImageInput) (provision.ImageRecord, CacheGeneration, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := in.Validate(); e != nil {
		return provision.ImageRecord{}, CacheGeneration{}, false, e
	}
	if !withinImageLimits(in.Limits, m.cfg.Limits) {
		return provision.ImageRecord{}, CacheGeneration{}, false, errors.New("preparation exceeds installed ceiling")
	}
	return m.preparedImage(ctx, in)
}

func verifyPreparationRecordBinding(desired ProvisionProperties, record provision.ImageRecord) error {
	if desired.ImageSpace == nil {
		return errors.New("preparation input has no owned storage binding")
	}
	if desired.ImageSpace.ReusedSource {
		if desired.ApprovedImageInput != nil || desired.Digest != record.ID || desired.ImageSpace.SourceGenerationID != record.ID {
			return errors.New("retained-source preparation changed its original immutable record")
		}
		return nil
	}
	in := desired.ApprovedImageInput
	if in == nil || in.JobID != desired.ImageSpace.JobID || record.Revision != provision.Revision(*in) || record.SourceKind != in.SourceKind || record.SourceRef != in.SourceRef || in.SourceKind != "registry" && record.SourceDigest != in.ArchiveDigest {
		return errors.New("preparation record differs from its full authenticated input")
	}
	return nil
}

func (m *ImageManager) completePreparationUnitLedgers(ctx context.Context, ledgers []string, proof CleanupEvidence) error {
	if err := validateScopedCleanup(proof, true, false); err != nil {
		return err
	}
	for _, id := range ledgers {
		outer, err := m.store.Provision(ctx, id)
		if err != nil {
			return err
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(outer.Desired, 64<<10, 16, &desired); err != nil {
			return err
		}
		if outer.Kind != "unit" || desired.Unit == nil || desired.Limits == nil {
			return errors.New("preparation completion lacks its exact helper intent")
		}
		internal, err := m.store.UnitProvisions(ctx, desired.Name)
		if err != nil {
			return err
		}
		for _, row := range internal {
			if !strings.HasPrefix(row.ID, "systemd-") {
				continue
			}
			var dispatch ProvisionProperties
			if err = gvxcontract.DecodeStrict(row.Desired, 64<<10, 16, &dispatch); err != nil {
				return err
			}
			if dispatch.Unit == nil || dispatch.Unit.Name != desired.Name || dispatch.Unit.Generation != desired.Unit.Generation || dispatch.Limits == nil || *dispatch.Limits != *desired.Limits {
				return errors.New("preparation completion changed its internal dispatch")
			}
			if row.CleanupState != "COMPLETE" {
				if err = m.store.CompleteProvisionCleanup(ctx, row.ID, proof); err != nil {
					return err
				}
			}
		}
		if outer.CleanupState != "COMPLETE" {
			if err = m.store.CompleteProvisionCleanup(ctx, id, proof); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *ImageManager) completeCommittedPreparationUnits(ctx context.Context, space ImageSpace) error {
	history, err := m.store.PreparationUnitProvisions(ctx, space.JobID)
	if err != nil {
		return err
	}
	if len(history) == 0 {
		return errors.New("committed preparation has no original helper history")
	}
	if err = m.store.RequirePreparationWriterDomain(ctx, space); err != nil {
		return err
	}
	settled, err := m.settlePreparationUnitHistory(ctx, space, history)
	if err != nil {
		return err
	}
	proof, err := m.storage.VerifyCommittedImageSpace(ctx, space, settled.Evidence)
	if err != nil {
		return err
	}
	return m.completePreparationUnitLedgers(ctx, settled.Ledgers, proof)
}
