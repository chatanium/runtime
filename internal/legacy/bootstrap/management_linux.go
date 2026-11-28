//go:build linux

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const managementMax = 60 << 10

type managementRequest struct {
	Version        uint32                         `json:"version"`
	Operation      string                         `json:"operation"`
	InstallationID RuntimeInstallationID          `json:"installation_id"`
	Input          *provision.ApprovedImageInput  `json:"input,omitempty"`
	Archive        bool                           `json:"archive,omitempty"`
	Credential     bool                           `json:"credential,omitempty"`
	Selector       string                         `json:"selector,omitempty"`
	WorkerInput    *bundle.DevelopmentWorkerInput `json:"worker_input,omitempty"`
	Revision       string                         `json:"revision,omitempty"`
	Enable         bool                           `json:"enable,omitempty"`
}
type managementResponse struct {
	Version    uint32            `json:"version"`
	Report     *CleanupReport    `json:"report,omitempty"`
	Service    *ServiceResult    `json:"service,omitempty"`
	ImageID    string            `json:"image_id,omitempty"`
	RevisionID string            `json:"revision_id,omitempty"`
	Failure    *OperationFailure `json:"failure,omitempty"`
}
type taskInputs struct{ archive, credential io.ReadCloser }
type ownedInputStream struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (s *ownedInputStream) Close() error {
	s.once.Do(func() { s.err = s.ReadCloser.Close() })
	return s.err
}
func ownInputStream(input io.ReadCloser) io.ReadCloser {
	if input == nil {
		return nil
	}
	return &ownedInputStream{ReadCloser: input}
}

type taskKey struct{}

func privateTaskInput(ctx context.Context, in provision.ApprovedImageInput) (io.ReadCloser, io.ReadCloser, error) {
	v, _ := ctx.Value(taskKey{}).(*taskInputs)
	if v == nil {
		if in.SourceKind != "registry" || in.CredentialRef != "" {
			return nil, nil, errors.New("private image bytes required")
		}
		return nil, nil, nil
	}
	if in.SourceKind != "registry" && v.archive == nil {
		return nil, nil, errors.New("pending offline preparation requires its private archive stream")
	}
	if in.CredentialRef != "" && v.credential == nil {
		return nil, nil, errors.New("pending credentialed preparation requires its exact task-only credential stream")
	}
	if in.SourceKind == "registry" && v.archive != nil || in.SourceKind != "registry" && v.credential != nil || in.CredentialRef == "" && v.credential != nil {
		return nil, nil, errors.New("unexpected private preparation stream")
	}
	return v.archive, v.credential, nil
}
func peerRoot(c *net.UnixConn) error {
	raw, e := c.SyscallConn()
	if e != nil {
		return e
	}
	var cred *unix.Ucred
	var inner error
	if e = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil {
		return e
	}
	if inner != nil {
		return inner
	}
	if cred.Uid != 0 {
		return errors.New("management requires kernel-authenticated root peer")
	}
	return nil
}
func (s *ownedSession) serveManagement() (*net.UnixListener, error) {
	path := filepath.Join(s.manifest.Paths.Control, "management.sock")
	if info, e := os.Lstat(path); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("management endpoint occupied")
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	listener, e := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		listener.Close()
		return nil, e
	}
	slots := make(chan struct{}, 4)
	go func() {
		for {
			c, e := listener.AcceptUnix()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() { defer func() { <-slots }(); s.handleManagement(c) }()
			default:
				c.Close()
			}
		}
	}()
	return listener, nil
}
func (s *ownedSession) handleManagement(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Minute))
	if peerRoot(c) != nil {
		return
	}
	buf := make([]byte, managementMax)
	oob := make([]byte, unix.CmsgSpace(8))
	n, on, flags, _, e := c.ReadMsgUnix(buf, oob)
	if e != nil {
		closeRights(oob[:on])
		return
	}
	fds := []int{}
	defer func() {
		for _, fd := range fds {
			if fd >= 0 {
				unix.Close(fd)
			}
		}
	}()
	messages, e := unix.ParseSocketControlMessage(oob[:on])
	if e != nil {
		closeRights(oob[:on])
		return
	}
	validAncillary := len(messages) <= 1
	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			validAncillary = false
			continue
		}
		fds = append(fds, rights...)
		for _, fd := range rights {
			unix.CloseOnExec(fd)
		}
	}
	if !validAncillary || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return
	}
	var req managementRequest
	if e = gvxcontract.DecodeStrict(buf[:n], managementMax, 12, &req); e != nil {
		return
	}
	response := managementResponse{Version: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if req.InstallationID != s.id {
		e = errors.New("management owner binding mismatch")
	} else if e = validateManagementFields(req, len(fds)); e == nil {
		switch req.Operation {
		case "stop":
			var report CleanupReport
			report, e = DrainOwnedSession(ctx, OwnedSession{s})
			response.Report = &report
		case "status":
			if req.Input != nil || req.Archive || req.Credential || len(fds) != 0 {
				e = errors.New("irrelevant status fields")
				break
			}
			m, err := s.store.Installation(ctx)
			e = err
			response.Report = &CleanupReport{InstallationID: s.id, DesiredRunState: m.DesiredRunState, ObservedState: "running"}
		case "prepare":
			inputs := &taskInputs{}
			defer closeTaskInputs(inputs)
			for index, fd := range fds {
				var file *os.File
				file, e = takeReadStream(fd, true)
				if e != nil {
					break
				}
				fds[index] = -1
				if req.Archive && index == 0 {
					inputs.archive = file
				} else {
					inputs.credential = file
				}
			}
			if e != nil {
				break
			}
			var image provision.ImageRecord
			image, e = s.prepareImage(context.WithValue(ctx, taskKey{}, inputs), *req.Input)
			if e == nil {
				response.ImageID = image.ID
			}
		case "inspect":
			var image provision.ImageRecord
			image, e = s.images.InspectPreparedImage(ctx, req.Selector)
			if e == nil {
				response.ImageID = image.ID
			}
		case "prepare_dev_worker":
			var input *os.File
			input, e = takeReadStream(fds[0], true)
			if e != nil {
				break
			}
			fds[0] = -1
			defer input.Close()
			var revision legacyhost.RevisionRecord
			revision, e = s.prepareDevelopmentWorker(ctx, *req.WorkerInput, input)
			if e == nil {
				response.RevisionID = revision.ID
			}
		case "discard_dev_revision":
			var report CleanupReport
			report, e = s.discardDevelopmentRevision(ctx, req.Revision)
			response.Report = &report
		case "service":
			var result ServiceResult
			result, e = s.installService(ctx, req.Enable)
			response.Service = &result
		default:
			e = errors.New("unknown management operation")
		}
	}
	if e != nil {
		response.Failure = &OperationFailure{Phase: "management", Code: "OPERATION_FAILED", Message: e.Error()}
	}
	raw, e := json.Marshal(response)
	if e == nil && len(raw) <= managementMax {
		c.Write(raw)
	}
}
func contactOwner(ctx context.Context, id RuntimeInstallationID, req managementRequest, inputs *taskInputs) (managementResponse, bool, error) {
	var response managementResponse
	if e := rootRequired(); e != nil {
		return response, false, e
	}
	control, e := controlPath(id)
	if e != nil {
		return response, false, e
	}
	if e = trustedPath(control, false); e != nil {
		return response, false, e
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	dialer := net.Dialer{}
	conn, e := dialer.DialContext(bounded, "unixpacket", filepath.Join(control, "management.sock"))
	if e != nil {
		if errors.Is(e, unix.ENOENT) || errors.Is(e, unix.ECONNREFUSED) {
			return response, false, nil
		}
		return response, false, e
	}
	c := conn.(*net.UnixConn)
	defer c.Close()
	if e = authenticateOwner(bounded, id, c); e != nil {
		return response, true, e
	}
	deadline, _ := bounded.Deadline()
	c.SetDeadline(deadline)
	stopClose := context.AfterFunc(bounded, func() { c.Close(); closeTaskInputs(inputs) })
	defer stopClose()
	req.Version = 1
	req.InstallationID = id
	raw, e := json.Marshal(req)
	if e != nil || len(raw) > managementMax {
		return response, true, errors.New("management request bound exceeded")
	}
	var send, writers []*os.File
	var pumps sync.WaitGroup
	defer func() {
		for _, f := range send {
			f.Close()
		}
		for _, f := range writers {
			f.Close()
		}
		closeTaskInputs(inputs)
		pumps.Wait()
	}()
	if inputs != nil {
		for _, r := range []io.ReadCloser{inputs.archive, inputs.credential} {
			if r == nil {
				continue
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				return response, true, err
			}
			send = append(send, reader)
			writers = append(writers, writer)
			pumps.Add(1)
			go func(r io.ReadCloser, w *os.File) { defer pumps.Done(); defer w.Close(); io.Copy(w, r) }(r, writer)
		}
	}
	var rights []int
	for _, f := range send {
		rights = append(rights, int(f.Fd()))
	}
	var ancillary []byte
	if len(rights) > 0 {
		ancillary = unix.UnixRights(rights...)
	}
	if _, _, e = c.WriteMsgUnix(raw, ancillary, nil); e != nil {
		return response, true, e
	}
	for _, f := range send {
		f.Close()
	}
	buf := make([]byte, managementMax)
	oob := make([]byte, unix.CmsgSpace(8))
	n, on, flags, _, e := c.ReadMsgUnix(buf, oob)
	closeRights(oob[:on])
	if e != nil {
		return response, true, e
	}
	if on != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return response, true, errors.New("invalid management response ancillary data")
	}
	if e = gvxcontract.DecodeStrict(buf[:n], managementMax, 16, &response); e != nil {
		return response, true, e
	}
	if response.Version != 1 {
		return response, true, errors.New("management version mismatch")
	}
	if response.Failure != nil {
		return response, true, errors.New(response.Failure.Code + ": " + response.Failure.Message)
	}
	return response, true, nil
}
func Stop(ctx context.Context, id RuntimeInstallationID) (report CleanupReport, retErr error) {
	if e := rootRequired(); e != nil {
		return report, e
	}
	response, live, e := contactOwner(ctx, id, managementRequest{Operation: "stop"}, nil)
	if live {
		if response.Report == nil {
			return CleanupReport{InstallationID: id}, errors.Join(e, host.ErrCleanupIncomplete)
		}
		if response.Report.Complete {
			e = errors.Join(e, waitOwnerRelease(ctx, id))
		}
		return *response.Report, e
	}
	if e != nil {
		return report, e
	}
	store, manifest, e := openInstallation(ctx, id)
	if e != nil {
		return report, e
	}
	store.Close()
	if manifest.ActiveRevision == "" {
		session, e := maintenance(ctx, id)
		if e != nil {
			return report, e
		}
		defer func() { retErr = errors.Join(retErr, closeMaintenance(session)) }()
		return cleanupProvisioning(ctx, session)
	}
	session, e := acquireSession(ctx, id, Foreground)
	if e != nil {
		return report, e
	}
	defer func() { retErr = errors.Join(retErr, closeMaintenance(session)) }()
	return DrainOwnedSession(ctx, OwnedSession{session})
}
func (s *ownedSession) prepareImage(ctx context.Context, in provision.ApprovedImageInput) (provision.ImageRecord, error) {
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	taskID := newID()
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return provision.ImageRecord{}, errors.New("owner is draining")
	}
	if s.taskCancel == nil {
		s.taskCancel = make(map[string]context.CancelFunc)
	}
	s.taskCancel[taskID] = cancel
	s.preparing.Add(1)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.taskCancel, taskID); s.mu.Unlock(); s.preparing.Done() }()
	normalized, e := normalizeImageInput(taskCtx, s.store, s.manifest, in)
	if e != nil {
		return provision.ImageRecord{}, e
	}
	image, e := s.images.PrepareImage(taskCtx, normalized)
	if e != nil {
		return provision.ImageRecord{}, e
	}
	revision, e := s.store.Revision(taskCtx, s.manifest.ActiveRevision)
	if e != nil {
		return provision.ImageRecord{}, e
	}
	cfg, e := runtime.DecodeConfig(revision.Config)
	if e != nil {
		return provision.ImageRecord{}, e
	}
	var module *runtime.ModuleSpec
	for index := range cfg.Modules {
		if string(cfg.Modules[index].ModuleID) == normalized.ModuleID {
			module = &cfg.Modules[index]
			break
		}
	}
	if module == nil {
		return provision.ImageRecord{}, errors.New("prepared candidate module disappeared")
	}
	selector := image.SourceRef
	if image.SourceKind != "registry" {
		selector = "record:" + image.ID
	}
	module.ImageDigest = selector
	policy, e := runtime.ApprovedLaunchPolicy(cfg, *module, image)
	if e != nil {
		return provision.ImageRecord{}, e
	}
	binding := legacyhost.ApprovedImageBinding{ModuleID: normalized.ModuleID, ImageSelector: selector, ImageRecordID: image.ID, ConfigRevision: normalized.ConfigRevision, ApprovalRevision: normalized.ApprovalRevision}
	if e = s.store.AuthorizePreparedCandidate(taskCtx, binding, policy); e != nil {
		return provision.ImageRecord{}, e
	}
	if e = s.store.BindPreparedImage(taskCtx, binding); e != nil {
		return provision.ImageRecord{}, e
	}
	return image, nil
}
func PrepareImage(ctx context.Context, id RuntimeInstallationID, in provision.ApprovedImageInput) (provision.ImageRecord, error) {
	return PrepareImageWithInput(ctx, id, in, nil, nil)
}
func PrepareImageWithInput(ctx context.Context, id RuntimeInstallationID, in provision.ApprovedImageInput, archive, credential io.ReadCloser) (provision.ImageRecord, error) {
	inputs := &taskInputs{archive: ownInputStream(archive), credential: ownInputStream(credential)}
	defer closeTaskInputs(inputs)
	cancelClose := context.AfterFunc(ctx, func() { closeTaskInputs(inputs) })
	defer cancelClose()
	store, m, e := openInstallation(ctx, id)
	if e != nil {
		return provision.ImageRecord{}, e
	}
	normalized, e := normalizeImageInput(ctx, store, m, in)
	store.Close()
	if e != nil {
		return provision.ImageRecord{}, e
	}
	req := managementRequest{Operation: "prepare", Input: &normalized, Archive: archive != nil, Credential: credential != nil}
	response, live, e := contactOwner(ctx, id, req, inputs)
	if live {
		if e != nil {
			return provision.ImageRecord{}, e
		}
		if response.ImageID == "" {
			return provision.ImageRecord{}, errors.New("missing prepared image result")
		}
		store, _, e := openInstallation(ctx, id)
		if e != nil {
			return provision.ImageRecord{}, e
		}
		defer store.Close()
		return store.Image(ctx, response.ImageID)
	}
	if e != nil {
		return provision.ImageRecord{}, e
	}
	s, e := acquireSession(ctx, id, Foreground)
	if e != nil {
		return provision.ImageRecord{}, e
	}
	defer s.store.Close()
	defer s.lease.Close()
	defer s.systemd.Close()
	defer s.supervisor.Close()
	defer DrainOwnedSession(context.Background(), OwnedSession{s})
	image, e := s.prepareImage(context.WithValue(ctx, taskKey{}, inputs), normalized)
	_, cleanup := DrainOwnedSession(context.Background(), OwnedSession{s})
	return image, errors.Join(e, cleanup)
}
func closeTaskInputs(v *taskInputs) {
	if v == nil {
		return
	}
	if v.archive != nil {
		v.archive.Close()
	}
	if v.credential != nil {
		v.credential.Close()
	}
}
func closeRights(raw []byte) {
	messages, _ := unix.ParseSocketControlMessage(raw)
	for _, m := range messages {
		fds, _ := unix.ParseUnixRights(&m)
		for _, fd := range fds {
			unix.CloseOnExec(fd)
			unix.Close(fd)
		}
	}
}
func authenticateOwner(ctx context.Context, id RuntimeInstallationID, c *net.UnixConn) error {
	if e := peerRoot(c); e != nil {
		return e
	}
	s, _, e := openInstallation(ctx, id)
	if e != nil {
		return e
	}
	owner, e := s.LeaseOwner(ctx)
	s.Close()
	if e != nil {
		return e
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return e
	}
	var cred *unix.Ucred
	var inner error
	if e = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil {
		return e
	}
	if inner != nil {
		return inner
	}
	if cred == nil {
		return errors.New("missing management peer credentials")
	}
	if int(cred.Pid) != owner.MainPID {
		return errors.New("management peer differs from lease owner")
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(boot)) != owner.BootID {
		return errors.New("management owner boot mismatch")
	}
	stat, e := os.ReadFile(filepath.Join("/proc", strconv.Itoa(owner.MainPID), "stat"))
	if e != nil {
		return e
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return errors.New("invalid owner process stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return errors.New("short owner process stat")
	}
	start, e := strconv.ParseUint(fields[19], 10, 64)
	if e != nil || start != owner.StartTime {
		return errors.New("management owner PID was reused")
	}
	exe, e := os.Open(filepath.Join("/proc", strconv.Itoa(owner.MainPID), "exe"))
	if e != nil {
		return e
	}
	defer exe.Close()
	hash, e := streamDigest(exe)
	if e != nil || hash != owner.ExecutableDigest {
		return errors.New("management owner executable mismatch")
	}
	groups, e := os.ReadFile(filepath.Join("/proc", strconv.Itoa(owner.MainPID), "cgroup"))
	if e != nil {
		return e
	}
	if !strings.Contains(string(groups), "0::"+owner.CgroupPath+"\n") {
		return errors.New("management owner cgroup mismatch")
	}
	return nil
}
func normalizeImageInput(ctx context.Context, s *legacyhost.Store, m legacyhost.InstallationManifest, in provision.ApprovedImageInput) (provision.ApprovedImageInput, error) {
	revision, e := s.Revision(ctx, m.ActiveRevision)
	if e != nil {
		return in, e
	}
	var binding *legacyhost.ApprovedImageBinding
	for index := range revision.Images {
		if revision.Images[index].ModuleID == in.ModuleID {
			binding = &revision.Images[index]
			break
		}
	}
	if binding == nil {
		return in, errors.New("candidate lacks existing module approval")
	}
	if in.JobID != "" {
		original, lookup := s.ImagePreparationInput(ctx, in.JobID)
		if lookup == nil {
			if original.ModuleID != binding.ModuleID || original.ConfigRevision != binding.ConfigRevision || original.ApprovalRevision != binding.ApprovalRevision {
				return in, errors.New("pending preparation no longer has the exact current module approval")
			}
			if in.SourceKind != "" && in.SourceKind != original.SourceKind || in.SourceRef != "" && in.SourceRef != original.SourceRef || in.Platform != "" && in.Platform != original.Platform || in.CredentialRef != "" && in.CredentialRef != original.CredentialRef || in.ConfigRevision != "" && in.ConfigRevision != original.ConfigRevision || in.ApprovalRevision != "" && in.ApprovalRevision != original.ApprovalRevision || in.Limits != (provision.PrepareLimits{}) && in.Limits != original.Limits {
				return in, errors.New("same-job preparation input differs from immutable original")
			}
			in = original
		} else if !errors.Is(lookup, sql.ErrNoRows) {
			return in, lookup
		}
	}
	if in.ConfigRevision != "" && in.ConfigRevision != binding.ConfigRevision || in.ApprovalRevision != "" && in.ApprovalRevision != binding.ApprovalRevision {
		return in, errors.New("candidate revision differs from approval")
	}
	in.ConfigRevision = binding.ConfigRevision
	in.ApprovalRevision = binding.ApprovalRevision
	if in.JobID == "" {
		in.JobID = newID()
	}
	if in.Platform == "" {
		in.Platform = "linux/amd64"
	}
	if in.SourceKind == "" {
		in.SourceKind = "registry"
	}
	old, e := s.Image(ctx, binding.ImageRecordID)
	if e != nil {
		return in, e
	}
	if old.SourceKind != in.SourceKind {
		return in, errors.New("candidate source-kind differs from approval")
	}
	if in.SourceKind == "registry" && strings.Split(old.SourceRef, "@")[0] != strings.Split(in.SourceRef, "@")[0] {
		return in, errors.New("candidate repository differs from approval")
	}
	maximum, e := approvedPreparationLimits(ctx, s, old, maximumPreparationLimits(m))
	if e != nil {
		return in, e
	}
	if in.Limits == (provision.PrepareLimits{}) {
		in.Limits = maximum
	}
	if e = checkPrepareLimits(in.Limits, maximum); e != nil {
		return in, e
	}
	if e = in.Validate(); e != nil {
		return in, e
	}
	return in, nil
}
func checkPrepareLimits(l, max provision.PrepareLimits) error {
	if e := l.Validate(); e != nil {
		return e
	}
	a := []int64{l.NanoCPUs, l.MemoryBytes, l.Tasks, l.InputBytes, l.ExpandedBytes, l.OutputBytes, l.Inodes, l.JSONBytes, l.DescriptorCount, l.IndexDepth, int64(l.Deadline)}
	b := []int64{max.NanoCPUs, max.MemoryBytes, max.Tasks, max.InputBytes, max.ExpandedBytes, max.OutputBytes, max.Inodes, max.JSONBytes, max.DescriptorCount, max.IndexDepth, int64(max.Deadline)}
	for i, n := range a {
		if n > b[i] {
			return errors.New("preparation exceeds installed upper limits")
		}
	}
	return nil
}
func maximumPreparationLimits(m legacyhost.InstallationManifest) provision.PrepareLimits {
	return imageConfig(m, bundle.Verified{}, host.UnitIdentity{}, nil).Limits
}
func approvedPreparationLimits(ctx context.Context, s *legacyhost.Store, image provision.ImageRecord, ceiling provision.PrepareLimits) (provision.PrepareLimits, error) {
	records, e := s.PendingProvisions(ctx)
	if e != nil {
		return provision.PrepareLimits{}, e
	}
	for _, record := range records {
		if record.Kind != "image" || record.State != "OBSERVED" {
			continue
		}
		var p legacyhost.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return provision.PrepareLimits{}, e
		}
		if p.Digest == image.ID && p.PrepareLimits != nil {
			if e = checkPrepareLimits(*p.PrepareLimits, ceiling); e != nil {
				return provision.PrepareLimits{}, e
			}
			return *p.PrepareLimits, nil
		}
	}
	return provision.PrepareLimits{}, errors.New("prepared source has no approved durable preparation bounds")
}
func validateManagementFields(r managementRequest, fds int) error {
	if r.Version != 1 || !validID(string(r.InstallationID)) || r.Enable && r.Operation != "service" {
		return errors.New("invalid management envelope")
	}
	switch r.Operation {
	case "stop", "status", "service":
		if r.Input != nil || r.WorkerInput != nil || r.Revision != "" || r.Selector != "" || r.Archive || r.Credential || fds != 0 {
			return errors.New("irrelevant management fields")
		}
	case "prepare":
		expected := 0
		if r.Archive {
			expected++
		}
		if r.Credential {
			expected++
		}
		if r.Input == nil || r.WorkerInput != nil || r.Revision != "" || r.Selector != "" || fds != expected {
			return errors.New("invalid image preparation fields")
		}
	case "inspect":
		if r.Input != nil || r.WorkerInput != nil || r.Revision != "" || r.Selector == "" || r.Archive || r.Credential || fds != 0 {
			return errors.New("invalid image inspection fields")
		}
	case "prepare_dev_worker":
		if r.Input != nil || r.WorkerInput == nil || r.Revision != "" || r.Selector != "" || r.Archive || r.Credential || fds != 1 {
			return errors.New("invalid development preparation fields")
		}
	case "discard_dev_revision":
		if r.Input != nil || r.WorkerInput != nil || !validID(r.Revision) || r.Selector != "" || r.Archive || r.Credential || fds != 0 {
			return errors.New("invalid development discard fields")
		}
	default:
		return errors.New("unknown management operation")
	}
	return nil
}
func takeReadStream(fd int, regular bool) (*os.File, error) {
	unix.CloseOnExec(fd)
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return nil, e
	}
	kind := st.Mode & unix.S_IFMT
	if kind != unix.S_IFIFO && (!regular || kind != unix.S_IFREG) {
		return nil, errors.New("private task FD is not an allowed data stream")
	}
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if e != nil {
		return nil, e
	}
	if flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, errors.New("private task FD is not read-only")
	}
	return os.NewFile(uintptr(fd), "private-task-input"), nil
}
