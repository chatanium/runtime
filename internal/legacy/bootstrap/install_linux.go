//go:build linux

package bootstrap

import (
	"bytes"
	"context"
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
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var sourceState struct {
	sync.Mutex
	source bundle.Source
}

func ConfigureSource(s bundle.Source) error {
	sourceState.Lock()
	defer sourceState.Unlock()
	if s == nil || sourceState.source != nil {
		return errors.New("bundle source must be configured exactly once")
	}
	sourceState.source = s
	return nil
}
func configuredSource() (bundle.Source, error) {
	sourceState.Lock()
	defer sourceState.Unlock()
	if sourceState.source == nil {
		return nil, errors.New("verified release source required")
	}
	return sourceState.source, nil
}
func openInstallation(ctx context.Context, id RuntimeInstallationID) (*legacyhost.Store, legacyhost.InstallationManifest, error) {
	var m legacyhost.InstallationManifest
	p, e := controlPath(id)
	if e != nil {
		return nil, m, e
	}
	gate, e := acquireManagementGuard(ctx)
	if e != nil {
		return nil, m, e
	}
	s, e := legacyhost.OpenStore(ctx, p, string(id), gate)
	if e != nil {
		closeUnadoptedManagementGuard(gate)
		return nil, m, e
	}
	m, e = s.Installation(ctx)
	if e != nil {
		s.Close()
		return nil, m, e
	}
	return s, m, nil
}
func ValidateInstalledConfig(ctx context.Context, id RuntimeInstallationID, path string, raw []byte) error {
	s, m, e := openInstallation(ctx, id)
	if e != nil {
		return e
	}
	defer s.Close()
	if path != m.Paths.Config {
		return errors.New("configuration path differs from installation approval")
	}
	r, e := s.Revision(ctx, m.ActiveRevision)
	if e != nil {
		return e
	}
	if provision.Digest(raw) != r.ConfigDigest {
		return errors.New("configuration differs from active approved revision")
	}
	return nil
}
func recordIntent(ctx context.Context, s *legacyhost.Store, kind, identity string, p legacyhost.ProvisionProperties, existed bool) (string, error) {
	id := newID()
	if id == "" {
		return "", errors.New("entropy unavailable")
	}
	e := s.BeginProvision(ctx, legacyhost.ProvisionIntent{ID: id, Kind: kind, Identity: identity, ExistedBefore: existed, ProductCreated: !existed, Desired: provisionJSON(p)})
	return id, e
}
func observePath(ctx context.Context, s *legacyhost.Store, id, identity string, p legacyhost.ProvisionProperties) error {
	var st unix.Stat_t
	if e := unix.Lstat(identity, &st); e != nil {
		return e
	}
	p.Dev = uint64(st.Dev)
	p.Ino = st.Ino
	p.Mode = st.Mode & 07777
	p.UID = st.Uid
	p.GID = st.Gid
	p.SizeBytes = 0
	if st.Mode&unix.S_IFMT == unix.S_IFREG {
		p.SizeBytes = st.Size
	}
	return s.ObserveProvision(ctx, id, legacyhost.ObjectObservation{Identity: identity, Attributes: provisionJSON(p)})
}
func createDirectory(ctx context.Context, s *legacyhost.Store, path string, mode uint32) error {
	if e := trustedPath(path, true); e != nil {
		return e
	}
	if _, e := os.Lstat(path); e == nil {
		return errors.New("unowned directory cannot be implicitly adopted")
	} else if !os.IsNotExist(e) {
		return e
	}
	p := legacyhost.ProvisionProperties{Path: path, Mode: mode, ProductCreated: true}
	id, e := recordIntent(ctx, s, "directory", path, p, false)
	if e != nil {
		return e
	}
	if e = os.Mkdir(path, os.FileMode(mode)); e != nil {
		return e
	}
	return observePath(ctx, s, id, path, p)
}
func writeNew(ctx context.Context, s *legacyhost.Store, kind, path string, data []byte, mode uint32) error {
	if e := trustedPath(path, true); e != nil {
		return e
	}
	p := legacyhost.ProvisionProperties{Path: path, Digest: provision.Digest(data), Mode: mode, ProductCreated: true}
	id, e := initIntent(ctx, s, kind, path, p, false)
	if e != nil {
		return e
	}
	records, e := s.PendingProvisions(ctx)
	if e != nil {
		return e
	}
	for _, record := range records {
		if record.ID == id && record.State == "OBSERVED" {
			if e = matchRecord(record); e != nil {
				return e
			}
			return nil
		}
	}
	if _, e = os.Lstat(path); e == nil {
		return errors.New("file exists without a completed durable creation observation")
	} else if !os.IsNotExist(e) {
		return e
	}
	fd, e := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	e = d.Sync()
	d.Close()
	if e != nil {
		return e
	}
	return observePath(ctx, s, id, path, p)
}
func validateAccount(i legacyhost.NumericIdentity) error {
	if !validAccountName(i.Name) || i.UID == 0 || i.GID == 0 {
		return errors.New("invalid dedicated identity")
	}
	u, e := user.Lookup(i.Name)
	if e != nil {
		return e
	}
	if u.Uid != strconv.FormatUint(uint64(i.UID), 10) || u.Gid != strconv.FormatUint(uint64(i.GID), 10) || u.HomeDir != "/nonexistent" {
		return errors.New("dedicated account identity mismatch")
	}
	g, e := user.LookupGroup(i.Name)
	if e != nil || g.Gid != u.Gid {
		return errors.New("dedicated group mismatch")
	}
	groups, e := u.GroupIds()
	if e != nil {
		return e
	}
	for _, group := range groups {
		if group != u.Gid {
			return errors.New("dedicated account has supplemental memberships")
		}
	}
	if e = validateAccountShell(i.Name); e != nil {
		return e
	}
	return validateUnsharedGroup(i.Name, u.Gid)
}
func provisionAccount(ctx context.Context, s *legacyhost.Store, d *legacyhost.Systemd, i legacyhost.NumericIdentity) error {
	if !validAccountName(i.Name) || i.UID == 0 || i.GID == 0 {
		return errors.New("invalid account approval")
	}
	p := legacyhost.ProvisionProperties{Name: i.Name, UID: i.UID, GID: i.GID, ProductCreated: i.ProductCreated}
	records, e := s.PendingProvisions(ctx)
	if e != nil {
		return e
	}
	var previous *legacyhost.ProvisionRecord
	for index := range records {
		r := &records[index]
		if r.Kind == "account" && r.Identity == i.Name && r.CleanupState != "COMPLETE" {
			if r.ProductCreated != i.ProductCreated || r.ExistedBefore == i.ProductCreated || !bytes.Equal(r.Desired, provisionJSON(p)) {
				return errors.New("account durable intent differs from approval")
			}
			previous = r
			break
		}
	}
	_, ue := user.Lookup(i.Name)
	_, ge := user.LookupGroup(i.Name)
	if ue != nil && !unknownUser(ue) {
		return ue
	}
	if ge != nil && !unknownGroup(ge) {
		return ge
	}
	if ue == nil {
		if i.ProductCreated && (previous == nil || previous.State != "OBSERVED") {
			return errors.New("existing account has no durable creation observation")
		}
		if e = validateAccount(i); e != nil {
			return e
		}
		id, e := initIntent(ctx, s, "account", i.Name, p, !i.ProductCreated)
		if e != nil {
			return e
		}
		return s.ObserveProvision(ctx, id, legacyhost.ObjectObservation{Identity: i.Name, Attributes: provisionJSON(p)})
	}
	if !i.ProductCreated {
		return errors.New("approved existing account is absent")
	}
	if _, e = user.LookupId(strconv.FormatUint(uint64(i.UID), 10)); e == nil {
		return errors.New("UID already allocated")
	} else if _, ok := e.(user.UnknownUserIdError); !ok {
		return e
	}
	if ge == nil {
		if previous == nil || previous.State != "OBSERVED" {
			return errors.New("existing group has no durable creation observation")
		}
		var observed legacyhost.ProvisionProperties
		if e = gvxcontract.DecodeStrict(previous.Observed.Attributes, 64<<10, 16, &observed); e != nil {
			return e
		}
		if observed.Source != "group" || observed.Name != i.Name || observed.GID != i.GID {
			return errors.New("partial account observation differs")
		}
		if e = validateGroupOnly(observed); e != nil {
			return e
		}
	} else {
		if previous != nil && previous.State == "OBSERVED" {
			return errors.New("recorded group is missing")
		}
		if _, e = user.LookupGroupId(strconv.FormatUint(uint64(i.GID), 10)); e == nil {
			return errors.New("GID already allocated")
		} else if _, ok := e.(user.UnknownGroupIdError); !ok {
			return e
		}
	}
	id, e := initIntent(ctx, s, "account", i.Name, p, false)
	if e != nil {
		return e
	}
	if ge != nil {
		if _, e = d.RunHelper(ctx, d.Owner(), bundle.ProgramID("groupadd"), []string{"--system", "--gid", strconv.FormatUint(uint64(i.GID), 10), i.Name}, nil, 65536); e != nil {
			return e
		}
		group := p
		group.Source = "group"
		group.UID = 0
		if e = validateGroupOnly(group); e != nil {
			return e
		}
		if e = s.ObserveProvision(ctx, id, legacyhost.ObjectObservation{Identity: i.Name, Attributes: provisionJSON(group)}); e != nil {
			return e
		}
	}
	if _, e = d.RunHelper(ctx, d.Owner(), bundle.ProgramID("useradd"), []string{"--system", "--uid", strconv.FormatUint(uint64(i.UID), 10), "--gid", strconv.FormatUint(uint64(i.GID), 10), "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", i.Name}, nil, 65536); e != nil {
		return e
	}
	if e = validateAccount(i); e != nil {
		return e
	}
	return s.ObserveProvision(ctx, id, legacyhost.ObjectObservation{Identity: i.Name, Attributes: provisionJSON(p)})
}
func validateInit(p ApprovedInitPlan) error {
	if !validID(p.PlanID) || !validID(string(p.InstallationID)) {
		return errors.New("invalid plan identity")
	}
	sum, e := InitPlanDigest(p)
	if e != nil || sum != p.PlanDigest {
		return errors.New("init approval digest mismatch")
	}
	control, e := controlPath(p.InstallationID)
	if e != nil {
		return e
	}
	if p.Paths.Control != control || p.Paths.Installation != filepath.Dir(control) {
		return errors.New("installation locator must use product control anchor")
	}
	for _, path := range []string{p.Paths.Config, p.Paths.Secrets, p.Paths.BackingFile, p.Paths.StorageRoot, p.Paths.EngineRoot, p.Paths.RunRoot, p.Paths.Launcher} {
		if e = trustedPlannedPath(path); e != nil {
			return e
		}
	}
	c, e := runtime.DecodeConfig(p.BaseConfig)
	if e != nil {
		return e
	}
	if len(c.Modules) != 0 || c.Host.RuntimeInstallationID != string(p.InstallationID) || c.Host.BundleDigest != p.BundleDigest || c.Host.ManagementDirectory != filepath.Join(p.Paths.StorageRoot, "app") || c.Host.StorageRoot != p.Paths.StorageRoot || c.Host.IPCRoot != filepath.Join(p.Paths.RunRoot, "instances") {
		return errors.New("base configuration binding mismatch")
	}
	seenUID, seenGID, seenName := map[uint32]bool{}, map[uint32]bool{}, map[string]bool{}
	if e = validateAppBudget(c, p.Budget, nil); e != nil {
		return e
	}
	for _, i := range []legacyhost.NumericIdentity{p.Identities.App, p.Identities.Sandbox, p.Identities.Preparer} {
		if seenUID[i.UID] || seenGID[i.GID] || seenName[i.Name] || i.UID == 0 || i.GID == 0 || !validAccountName(i.Name) {
			return errors.New("distinct dedicated identities required")
		}
		seenUID[i.UID] = true
		seenGID[i.GID] = true
		seenName[i.Name] = true
	}
	if e = validateObjects(p.Objects, false); e != nil {
		return e
	}
	if _, e = backingSize(p.Budget); e != nil {
		return e
	}
	if e = validateSecretBindings(c, p.SecretSources); e != nil {
		return e
	}
	if e = validateInitSecretObservations(p); e != nil {
		return e
	}
	return validateInitScope(p)
}
func validateObjects(objects []ApprovedObject, remove bool) error {
	seen := map[string]bool{}
	for _, object := range objects {
		switch object.Kind {
		case "management-anchor":
			if object.Action != "create" && object.Action != "reuse" {
				return errors.New("retained management anchor cannot be removed or replaced")
			}
		case "account", "directory", "backing", "loop", "mount", "unit", "bundle", "config", "secret", "image", "shared-network-anchor", "development-worker":
		default:
			return errors.New("unknown approved object kind")
		}
		if object.Identity == "" || seen[object.Kind+":"+object.Identity] {
			return errors.New("duplicate approved object")
		}
		seen[object.Kind+":"+object.Identity] = true
		if remove && object.Action != "remove" {
			return errors.New("purge scope must remove")
		}
		switch object.Action {
		case "create":
			if object.ObservationDigest != "" {
				return errors.New("create cannot claim existing identity")
			}
		case "reuse", "replace", "remove":
			if !provision.ValidDigest(object.ObservationDigest) {
				return errors.New("current object observation approval required")
			}
		default:
			return errors.New("invalid object action")
		}
	}
	return nil
}
func Initialize(ctx context.Context, p ApprovedInitPlan, approve func(context.Context, ModuleReview) (ApprovedModuleConfig, error)) (RuntimeInstallationID, error) {
	return InitializeWithInputs(ctx, p, approve, nil)
}
func InitializeWithInputs(ctx context.Context, p ApprovedInitPlan, approve func(context.Context, ModuleReview) (ApprovedModuleConfig, error), inputs func(context.Context, provision.ApprovedImageInput) (io.ReadCloser, io.ReadCloser, error)) (result RuntimeInstallationID, retErr error) {
	if e := rootRequired(); e != nil {
		return "", e
	}
	if e := validateInit(p); e != nil {
		return "", e
	}
	if approve == nil && len(p.Modules) > 0 {
		return "", errors.New("module approval callback required")
	}
	source, e := configuredSource()
	if e != nil {
		return "", e
	}
	raw, e := source.Manifest()
	if e != nil {
		return "", e
	}
	bm, e := bundle.VerifyManifest(raw)
	if e != nil || bm.Digest != p.BundleDigest {
		return "", errors.New("approved bundle mismatch")
	}
	baseConfig, e := runtime.DecodeConfig(p.BaseConfig)
	if e != nil {
		return "", e
	}
	if e = legacyhost.VerifyNetworkPrerequisites(ctx, networkPlanConfig(baseConfig), p.NetworkPrerequisites); e != nil {
		return "", e
	}
	anchors, e := reviewNetworkAnchors(ctx, p.Paths, p.Objects, baseConfig, "init", p.PlanID, p.PlanDigest)
	if e != nil {
		return "", e
	}
	if _, e = cleanupTimeout(baseConfig); e != nil {
		return "", e
	}
	size, e := backingSize(p.Budget)
	if e != nil {
		return "", e
	}
	m := legacyhost.InstallationManifest{Format: gvxcontract.InstallationFormat, FormatVersion: 1, SchemaVersion: 1, RuntimeInstallationID: string(p.InstallationID), State: "PROVISIONING", DesiredRunState: "STOPPED", BundleDigest: p.BundleDigest, Paths: p.Paths, Identities: p.Identities, Budget: p.Budget, Backing: legacyhost.BackingIdentity{SizeBytes: size}}
	planRaw, e := json.Marshal(p)
	if e != nil {
		return "", e
	}
	_, statErr := os.Lstat(p.Paths.Control)
	controlExists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return "", statErr
	}
	currentAnchor, e := legacyhost.ObserveManagementAnchor(ctx)
	if e != nil {
		return "", e
	}
	if currentAnchor.Lock.Absent {
		if controlExists {
			return p.InstallationID, errors.New("known installation has lost its retained management anchor")
		}
		if _, e = legacyhost.EnsureManagementAnchor(ctx, p.ManagementAnchor); e != nil {
			return "", e
		}
	} else if !p.ManagementAnchor.Lock.Absent {
		if _, e = legacyhost.EnsureManagementAnchor(ctx, p.ManagementAnchor); e != nil {
			return "", e
		}
	} else if !controlExists {
		return "", errors.New("management anchor appeared after initialization approval; review its reuse in a new plan")
	}
	gate, e := acquireManagementGuard(ctx)
	if e != nil {
		return "", e
	}
	var s *legacyhost.Store
	if !controlExists {
		if e = inspectInitCreates(p); e != nil {
			closeUnadoptedManagementGuard(gate)
			return "", e
		}
		s, e = legacyhost.CreateStoreWithManagementPlan(ctx, m, legacyhost.ManagementPlanRecord{Kind: "init", ID: p.PlanID, Digest: p.PlanDigest, Plan: planRaw, Phase: "APPROVED"}, gate)
	} else {
		s, e = legacyhost.OpenStore(ctx, p.Paths.Control, string(p.InstallationID), gate)
	}
	if e != nil {
		closeUnadoptedManagementGuard(gate)
		return "", e
	}
	defer s.Close()
	lease, e := s.AcquireLease(ctx)
	if e != nil {
		return p.InstallationID, e
	}
	defer lease.Close()
	transaction, e := s.ManagementPlan(ctx, "init", p.PlanID)
	if e != nil {
		return p.InstallationID, e
	}
	if transaction.Digest != p.PlanDigest || !bytes.Equal(transaction.Plan, planRaw) {
		return p.InstallationID, errors.New("initialization differs from durable approved transaction")
	}
	if e = verifyInitManagementAnchor(ctx, s); e != nil {
		return p.InstallationID, e
	}
	m, e = s.Installation(ctx)
	if e != nil {
		return p.InstallationID, e
	}
	if transaction.Phase == "COMMITTED" {
		if m.State != "READY" || m.ActiveRevision == "" {
			return p.InstallationID, errors.New("committed initialization state changed")
		}
		return p.InstallationID, nil
	}
	if transaction.Phase != "APPROVED" && transaction.Phase != "PREPARED" {
		return p.InstallationID, errors.New("unknown initialization transaction phase")
	}
	if m.Paths != p.Paths || m.Identities != p.Identities || m.Budget != p.Budget || m.BundleDigest != p.BundleDigest {
		return p.InstallationID, errors.New("initialization manifest differs from its durable approval")
	}
	var d *legacyhost.Systemd
	var owner host.UnitIdentity
	defer func() {
		if d != nil {
			d.Close()
		}
	}()
	if m.State == "RECOVERY_REQUIRED" {
		d, owner, m, e = recoverApprovedInitialization(ctx, s, lease, m, p, baseConfig)
		if e != nil {
			return p.InstallationID, e
		}
	}
	if (m.State != "PROVISIONING" && !(m.State == "READY" && transaction.Phase == "PREPARED")) || m.DesiredRunState != "STOPPED" || (m.ActiveRevision != "" && transaction.Phase != "PREPARED") {
		return p.InstallationID, errors.New("initialization cannot adopt a non-provisioning installation")
	}
	baseRevision := legacyhost.RevisionRecord{ID: p.PlanID, ConfigDigest: provision.Digest(p.BaseConfig), BundleDigest: p.BundleDigest, Config: p.BaseConfig, PublicProfile: profile(baseConfig)}
	if m.PendingRevision == "" && m.ActiveRevision == "" {
		if e = s.SetPendingRevision(ctx, baseRevision); e != nil {
			return p.InstallationID, e
		}
		m.PendingRevision = baseRevision.ID
	}
	if e = provisionDirectories(ctx, s, p); e != nil {
		return p.InstallationID, e
	}
	if e = provisionNetworkAnchors(ctx, s, anchors, "init", p.PlanID, p.PlanDigest); e != nil {
		return p.InstallationID, e
	}
	bundleID, e := initIntent(ctx, s, "bundle", p.Paths.EngineRoot, legacyhost.ProvisionProperties{Path: p.Paths.EngineRoot, Digest: p.BundleDigest, ProductCreated: true}, false)
	if e != nil {
		return p.InstallationID, e
	}
	verified, e := publishBundle(ctx, s, source, p.Paths.EngineRoot)
	if e != nil {
		return p.InstallationID, e
	}
	if e = observeBundle(ctx, s, bundleID, p.Paths.EngineRoot, verified); e != nil {
		return p.InstallationID, e
	}
	if d == nil {
		d, e = legacyhost.NewSystemd(ctx, verified)
		if e != nil {
			return p.InstallationID, e
		}
		owner, e = d.RegisterForegroundOwner(ctx, string(p.InstallationID))
		if e != nil {
			return p.InstallationID, e
		}
		if e = lease.BindOwner(ctx, owner); e != nil {
			return p.InstallationID, e
		}
		if e = d.BindStore(s); e != nil {
			return p.InstallationID, e
		}
	}
	recovered, e := d.RecoverHelpers(ctx)
	if e != nil {
		return p.InstallationID, e
	}
	if e = ensureBootEphemeral(ctx, s, m, recovered); e != nil {
		return p.InstallationID, e
	}
	for _, i := range []legacyhost.NumericIdentity{p.Identities.App, p.Identities.Sandbox, p.Identities.Preparer} {
		if e = provisionAccount(ctx, s, d, i); e != nil {
			return p.InstallationID, e
		}
	}
	if e = provisionDevWatchLock(ctx, s, m); e != nil {
		return p.InstallationID, e
	}
	backingRecords, e := s.PendingProvisions(ctx)
	if e != nil {
		return p.InstallationID, e
	}
	for _, record := range backingRecords {
		if record.Kind == "backing" && record.Identity == m.Paths.BackingFile {
			if record.CleanupState == "COMPLETE" {
				return p.InstallationID, errors.New("retired backing cannot be recreated")
			}
			if record.State == "OBSERVED" {
				if e = matchRecord(record); e != nil {
					return p.InstallationID, e
				}
			}
		}
	}
	backing, e := legacyhost.CreateBacking(ctx, m, s, d)
	if e != nil {
		return p.InstallationID, e
	}
	if m.Backing != backing {
		if e = s.SetBacking(ctx, backing); e != nil {
			return p.InstallationID, e
		}
		m.Backing = backing
	}
	if e = legacyhost.AttachBacking(ctx, m, s, d); e != nil {
		return p.InstallationID, e
	}
	cfg, e := runtime.DecodeConfig(p.BaseConfig)
	if e != nil {
		return p.InstallationID, e
	}
	sc := supervisorConfig(m, cfg)
	storage, e := legacyhost.NewStorage(ctx, sc, s, d)
	if e != nil {
		return p.InstallationID, e
	}
	defer storage.Close()
	images, e := legacyhost.NewImageManager(imageConfig(m, verified, owner, inputs), s, d, storage)
	if e != nil {
		return p.InstallationID, e
	}
	defer func() {
		if retErr == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		failure := images.Recover(cleanup)
		quota, qe := storage.ReclaimEvidence(cleanup)
		failure = errors.Join(failure, qe, storage.Close())
		evidence, se := d.SettleHelpers(cleanup)
		failure = errors.Join(failure, se)
		evidence.QuotaReclaimed = quota.QuotaReclaimed
		if failure == nil {
			failure = legacyhost.DetachBacking(cleanup, m, s, d, evidence)
		}
		if failure != nil {
			failure = errors.Join(failure, s.RequireRecovery(cleanup, "initialization cleanup is incomplete"))
		}
		retErr = errors.Join(retErr, failure)
	}()
	revision := legacyhost.RevisionRecord{}
	modules := make([]runtime.ModuleSpec, 0, len(p.Modules))
	bindings := make([]legacyhost.ApprovedImageBinding, 0, len(p.Modules))
	if transaction.Phase == "PREPARED" || (m.PendingRevision != "" && m.PendingRevision != baseRevision.ID) {
		revisionID := m.PendingRevision
		if revisionID == "" {
			revisionID = m.ActiveRevision
		}
		revision, e = s.Revision(ctx, revisionID)
		if e != nil {
			return p.InstallationID, e
		}
		if transaction.Phase == "APPROVED" {
			if e = s.AdvanceManagementPlan(ctx, "init", p.PlanID, p.PlanDigest, "APPROVED", "PREPARED"); e != nil {
				return p.InstallationID, e
			}
		}
	} else {
		for _, in := range p.Modules {
			if in.Image.ModuleID != string(in.Candidate.ModuleID) || in.Image.ConfigRevision != in.Candidate.ConfigRevision || in.Image.ApprovalRevision != in.Candidate.ApprovalRevision {
				return p.InstallationID, errors.New("preparation and candidate binding mismatch")
			}
			image, e := images.PrepareImage(ctx, in.Image)
			if e != nil {
				return p.InstallationID, e
			}
			if image.SourceKind == "registry" {
				in.Candidate.ImageDigest = image.SourceRef
			} else {
				in.Candidate.ImageDigest = "record:" + image.ID
			}
			if e = s.BindPreparedImage(ctx, legacyhost.ApprovedImageBinding{ModuleID: string(in.Candidate.ModuleID), ImageSelector: in.Candidate.ImageDigest, ImageRecordID: image.ID, ConfigRevision: in.Candidate.ConfigRevision, ApprovalRevision: in.Candidate.ApprovalRevision}); e != nil {
				return p.InstallationID, e
			}
			r := ModuleReview{PlanID: p.PlanID, Candidate: in.Candidate, Image: image, HostLimits: reviewLimits(cfg, in.Candidate)}
			r.ReviewDigest, e = ModuleReviewDigest(r)
			if e != nil {
				return p.InstallationID, e
			}
			a, e := approve(ctx, r)
			if e != nil {
				return p.InstallationID, e
			}
			if e = ValidateModuleApproval(r, a); e != nil {
				return p.InstallationID, e
			}
			if e = runtime.ValidatePreparedApproval(cfg, a.Module, image.Declaration); e != nil {
				return p.InstallationID, e
			}
			modules = append(modules, a.Module)
			bindings = append(bindings, legacyhost.ApprovedImageBinding{ModuleID: string(a.Module.ModuleID), ImageSelector: a.Module.ImageDigest, ImageRecordID: image.ID, ConfigRevision: a.Module.ConfigRevision, ApprovalRevision: a.Module.ApprovalRevision})
		}
		config, e := exactConfig(p.BaseConfig, modules)
		if e != nil {
			return p.InstallationID, e
		}
		policies, e := launchPolicies(ctx, s, config, bindings)
		if e != nil {
			return p.InstallationID, e
		}
		if e = validateAppBudget(cfg, p.Budget, policies); e != nil {
			return p.InstallationID, e
		}
		revision = legacyhost.RevisionRecord{ID: newID(), ConfigDigest: provision.Digest(config), BundleDigest: verified.Digest, Config: config, Images: bindings, LaunchPolicies: policies, PublicProfile: profile(cfg)}
		if e = s.SetPendingRevision(ctx, revision); e != nil {
			return p.InstallationID, e
		}
		if e = s.AdvanceManagementPlan(ctx, "init", p.PlanID, p.PlanDigest, "APPROVED", "PREPARED"); e != nil {
			return p.InstallationID, e
		}
	}
	if e = writeNew(ctx, s, "config", p.Paths.Config, revision.Config, 0600); e != nil {
		return p.InstallationID, e
	}
	secretRaw, e := jsonSecrets(p.SecretSources)
	if e != nil {
		return p.InstallationID, e
	}
	if e = writeNew(ctx, s, "secret", p.Paths.Secrets, secretRaw, 0600); e != nil {
		return p.InstallationID, e
	}
	if e = installApprovedLauncher(ctx, s, p); e != nil {
		return p.InstallationID, e
	}
	if e = images.Recover(ctx); e != nil {
		return p.InstallationID, e
	}
	quota, e := storage.ReclaimEvidence(ctx)
	if e != nil {
		return p.InstallationID, e
	}
	if e = storage.Close(); e != nil {
		return p.InstallationID, e
	}
	evidence, e := d.SettleHelpers(ctx)
	if e != nil {
		return p.InstallationID, e
	}
	evidence.QuotaReclaimed = quota.QuotaReclaimed
	if e = legacyhost.DetachBacking(ctx, m, s, d, evidence); e != nil {
		return p.InstallationID, e
	}
	if e = completeEvidence(ctx, m, &evidence); e != nil {
		return p.InstallationID, e
	}
	if m.ActiveRevision != revision.ID {
		if e = s.ActivateRevision(ctx, revision.ID, evidence); e != nil {
			return p.InstallationID, e
		}
	}
	if e = s.CompleteManagementPlan(ctx, "init", p.PlanID, p.PlanDigest, "PREPARED", evidence); e != nil {
		return p.InstallationID, e
	}
	return p.InstallationID, nil
}
func installLauncher(ctx context.Context, s *legacyhost.Store, path string) error {
	self, e := os.Executable()
	if e != nil {
		return e
	}
	raw, e := readProtected(self, 1<<30)
	if e != nil {
		return e
	}
	return writeNew(ctx, s, "config", path, raw, 0755)
}
func profile(c runtime.Config) host.NetworkProfile { return c.Host.Network.Profile }
func supervisorConfig(m legacyhost.InstallationManifest, c runtime.Config) legacyhost.SupervisorConfig {
	return legacyhost.SupervisorConfig{SocketPath: filepath.Join(m.Paths.Control, "runtime.sock"), RuntimeUID: m.Identities.App.UID, RuntimeGID: m.Identities.App.GID, ManagementDirectory: m.Paths.Control, StorageRoot: m.Paths.StorageRoot, IPCRoot: m.Paths.RunRoot, MaxMessageBytes: c.Limits.ControlMessageMaxBytes, OperationTimeout: time.Duration(c.Limits.HostOperationDeadline), ReconcileInterval: time.Second, MaxConnections: 64, RuntimeInstallationID: m.RuntimeInstallationID, App: m.Identities.App, Sandbox: m.Identities.Sandbox, Preparer: m.Identities.Preparer, PublicProfile: profile(c), StartupTimeout: time.Duration(c.Defaults.StartupDeadline)}
}
func backingSize(b legacyhost.StorageBudget) (int64, error) {
	var total int64
	if b.AppBytes <= 0 || b.AppInodes <= 0 || b.AppBytes > b.DataBytes || b.AppInodes > b.DataInodes || b.AppBytes%4096 != 0 {
		return 0, errors.New("invalid app subreservation of data pool")
	}
	for _, n := range []int64{b.DataBytes, b.SourceBytes, b.CacheBytes, b.PreparationBytes, b.MetadataHeadroomBytes} {
		if n <= 0 || n > math.MaxInt64-total {
			return 0, errors.New("finite nonoverflowing storage budget required")
		}
		total += n
	}
	for _, n := range []int64{b.DataInodes, b.SourceInodes, b.CacheInodes, b.PreparationInodes, b.MetadataHeadroomInodes} {
		if n <= 0 {
			return 0, errors.New("finite inode budget required")
		}
	}
	if total%4096 != 0 {
		return 0, errors.New("backing budget must align to 4096 bytes")
	}
	return total, nil
}
func trustedPlannedPath(path string) error {
	if path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("clean absolute approved path required")
	}
	for p := path; ; p = filepath.Dir(p) {
		_, e := os.Lstat(p)
		if e == nil {
			return trustedPath(p, false)
		}
		if !os.IsNotExist(e) {
			return e
		}
		if filepath.Dir(p) == p {
			return e
		}
	}
}
func validateInitScope(p ApprovedInitPlan) error {
	managementObject, e := initManagementAnchorObject(p.ManagementAnchor)
	if e != nil {
		return e
	}
	if e = validateInitManagementPaths(p); e != nil {
		return e
	}
	required := map[string]string{"directory:" + p.Paths.EngineRoot: "create", "directory:" + p.Paths.StorageRoot: "create", "directory:" + p.Paths.RunRoot: "create", "directory:" + filepath.Join(p.Paths.RunRoot, "netns"): "create", "directory:" + filepath.Join(p.Paths.RunRoot, "instances"): "create", "backing:" + p.Paths.BackingFile: "create", "bundle:" + p.Paths.EngineRoot: "create", "config:" + p.Paths.Config: "create", "config:" + p.Paths.Launcher: "create", "secret:" + p.Paths.Secrets: "create"}
	required["config:"+filepath.Join(p.Paths.Installation, "dev-watch.lock")] = "create"
	required[managementObject.Kind+":"+managementObject.Identity] = managementObject.Action
	for _, object := range p.Objects {
		if object.Kind == "config" && object.Identity == p.Paths.Launcher && object.Action == "reuse" {
			required["config:"+p.Paths.Launcher] = "reuse"
		}
	}
	for _, identity := range []legacyhost.NumericIdentity{p.Identities.App, p.Identities.Sandbox, p.Identities.Preparer} {
		if !validAccountName(identity.Name) {
			return errors.New("unsupported static account name")
		}
		action := "reuse"
		if identity.ProductCreated {
			action = "create"
		}
		required["account:"+identity.Name] = action
	}
	for _, object := range p.Objects {
		if object.Action != "create" && object.Action != "reuse" {
			return errors.New("initialization cannot remove or replace existing objects")
		}
		key := object.Kind + ":" + object.Identity
		action, exists := required[key]
		if !exists {
			continue
		}
		if action != object.Action {
			return errors.New("approved object action differs from required mutation")
		}
		if object.Kind == "management-anchor" && object.ObservationDigest != managementObject.ObservationDigest {
			return errors.New("management anchor observation differs from initialization approval")
		}
		if object.Kind == "account" && action == "reuse" {
			for _, identity := range []legacyhost.NumericIdentity{p.Identities.App, p.Identities.Sandbox, p.Identities.Preparer} {
				if identity.Name != object.Identity {
					continue
				}
				if e := validateAccount(identity); e != nil {
					return e
				}
				observation := legacyhost.ObjectObservation{Identity: identity.Name, Attributes: provisionJSON(legacyhost.ProvisionProperties{Name: identity.Name, UID: identity.UID, GID: identity.GID})}
				sum, e := ObjectObservationDigest(observation)
				if e != nil || sum != object.ObservationDigest {
					return errors.New("reused account observation changed")
				}
			}
		}
		if object.Kind == "config" && object.Identity == p.Paths.Launcher && action == "reuse" {
			observation, e := launcherObservation(p.Paths.Launcher)
			if e != nil {
				return e
			}
			sum, e := ObjectObservationDigest(observation)
			if e != nil || sum != object.ObservationDigest {
				return errors.New("preinstalled launcher observation changed")
			}
		}
		delete(required, key)
	}
	if len(required) != 0 {
		return errors.New("init plan omits required object approval")
	}
	for _, path := range []string{p.Paths.Control, p.Paths.EngineRoot, p.Paths.BackingFile, p.Paths.Config, p.Paths.Secrets, p.Paths.Launcher, p.Paths.Installation} {
		if p.Paths.StorageRoot == path || isAncestor(p.Paths.StorageRoot, path) {
			return errors.New("backing mount would shadow protected installation state/code")
		}
	}
	seen := map[string]bool{filepath.Join(p.Paths.Installation, "dev-watch.lock"): true}
	for _, path := range []string{p.Paths.Control, p.Paths.EngineRoot, p.Paths.StorageRoot, p.Paths.RunRoot, p.Paths.BackingFile, p.Paths.Config, p.Paths.Secrets, p.Paths.Launcher} {
		if seen[path] {
			return errors.New("installation object paths must be distinct")
		}
		seen[path] = true
	}
	return nil
}
func validateSecretBindings(c runtime.Config, sources []SecretSource) error {
	if _, e := jsonSecrets(sources); e != nil {
		return e
	}
	bindings := map[string]string{}
	for backend, config := range c.Backends {
		for name, ref := range config.SecretSources {
			bindings[backend+":"+name] = ref
		}
	}
	for _, source := range sources {
		key := source.BackendID + ":" + source.SecretName
		expected := source.SourceKind + ":" + source.SourceReference
		if bindings[key] != expected {
			return errors.New("secret source differs from exact backend configuration")
		}
		delete(bindings, key)
	}
	if len(bindings) != 0 {
		return errors.New("backend secret lacks explicit approved source")
	}
	return nil
}
func reviewLimits(c runtime.Config, s runtime.ModuleSpec) host.ResourceLimits {
	class := "general"
	if s.Approval != nil && s.Approval.ResourceClass == 2 {
		class = "media"
	}
	p := c.ResourceProfiles[class]
	return host.ResourceLimits{NanoCPUs: int64(p.CPUMillicores) * 1e6, MemoryBytes: int64(p.MemoryBytes), Pids: int64(p.MaxPids), PersistentBytes: int64(p.PersistentBytes), ScratchBytes: int64(p.ScratchBytes), PersistentInodes: c.Limits.PersistentInodeLimit, ScratchInodes: c.Limits.ScratchInodeLimit, ControlMessageMaxBytes: int64(c.Limits.ControlMessageMaxBytes), LogBufferBytes: c.Limits.LogBufferBytes, LogFileMaxBytes: c.Limits.LogFileMaxBytes, LogRetainedFiles: c.Limits.LogRetainedFiles}
}
