//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
	"golang.org/x/sys/unix"
)

// PlanUpdate proposes a release from this externally verified launcher's embedded
// Source. It neither installs the source nor changes the installed run intent.
func PlanUpdate(ctx context.Context, id RuntimeInstallationID) (ApprovedUpdatePlan, error) {
	var a ApprovedUpdatePlan
	s, e := openMetadata(ctx, id)
	if e != nil {
		return a, e
	}
	defer s.Close()
	m, e := s.Installation(ctx)
	if e != nil {
		return a, e
	}
	source, e := configuredSource()
	if e != nil {
		return a, e
	}
	raw, e := source.Manifest()
	if e != nil {
		return a, e
	}
	manifest, e := bundle.VerifyManifest(raw)
	if e != nil {
		return a, e
	}
	plans, e := s.ManagementPlans(ctx, "update")
	if e != nil {
		return a, e
	}
	for _, plan := range plans {
		if plan.Phase == "COMMITTED" {
			continue
		}
		if e = gvxcontract.DecodeStrict(plan.Plan, 32<<20, 32, &a); e != nil {
			return a, e
		}
		if a.CandidateBundleDigest != manifest.Digest {
			return a, errors.New("unfinished update requires its original externally verified launcher")
		}
		return a, nil
	}
	if m.ActiveRevision == "" || m.PendingRevision != "" || m.State != "READY" || !compatibleBundle(manifest, m) {
		return a, errors.New("update planning requires a compatible installed release without pending recovery")
	}
	previous, e := s.Revision(ctx, m.ActiveRevision)
	if e != nil {
		return a, e
	}
	if previous.DevelopmentWorker != nil {
		return a, errors.New("development revision is not a release update base")
	}
	installedConfig, e := readProtected(m.Paths.Config, 16<<20)
	if e != nil {
		return a, e
	}
	if provision.Digest(installedConfig) != previous.ConfigDigest {
		return a, errors.New("installed configuration differs from active approval")
	}
	config, e := runtime.DecodeConfig(previous.Config)
	if e != nil {
		return a, e
	}
	references, replacements, e := selectUpdateReacquisitions(ctx, s, id, previous, manifest.Digest, nil)
	if e != nil {
		return a, e
	}
	candidate := previous
	candidate.ID = newID()
	candidate.BundleDigest = manifest.Digest
	candidate.Images = applyReacquiredBindings(previous.Images, replacements)
	candidate.Config, e = reacquiredUpdateConfig(previous.Config, manifest.Digest, replacements)
	if e != nil {
		return a, e
	}
	candidate.ConfigDigest = provision.Digest(candidate.Config)
	candidate.LaunchPolicies, e = launchPolicies(ctx, s, candidate.Config, candidate.Images)
	if e != nil {
		return a, e
	}
	a = ApprovedUpdatePlan{InstallationID: id, PlanID: newID(), ExpectedActiveRevision: m.ActiveRevision, CandidateBundleDigest: manifest.Digest, BackupID: newID(), CandidateRevision: candidate, ReacquiredPreparations: references}
	if !validID(a.PlanID) || !validID(a.BackupID) || !validID(candidate.ID) {
		return a, errors.New("entropy unavailable")
	}
	base := filepath.Join(m.Paths.Installation, "backup-"+a.BackupID)
	for _, item := range []struct{ kind, path string }{{"config", base + ".json"}, {"config", base + ".sqlite"}, {"backing", base + ".xfs"}} {
		if _, e = os.Lstat(item.path); !os.IsNotExist(e) {
			return a, errors.Join(e, errors.New("proposed backup destination is not absent"))
		}
		a.Objects = append(a.Objects, ApprovedObject{Kind: item.kind, Identity: item.path, Action: "create"})
	}
	for _, path := range []string{m.Paths.Config, m.Paths.Launcher} {
		r, e := updateFileRecord(ctx, s, path)
		if e != nil {
			return a, e
		}
		sum, e := ObjectObservationDigest(r.Observed)
		if e != nil {
			return a, e
		}
		a.Objects = append(a.Objects, ApprovedObject{Kind: "config", Identity: path, Action: "replace", ObservationDigest: sum})
	}
	if manifest.Digest != m.BundleDigest {
		path := filepath.Join(m.Paths.EngineRoot, strings.TrimPrefix(manifest.Digest, "sha256:"))
		action := "create"
		records, e := s.ObjectProvisions(ctx, "bundle", path)
		if e != nil {
			return a, e
		}
		if len(records) != 0 {
			for _, r := range records {
				if r.State != "OBSERVED" || r.CleanupState == "COMPLETE" || !r.ProductCreated || r.ExistedBefore {
					return a, errors.New("candidate bundle has incomplete or retired ownership")
				}
				if e = matchRecord(r); e != nil {
					return a, e
				}
			}
			if _, e = bundle.VerifyDirectory(ctx, path, manifest); e != nil {
				return a, e
			}
			action = "reuse"
		} else if _, e = os.Lstat(path); !os.IsNotExist(e) {
			return a, errors.Join(e, errors.New("candidate bundle path has no live ownership"))
		}
		a.Objects = append(a.Objects, ApprovedObject{Kind: "bundle", Identity: path, Action: action})
	}
	if config.Host.Network.Profile != host.NetworkNone {
		anchors, e := host.InspectNetworkAnchors(ctx)
		if e != nil {
			return a, e
		}
		for _, anchor := range anchors {
			if !anchor.Exists {
				return a, errors.New("installed PUBLIC network anchor is missing")
			}
			sum, e := NetworkAnchorObservationDigest(anchor)
			if e != nil {
				return a, e
			}
			a.Objects = append(a.Objects, ApprovedObject{Kind: "shared-network-anchor", Identity: anchor.Path, Action: "reuse", ObservationDigest: sum})
		}
	}
	a.PlanDigest, e = UpdatePlanDigest(a)
	return a, e
}

// updateFileRecord includes an explicitly observed preinstalled launcher, but
// never a retired historical receipt or an unobserved pathname.
func updateFileRecord(ctx context.Context, s interface {
	PendingProvisions(context.Context) ([]host.ProvisionRecord, error)
}, path string) (host.ProvisionRecord, error) {
	records, e := s.PendingProvisions(ctx)
	if e != nil {
		return host.ProvisionRecord{}, e
	}
	for _, r := range records {
		if r.Kind == "config" && r.Identity == path && r.State == "OBSERVED" && r.CleanupState != "COMPLETE" && matchRecord(r) == nil {
			return r, nil
		}
	}
	return host.ProvisionRecord{}, errors.New("update file has no matching live observation")
}

type updateTransactionState struct {
	Config         host.ProvisionRecord `json:"config"`
	Launcher       host.ProvisionRecord `json:"launcher"`
	LauncherDigest string               `json:"launcher_digest"`
}

func advanceUpdate(ctx context.Context, s *host.Store, r *host.ManagementPlanRecord, phase string) error {
	phases := map[string]int{"APPROVED": 0, "BACKED_UP": 1, "PUBLISHED": 2, "CACHES_READY": 3, "PENDING": 4, "CONFIG_REPLACED": 5, "LAUNCHER_REPLACED": 6, "ACTIVATED": 7}
	if r.Phase == "COMMITTED" {
		return nil
	}
	current, ok := phases[r.Phase]
	next, valid := phases[phase]
	if !ok || !valid {
		return errors.New("unknown update transaction phase")
	}
	if current >= next {
		return nil
	}
	if next != current+1 {
		return errors.New("update phase boundary skipped")
	}
	if e := s.AdvanceManagementPlan(ctx, "update", r.ID, r.Digest, r.Phase, phase); e != nil {
		return e
	}
	r.Phase = phase
	return nil
}

func updateStagePath(path, planID string) string {
	return filepath.Join(filepath.Dir(path), ".chatanium-update-"+strings.TrimPrefix(provision.DomainDigest("chatanium-update-stage-v1", []byte(planID+"\x00"+path)), "sha256:"))
}

func updateStageAt(r host.ProvisionRecord, path string) error {
	r.Identity = path
	return matchRecord(r)
}

func verifyUpdateReplacement(ctx context.Context, s *host.Store, previous host.ProvisionRecord, raw []byte, planID string) error {
	records, e := s.ObjectProvisions(ctx, "config", previous.Identity)
	if e != nil {
		return e
	}
	for _, r := range records {
		var p host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(r.Desired, 64<<10, 16, &p); e != nil {
			return e
		}
		if p.Source != updateStagePath(previous.Identity, planID) || p.Revision != previous.ID || p.Digest != provision.Digest(raw) {
			continue
		}
		if r.CleanupState == "COMPLETE" {
			return errors.New("replacement has been retired")
		}
		if r.State == "OBSERVED" {
			return matchRecord(r)
		}
		stages, e := s.ObjectProvisions(ctx, "config", p.Source)
		if e != nil {
			return e
		}
		for _, stage := range stages {
			if stage.State == "OBSERVED" && stage.CleanupState != "COMPLETE" && updateStageAt(stage, previous.Identity) == nil {
				return nil
			}
		}
	}
	return errors.New("approved replacement has no matching physical receipt")
}

func validateUpdateFiles(ctx context.Context, s *ownedSession, a ApprovedUpdatePlan, state updateTransactionState, launcher []byte) error {
	for _, item := range []struct {
		old host.ProvisionRecord
		raw []byte
	}{{state.Config, a.CandidateRevision.Config}, {state.Launcher, launcher}} {
		approved := false
		sum, e := ObjectObservationDigest(item.old.Observed)
		if e != nil {
			return e
		}
		for _, o := range a.Objects {
			if o.Kind == "config" && o.Identity == item.old.Identity && o.Action == "replace" && o.ObservationDigest == sum {
				approved = true
			}
		}
		if !approved {
			return errors.New("update journal original observation differs from approval")
		}
		if matchRecord(item.old) == nil {
			continue
		}
		if e = verifyUpdateReplacement(ctx, s.store, item.old, item.raw, a.PlanID); e != nil {
			return e
		}
	}
	if state.Config.Identity != s.manifest.Paths.Config || state.Launcher.Identity != s.manifest.Paths.Launcher {
		return errors.New("update journal paths differ from installation")
	}
	return nil
}

// Complete or resume only the byte-exact prefix of this intent's protected file.
// Completed observations bind both the kernel identity and full content hash.
func updateStagedFile(ctx context.Context, s *host.Store, path string, raw []byte, mode uint32) (host.ProvisionRecord, error) {
	p := host.ProvisionProperties{Path: path, Digest: provision.Digest(raw), Mode: mode, ProductCreated: true}
	r, e := backupRecord(ctx, s, "config", path, p)
	if e != nil || r.State == "OBSERVED" {
		return r, e
	}
	if e = trustedPath(path, true); e != nil {
		return r, e
	}
	fd, e := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if e != nil {
		return r, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return r, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&07777&^mode != 0 || st.Size < 0 || st.Size > int64(len(raw)) {
		return r, errors.New("partial update file identity changed")
	}
	prefix := make([]byte, min(st.Size, 256<<10))
	var offset int64
	for offset < st.Size {
		if e = ctx.Err(); e != nil {
			return r, e
		}
		n := min(int64(len(prefix)), st.Size-offset)
		if _, e = io.ReadFull(f, prefix[:n]); e != nil {
			return r, e
		}
		if !bytes.Equal(prefix[:n], raw[offset:offset+n]) {
			return r, errors.New("partial update file differs from approved bytes")
		}
		offset += n
	}
	if e = ctx.Err(); e != nil {
		return r, e
	}
	if e = unix.Fchmod(fd, mode); e != nil {
		return r, e
	}
	if n, writeErr := f.Write(raw[offset:]); writeErr != nil {
		return r, writeErr
	} else if n != len(raw)-int(offset) {
		return r, io.ErrShortWrite
	}
	if e = f.Sync(); e != nil {
		return r, e
	}
	if e = f.Close(); e != nil {
		return r, e
	}
	if e = syncDirectory(filepath.Dir(path)); e != nil {
		return r, e
	}
	if e = observePath(ctx, s, r.ID, path, p); e != nil {
		return r, e
	}
	return s.Provision(ctx, r.ID)
}

func completeUpdateStage(ctx context.Context, s *host.Store, path string, proof host.CleanupEvidence) error {
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return errors.Join(e, errors.New("consumed update stage unexpectedly exists"))
	}
	records, e := s.ObjectProvisions(ctx, "config", path)
	if e != nil {
		return e
	}
	for _, r := range records {
		if r.CleanupState != "COMPLETE" {
			if r.State != "OBSERVED" {
				return errors.New("consumed stage lacks durable identity")
			}
			if e = s.CompleteProvisionCleanup(ctx, r.ID, proof); e != nil {
				return e
			}
		}
	}
	return nil
}
