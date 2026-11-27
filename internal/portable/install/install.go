package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/releasepayload"
	"github.com/thirdscam/chatanium/internal/runtime"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var generationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Manifest is the owner-reviewed projection of the exact installation paths,
// bundle, and runtime.Config document. SQLite binds it to the active revision.
type Manifest struct {
	ID               string                  `json:"installation_id"`
	Format           string                  `json:"format"`
	State            string                  `json:"state"`
	CodeDir          string                  `json:"code_directory"`
	PlanDigest       string                  `json:"plan_digest"`
	ConfigPlanDigest string                  `json:"config_plan_digest,omitempty"`
	Revision         string                  `json:"configuration_revision,omitempty"`
	Owner            string                  `json:"owner"`
	IPCFallback      string                  `json:"ipc_fallback_parent"`
	BudgetBytes      int64                   `json:"budget_bytes"`
	MetadataBytes    int64                   `json:"metadata_bytes"`
	LogBytes         int64                   `json:"log_bytes"`
	Bundle           bundle.PortableManifest `json:"bundle"`
	Config           json.RawMessage         `json:"config"`
	Modules          []Module                `json:"modules"`
}

// Module couples immutable image provenance with the exact approved launch and
// grants. ReviewJSON is encoded as bytes, not a re-serialized JSON object.
type Module struct {
	ID              string            `json:"module_id"`
	Generation      images.Generation `json:"generation"`
	Approval        store.Approval    `json:"approval"`
	AcquisitionJSON []byte            `json:"acquisition_json"`
	ReviewJSON      []byte            `json:"review_json"`
}

type Installation struct {
	Path      string
	Root      *os.Root
	Manifest  Manifest
	OwnerLock *process.OwnerLock
}

func (i *Installation) Close() error {
	var err error
	if i.Root != nil {
		err = i.Root.Close()
		i.Root = nil
	}
	if i.OwnerLock != nil {
		err = errors.Join(err, i.OwnerLock.Close())
		i.OwnerLock = nil
	}
	return err
}

func hashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	// Match json.Marshal's treatment of nested RawMessage, including HTML
	// escapes, so the authorizing digest survives manifest serialization.
	return json.Marshal(raw)
}

func documentDigest(raw json.RawMessage) (string, error) {
	compact, err := canonicalJSON(raw)
	if err != nil {
		return "", err
	}
	return hashBytes(compact), nil
}

func codeDirectory(digest string) string { return "code-" + strings.TrimPrefix(digest, "sha256:") }

func identity(m Manifest) store.InstallationIdentity {
	return store.InstallationIdentity{ID: m.ID, Owner: m.Owner, Target: m.Bundle.Target.OS + "/" + m.Bundle.Target.Arch + "/" + m.Bundle.Target.Backend, BundleDigest: m.Bundle.Digest, EngineDigest: m.Bundle.Engine.ExecutableDigest}
}

// A nonempty expectedID binds a secondary manifest to the active installation.
func decodeManifest(root *os.Root, name, expectedID string) (Manifest, error) {
	raw, err := readDocument(root, name)
	if err != nil {
		return Manifest{}, err
	}
	var envelope struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(raw, &envelope) == nil && envelope.Format != Format {
		return Manifest{}, ErrLegacy
	}
	var m Manifest
	if err := gvxcontract.DecodeStrict(raw, maxDocument, 128, &m); err != nil {
		return Manifest{}, fmt.Errorf("invalid portable installation manifest: %w", err)
	}
	if !generationPattern.MatchString(m.ID) || expectedID != "" && m.ID != expectedID || m.Format != Format || !digestPattern.MatchString(m.PlanDigest) || !digestPattern.MatchString(m.Bundle.Digest) || m.Bundle.Format != Format || m.CodeDir != codeDirectory(m.Bundle.Digest) || m.Modules == nil {
		return Manifest{}, errors.New("invalid portable installation identity")
	}
	owner, err := process.OwnerIdentity()
	if err != nil || m.Owner != owner {
		return Manifest{}, errors.New("portable installation belongs to another native owner")
	}
	fallback, err := ipcpath.FallbackBase()
	if err != nil {
		return Manifest{}, err
	}
	if m.IPCFallback == "" || m.IPCFallback != fallback {
		return Manifest{}, errors.New("APPROVAL_MISMATCH: native IPC fallback path differs from the installation plan")
	}
	// A staging or backup marker still describes the final runtime paths.
	path, err := Directory()
	if err != nil {
		return Manifest{}, err
	}
	if err := verifyStoredReviews(m, path); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func openInstallation(parent *os.Root, path string) (*Installation, error) {
	root, err := privateChild(parent, filepath.Base(path), false)
	if err != nil {
		return nil, err
	}
	m, err := decodeManifest(root, manifestName, "")
	if err != nil {
		root.Close()
		return nil, err
	}
	return &Installation{Path: path, Root: root, Manifest: m}, nil
}

// InstalledManifest returns nil only when the singleton has not been published.
// An existing directory without its manifest is damaged, not a fresh install.
func InstalledManifest(path string) (*Manifest, error) {
	parent, err := anchor(path, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := requireNoPurgeReceipt(parent, path); err != nil {
		return nil, err
	}
	root, err := privateChild(parent, filepath.Base(path), false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	m, err := decodeManifest(root, manifestName, "")
	if err != nil {
		return nil, fmt.Errorf("cannot open existing installation at %s: %w", path, err)
	}
	return &m, nil
}

func requireNoPurgeReceipt(parent *os.Root, path string) error {
	name := purgeTerminalName(path)
	for _, leaf := range [...]string{name, ".writing-" + name} {
		if _, err := parent.Lstat(leaf); err == nil {
			return fmt.Errorf("%w: finish the pending purge before setup", store.ErrCleanupPending)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Open reads the durable typed manifest without taking the foreground writer
// lock. Stop uses it while the authenticated owner is already running.
func Open(path string) (*Installation, error) {
	parent, err := anchor(path, false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return openInstallation(parent, path)
}

// Lock holds the native writer lock for a foreground run or offline operation.
// Guardian children can keep OwnerLock held after unexpected supervisor exit.
func Lock(path string) (*Installation, error) {
	return lockPath(path, nil)
}

func lockPath(path string, check func(*Manifest) error) (*Installation, error) {
	parent, err := anchor(path, false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	gate, err := process.Lock(filepath.Join(parent.Name(), anchorLock))
	if err != nil {
		return nil, err
	}
	defer gate.Close()
	return lockInstallationChecked(parent, path, check)
}

func lockInstallation(parent *os.Root, path string) (*Installation, error) {
	return lockInstallationChecked(parent, path, nil)
}

func lockInstallationChecked(parent *os.Root, path string, check func(*Manifest) error) (*Installation, error) {
	i, err := openInstallation(parent, path)
	if err != nil {
		return nil, err
	}
	i.OwnerLock, err = process.Lock(filepath.Join(path, ownerLock))
	if err == nil && check != nil {
		err = check(&i.Manifest)
	}
	if err == nil {
		err = i.reconcile(context.Background())
	}
	if err != nil {
		return nil, errors.Join(err, i.Close())
	}
	return i, nil
}

func (i *Installation) Store(ctx context.Context) (*store.Store, error) {
	return i.openStore(ctx, i.Manifest)
}

func (i *Installation) openStore(ctx context.Context, m Manifest) (*store.Store, error) {
	info, err := i.Root.Lstat(store.DatabaseName)
	if err != nil {
		return nil, err
	}
	if !ownedFile(info) || !safeEntry(info) {
		return nil, errors.New("portable ledger is not an owned regular file")
	}
	return store.Open(ctx, i.Path, identity(m))
}

// VerifyBundle reopens the exact immutable, target-bound code directory and
// verifies all bytes against this executable's pinned bundle source.
func (i *Installation) VerifyBundle(ctx context.Context) error {
	root, err := openChild(i.Root, i.Manifest.CodeDir)
	if err != nil {
		return err
	}
	defer root.Close()
	verified, err := releasepayload.VerifyPortable(ctx, root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(verified, i.Manifest.Bundle) {
		return store.ErrApprovalMismatch
	}
	return nil
}

func (i *Installation) beginEpoch(ctx context.Context, db *store.Store) (string, error) {
	if i.OwnerLock == nil {
		return "", errors.New("portable operation needs the offline writer lock")
	}
	boot, err := process.BootIdentity()
	if err != nil {
		return "", err
	}
	self, err := process.SelfIdentity()
	if err != nil {
		return "", err
	}
	epoch, err := db.BeginOfflineEpoch(ctx, store.EpochIdentity{BootID: boot, PID: os.Getpid(), StartIdentity: self})
	return epoch.ID, err
}

func writeManifest(root *os.Root, name string, m Manifest) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(raw) > maxDocument {
		return errors.New("installation manifest exceeds its bound")
	}
	return writeNew(root, name, raw)
}

func (i *Installation) commitManifest(m Manifest) error {
	if err := replaceFile(i.Root, pendingName, manifestName); err != nil {
		return err
	}
	i.Manifest = m
	return nil
}

// reconcile completes or rolls back a manifest publication interrupted between
// SQLite's commit and the atomic manifest rename. Only an already-persisted
// matching SQLite identity/config digest can select the new manifest.
func (i *Installation) reconcile(ctx context.Context) (resultErr error) {
	next, err := decodeManifest(i.Root, pendingName, i.Manifest.ID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	db, err := i.openStore(ctx, next)
	if errors.Is(err, store.ErrIdentity) {
		db, err = i.Store(ctx)
	}
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, db.Close()) }()
	record, err := db.Installation(ctx)
	if err != nil {
		return err
	}
	digest, err := documentDigest(next.Config)
	if err != nil {
		return err
	}
	if next.Revision == "" {
		digest = ""
	}
	if record.BundleDigest == next.Bundle.Digest && record.EngineDigest == next.Bundle.Engine.ExecutableDigest && record.PlanDigest == next.PlanDigest && record.ConfigRevision == next.Revision && record.ConfigDigest == digest {
		if record.State == store.Initializing && next.State == store.Ready && next.Revision != "" {
			// Configure committed before Activate. The approved revision, plan
			// and bytes are durable, so complete the interrupted activation.
			epoch, err := i.beginEpoch(ctx, db)
			if err != nil {
				return err
			}
			defer finishEpoch(ctx, db, epoch, &resultErr)
			if err := db.Activate(ctx, epoch, next.PlanDigest, next.Revision); err != nil {
				return err
			}
			record.State = store.Ready
		}
		if record.State == next.State {
			return i.commitManifest(next)
		}
	}
	return errors.Join(i.Root.Remove(pendingName), syncDirectory(i.Root))
}

// Secrets reads only explicit owner-only files named in the approved config;
// nothing is read from the ambient environment. Worker receives this map over
// the private native control channel, not the module IPC.
func (i *Installation) Secrets() (map[string]string, error) {
	cfg, err := runtime.DecodeConfig(i.Manifest.Config)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for backendID, backend := range cfg.Backends {
		for secretName, source := range backend.SecretSources {
			path, ok := strings.CutPrefix(source, "file:")
			if !ok || !filepath.IsAbs(path) {
				return nil, errors.New("portable backend secret must be an explicit file:/absolute/path source")
			}
			file, err := OpenInput(path, true)
			if err != nil {
				return nil, errors.New("cannot open approved backend secret as an owner-only file")
			}
			data, readErr := readBounded(file)
			if err := errors.Join(readErr, file.Close()); err != nil {
				return nil, errors.New("cannot read approved backend secret")
			}
			if len(data) == 0 || len(data) > 64<<10 {
				return nil, errors.New("approved backend secret file has invalid size")
			}
			result[backendID+":"+secretName] = string(data)
		}
	}
	return result, nil
}
