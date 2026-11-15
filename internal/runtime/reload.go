package runtime

import (
	"context"
	"strings"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

// Gates live for the manager's lifetime, bounded by the installed ID set.
// The manager mutex protects the map, reload marker and last committed image,
// not slow lifecycle work. Only the ordinary RUNNING transition commits images.
// Never wait for a gate while holding manager/instance locks. Where both locks
// are needed, the order is manager -> instance; cleanup retains its own instance.
type moduleLifecycle struct {
	gate                 chan struct{}
	reloading            bool
	committedImageDigest string
}

func (m *Manager) acquireLifecycle(ctx context.Context, id ModuleID, reload bool) (*moduleLifecycle, error) {
	if ctx == nil {
		return nil, invalidConfig()
	}
	if ctx.Err() != nil {
		return nil, contextError(ctx)
	}
	m.mu.Lock()
	if _, installed := m.installed[id]; !installed {
		m.mu.Unlock()
		return nil, ErrModuleNotInstalled
	}
	// Existing package fixtures construct managers directly.
	if m.lifecycles == nil {
		m.lifecycles = make(map[ModuleID]*moduleLifecycle)
	}
	lifecycle := m.lifecycles[id]
	if lifecycle == nil {
		lifecycle = &moduleLifecycle{gate: make(chan struct{}, 1)}
		lifecycle.gate <- struct{}{}
		m.lifecycles[id] = lifecycle
	}
	if reload && lifecycle.reloading {
		m.mu.Unlock()
		return nil, ErrReloadInProgress
	}
	if reload {
		lifecycle.reloading = true
	}
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		if reload {
			m.mu.Lock()
			lifecycle.reloading = false
			m.mu.Unlock()
		}
		return nil, contextError(ctx)
	case <-lifecycle.gate:
		if ctx.Err() != nil {
			m.releaseLifecycle(lifecycle, reload)
			return nil, contextError(ctx)
		}
		return lifecycle, nil
	}
}

func (m *Manager) releaseLifecycle(lifecycle *moduleLifecycle, reload bool) {
	if reload {
		m.mu.Lock()
		lifecycle.reloading = false
		m.mu.Unlock()
	}
	lifecycle.gate <- struct{}{}
}

// ModuleSnapshot atomically observes the current instance and reload marker.
// Unlike Instance.Snapshot it does not copy grants or expose private errors.
func (m *Manager) ModuleSnapshot(id ModuleID) (ModuleSnapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.moduleSnapshotLocked(id)
}

func (m *Manager) moduleSnapshotLocked(id ModuleID) (ModuleSnapshot, bool) {
	i := m.instances[id]
	if i == nil {
		return ModuleSnapshot{}, false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	snapshot := ModuleSnapshot{Principal: i.principal, ImageDigest: i.spec.ImageDigest, State: i.state, CleanupComplete: i.cleanupComplete}
	if lifecycle := m.lifecycles[id]; lifecycle != nil {
		snapshot.Reloading = lifecycle.reloading
		snapshot.CommittedImageDigest = lifecycle.committedImageDigest
	}
	return snapshot, true
}

// DevelopmentReload replaces only an installed instance's immutable image. It
// uses the ordinary host, cleanup and launch paths; no rollback is attempted.
// Errors are deliberately finite and omit untrusted host/configuration text.
func (m *Manager) DevelopmentReload(ctx context.Context, id ModuleID, expected InstanceID, image string) (snapshot ModuleSnapshot, err error) {
	if !m.options.DevelopmentMode {
		return snapshot, ErrDevelopmentDisabled
	}
	lifecycle, err := m.acquireLifecycle(ctx, id, true)
	if err != nil {
		return snapshot, err
	}
	defer func() {
		// Clear the marker and capture the settled instance together, before a
		// waiting Launch/Stop can acquire the gate and change that observation.
		m.mu.Lock()
		lifecycle.reloading = false
		snapshot, _ = m.moduleSnapshotLocked(id)
		m.mu.Unlock()
		lifecycle.gate <- struct{}{}
	}()
	m.mu.Lock()
	old := m.instances[id]
	if old == nil {
		m.mu.Unlock()
		return snapshot, ErrModuleInstanceNotFound
	}
	old.mu.Lock()
	if expected == "" || old.principal.InstanceID != expected {
		old.mu.Unlock()
		m.mu.Unlock()
		return snapshot, ErrStaleInstance
	}
	if !imagePattern.MatchString(image) {
		old.mu.Unlock()
		m.mu.Unlock()
		return snapshot, ErrInvalidReloadImage
	}
	repository, _, _ := strings.Cut(image, "@")
	currentRepository, _, _ := strings.Cut(old.spec.ImageDigest, "@")
	if repository != currentRepository {
		old.mu.Unlock()
		m.mu.Unlock()
		return snapshot, ErrImageRepositoryChanged
	}
	spec := cloneSpec(old.spec)
	old.mu.Unlock()
	m.mu.Unlock()
	spec.ImageDigest = image
	preflight, cancel := context.WithTimeout(ctx, time.Duration(m.config.Defaults.StartupDeadline))
	err = m.preflightReload(preflight, spec)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return snapshot, contextError(ctx)
		}
		return snapshot, ErrReloadPreflight
	}
	if ctx.Err() != nil {
		return snapshot, contextError(ctx)
	}
	if err = m.stop(ctx, id); err != nil {
		if ctx.Err() != nil {
			return snapshot, contextError(ctx)
		}
		return snapshot, ErrReloadCleanup
	}
	old.mu.Lock()
	clean := old.cleanupComplete && old.cleanupError == nil
	old.mu.Unlock()
	if !clean {
		return snapshot, ErrReloadCleanup
	}
	if ctx.Err() != nil {
		return snapshot, contextError(ctx)
	}
	if _, err = m.launch(ctx, spec); err != nil {
		if ctx.Err() != nil {
			return snapshot, contextError(ctx)
		}
		return snapshot, ErrReloadLaunch
	}
	return snapshot, nil
}

// This side-effect-free declaration check catches knowably invalid candidates
// before stopping a healthy instance. Launch repeats it and verifies the live
// manifest, actual backend grants and host resources after positive cleanup.
func (m *Manager) preflightReload(ctx context.Context, spec ModuleSpec) error {
	if err := m.config.validateSpec(spec); err != nil {
		return err
	}
	declaration, err := m.options.Host.ImageManifest(ctx, spec.ImageDigest)
	if err != nil {
		return err
	}
	manifest, err := m.parseImageManifest(declaration)
	if err != nil {
		return err
	}
	if _, err := negotiateCore(manifest, spec.Approval); err != nil {
		return err
	}
	for _, requirement := range manifest.BackendRequirements {
		backend, ok := m.backends[requirement.BackendId]
		approved := backendGrant(spec.Approval, requirement.BackendId)
		if !ok || requirement.ProtocolMajor != backend.Major || approved == nil || approved.ProtocolMajor != backend.Major {
			if requirement.Required || len(requirement.RequiredCapabilities) != 0 {
				return ErrReloadPreflight
			}
			continue
		}
		capabilities, err := negotiateCapabilities(requirement.RequiredCapabilities, requirement.OptionalCapabilities, approved.Capabilities, backend.supports)
		if err != nil {
			return err
		}
		if err := backend.validateGrant(&wire.BackendGrant{BackendId: backend.ID, ProtocolMajor: backend.Major, Capabilities: capabilities}); err != nil {
			return err
		}
	}
	return nil
}
