package install

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/runtime"
)

func TestModuleFreeConfigurationAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime")
	m := Manifest{ID: "fixture", State: store.Initializing, BudgetBytes: DefaultBudgetBytes, Bundle: bundle.PortableManifest{Digest: hashBytes([]byte("bundle"))}}
	var err error
	m.Config, err = defaultConfig(m.ID, m.Bundle.Digest, path)
	if err != nil {
		t.Fatal(err)
	}
	i := Installation{Path: path, Manifest: m}
	if _, err := i.verifyCandidateConfig(Candidate{Format: Format, Config: m.Config}); err != nil {
		t.Fatalf("default candidate rejected: %v", err)
	}

	for name, change := range map[string]func(*testing.T, *runtime.Config){
		"custom limit": func(_ *testing.T, cfg *runtime.Config) { cfg.Limits.ControlRPCsPerInstance++ },
		"backend and secret source": func(t *testing.T, cfg *runtime.Config) {
			body, err := json.Marshal(map[string]string{"ownership_directory": filepath.Join(path, "app", "discord")})
			if err != nil {
				t.Fatal(err)
			}
			cfg.Backends["discord"] = runtime.BackendConfig{Major: 2, Config: body, SecretSources: map[string]string{"bot_token": "file:" + filepath.Join(path, "secret")}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := runtime.DefaultPortableConfig(m.ID, m.Bundle.Digest, path, filepath.Join(path, "ipc"))
			change(t, &cfg)
			raw, err := runtime.EncodePortableConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := i.verifyCandidateConfig(Candidate{Format: Format, Config: raw}); !errors.Is(err, store.ErrApprovalMismatch) {
				t.Fatalf("nondefault empty candidate: %v, want approval mismatch", err)
			}
			forged := m
			forged.Config, forged.State = raw, store.Ready
			bindEmptyRevision(t, path, &forged)
			if err := verifyStoredReviews(forged, path); !errors.Is(err, store.ErrApprovalMismatch) {
				t.Fatalf("nondefault empty manifest with matching digests: %v, want approval mismatch", err)
			}
		})
	}

	i.Manifest.State = store.Ready
	i.Manifest.Modules = []Module{{ID: "keep"}}
	if _, err := i.verifyCandidateConfig(Candidate{Format: Format, Config: m.Config}); !errors.Is(err, store.ErrState) {
		t.Fatalf("module-free downgrade: %v, want state rejection", err)
	}

	m.State = store.Ready
	if err := verifyStoredReviews(m, path); !errors.Is(err, store.ErrApprovalMismatch) {
		t.Fatalf("unsigned module-free READY: %v, want approval mismatch", err)
	}
	bindEmptyRevision(t, path, &m)
	if err := verifyStoredReviews(m, path); err != nil {
		t.Fatalf("reviewed module-free READY: %v", err)
	}
	m.State = store.Uninstalled
	if err := verifyStoredReviews(m, path); err != nil {
		t.Fatalf("retained module-free review: %v", err)
	}
	m.ConfigPlanDigest = hashBytes([]byte("another plan"))
	if err := verifyStoredReviews(m, path); !errors.Is(err, store.ErrApprovalMismatch) {
		t.Fatalf("forged confirmation plan: %v, want approval mismatch", err)
	}
}

func bindEmptyRevision(t *testing.T, path string, m *Manifest) {
	t.Helper()
	configuration, plan, err := planConfiguration(path, *m, hashBytes(m.Config), []store.Approval{})
	if err != nil {
		t.Fatal(err)
	}
	m.Revision, m.ConfigPlanDigest = configuration.Revision, plan.PlanDigest
}
