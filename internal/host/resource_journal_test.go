//go:build linux

package host

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

type cacheExposureFixture struct {
	store      *Store
	space      ImageSpace
	birthID    string
	properties ProvisionProperties
}

// Real SQLite/lease transitions with native-identity journal fixture values;
// no ownership changes, XFS operation or native cache publication is exercised.
func newCacheExposureFixture(t *testing.T, observeBirth bool) cacheExposureFixture {
	t.Helper()
	ctx := context.Background()
	base := newCreateStateFixture(t, EgressNone)
	store := base.journal
	manifest, err := store.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Paths.StorageRoot = filepath.Join(base.directory, "storage")
	manifest.Identities.App.GID = 1003
	manifest.Budget.CacheBytes, manifest.Budget.CacheInodes = 1<<20, 128
	if _, err = store.db.ExecContext(ctx, "UPDATE runtime_installations SET manifest=? WHERE id=?", writerTestJSON(t, manifest), store.productID); err != nil {
		t.Fatal(err)
	}
	job := strings.Repeat("c", 32)
	project, err := store.ReserveStorage(ctx, job+":cache", "cache", 4096, 16)
	if err != nil {
		t.Fatal(err)
	}
	space := ImageSpace{JobID: job, ProvisionID: strings.Repeat("d", 32), Source: filepath.Join(manifest.Paths.StorageRoot, "images", job), Cache: filepath.Join(manifest.Paths.StorageRoot, "prepared", job), Work: filepath.Join(manifest.Paths.StorageRoot, "preparation", job), SourceProject: 71, CacheProject: project, WorkProject: 73}
	spaceProperties := ProvisionProperties{Name: "image-space", ImageSpace: &space, ProductCreated: true}
	if err = store.BeginProvision(ctx, ProvisionIntent{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + job, ProductCreated: true, Desired: writerTestJSON(t, spaceProperties)}); err != nil {
		t.Fatal(err)
	}
	if err = store.ObserveProvision(ctx, space.ProvisionID, ObjectObservation{Identity: "image-space:" + job, Attributes: writerTestJSON(t, spaceProperties)}); err != nil {
		t.Fatal(err)
	}
	birthID := strings.Repeat("e", 32)
	birth := ProvisionProperties{Path: space.Cache, Parent: filepath.Dir(space.Cache), Mode: 0700, ProductCreated: true}
	if err = store.BeginProvision(ctx, ProvisionIntent{ID: birthID, Kind: "directory", Identity: space.Cache, ProductCreated: true, Desired: writerTestJSON(t, birth)}); err != nil {
		t.Fatal(err)
	}
	birth.Dev, birth.Ino = 19, 131
	if observeBirth {
		if err = store.ObserveProvision(ctx, birthID, ObjectObservation{Identity: space.Cache, Attributes: writerTestJSON(t, birth)}); err != nil {
			t.Fatal(err)
		}
	}
	properties := ProvisionProperties{Name: imageCacheExposureName, Path: space.Cache, Parent: filepath.Dir(space.Cache), Source: space.ProvisionID, Dev: birth.Dev, Ino: birth.Ino, UID: 0, GID: manifest.Identities.App.GID, Mode: 0710, ProductCreated: true}
	return cacheExposureFixture{store: store, space: space, birthID: birthID, properties: properties}
}

func TestImageCacheExposureProvisionBindsPrivateBirth(t *testing.T) {
	f := newCacheExposureFixture(t, true)
	ctx := context.Background()
	id := newID()
	if err := f.store.BeginProvision(ctx, ProvisionIntent{ID: id, Kind: "directory", Identity: f.space.Cache, ProductCreated: true, Desired: writerTestJSON(t, f.properties)}); err != nil {
		t.Fatalf("real cache publication shape rejected before native exposure: %v", err)
	}
	changed := f.properties
	changed.Ino++
	if err := f.store.ObserveProvision(ctx, id, ObjectObservation{Identity: f.space.Cache, Attributes: writerTestJSON(t, changed)}); err == nil {
		t.Fatal("cache exposure replaced the inode pinned before native effects")
	}
	dropped := f.properties
	dropped.Name, dropped.Source = "", ""
	if err := f.store.ObserveProvision(ctx, id, ObjectObservation{Identity: f.space.Cache, Attributes: writerTestJSON(t, dropped)}); err == nil {
		t.Fatal("cache exposure discarded its scoped publication binding")
	}
	if err := f.store.ObserveProvision(ctx, id, ObjectObservation{Identity: f.space.Cache, Attributes: writerTestJSON(t, f.properties)}); err != nil {
		t.Fatalf("exact synchronized exposure observation rejected: %v", err)
	}
	record, err := f.store.Provision(ctx, id)
	if err != nil || record.State != "OBSERVED" {
		t.Fatalf("cache publication was not journaled: %+v %v", record, err)
	}
	if err = f.store.ObserveProvision(ctx, f.birthID, ObjectObservation{Identity: f.space.Cache, Attributes: writerTestJSON(t, f.properties)}); err == nil {
		t.Fatal("ordinary private directory birth was reinterpreted as cache exposure")
	}
	// Replay may run after C has durably marked the same space committed.
	committed := f.space
	committed.Committed = true
	spaceProperties := ProvisionProperties{Name: "image-space", ImageSpace: &committed, ProductCreated: true}
	if err = f.store.ObserveProvision(ctx, f.space.ProvisionID, ObjectObservation{Identity: "image-space:" + f.space.JobID, Attributes: writerTestJSON(t, spaceProperties)}); err != nil {
		t.Fatal(err)
	}
	if err = f.store.ObserveProvision(ctx, id, ObjectObservation{Identity: f.space.Cache, Attributes: writerTestJSON(t, f.properties)}); err != nil {
		t.Fatalf("exact committed-space exposure replay rejected: %v", err)
	}
}

func TestImageCacheExposureRejectsUnboundPublicationShape(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ProvisionProperties)
	}{
		{"arbitrary directory name", func(p *ProvisionProperties) { p.Name = "other-directory-purpose" }},
		{"ordinary directory source", func(p *ProvisionProperties) { p.Name = "" }},
		{"unknown source", func(p *ProvisionProperties) { p.Source = strings.Repeat("f", 32) }},
		{"foreign path", func(p *ProvisionProperties) { p.Path = filepath.Join(p.Parent, strings.Repeat("f", 32)) }},
		{"wrong parent", func(p *ProvisionProperties) { p.Parent = filepath.Dir(p.Parent) }},
		{"wrong runtime group", func(p *ProvisionProperties) { p.GID++ }},
		{"nonroot owner", func(p *ProvisionProperties) { p.UID = 1001 }},
		{"wrong mode", func(p *ProvisionProperties) { p.Mode = 0755 }},
		{"wrong native device", func(p *ProvisionProperties) { p.Dev++ }},
		{"wrong native inode", func(p *ProvisionProperties) { p.Ino++ }},
		{"not product created", func(p *ProvisionProperties) { p.ProductCreated = false }},
		{"readonly piggyback", func(p *ProvisionProperties) { p.ReadOnly = true }},
		{"volume piggyback", func(p *ProvisionProperties) {
			p.Volume = &BackingIdentity{Dev: 19, Ino: 7, XFSUUID: "fixture", SizeBytes: 4096}
		}},
		{"remove piggyback", func(p *ProvisionProperties) { p.Source = "remove"; p.Revision = "remove-id" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newCacheExposureFixture(t, true)
			properties := f.properties
			test.change(&properties)
			if err := f.store.BeginProvision(context.Background(), ProvisionIntent{ID: newID(), Kind: "directory", Identity: properties.Path, ProductCreated: true, Desired: writerTestJSON(t, properties)}); err == nil {
				t.Fatal("unbound special directory shape gained publication authority")
			}
		})
	}
	t.Run("unobserved private birth", func(t *testing.T) {
		f := newCacheExposureFixture(t, false)
		if err := f.store.BeginProvision(context.Background(), ProvisionIntent{ID: newID(), Kind: "directory", Identity: f.space.Cache, ProductCreated: true, Desired: writerTestJSON(t, f.properties)}); err == nil {
			t.Fatal("unobserved cache directory became exposed")
		}
	})
	t.Run("retiring cache claim", func(t *testing.T) {
		f := newCacheExposureFixture(t, true)
		ctx := context.Background()
		if err := f.store.CheckStorageRelease(ctx, f.space.JobID+":cache"); err != nil {
			t.Fatal(err)
		}
		if err := f.store.BeginProvision(ctx, ProvisionIntent{ID: newID(), Kind: "directory", Identity: f.space.Cache, ProductCreated: true, Desired: writerTestJSON(t, f.properties)}); err == nil {
			t.Fatal("retiring cache project gained exposure authority")
		}
	})
	t.Run("outer image is not C image space", func(t *testing.T) {
		f := newCacheExposureFixture(t, true)
		ctx := context.Background()
		outerID := newID()
		properties := ProvisionProperties{ImageSpace: &f.space, ProductCreated: true}
		if err := f.store.BeginProvision(ctx, ProvisionIntent{ID: outerID, Kind: "image", Identity: f.space.JobID, ProductCreated: true, Desired: writerTestJSON(t, properties)}); err != nil {
			t.Fatal(err)
		}
		exposure := f.properties
		exposure.Source = outerID
		if err := f.store.BeginProvision(ctx, ProvisionIntent{ID: newID(), Kind: "directory", Identity: f.space.Cache, ProductCreated: true, Desired: writerTestJSON(t, exposure)}); err == nil {
			t.Fatal("outer acquisition row was treated as storage image-space origin")
		}
	})
}
