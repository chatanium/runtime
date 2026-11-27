package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/discordacl"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

func TestDiscordACLApplyThenRevokeWithoutRestart(t *testing.T) {
	ctx := t.Context()
	digest := func(s string) string { return "sha256:" + strings.Repeat(s, 64) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	binding := digest("a")
	dir := filepath.Join(t.TempDir(), "installation")
	must(os.Mkdir(dir, 0o700))
	db, err := store.Create(ctx, dir, store.Installation{
		InstallationIdentity: store.InstallationIdentity{ID: "test-install", Owner: "uid:1", Target: "linux/amd64/systrap",
			BundleDigest: binding, EngineDigest: digest("b")}, PlanDigest: digest("c"), BudgetBytes: 128 << 20,
		MetadataBytes: 4 << 20, LogBytes: 1 << 20,
	})
	must(err)
	defer db.Close()
	offline, err := db.BeginOfflineEpoch(ctx, store.EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "offline1"})
	must(err)
	image, err := db.ReserveImage(ctx, offline.ID, "", digest("d"), 2<<20)
	must(err)
	proof := store.PublishProof{WritersExited: true, Verified: true, ReadOnly: true, Synchronized: true}
	must(db.StageImage(ctx, offline.ID, image.ID, proof))
	must(db.PublishImage(ctx, offline.ID, image.ID, proof))
	module := store.Approval{ModuleID: "hello", ReviewDigest: digest("e"), ImageDigest: image.Digest, ImageGeneration: image.ID,
		DeclarationDigest: digest("f"), ResourceFormat: store.VolumeResourceFormat, UID: 1000, GID: 1000,
		PersistentBytes: store.MinVolumeBytes, ScratchBytes: store.MinVolumeBytes, CPUMillicores: 100,
		MemoryBytes: 6 << 20, MaxPIDs: 16, Network: store.NetworkProfile{Mode: store.NetworkNone}}
	revision := digest("1")
	must(db.Configure(ctx, offline.ID, "", store.Configuration{Revision: revision, ConfigDigest: digest("2"), Approvals: []store.Approval{module}}))
	must(db.Activate(ctx, offline.ID, digest("c"), revision))
	must(db.EndEpoch(ctx, offline.ID))
	epoch, err := db.BeginEpoch(ctx, store.EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "first-run"})
	must(err)
	must(db.StartWorker(ctx, epoch.ID))

	life, cancel := context.WithCancel(ctx)
	defer cancel()
	grant := discordacl.Policy{Scopes: []discordacl.Scope{{GuildID: "123"}}}
	a := aclOwner{db: db, epoch: epoch.ID, revision: revision, life: life, fenceWorker: cancel,
		worker: make(chan workerACLRequest, 2), modules: map[string]aclModule{"hello": {binding: binding,
			status: discordacl.Status{Managed: true}, review: aclReview{token: "approved-grant", status: discordacl.Status{
				Managed: true, Policy: grant, Labels: []string{"Game night"},
			}},
		}}}
	changes := make(chan store.DiscordACLRecord, 2)
	go func() {
		for range 2 {
			select {
			case request := <-a.worker:
				rows, err := db.DiscordACLs(life)
				changes <- rows["hello"]
				request.result <- err
			case <-life.Done():
				return
			}
		}
	}()
	call := func(op string, query discordacl.Query, into any) {
		t.Helper()
		query.Module = "hello"
		data, err := json.Marshal(query)
		must(err)
		reply, err := a.control(ctx, op, data)
		must(err)
		must(json.Unmarshal(reply, into))
	}
	var status discordacl.Status
	call(discordacl.Apply, discordacl.Query{Policy: grant, Approval: "approved-grant"}, &status)
	if saved := <-changes; !saved.Policy.Allows(grant.Scopes[0]) {
		t.Fatalf("worker received grant before ledger stored it: %+v", saved)
	}
	call(discordacl.Show, discordacl.Query{}, &status)
	if !status.Policy.Allows(grant.Scopes[0]) {
		t.Fatalf("second shell did not see the acknowledged grant: %+v", status)
	}
	var plan discordacl.Plan
	call(discordacl.Preview, discordacl.Query{}, &plan)
	if !plan.Before.Policy.Allows(grant.Scopes[0]) || len(plan.After.Policy.Scopes) != 0 {
		t.Fatalf("revocation review does not show the transition: %+v", plan)
	}
	call(discordacl.Apply, discordacl.Query{Approval: plan.Digest}, &status)
	if !status.Managed || len(status.Policy.Scopes) != 0 || len(a.worker) != 0 {
		t.Fatalf("revocation not applied on the same worker: %+v", status)
	}
	select {
	case saved := <-changes:
		if saved.Binding != binding || len(saved.Policy.Scopes) != 0 {
			t.Fatalf("worker received revocation before ledger stored it: %+v", saved)
		}
	default:
		t.Fatal("revocation was acknowledged without sending it to the worker")
	}
}
