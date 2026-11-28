//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"os"
)

func completedRemoval(ctx context.Context, store *host.Store, record host.ProvisionRecord) (bool, error) {
	removal, exists, e := removalFor(ctx, store, record)
	if e != nil {
		return false, e
	}
	return exists && (record.CleanupState == "COMPLETE" || removal.CleanupState == "COMPLETE"), nil
}
func completedObjectAbsent(record host.ProvisionRecord) error {
	var p host.ProvisionProperties
	if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return e
	}
	if record.Kind == "account" {
		return terminalAccountAbsent(terminalAbsenceGuard{Kind: "account", Name: p.Name, UID: p.UID, GID: p.GID, GroupOnly: p.Source == "group"})
	}
	path := record.Identity
	if record.Kind == "bundle" {
		path = p.Path
	}
	if _, e := os.Lstat(path); e == nil {
		return errors.New("completed removal cannot authorize a reappeared path")
	} else if !os.IsNotExist(e) {
		return e
	}
	return trustedPathParent(path)
}
func rejectCompletedReappearance(ctx context.Context, store *host.Store, record host.ProvisionRecord) (bool, error) {
	complete, e := completedRemoval(ctx, store, record)
	if e != nil || !complete {
		return complete, e
	}
	return true, completedObjectAbsent(record)
}
