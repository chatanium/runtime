//go:build linux

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/runtime"
	"os"
	"path/filepath"
	"strings"
)

func sharedNetworkObject(kind, path string) bool {
	return kind == "management-anchor" || kind == "shared-network-anchor" || path == "/var/lib/chatanium" || path == legacyhost.NetworkIPAMRoot || path == filepath.Join(legacyhost.NetworkIPAMRoot, "lock")
}
func NetworkAnchorObservationDigest(object legacyhost.NetworkAnchorObject) (string, error) {
	return digest("chatanium-network-anchor-review-v1", object)
}
func reviewNetworkAnchors(ctx context.Context, paths host.InstallationPaths, objects []ApprovedObject, config runtime.Config, kind, planID, planDigest string) ([]legacyhost.NetworkAnchorObject, error) {
	for _, root := range []string{paths.Installation, paths.Control, paths.EngineRoot, paths.StorageRoot, paths.BackingFile, paths.RunRoot, paths.Config, paths.Secrets, paths.Launcher} {
		if root == "/var/lib/chatanium" || root == legacyhost.NetworkIPAMRoot || isAncestor(root, legacyhost.NetworkIPAMRoot) || isAncestor(legacyhost.NetworkIPAMRoot, root) {
			return nil, errors.New("installation root overlaps shared host-wide network infrastructure")
		}
	}
	if config.Host.Network.Profile == host.NetworkNone {
		for _, object := range objects {
			if object.Kind == "shared-network-anchor" {
				return nil, errors.New("NONE profile cannot provision network infrastructure")
			}
		}
		return nil, nil
	}
	anchors, e := legacyhost.InspectNetworkAnchors(ctx)
	if e != nil {
		return nil, e
	}
	for index, anchor := range anchors {
		var approved *ApprovedObject
		for i := range objects {
			if objects[i].Kind == "shared-network-anchor" && objects[i].Identity == anchor.Path {
				approved = &objects[i]
				break
			}
		}
		if approved == nil {
			return nil, errors.New("shared network anchor approval is required")
		}
		if approved.Action == "create" && anchor.Exists {
			original, e := replayCreatedAnchor(ctx, paths, config.Host.RuntimeInstallationID, kind, planID, planDigest, anchor)
			if e != nil {
				return nil, e
			}
			anchors[index] = original
			continue
		}
		action := "create"
		if anchor.Exists {
			action = "reuse"
		}
		if approved.Action != action {
			return nil, errors.New("shared network anchor changed since approval")
		}
		if anchor.Exists {
			sum, e := NetworkAnchorObservationDigest(anchor)
			if e != nil || sum != approved.ObservationDigest {
				return nil, errors.New("shared network anchor identity differs from approval")
			}
		}
	}
	return anchors, nil
}
func provisionNetworkAnchors(ctx context.Context, s *legacyhost.Store, anchors []legacyhost.NetworkAnchorObject, kind, planID, planDigest string) error {
	if len(anchors) == 0 {
		return nil
	}
	plan, e := s.ManagementPlan(ctx, kind, planID)
	if e != nil || plan.Digest != planDigest {
		return errors.New("network anchors require their exact durable approved transaction")
	}
	for _, original := range anchors {
		intent, e := networkAnchorIntentID(planDigest, original.Path)
		if e != nil {
			return e
		}
		properties := original.Properties
		properties.ProductCreated = !original.Exists
		record, e := s.Provision(ctx, intent)
		if e == nil {
			if record.Kind != "shared-network-anchor" || record.Identity != original.Path || record.ExistedBefore != original.Exists || record.CleanupState == "COMPLETE" {
				return errors.New("shared anchor replay identity changed")
			}
			var wanted legacyhost.ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &wanted); e != nil {
				return e
			}
			if string(provisionJSON(wanted)) != string(provisionJSON(properties)) {
				return errors.New("shared anchor original approval properties changed")
			}
			if record.State == "OBSERVED" {
				current, e := currentNetworkAnchor(ctx, original.Path)
				if e != nil {
					return e
				}
				if e = matchAnchorObservation(record, current); e != nil {
					return e
				}
				continue
			}
		} else if errors.Is(e, sql.ErrNoRows) {
			if e = s.BeginProvision(ctx, legacyhost.ProvisionIntent{ID: intent, Kind: "shared-network-anchor", Identity: original.Path, ExistedBefore: original.Exists, ProductCreated: !original.Exists, Desired: provisionJSON(properties)}); e != nil {
				return e
			}
		} else {
			return e
		}
		expected := original
		current, e := currentNetworkAnchor(ctx, original.Path)
		if e != nil {
			return e
		}
		if !original.Exists && current.Exists {
			if original.Path != "/var/lib/chatanium" || kind != "init" {
				return errors.New("unobserved shared anchor appeared; it cannot be adopted")
			}
			parent, e := ownedRecord(ctx, s, "directory", original.Path)
			if e != nil {
				return e
			}
			if e = matchRecord(parent); e != nil {
				return e
			}
			expected = current
		} else if original.Exists {
			before, e := NetworkAnchorObservationDigest(original)
			if e != nil {
				return e
			}
			now, e := NetworkAnchorObservationDigest(current)
			if e != nil || before != now {
				return errors.New("shared anchor changed before reuse")
			}
		}
		observation, e := legacyhost.ProvisionNetworkAnchor(ctx, expected)
		if e != nil {
			return e
		}
		var actual legacyhost.ProvisionProperties
		if e = gvxcontract.DecodeStrict(observation.Attributes, 64<<10, 16, &actual); e != nil {
			return e
		}
		actual.ProductCreated = !original.Exists
		observation.Attributes = provisionJSON(actual)
		if e = s.ObserveProvision(ctx, intent, observation); e != nil {
			return e
		}
	}
	return nil
}
func networkAnchorIntentID(planDigest, path string) (string, error) {
	sum, e := digest("chatanium-network-anchor-step-v1", struct{ Plan, Path string }{planDigest, path})
	return "anchor-" + strings.TrimPrefix(sum, "sha256:"), e
}
func currentNetworkAnchor(ctx context.Context, path string) (legacyhost.NetworkAnchorObject, error) {
	anchors, e := legacyhost.InspectNetworkAnchors(ctx)
	if e != nil {
		return legacyhost.NetworkAnchorObject{}, e
	}
	for _, anchor := range anchors {
		if anchor.Path == path {
			return anchor, nil
		}
	}
	return legacyhost.NetworkAnchorObject{}, os.ErrNotExist
}
func matchAnchorObservation(record legacyhost.ProvisionRecord, current legacyhost.NetworkAnchorObject) error {
	if !current.Exists {
		return errors.New("observed shared anchor disappeared")
	}
	var observed legacyhost.ProvisionProperties
	if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); e != nil {
		return e
	}
	actual := current.Properties
	observed.ProductCreated = false
	actual.ProductCreated = false
	if string(provisionJSON(observed)) != string(provisionJSON(actual)) {
		return errors.New("shared anchor native observation changed")
	}
	return nil
}
func replayCreatedAnchor(ctx context.Context, paths host.InstallationPaths, installation, kind, planID, planDigest string, anchor legacyhost.NetworkAnchorObject) (legacyhost.NetworkAnchorObject, error) {
	if e := rootRequired(); e != nil {
		return anchor, e
	}
	control, e := controlPath(RuntimeInstallationID(installation))
	if e != nil {
		return anchor, e
	}
	if paths.Control != control {
		return anchor, errors.New("shared anchor replay differs from fixed installation locator")
	}
	reader, e := openMetadata(ctx, RuntimeInstallationID(installation))
	if e != nil {
		return anchor, errors.New("created shared anchor has no matching transaction observation")
	}
	defer reader.Close()
	plan, e := reader.ManagementPlan(ctx, kind, planID)
	if e != nil || plan.Digest != planDigest {
		return anchor, errors.New("shared anchor transaction approval changed")
	}
	id, e := networkAnchorIntentID(planDigest, anchor.Path)
	if e != nil {
		return anchor, e
	}
	record, e := reader.Provision(ctx, id)
	if (errors.Is(e, sql.ErrNoRows) || e == nil && record.State == "INTENT") && kind == "init" && anchor.Path == "/var/lib/chatanium" {
		parents, lookup := reader.ObjectProvisions(ctx, "directory", anchor.Path)
		if lookup != nil {
			return anchor, lookup
		}
		for _, parent := range parents {
			if parent.State == "OBSERVED" && parent.CleanupState != "COMPLETE" && parent.ProductCreated && !parent.ExistedBefore && matchRecord(parent) == nil {
				if e == nil {
					var original legacyhost.ProvisionProperties
					if decode := gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &original); decode != nil {
						return anchor, decode
					}
					anchor.Properties = original
				}
				anchor.Exists = false
				return anchor, nil
			}
		}
	}
	if e != nil || record.Kind != "shared-network-anchor" || record.Identity != anchor.Path || record.State != "OBSERVED" || record.ExistedBefore || !record.ProductCreated || record.CleanupState == "COMPLETE" {
		return anchor, errors.New("shared anchor creation lacks an exact same-transaction observed receipt")
	}
	if e = matchAnchorObservation(record, anchor); e != nil {
		return anchor, e
	}
	var original legacyhost.ProvisionProperties
	if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &original); e != nil {
		return anchor, e
	}
	return legacyhost.NetworkAnchorObject{Path: anchor.Path, Exists: false, Properties: original}, nil
}
