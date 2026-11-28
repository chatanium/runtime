package bootstrap

import (
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"path/filepath"
	"strings"
)

func isAncestor(parent, path string) bool {
	return filepath.IsAbs(parent) && filepath.Clean(parent) == parent && parent != path && strings.HasPrefix(path, parent+"/")
}
func insideStorage(record host.ProvisionRecord, m host.InstallationManifest) bool {
	if record.Kind == "directory" {
		if isAncestor(m.Paths.StorageRoot, record.Identity) {
			return true
		}
		if record.Identity != m.Paths.StorageRoot || record.State != "OBSERVED" {
			return false
		}
		var p host.ProvisionProperties
		if gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p) != nil {
			return false
		}
		return p.Path == m.Paths.StorageRoot && p.Dev != 0 && p.Ino != 0 && p.Volume != nil && *p.Volume == m.Backing && m.Backing.Dev != 0 && m.Backing.Ino != 0 && m.Backing.XFSUUID != ""
	}
	if record.Kind != "image" && record.Kind != "development-worker" {
		return false
	}
	raw := record.Observed.Attributes
	if record.State != "OBSERVED" {
		raw = record.Desired
	}
	var p host.ProvisionProperties
	if gvxcontract.DecodeStrict(raw, 64<<10, 16, &p) != nil {
		return false
	}
	if p.ImageSpace == nil {
		return false
	}
	for _, path := range []string{p.ImageSpace.Source, p.ImageSpace.Cache, p.ImageSpace.Work} {
		if path != "" && !isAncestor(m.Paths.StorageRoot, path) {
			return false
		}
	}
	return true
}
