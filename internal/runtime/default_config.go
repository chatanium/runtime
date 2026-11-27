package runtime

import (
	"encoding/json"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/host"
)

// DefaultInstallationConfig proposes finite, visible operator choices only.
// The installation owner supplies observed identity/bundle/paths; no path is
// created, image prepared, grant issued or runtime epoch started here.
func DefaultInstallationConfig(id, bundle string, paths host.InstallationPaths) ([]byte, error) {
	config := DefaultPortableConfig(id, bundle, paths.StorageRoot, filepath.Join(paths.RunRoot, "instances"))
	config.Host.Format = ""
	config.Host.QuotaBackend = "xfs-project"
	config.Limits.PersistentInodeLimit = 64 << 10
	config.Limits.ScratchInodeLimit = 16 << 10
	config.Limits.UploadRecordsPerInstance = 32
	config.Limits.UploadRecordsPerHost = 256
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(struct {
		Config
		Modules []moduleJSON `json:"modules"`
	}{config, []moduleJSON{}}, "", "  ")
}
