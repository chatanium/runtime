package runtime

import "path/filepath"

// These paths are projections of the installed storage root, never additional
// worker-selected mounts or aliases outside the quota-backed data volume.
func (h HostConfig) AppDirectory() string    { return filepath.Join(h.StorageRoot, "app") }
func (h HostConfig) NativeDirectory() string { return filepath.Join(h.AppDirectory(), "native") }
func (h HostConfig) ModuleMountRoots() []string {
	if h.Format == PortableFormat {
		// GVX ext4lite images are opened by the supervisor and no host
		// directories are exposed as module mounts.
		return nil
	}
	return []string{filepath.Join(h.StorageRoot, "persistent"), filepath.Join(h.StorageRoot, "instances")}
}
func (h HostConfig) ValidateDevelopmentSocket(path string) error {
	if !cleanAbsolute(h.StorageRoot) || h.ManagementDirectory != h.AppDirectory() || !cleanAbsolute(path) || filepath.Dir(path) != h.NativeDirectory() {
		return invalidConfig()
	}
	return nil
}
