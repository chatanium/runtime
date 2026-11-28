package host

import (
	"strings"

	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

// ValidateLaunchPolicy checks a reviewed launch policy before an instance ID is assigned.
func ValidateLaunchPolicy(s sharedhost.LaunchSpec) error { return validateLaunchSpec(s, false) }
func validateLaunchSpec(s sharedhost.LaunchSpec, instance bool) error {
	if s.ModuleID == "" || instance && !safeID(s.InstanceID) || !instance && s.InstanceID != "" || s.UID == 0 || s.GID == 0 {
		return invalid("module identity, fresh instance ID and nonroot UID/GID required")
	}
	if err := validateImageDigest(s.ImageDigest); err != nil {
		return err
	}
	if s.InitialEgress != sharedhost.EgressNone && s.InitialEgress != sharedhost.EgressPublicInternet {
		return invalid("initial egress topology must be explicit NONE or PUBLIC")
	}
	if len(s.Entrypoint) == 0 || !strings.HasPrefix(s.Entrypoint[0], "/") {
		return invalid("absolute image entrypoint required")
	}
	for _, args := range [][]string{s.Entrypoint, s.Args} {
		for _, a := range args {
			if strings.IndexByte(a, 0) >= 0 {
				return invalid("process argument contains NUL")
			}
		}
	}
	r := s.Resources
	for _, n := range []int64{r.NanoCPUs, r.MemoryBytes, r.Pids, r.PersistentBytes, r.ScratchBytes, r.PersistentInodes, r.ScratchInodes, r.ControlMessageMaxBytes, r.LogBufferBytes, r.LogFileMaxBytes, int64(r.LogRetainedFiles)} {
		if n <= 0 {
			return invalid("all resource and logging limits must be finite positive")
		}
	}
	if r.PersistentBytes%512 != 0 || r.ScratchBytes%512 != 0 || r.LogBufferBytes < r.ControlMessageMaxBytes {
		return invalid("inconsistent byte limits")
	}
	return nil
}
func safeID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validateImageDigest(s string) error {
	if e := provision.ValidateSelector(s); e != nil {
		return invalid(e.Error())
	}
	return nil
}
