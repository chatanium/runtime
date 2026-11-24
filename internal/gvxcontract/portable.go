package gvxcontract

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	portableRootDigestDomain = "chatanium-root-init-portable-v2"
	portableImageGroupBytes  = 16 << 20
	portableImageMaxBytes    = 64 << 40
	portableGuestMaxPIDs     = 4 << 20 // pinned GVX root cgroup2 bound
)

func (l PortableRootLimits) valid() bool {
	return l.MaxPIDs > 0 && l.MaxPIDs <= portableGuestMaxPIDs &&
		validPortableImageBytes(l.PersistentBytes) && validPortableImageBytes(l.ScratchBytes) && l.ShmBytes >= 0
}

func validPortableImageBytes(n int64) bool {
	return n >= portableImageGroupBytes && n <= portableImageMaxBytes && n%portableImageGroupBytes == 0
}

func validPortableIdentity(uid, gid uint32) bool {
	return uid != 0 && gid != 0 && uid != ^uint32(0) && gid != ^uint32(0)
}

func validPortableBinding(b RootBinding) bool {
	for _, id := range [...]string{b.RuntimeInstallationID, b.EpochID, b.InstanceID, b.IntentID, b.Nonce} {
		if id == "" || !utf8.ValidString(id) || strings.IndexByte(id, 0) >= 0 {
			return false
		}
	}
	return true
}

func validPortableRoot(r RootInitEntry, target RootAttrs) bool {
	if !validPortableIdentity(target.UID, target.GID) || r.Target != target {
		return false
	}
	switch r.RootID {
	case "persistent":
		return r.Disposition == RootDispositionRetained || r.Pre == (RootAttrs{Mode: 0755})
	case "scratch", "tmp":
		return r.Disposition == RootDispositionNew && r.Pre == (RootAttrs{Mode: 0700})
	default:
		return false
	}
}

// NewPortableRootManifest constructs the digest-bound portable-v2 INIT manifest.
// Set persistentNew only for a supervisor-authorized new volume. Scratch and
// tmp are created anew on the same scratch volume in every instance.
func NewPortableRootManifest(binding RootBinding, limits PortableRootLimits, uid, gid uint32, persistentNew bool) (RootInitManifest, error) {
	if !validPortableBinding(binding) || !limits.valid() || !validPortableIdentity(uid, gid) {
		return RootInitManifest{}, errors.New("invalid portable root binding, limits or identity")
	}
	target := RootAttrs{UID: uid, GID: gid, Mode: 0700}
	persistent := RootInitEntry{RootID: "persistent", Mountpoint: PortablePersistentPath, Disposition: RootDispositionRetained, Pre: target, Target: target}
	if persistentNew {
		persistent.Disposition = RootDispositionNew
		persistent.Pre = RootAttrs{Mode: 0755}
	}
	payload := RootInitPayload{
		Version:               PortableRootPayloadVersion,
		RuntimeInstallationID: binding.RuntimeInstallationID,
		EpochID:               binding.EpochID,
		InstanceID:            binding.InstanceID,
		IntentID:              binding.IntentID,
		Nonce:                 binding.Nonce,
		Roots: []RootInitEntry{
			persistent,
			{RootID: "scratch", Mountpoint: PortableScratchPath, Disposition: RootDispositionNew, Pre: RootAttrs{Mode: 0700}, Target: target},
			{RootID: "tmp", Mountpoint: PortableTmpPath, Disposition: RootDispositionNew, Pre: RootAttrs{Mode: 0700}, Target: target},
		},
		PortableLimits: &limits,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return RootInitManifest{}, err
	}
	return RootInitManifest{Digest: rootDigest(portableRootDigestDomain, raw), Payload: raw}, nil
}
