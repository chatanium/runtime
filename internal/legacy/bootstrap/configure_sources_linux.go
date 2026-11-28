//go:build linux

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
	"golang.org/x/sys/unix"
)

// SecretSourceObservation binds source references, not secret values. Protected
// file identity and change timestamps are reviewed without reading its contents.
type SecretSourceObservation struct {
	Source    SecretSource `json:"source"`
	Dev       uint64       `json:"dev,omitempty"`
	Ino       uint64       `json:"ino,omitempty"`
	UID       uint32       `json:"uid,omitempty"`
	GID       uint32       `json:"gid,omitempty"`
	Mode      uint32       `json:"mode,omitempty"`
	SizeBytes int64        `json:"size_bytes,omitempty"`
	MTimeNS   int64        `json:"mtime_ns,omitempty"`
	CTimeNS   int64        `json:"ctime_ns,omitempty"`
}

func configuredSecretSources(c runtime.Config) ([]SecretSource, error) {
	sources := make([]SecretSource, 0)
	for backend, config := range c.Backends {
		for name, reference := range config.SecretSources {
			kind, value, ok := strings.Cut(reference, ":")
			if !ok {
				return nil, errors.New("secret source must identify its explicit provider")
			}
			sources = append(sources, SecretSource{BackendID: backend, SecretName: name, SourceKind: kind, SourceReference: value})
		}
	}
	sort.Slice(sources, func(i, j int) bool {
		a, b := sources[i], sources[j]
		if a.BackendID != b.BackendID {
			return a.BackendID < b.BackendID
		}
		return a.SecretName < b.SecretName
	})
	return sources, validateSecretBindings(c, sources)
}

func observeSecretSources(sources []SecretSource) ([]SecretSourceObservation, error) {
	observations := make([]SecretSourceObservation, 0, len(sources))
	if _, e := jsonSecrets(sources); e != nil {
		return nil, e
	}
	for _, source := range sources {
		observation := SecretSourceObservation{Source: source}
		if source.SourceKind == "protected-file" {
			fd, e := unix.Open(source.SourceReference, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
			if e != nil {
				return nil, e
			}
			var st unix.Stat_t
			e = unix.Fstat(fd, &st)
			unix.Close(fd)
			if e != nil {
				return nil, e
			}
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != 0 || st.Nlink != 1 || st.Size < 0 || st.Size > WorkerSecretMaxBytes {
				return nil, errors.New("secret source must be a bounded root-owned 0600 regular file")
			}
			observation.Dev = uint64(st.Dev)
			observation.Ino = st.Ino
			observation.UID = st.Uid
			observation.GID = st.Gid
			observation.Mode = st.Mode & 07777
			observation.SizeBytes = st.Size
			observation.MTimeNS = st.Mtim.Nano()
			observation.CTimeNS = st.Ctim.Nano()
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func secretDescriptorObservation(path string) (legacyhost.ObjectObservation, string, error) {
	raw, e := readProtected(path, WorkerSecretMaxBytes)
	if e != nil {
		return legacyhost.ObjectObservation{}, "", e
	}
	var st unix.Stat_t
	if e = unix.Lstat(path, &st); e != nil {
		return legacyhost.ObjectObservation{}, "", e
	}
	if st.Mode&07777 != 0600 {
		return legacyhost.ObjectObservation{}, "", errors.New("secret descriptor mode changed")
	}
	sum := provision.Digest(raw)
	properties := legacyhost.ProvisionProperties{Path: path, Digest: sum, Dev: uint64(st.Dev), Ino: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, SizeBytes: st.Size}
	return legacyhost.ObjectObservation{Identity: path, Attributes: provisionJSON(properties)}, sum, nil
}

func configureAuthority(ctx context.Context, m legacyhost.InstallationManifest, c runtime.Config) ([]SecretSource, []SecretSourceObservation, []ApprovedObject, error) {
	sources, e := configuredSecretSources(c)
	if e != nil {
		return nil, nil, nil, e
	}
	observations, e := observeSecretSources(sources)
	if e != nil {
		return nil, nil, nil, e
	}
	current, currentDigest, e := secretDescriptorObservation(m.Paths.Secrets)
	if e != nil {
		return nil, nil, nil, e
	}
	currentObservation, e := ObjectObservationDigest(current)
	if e != nil {
		return nil, nil, nil, e
	}
	desired, e := jsonSecrets(sources)
	if e != nil {
		return nil, nil, nil, e
	}
	action := "reuse"
	if currentDigest != provision.Digest(desired) {
		action = "replace"
	}
	objects := []ApprovedObject{{Kind: "secret", Identity: m.Paths.Secrets, Action: action, ObservationDigest: currentObservation}}
	if c.Host.Network.Profile != host.NetworkNone {
		anchors, e := legacyhost.InspectNetworkAnchors(ctx)
		if e != nil {
			return nil, nil, nil, e
		}
		for _, anchor := range anchors {
			object := ApprovedObject{Kind: "shared-network-anchor", Identity: anchor.Path, Action: "create"}
			if anchor.Exists {
				object.Action = "reuse"
				object.ObservationDigest, e = NetworkAnchorObservationDigest(anchor)
				if e != nil {
					return nil, nil, nil, e
				}
			}
			objects = append(objects, object)
		}
	}
	return sources, observations, objects, nil
}

func configureSecretObject(p ApprovedConfigurePlan, path string) (ApprovedObject, error) {
	var secret ApprovedObject
	for _, object := range p.Objects {
		if object.Kind == "shared-network-anchor" {
			if object.Action != "create" && object.Action != "reuse" {
				return secret, errors.New("configure cannot remove shared network infrastructure")
			}
			continue
		}
		if object.Kind != "secret" || object.Identity != path || (object.Action != "reuse" && object.Action != "replace") || secret.Identity != "" {
			return secret, errors.New("configuration scope exceeds observed secret and shared-network objects")
		}
		secret = object
	}
	if secret.Identity == "" {
		return secret, errors.New("configuration omits exact secret descriptor observation")
	}
	return secret, validateObjects(p.Objects, false)
}

func currentSecretRecord(ctx context.Context, s *legacyhost.Store, path string) (legacyhost.ProvisionRecord, error) {
	records, e := s.ObjectProvisions(ctx, "secret", path)
	if e != nil {
		return legacyhost.ProvisionRecord{}, e
	}
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		if record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
			continue
		}
		if e = matchRecord(record); e == nil {
			return record, nil
		}
	}
	return legacyhost.ProvisionRecord{}, errors.New("secret descriptor has no matching live durable observation")
}

func validateSecretSourceObservations(sources []SecretSource, want []SecretSourceObservation) error {
	actual, e := observeSecretSources(sources)
	if e != nil {
		return e
	}
	a, e := json.Marshal(actual)
	if e != nil {
		return e
	}
	b, e := json.Marshal(want)
	if e != nil {
		return e
	}
	if string(a) != string(b) {
		return errors.New("secret source identity changed after approval")
	}
	return nil
}

func initSecretObjects(p *ApprovedInitPlan, c runtime.Config) error {
	sources, e := configuredSecretSources(c)
	if e != nil {
		return e
	}
	observations, e := observeSecretSources(sources)
	if e != nil {
		return e
	}
	p.SecretSources = sources
	seen := map[string]bool{}
	for _, observation := range observations {
		if observation.Source.SourceKind != "protected-file" || seen[observation.Source.SourceReference] {
			continue
		}
		path := observation.Source.SourceReference
		seen[path] = true
		observation.Source = SecretSource{SourceKind: "protected-file", SourceReference: path}
		sum, e := digest("chatanium-secret-source-observation-v1", observation)
		if e != nil {
			return e
		}
		p.Objects = append(p.Objects, ApprovedObject{Kind: "secret", Identity: path, Action: "reuse", ObservationDigest: sum})
	}
	return nil
}

func validateInitSecretObservations(p ApprovedInitPlan) error {
	observations, e := observeSecretSources(p.SecretSources)
	if e != nil {
		return e
	}
	for _, observation := range observations {
		if observation.Source.SourceKind != "protected-file" {
			continue
		}
		path := observation.Source.SourceReference
		observation.Source = SecretSource{SourceKind: "protected-file", SourceReference: path}
		sum, e := digest("chatanium-secret-source-observation-v1", observation)
		if e != nil {
			return e
		}
		found := false
		for _, object := range p.Objects {
			if object.Kind == "secret" && object.Identity == path && object.Action == "reuse" && object.ObservationDigest == sum {
				found = true
				break
			}
		}
		if !found {
			return errors.New("protected secret source lacks exact observed plan approval")
		}
	}
	return nil
}
