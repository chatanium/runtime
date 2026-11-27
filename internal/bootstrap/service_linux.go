//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/host"
	"os"
	"time"
)

func InstallService(ctx context.Context, id RuntimeInstallationID, enable, now bool) (ServiceResult, error) {
	result := ServiceResult{InstallationID: id, InstallationState: "unknown", EnablementState: "unknown", ActivationState: "unknown"}
	if e := rootRequired(); e != nil {
		return result, e
	}
	if now {
		report, e := Stop(ctx, id)
		if e != nil || !report.Complete {
			return result, errors.Join(e, host.ErrCleanupIncomplete)
		}
	} else {
		response, live, e := contactOwner(ctx, id, managementRequest{Operation: "service", Enable: enable}, nil)
		if live {
			if response.Service == nil {
				return result, errors.Join(e, errors.New("live service result missing"))
			}
			return *response.Service, e
		}
		if e != nil {
			return result, e
		}
	}
	session, e := maintenance(ctx, id)
	if e != nil {
		return result, e
	}
	defer closeMaintenance(session)
	if now {
		if _, lookup := ownedRecord(ctx, session.store, "unit", servicePath(id)); lookup == nil {
			if e = stopOwnedManager(ctx, session); e != nil {
				return result, e
			}
		}
	}
	result, e = session.installService(ctx, enable)
	if e != nil || !now {
		return result, e
	}
	if e = session.store.SetDesired(ctx, "RUNNING", newID()); e != nil {
		return result, e
	}
	result.DesiredRunState = "RUNNING"
	if e = session.lease.Close(); e != nil {
		return result, e
	}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(session.config.Defaults.StartupDeadline))
	defer cancel()
	metadata, e := openMetadata(bounded, id)
	if e != nil {
		return result, e
	}
	if e = metadata.Close(); e != nil {
		return result, e
	}
	if e = session.systemd.StartManager(bounded, serviceName(id)); e != nil {
		return result, e
	}
	for {
		metadata, e := openMetadata(bounded, id)
		if e != nil {
			return result, e
		}
		enabled, active, _, observation := session.systemd.ManagerStateFromMetadata(bounded, serviceName(id), metadata)
		observation = errors.Join(observation, metadata.Close())
		result.EnablementState = enabled
		result.ActivationState = active
		if observation == nil && active == "active" {
			return result, nil
		}
		select {
		case <-bounded.Done():
			return result, errors.Join(observation, bounded.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func (s *ownedSession) installService(ctx context.Context, enable bool) (ServiceResult, error) {
	result := ServiceResult{InstallationID: s.id, DesiredRunState: s.manifest.DesiredRunState, InstallationState: "unknown", EnablementState: "unknown", ActivationState: "unknown"}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return result, errors.New("installation is draining")
	}
	s.preparing.Add(1)
	s.mu.Unlock()
	defer s.preparing.Done()
	current, e := s.store.Installation(ctx)
	if e != nil {
		return result, e
	}
	result.DesiredRunState = current.DesiredRunState
	if current.State != "READY" {
		return result, errors.New("service installation requires READY")
	}
	raw, e := unitText(current)
	if e != nil {
		return result, e
	}
	path := servicePath(s.id)
	if _, e = os.Lstat(path); e == nil {
		record, e := ownedRecord(ctx, s.store, "unit", path)
		if e != nil {
			return result, e
		}
		if e = matchRecord(record); e != nil {
			return result, e
		}
		actual, e := readProtected(path, 64<<10)
		if e != nil {
			return result, e
		}
		if string(actual) != string(raw) {
			return result, errors.New("existing unit differs from approved product unit")
		}
	} else if os.IsNotExist(e) {
		if e = writeNew(ctx, s.store, "unit", path, raw, 0644); e != nil {
			return result, e
		}
	} else {
		return result, e
	}
	result.InstallationState = "present"
	if e = s.systemd.Reload(ctx); e != nil {
		return result, e
	}
	if enable {
		if e = s.systemd.EnableUnit(ctx, serviceName(s.id)); e != nil {
			return result, e
		}
	}
	result.EnablementState, result.ActivationState, _, e = s.systemd.ManagerState(ctx, serviceName(s.id))
	return result, e
}
func stopOwnedManager(ctx context.Context, s *ownedSession) error {
	record, e := ownedRecord(ctx, s.store, "unit", servicePath(s.id))
	if e != nil {
		return e
	}
	if e = matchPurgeRecord(ctx, s.store, record); e != nil {
		return e
	}
	if removedPath(record.Identity) {
		return s.systemd.ManagerAbsent(ctx, serviceName(s.id))
	}
	if e = s.systemd.ManagerAbsent(ctx, serviceName(s.id)); e == nil {
		return nil
	}
	if e = s.systemd.StopManager(ctx, serviceName(s.id)); e != nil {
		return e
	}
	return s.systemd.ManagerAbsent(ctx, serviceName(s.id))
}
func validateServiceDefinition(ctx context.Context, store *host.Store, m host.InstallationManifest) error {
	record, e := ownedRecord(ctx, store, "unit", servicePath(RuntimeInstallationID(m.RuntimeInstallationID)))
	if e != nil {
		return e
	}
	if e = matchRecord(record); e != nil {
		return e
	}
	expected, e := unitText(m)
	if e != nil {
		return e
	}
	actual, e := readProtected(record.Identity, 64<<10)
	if e != nil {
		return e
	}
	if string(expected) != string(actual) {
		return errors.New("service definition differs from fixed product policy")
	}
	return nil
}
