//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

func routeNotificationError(data []byte, flags int) error {
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(data) == 0 {
		return errors.New("route monitor notification truncated or empty")
	}
	for len(data) > 0 {
		if len(data) < unix.NLMSG_HDRLEN {
			return errors.New("route monitor header truncated")
		}
		length := int(binary.NativeEndian.Uint32(data[:4]))
		if length < unix.NLMSG_HDRLEN || length > len(data) {
			return errors.New("route monitor length invalid")
		}
		kind := binary.NativeEndian.Uint16(data[4:6])
		if kind == unix.NLMSG_ERROR || kind == unix.NLMSG_OVERRUN {
			return errors.New("route monitor notification loss")
		}
		if length == len(data) {
			return nil
		}
		aligned := (length + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if aligned > len(data) {
			return errors.New("route monitor padding truncated")
		}
		data = data[aligned:]
	}
	return nil
}
func (n *Network) drainNotifications() error {
	var buffer [65536]byte
	for _, fd := range []int{n.routeFD, n.firewallFD} {
		if fd < 0 {
			continue
		}
		drained := false
		for range 256 {
			size, _, flags, _, err := unix.Recvmsg(fd, buffer[:], nil, unix.MSG_DONTWAIT)
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				drained = true
				break
			}
			if err != nil {
				return err
			}
			if err = routeNotificationError(buffer[:size], flags); err != nil {
				return err
			}
		}
		if !drained {
			return errors.New("network monitor burst exceeds bound")
		}
	}
	return nil
}
func (n *Network) Close() error {
	n.mu.Lock()
	cancel, started, done := n.monitorCancel, n.monitorStarted, n.monitorDone
	if !started {
		for _, fd := range []int{n.routeFD, n.firewallFD} {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
		n.routeFD = -1
		n.firewallFD = -1
		err := n.namespacePinsPending()
		n.mu.Unlock()
		return err
	}
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	timer := time.NewTimer(n.cfg.OperationTimeout + time.Second)
	defer timer.Stop()
	select {
	case <-done:
		n.mu.Lock()
		err := errors.Join(n.monitorErr, n.namespacePinsPending())
		n.mu.Unlock()
		return err
	case <-timer.C:
		return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("network monitor has not joined"))
	}
}
func (n *Network) namespacePinsPending() error {
	for _, a := range n.owned {
		if a.namespacePin != nil {
			return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("owned network namespace pin is retained until terminal reconciliation"))
		}
	}
	return nil
}
func (n *Network) Monitor(ctx context.Context, onFailure func(sharedhost.Ownership, error)) error {
	if n.reconciliationOnly {
		return invalid("reconciliation-only network has no admission monitor")
	}
	n.mu.Lock()
	if n.monitorStarted || n.routeFD < 0 {
		n.mu.Unlock()
		return errors.New("network monitor already running or unavailable")
	}
	ctx, cancel := context.WithCancel(ctx)
	n.monitorCancel = cancel
	n.monitorStarted = true
	n.monitorReady = true
	close(n.ready)
	n.mu.Unlock()
	defer func() {
		cancel()
		n.mu.Lock()
		n.monitorReady = false
		for _, fd := range []int{n.routeFD, n.firewallFD} {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
		n.routeFD = -1
		n.firewallFD = -1
		close(n.monitorDone)
		n.mu.Unlock()
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var buffers [2][65536]byte
	for {
		select {
		case <-ctx.Done():
			cleanup, cancel := context.WithTimeout(context.Background(), n.cfg.OperationTimeout)
			n.mu.Lock()
			err := n.closeAll(cleanup)
			if err != nil {
				n.monitorErr = errors.Join(n.monitorErr, err)
			}
			n.mu.Unlock()
			cancel()
			return errors.Join(ctx.Err(), err)
		default:
		}
		fds := []unix.PollFd{{Fd: int32(n.routeFD), Events: unix.POLLIN}, {Fd: int32(n.firewallFD), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		n.mu.Lock()
		var events [2][]byte
		for index, poll := range fds {
			if poll.Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				err = errors.New("network monitor lost authority")
			}
			if poll.Revents&unix.POLLIN == 0 {
				continue
			}
			size, _, flags, _, receiveErr := unix.Recvmsg(int(poll.Fd), buffers[index][:], nil, unix.MSG_DONTWAIT)
			if errors.Is(receiveErr, unix.EAGAIN) {
				continue
			}
			if receiveErr != nil {
				err = receiveErr
				continue
			}
			if receiveErr = routeNotificationError(buffers[index][:size], flags); receiveErr != nil {
				err = receiveErr
				continue
			}
			events[index] = buffers[index][:size]
		}
		check := false
		select {
		case <-ticker.C:
			check = true
		default:
		}
		var failures []struct {
			o   sharedhost.Ownership
			err error
		}
		for _, a := range n.owned {
			if a.Record.State != "OPEN" {
				continue
			}
			cause := err
			if cause == nil && (n.notificationRelevant(events[0], a, false) || n.notificationRelevant(events[1], a, true)) {
				cause = errors.New("network authority changed; revocation precedes revalidation")
			}
			if cause == nil && check {
				cause = n.verify(ctx, a, true)
			}
			if cause != nil {
				cleanup, cancel := context.WithTimeout(context.Background(), n.cfg.OperationTimeout)
				closeErr := n.close(cleanup, a)
				if closeErr != nil {
					n.monitorErr = errors.Join(n.monitorErr, closeErr)
				}
				cancel()
				failures = append(failures, struct {
					o   sharedhost.Ownership
					err error
				}{a.Owner, errors.Join(cause, closeErr)})
			}
		}
		if err != nil {
			n.monitorErr = err
		}
		n.mu.Unlock()
		for _, failure := range failures {
			if onFailure != nil {
				onFailure(failure.o, failure.err)
			}
		}
		if err != nil {
			return err
		}
	}
}

func (n *Network) Reconcile(ctx context.Context, o sharedhost.Ownership) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	a, err := n.allocation(o)
	if err != nil {
		r, lookupErr := n.store.Network(ctx, o)
		if lookupErr != nil {
			return n.requireNoNetworkIntent(ctx, o)
		}
		a = &networkAllocation{Owner: o, BootID: r.BootID, Record: r, Rules: map[string]string{}, Topology: map[string]string{}, Flows: map[string]string{}}
		n.owned[o.InstanceID] = a
	}
	if a.Record.NetnsPath != filepath.Join(n.cfg.RunRoot, "netns", "ct-"+networkToken(n.product, a.Record.Generation)) {
		return prerequisite(errors.New("network namespace cleanup path differs from installed owned run root"))
	}
	if a.Record.Profile != sharedhost.NetworkNone {
		lock, e := networkLock(ctx)
		if e != nil {
			return e
		}
		defer networkUnlock(lock)
	}
	if a.Record.State == "CLEANED" {
		return n.save(ctx, a)
	}
	if n.reconciliationOnly {
		present, inspectErr := networkOptionalNamespaceDirectory(n.cfg.RunRoot)
		if inspectErr != nil {
			return inspectErr
		}
		if !present {
			boot, bootErr := networkBootID()
			if bootErr != nil {
				return bootErr
			}
			if a.Record.BootID == "" || a.Record.BootID == boot {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("same-boot missing network root has no absence proof"))
			}
		}
	}
	if o.Unit.Name != "" {
		a.Owner.Unit = o.Unit
	}
	observation, unitErr := n.store.Unit(ctx, a.Owner)
	if unitErr == nil {
		boot, bootErr := networkBootID()
		if bootErr != nil {
			return bootErr
		}
		if a.Owner.Unit.Name != "" && a.Owner.Unit != observation.Unit {
			return errors.New("network cleanup unit identity differs from durable observation")
		}
		a.Owner.Unit = observation.Unit
		var evidence CleanupEvidence
		var evidenceErr error
		if observation.Exit != nil {
			evidence, evidenceErr = n.systemd.Settle(ctx, observation.Unit)
		} else {
			service, found, e := n.store.LookupCreate(ctx, a.Owner, CreateService)
			if e != nil {
				return e
			}
			if !found || service.State != CreateObserved {
				return ErrCreateUnresolved
			}
			// An absent native outcome remains UNKNOWN. Only the root's separately
			// durable, exact-invocation physical absence proof can authorize cleanup.
			evidence, evidenceErr = n.store.UnitAbsence(ctx, a.Owner)
		}
		if evidenceErr != nil {
			return evidenceErr
		}
		if observation.Exit == nil && !evidence.MountsAbsent {
			return errors.New("network cleanup observed-unit private mount namespace absence is unproven")
		}
		if evidence.BootID != boot || len(evidence.Units) != 1 || evidence.Units[0] != observation.Unit || !evidence.JobsAbsent || !evidence.ProcessesAbsent || !evidence.TransportsClosed || !evidence.OpenReferencesAbsent {
			return errors.New("network cleanup exact unit absence barrier incomplete")
		}
	} else {
		if !errors.Is(unitErr, sql.ErrNoRows) {
			return unitErr
		}
		service, submitted, e := n.store.LookupCreate(ctx, a.Owner, CreateService)
		if e != nil {
			return e
		}
		if submitted && service.State != CreateRejected {
			return ErrCreateUnresolved
		}
	}
	record, submitted, err := n.store.LookupCreate(ctx, a.Owner, CreateNetwork)
	if err != nil {
		return err
	}
	if submitted && record.State == CreateSubmitted {
		boot, bootErr := networkBootID()
		if bootErr != nil {
			return bootErr
		}
		if a.BootID == "" || a.BootID == boot {
			return ErrCreateUnresolved
		}
		if err = networkUnmountNamespace(a); err != nil {
			return err
		}
		if err = n.proveAbsent(ctx, a); err != nil {
			return err
		}
		if err = n.store.RejectCreate(ctx, a.Owner, CreateNetwork, record.Identity, "boot-fenced:"+a.BootID+"->"+boot); err != nil {
			return err
		}
		a.Record.State = "CLEANED"
		return n.save(ctx, a)
	}
	if a.namespacePin != nil {
		err = a.namespacePin.Close()
		a.namespacePin = nil
		if err != nil {
			return err
		}
	}
	r := &a.Record
	if r.NetnsIno == 0 {
		// A completed rejection may leave no namespace. A single missing pathname
		// never settles a submitted operation or releases its reserved prefix.
		if submitted && record.State != CreateRejected {
			return ErrCreateUnresolved
		}
		if err = networkUnmountNamespace(a); err != nil {
			return err
		}
		if err = n.proveAbsent(ctx, a); err != nil {
			return err
		}
		r.State = "CLEANED"
		return n.save(ctx, a)
	}
	if r.Profile != sharedhost.NetworkNone {
		links, e := n.links(ctx, "")
		if e != nil {
			return e
		}
		hostExists := false
		for _, l := range links {
			if l.IfName == r.HostInterface {
				hostExists = true
			}
		}
		if hostExists {
			if err = n.revokeForCleanup(ctx, a); err != nil {
				return err
			}
		} else {
			if err = n.clearFlows(ctx, a); err != nil {
				return err
			}
		}
		if err = n.removeFirewall(ctx, a); err != nil {
			return err
		}
		if hostExists {
			if err = n.verifyLink(ctx, a); err != nil {
				return err
			}
			if _, err = n.ip(ctx, "", "link", "delete", r.HostInterface); err != nil {
				return err
			}
		}
	}
	if err = networkNamespaceReferencesAbsent(r); err != nil {
		return err
	}
	if err = networkUnmountNamespace(a); err != nil {
		return err
	}
	if err = n.proveAbsent(ctx, a); err != nil {
		return err
	}
	r.State = "CLEANED"
	return n.save(ctx, a)
}
func networkNamespaceReferencesAbsent(r *NetworkRecord) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	if len(entries) > 131072 {
		return errors.New("process inventory exceeds network cleanup bound")
	}
	check := func(path string) error {
		var st unix.Stat_t
		err := unix.Stat(path, &st)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Ino == r.NetnsIno && uint64(st.Dev) == r.NetnsDev {
			return errors.New("owned network namespace still has process or FD references")
		}
		return nil
	}
	for _, entry := range entries {
		if _, err = strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		root := filepath.Join("/proc", entry.Name())
		if err = check(filepath.Join(root, "ns/net")); err != nil {
			return err
		}
		fds, e := os.ReadDir(filepath.Join(root, "fd"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if len(fds) > 65536 {
			return errors.New("process FD inventory exceeds cleanup bound")
		}
		for _, fd := range fds {
			path := filepath.Join(root, "fd", fd.Name())
			target, e := os.Readlink(path)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return e
			}
			if strings.HasPrefix(target, "net:[") {
				if e = check(path); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func (n *Network) proveAbsent(ctx context.Context, a *networkAllocation) error {
	r := a.Record
	if err := n.verifyFlowsAbsent(ctx, a); err != nil {
		return err
	}
	if _, err := os.Lstat(r.NetnsPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("owned network namespace mount absence unproven")
	}
	if err := networkNamespaceReferencesAbsent(&r); err != nil {
		return err
	}
	if err := networkNamespaceMountsAbsent(&r); err != nil {
		return err
	}
	if r.Profile == sharedhost.NetworkNone {
		return nil
	}
	links, err := n.links(ctx, "")
	if err != nil {
		return err
	}
	for _, l := range links {
		if l.IfName == r.HostInterface || l.IfName == r.PeerInterface || (r.HostIfIndex != 0 && l.IfIndex == r.HostIfIndex) || (r.PeerIfIndex != 0 && l.IfIndex == r.PeerIfIndex) {
			return errors.New("owned veth absence unproven")
		}
	}
	f, i, nat := networkChains(r)
	if r.Profile != sharedhost.NetworkNone {
		for _, family := range []int{4, 6} {
			tables := []string{"filter"}
			if family == 4 || r.Profile == sharedhost.NetworkPublicDual {
				tables = append(tables, "nat")
			}
			for _, table := range tables {
				raw, err := n.tables(ctx, family, "", table, "-S")
				if err != nil {
					return err
				}
				for _, token := range []string{f, i, nat, r.HostInterface, r.PeerInterface} {
					if token != "" && strings.Contains(string(raw), token) {
						return errors.New("owned filter/NAT references remain")
					}
				}
			}
		}
		for _, family := range []string{"-4", "-6"} {
			routes, err := n.routes(ctx, "", family)
			if err != nil {
				return err
			}
			for _, route := range routes {
				if route.Dev == r.HostInterface || route.Dev == r.PeerInterface {
					return errors.New("owned connected route remains")
				}
				for _, s := range []string{r.IPv4Prefix, r.IPv6Prefix} {
					if s != "" && route.Dst != "" && route.Dst != "default" {
						p, e := parseAddressPrefix(route.Dst)
						q, _ := parseAddressPrefix(s)
						if e != nil {
							return e
						}
						if p.Overlaps(q) {
							return fmt.Errorf("reserved prefix still has route %s", route.Dst)
						}
					}
				}
			}
		}
	}
	return nil
}
func networkNamespaceMountsAbsent(r *NetworkRecord) error {
	if r.NetnsIno == 0 {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	if len(entries) > 131072 {
		return errors.New("mount owner inventory exceeds bound")
	}
	knownMountNamespaces := make(map[string]bool)
	unescape := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	for _, entry := range entries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		root := filepath.Join("/proc", entry.Name())
		namespace, e := os.Readlink(filepath.Join(root, "ns/mnt"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		knownMountNamespaces[namespace] = true
		file, e := os.Open(filepath.Join(root, "mountinfo"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		e = errors.Join(e, file.Close())
		if e != nil {
			return e
		}
		if len(raw) > 1<<20 {
			return errors.New("process mount inventory exceeds bound")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, " - nsfs ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				return errors.New("malformed namespace mount inventory")
			}
			path := unescape.Replace(fields[4])
			if !filepath.IsAbs(path) {
				return errors.New("nonabsolute namespace mount path")
			}
			var st unix.Stat_t
			e = unix.Stat(filepath.Join(root, "root", strings.TrimPrefix(path, "/")), &st)
			if errors.Is(e, unix.ENOENT) || errors.Is(e, unix.ESRCH) {
				continue
			}
			if e != nil {
				return e
			}
			if st.Ino == r.NetnsIno && uint64(st.Dev) == r.NetnsDev {
				return errors.New("owned network namespace still has a mount reference")
			}
		}
	}
	for _, entry := range entries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		root := filepath.Join("/proc", entry.Name(), "fd")
		fds, e := os.ReadDir(root)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if len(fds) > 65536 {
			return errors.New("mount namespace FD inventory exceeds bound")
		}
		for _, fd := range fds {
			target, e := os.Readlink(filepath.Join(root, fd.Name()))
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return e
			}
			if strings.HasPrefix(target, "mnt:[") && !knownMountNamespaces[target] {
				return errors.Join(sharedhost.ErrCleanupIncomplete, errors.New("uninspectable pinned mount namespace retains possible network mount references"))
			}
		}
	}
	return nil
}

// ReconcileOwned walks only this installation's durably inventoried allocations.
// Each result is produced by Reconcile's existing unit/kernel/IPAM barriers.
func (n *Network) ReconcileOwned(ctx context.Context) error {
	n.mu.Lock()
	owners := make([]sharedhost.Ownership, 0, len(n.owned))
	for _, allocation := range n.owned {
		owners = append(owners, allocation.Owner)
	}
	n.mu.Unlock()
	var failures []error
	for _, owner := range owners {
		if err := n.Reconcile(ctx, owner); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
