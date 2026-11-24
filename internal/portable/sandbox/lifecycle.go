package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxipc"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

var (
	errStopped = errors.New("portable run stopped")
	errExited  = errors.New("portable guest and engine exited")
)

type instance struct {
	module       Module
	run          store.Run
	ctx          context.Context
	cancel       context.CancelCauseFunc
	startupTimer *time.Timer
	done         chan struct{}

	// Open owns plumbing until it returns; egress serializes all live grants
	// and terminal changes. Cleanup locks them in this order after canceling.
	startMu                                     sync.Mutex
	openAttempted, launchBegun, unobservedStart bool
	runDirOwned, controlOwned                   bool
	controlDir                                  string
	identity                                    engine.InstanceIdentity
	policyDigest                                string
	child                                       *process.Child
	adapter                                     *engine.GVXAdapter
	pipes                                       *stdio
	endpoint                                    *stream
	logsDone, pumpsDone                         chan struct{}
	completing                                  atomic.Bool
	startupPhase                                string
	startupErr                                  error
	startupLog                                  *startupLog

	egressMu   sync.Mutex
	authorized bool

	// Only the observer writes a natural result, before publishing ctx.Done.
	exit       host.ProcessExit
	finalMu    sync.Mutex
	cleanupErr error
}

func (b *Backend) newInstance(module Module, run store.Run) *instance {
	ctx, cancel := context.WithCancelCause(context.Background())
	i := &instance{module: module, run: run, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	i.startupTimer = time.AfterFunc(b.opts.StartupTimeout, func() { cancel(context.DeadlineExceeded) })
	go func() {
		<-ctx.Done()
		i.startupTimer.Stop()
		b.cleanup(i)
		close(i.done)
	}()
	return i
}

func (b *Backend) SetEgress(ctx context.Context, id string, desired host.EgressPolicy) (retErr error) {
	defer annotateRPCError(&retErr)
	i, err := b.lookup(id)
	if err != nil {
		if desired == host.EgressNone {
			return b.confirmAbsent(ctx, id)
		}
		return err
	}
	i.startMu.Lock()
	i.egressMu.Lock()
	ready := i.endpoint != nil && i.adapter != nil
	granting := desired == host.EgressPublicInternet ||
		desired == host.EgressNone && ready && !i.authorized && i.run.Approval.Network.Mode == store.NetworkNone
	i.startMu.Unlock()
	err = b.setEgress(ctx, i, ready, desired)
	i.egressMu.Unlock()
	if i.ctx.Err() != nil {
		if err == nil && granting {
			err = context.Cause(i.ctx)
		}
		return errors.Join(err, b.awaitCleanup(ctx, i))
	}
	return err
}

func (b *Backend) setEgress(ctx context.Context, i *instance, ready bool, desired host.EgressPolicy) error {
	fail := func(err error) error {
		i.cancel(err)
		return err
	}
	if i.ctx.Err() != nil {
		if desired == host.EgressNone {
			return nil // The existing cleanup owns the sealed generation.
		}
		return engine.ErrEgressRevoked
	}
	public := i.run.Approval.Network.Mode == store.NetworkPublic
	wanted := host.EgressNone
	if public {
		wanted = host.EgressPublicInternet
	}
	// NONE is a verification for a permanent net=none launch on its first
	// authenticated call. It is a terminal revocation for a NAT candidate,
	// including while its initial policy is still deny-all.
	if desired == host.EgressNone && (public || i.authorized || !ready) {
		if !ready {
			i.cancel(errStopped)
			return nil
		}
		// Never let a canceled client bypass a requested revocation. Seal the
		// durable generation first, then replace with deny and kill the peer.
		revoke, cancel := context.WithTimeout(context.Background(), b.opts.CleanupTimeout)
		defer cancel()
		sealErr := b.opts.Store.SealEgress(revoke, i.run.Key, i.run.EgressGeneration)
		err := i.adapter.SetEgress(revoke, i.run.InstanceID, engine.EgressPolicy{Identity: i.identity})
		i.cancel(errStopped)
		return errors.Join(sealErr, err)
	}
	if !ready || desired != wanted {
		return fail(store.ErrApprovalMismatch)
	}
	if !i.authorized {
		i.startupPhase = "authorize-egress"
	}
	grant, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(i.ctx, cancel)
	defer stop()
	install, err := b.opts.Store.Installation(grant)
	if err != nil {
		return fail(err)
	}
	if install.EpochID != i.run.Key.EpochID || install.ConfigRevision != i.run.ConfigRevision || install.Desired != store.DesiredRunning {
		return fail(store.ErrApprovalMismatch)
	}
	if err := i.adapter.SetEgress(grant, i.run.InstanceID, engine.EgressPolicy{Identity: i.identity, Open: true}); err != nil {
		return fail(err)
	}
	if public && !i.authorized {
		if err := b.opts.Store.SetEgressOpen(grant, i.run.Key, i.run.EgressGeneration, i.policyDigest); err != nil {
			return fail(err)
		}
	}
	if !i.authorized {
		if err := b.opts.Store.MarkRunning(grant, i.run.Key); err != nil {
			return fail(err)
		}
	}
	// Also cover an installation stop racing with the uncached native RPC,
	// even for permanent NONE or an idempotent public recheck.
	install, err = b.opts.Store.Installation(grant)
	if err != nil {
		return fail(err)
	}
	if install.EpochID != i.run.Key.EpochID || install.ConfigRevision != i.run.ConfigRevision || install.Desired != store.DesiredRunning {
		return fail(store.ErrApprovalMismatch)
	}
	if !i.authorized && !i.startupTimer.Stop() {
		return fail(context.DeadlineExceeded)
	}
	if err := grant.Err(); err != nil {
		return fail(err)
	}
	i.authorized = true
	return nil
}

type completion struct {
	exit host.ProcessExit
	err  error
}

func (b *Backend) watch(i *instance, codec *gvxipc.Codec, limit int) {
	result := make(chan completion, 1)
	sent := make(chan error, 1)
	bridgeExit := make(chan struct{})
	i.pumpsDone = make(chan struct{})
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		exit, err := i.endpoint.receive(codec, limit, bridgeExit, &i.completing)
		result <- completion{exit: exit, err: err}
	}()
	go func() {
		defer pumps.Done()
		sent <- i.endpoint.send(codec)
	}()
	go func() {
		pumps.Wait()
		close(i.pumpsDone)
	}()
	go b.observe(i, bridgeExit, sent, result)
}

func (b *Backend) observe(i *instance, bridgeExit <-chan struct{}, sent <-chan error, result <-chan completion) {
	native, control, departed := i.child.Done(), i.adapter.Done(), i.endpoint.departed
	var received completion
	var sendErr error
	var timer *time.Timer
	var drained <-chan time.Time
	startDrain := func() {
		if timer == nil {
			timer = time.NewTimer(b.opts.CleanupTimeout)
			drained = timer.C
		}
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		if native == nil && result == nil {
			if err := verifyExit(i.child, received.exit); err != nil {
				i.cancel(err)
			} else if i.ctx.Err() == nil {
				i.exit = received.exit
				i.cancel(errExited)
			}
			return
		}
		select {
		case <-i.ctx.Done():
			return
		case <-native:
			native = nil
			if !i.child.Observed() {
				i.cancel(process.ErrUnobserved)
				return
			}
			startDrain()
		case <-control:
			control = nil
			controlErr := i.adapter.Err()
			if !errors.Is(controlErr, engine.ErrPeerClosing) && !i.completing.Load() && !i.child.Observed() {
				i.cancel(controlErr)
				return
			}
			startDrain()
		case <-departed:
			departed = nil
			startDrain()
		case <-bridgeExit:
			bridgeExit = nil
			startDrain()
		case sendErr = <-sent:
			sent = nil
			if sendErr != nil {
				// An EPIPE/closed endpoint may race a written terminal frame.
				// Only validated EXIT plus matching native result wins the race.
				startDrain()
			}
		case received = <-result:
			result = nil
			if received.err != nil {
				i.cancel(errors.Join(received.err, sendErr))
				return
			}
			startDrain()
		case <-drained:
			i.cancel(errors.Join(errors.New("sandbox bridge exit or native writer join unconfirmed"), sendErr))
			return
		}
	}
}

func verifyExit(child *process.Child, result host.ProcessExit) error {
	if !child.Observed() {
		return process.ErrUnobserved
	}
	want := int64(result.Value)
	if result.Kind == "signal" {
		want += 128
	}
	if err := child.Wait(); err == nil {
		if result.Kind == "exit" && want == 0 {
			return nil
		}
	} else {
		var status *process.ExitError
		if errors.As(err, &status) && result.Kind != "" && want != 0 && status.Signal == 0 && status.Code == want {
			return nil
		}
		return fmt.Errorf("guest EXIT disagrees with the observed GVX result: %w", err)
	}
	return errors.New("guest EXIT disagrees with the observed GVX result")
}

func waitChannel(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Backend) cleanup(i *instance) {
	i.startMu.Lock()
	defer i.startMu.Unlock()
	i.egressMu.Lock()
	defer i.egressMu.Unlock()
	i.finalMu.Lock()
	defer i.finalMu.Unlock()
	if i.endpoint != nil {
		i.endpoint.abort(net.ErrClosed)
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.opts.CleanupTimeout)
	defer cancel()
	if i.launchBegun {
		// Control loss can already have triggered the adapter's independent
		// force path; it too records STOPPED before issuing a kill.
		_ = b.opts.Store.StopRun(ctx, i.run.Key)
	}
	if i.child != nil && !i.child.Observed() {
		if i.adapter != nil {
			grace := min(b.opts.CleanupTimeout/4, 2*time.Second).Truncate(time.Millisecond)
			stopping, stop := context.WithTimeout(ctx, b.opts.CleanupTimeout/2)
			_ = i.adapter.Stop(stopping, grace)
			stop()
		}
		_ = i.child.Stop(ctx, nil)
	}
	if i.child != nil && i.child.Observed() && i.logsDone != nil {
		// The last engine writer is closed. Give the bounded rotation time to
		// consume the final diagnostic slab before closing our descriptors.
		drain, drained := context.WithTimeout(ctx, b.opts.CleanupTimeout/4)
		_ = waitChannel(drain, i.logsDone)
		drained()
	}
	b.reportStartupFailure(i)
	if i.pipes != nil {
		i.pipes.closeHost()
	}
	if i.adapter != nil {
		_ = i.adapter.Close()
	}
	i.cleanupErr = b.finishCleanup(ctx, i)
}

func (b *Backend) finishCleanup(ctx context.Context, i *instance) error {
	pending := func(err error) error { return errors.Join(store.ErrCleanupPending, err) }
	if i.unobservedStart || i.child != nil && !i.child.Observed() {
		return pending(process.ErrUnobserved)
	}
	if err := errors.Join(waitChannel(ctx, i.logsDone), waitChannel(ctx, i.pumpsDone)); err != nil {
		return pending(err)
	}
	// Reload durable birth/initialization: a canceled SQLite commit to
	// RecordPersistent may have succeeded. Never reclaim a retained image on
	// the basis of a stale in-memory startup observation.
	run, err := b.opts.Store.Run(ctx, i.run.Key)
	if errors.Is(err, store.ErrNotFound) {
		// A prior release may have committed before its context expired.
		return nil
	}
	if err != nil {
		return pending(err)
	}
	if !run.LaunchBegun {
		if err := b.opts.Store.CancelRun(ctx, b.opts.Epoch, run.Key); err != nil {
			return pending(err)
		}
		return nil
	}
	if !run.CleanupPending {
		if err := b.opts.Store.StopRun(ctx, run.Key); err != nil {
			return pending(err)
		}
	}
	if err := releaseObserved(ctx, b.opts.Store, b.opts.Root, b.opts.Epoch, run, i); err != nil {
		return pending(err)
	}
	return nil
}

func (b *Backend) awaitCleanup(ctx context.Context, i *instance) error {
	if err := waitChannel(ctx, i.done); err != nil {
		return errors.Join(store.ErrCleanupPending, err)
	}
	i.finalMu.Lock()
	defer i.finalMu.Unlock()
	return i.cleanupErr
}

func (b *Backend) retryCleanup(ctx context.Context, i *instance) error {
	if err := waitChannel(ctx, i.done); err != nil {
		return errors.Join(store.ErrCleanupPending, err)
	}
	i.finalMu.Lock()
	defer i.finalMu.Unlock()
	if i.cleanupErr != nil {
		i.cleanupErr = b.finishCleanup(ctx, i)
	}
	return i.cleanupErr
}

func (b *Backend) Wait(ctx context.Context, id string) (_ host.ProcessExit, retErr error) {
	defer annotateRPCError(&retErr)
	i, err := b.lookup(id)
	if err != nil {
		return host.ProcessExit{}, err
	}
	err = b.awaitCleanup(ctx, i)
	if err != nil {
		return host.ProcessExit{}, err
	}
	if cause := context.Cause(i.ctx); cause != errExited {
		return host.ProcessExit{}, cause
	}
	return i.exit, nil
}

func (b *Backend) confirmAbsent(ctx context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live[id] != nil {
		return store.ErrCleanupPending
	}
	runs, err := b.opts.Store.Runs(ctx)
	if err != nil {
		return err
	}
	for _, run := range runs {
		if run.InstanceID == id {
			return store.ErrCleanupPending
		}
	}
	return nil
}

func (b *Backend) Terminate(ctx context.Context, id string) (retErr error) {
	defer annotateRPCError(&retErr)
	i, err := b.lookup(id)
	if err != nil {
		return b.confirmAbsent(ctx, id)
	}
	i.cancel(errStopped)
	return b.retryCleanup(ctx, i)
}

func (b *Backend) Release(ctx context.Context, id string) (retErr error) {
	defer annotateRPCError(&retErr)
	i, err := b.lookup(id)
	if err != nil {
		return b.confirmAbsent(ctx, id)
	}
	i.cancel(errStopped)
	if err = b.retryCleanup(ctx, i); err != nil {
		return err
	}
	b.mu.Lock()
	if b.live[id] == i {
		delete(b.live, id)
	}
	b.mu.Unlock()
	return nil
}

// Close terminates every run immediately when the authenticated worker or
// supervisor dies; cleanup continues even if the caller's wait times out.
func (b *Backend) Close(ctx context.Context) error {
	b.mu.Lock()
	b.closing = true
	live := make([]*instance, 0, len(b.live))
	for _, i := range b.live {
		i.cancel(errStopped)
		live = append(live, i)
	}
	b.mu.Unlock()
	var err error
	for _, i := range live {
		err = errors.Join(err, b.retryCleanup(ctx, i))
	}
	return err
}

// Reconcile never adopts a PID or connects to a prior control endpoint. The
// only crash-boundary evidence it accepts for a launched scope is a reliable
// change of boot identity; the file/volume proof still has to hold afterward.
func (b *Backend) Reconcile(ctx context.Context) (retErr error) {
	defer annotateRPCError(&retErr)
	b.mu.Lock()
	defer b.mu.Unlock()
	runs, err := b.opts.Store.Runs(ctx)
	if err != nil {
		return err
	}
	var result error
	for _, run := range runs {
		if live := b.live[run.InstanceID]; live != nil && live.run.Key == run.Key {
			if live.ctx.Err() != nil {
				result = errors.Join(result, b.retryCleanup(ctx, live))
			}
			continue
		}
		result = errors.Join(result, reconcileRun(ctx, b.opts.Store, b.opts.Root, b.epoch, run))
	}
	return result
}

var _ io.ReadWriteCloser = (*stream)(nil)
