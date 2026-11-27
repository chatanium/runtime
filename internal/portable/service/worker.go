package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/session"
)

type workerLaunch struct {
	self, program, dir                string
	lock                              *process.OwnerLock
	init                              session.WorkerInit
	stop, serveDone                   <-chan struct{}
	acl                               <-chan workerACLRequest
	startup, drain, cleanup, duration time.Duration
	moduleCount                       int
	observe                           func(session.WorkerEvent) error
	fence                             func(context.Context) error
}

var errWorkerACLUncertain = errors.New("worker Discord ACL update outcome is uncertain")

type workerACLRequest struct {
	change session.WorkerACLChange
	result chan error // Buffered so a departed caller cannot block the worker owner.
}

type readEvent struct {
	event session.WorkerEvent
	err   error
}

// runWorker returns native exit evidence independently of the worker protocol's
// result: a FAILED worker may still have been reaped, and DRAINED is not a reap.
func runWorker(ctx context.Context, w workerLaunch) (result error, observed bool) {
	if err := ctx.Err(); err != nil {
		return err, true
	}
	inRead, in, err := os.Pipe()
	if err != nil {
		return err, true
	}
	defer in.Close()
	out, outWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		return err, true
	}
	defer out.Close()
	child, err := process.Start(w.self, process.Spec{Path: w.program, Dir: w.dir, Args: []string{session.WorkerArg}, Stdin: inRead, Stdout: outWrite, OwnerLock: w.lock})
	inRead.Close()
	outWrite.Close()
	if err != nil {
		return err, !errors.Is(err, process.ErrUnobserved)
	}
	events := make(chan readEvent, 1)
	quit := make(chan struct{})
	defer close(quit)
	go func() {
		defer close(events)
		for {
			event, err := session.ReadWorkerEvent(out)
			select {
			case events <- readEvent{event, err}:
			case <-quit:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	startup, stopStartup := context.WithTimeout(ctx, w.startup)
	defer stopStartup()
	stopWrite := context.AfterFunc(startup, func() { in.Close() })
	initErr := session.WriteWorkerInit(in, w.init)
	stopWrite()
	clear(w.init.Secrets)
	var timer *time.Timer
	var stopAfter <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	ready := false
	result = initErr
	startupDone := startup.Done()
	var pending workerACLRequest
	var aclTimer *time.Timer
	var aclDeadline <-chan time.Time
	var aclWrite <-chan error
	var aclWriteErr error
	replyACL := func(err error) {
		aclTimer.Stop()
		aclDeadline = nil
		pending.result <- err
		pending = workerACLRequest{}
	}
	for result == nil {
		var requests <-chan workerACLRequest
		if ready && pending.result == nil && aclWrite == nil {
			requests = w.acl
		}
		select {
		case <-ctx.Done():
			goto draining
		case <-w.stop:
			goto draining
		case <-w.serveDone:
			result = errors.New("worker control listener closed")
			goto draining
		case <-startupDone:
			if ctx.Err() == nil {
				result = fmt.Errorf("worker readiness: %w", startup.Err())
			}
			goto draining
		case <-stopAfter:
			goto draining
		case req, ok := <-requests:
			if !ok {
				w.acl = nil
				continue
			}
			// A stop already observable at admission must win over the update.
			select {
			case <-ctx.Done():
			case <-w.stop:
			case <-stopAfter:
			case <-w.serveDone:
				result = errors.New("worker control listener closed")
			default:
				pending = req
				aclTimer = time.NewTimer(w.cleanup)
				aclDeadline = aclTimer.C
				done := make(chan error, 1)
				aclWrite = done
				// The owner may fence immediately on STOP, even if the pipe is full.
				// It waits for this writer before sending DRAIN on the same stream.
				go func() { done <- session.WriteWorkerACL(in, req.change) }()
				continue
			}
			req.result <- errors.New("worker is draining")
			goto draining
		case aclWriteErr = <-aclWrite:
			aclWrite = nil
			if aclWriteErr != nil {
				result = fmt.Errorf("writing worker ACL update: %w", aclWriteErr)
				goto draining
			}
		case <-aclDeadline:
			result = fmt.Errorf("worker ACL acknowledgement: %w", context.DeadlineExceeded)
			goto draining
		case msg := <-events:
			if msg.err != nil {
				result = fmt.Errorf("worker event stream before drain: %w", msg.err)
				goto draining
			}
			if msg.event.Type == "FAILED" {
				result = fmt.Errorf("worker failed: %s", msg.event.Reason)
				if w.observe != nil {
					result = errors.Join(result, w.observe(msg.event))
				}
				goto draining
			}
			if msg.event.Type == "ACL_ACK" {
				ack := msg.event.ACL
				if pending.result == nil || ack.Revision != pending.change.Revision {
					result = errors.New("unexpected worker ACL acknowledgement revision")
					goto draining
				}
				if ack.Status == session.WorkerACLApplied {
					replyACL(nil)
				} else {
					replyACL(errors.New("worker rejected Discord ACL update"))
				}
				continue
			}
			if msg.event.Type != "STATUS" && (msg.event.Type != "READY" || ready) {
				result = errors.New("unexpected worker lifecycle event")
				goto draining
			}
			if msg.event.Type == "READY" {
				if len(msg.event.Modules) != w.moduleCount {
					result = errors.New("worker readiness does not cover the approved modules")
					goto draining
				}
				ready = true
				startupDone = nil
				stopStartup()
				if w.duration > 0 {
					timer = time.NewTimer(w.duration)
					stopAfter = timer.C
				}
			}
			if w.observe != nil {
				result = w.observe(msg.event)
			}
		}
	}

draining:
	stopStartup()
	lateACLRevision := pending.change.Revision
	if pending.result != nil {
		err := errWorkerACLUncertain
		if result != nil {
			err = fmt.Errorf("%w: %w", errWorkerACLUncertain, result)
		}
		replyACL(err)
	}
	fenceCtx, stopFence := context.WithTimeout(context.Background(), w.cleanup)
	fenceErr := w.fence(fenceCtx)
	stopFence()
	result = errors.Join(result, fenceErr)
	// Keep the authenticated backend listening while the worker drains. Once
	// the deadline expires the owner closes the native scope regardless of RPC.
	drainCtx, stopDrain := context.WithTimeout(context.Background(), w.drain)
	defer stopDrain()
	deadline, _ := drainCtx.Deadline()
	if aclWrite != nil {
		select {
		case aclWriteErr = <-aclWrite:
		case <-drainCtx.Done():
			aclWriteErr = drainCtx.Err()
		}
	}
	// A failed write may have left a partial frame. Do not append DRAIN to it.
	drainErr := aclWriteErr
	if drainErr == nil {
		stopWrite = context.AfterFunc(drainCtx, func() { in.Close() })
		drainErr = session.WriteWorkerDrain(in, deadline)
		stopWrite()
	}
	in.Close()
	if drainErr == nil {
		for {
			select {
			case msg, ok := <-events:
				if !ok {
					drainErr = errors.New("worker event stream closed before DRAINED")
					goto settle
				}
				if msg.err != nil {
					drainErr = fmt.Errorf("worker closed before DRAINED: %w", msg.err)
					goto settle
				}
				switch msg.event.Type {
				case "ACL_ACK":
					if lateACLRevision == 0 || msg.event.ACL.Revision != lateACLRevision {
						drainErr = errors.New("unexpected worker ACL acknowledgement during drain")
						goto settle
					}
					lateACLRevision = 0
				case "DRAINED":
					if len(msg.event.Modules) != w.moduleCount || !msg.event.Clean {
						drainErr = errors.New("worker reported incomplete drain")
					} else if w.observe != nil {
						drainErr = w.observe(msg.event)
					}
					if drainErr == nil {
						select {
						case <-child.Done():
							drainErr = child.Wait()
						case <-drainCtx.Done():
							drainErr = drainCtx.Err()
						}
					}
					goto settle
				case "FAILED":
					drainErr = fmt.Errorf("worker failed during drain: %s", msg.event.Reason)
					goto settle
				}
			case <-drainCtx.Done():
				drainErr = drainCtx.Err()
				goto settle
			}
		}
	}
settle:
	cleanup, cancel := context.WithTimeout(context.Background(), w.cleanup)
	defer cancel()
	stopErr := child.Stop(cleanup, nil)
	return errors.Join(result, drainErr, stopErr), child.Observed()
}
