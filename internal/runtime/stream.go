package runtime

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// A derived Context alone cannot interrupt grpc's underlying RecvMsg/SendMsg.
// Return the real handler on deadline so grpc cancels its transport. Keep its
// control-RPC slot until both the handler and every blocked I/O worker exit.
// There is at most one worker per direction and no deferred worker join that
// would prevent the real handler from returning and canceling that transport.
type boundStream struct {
	grpc.ServerStream
	ctx       context.Context
	mu        sync.Mutex
	receiving bool
	sending   bool
	pending   int
	returned  bool
	finish    func()
}

func (s *boundStream) Context() context.Context { return s.ctx }
func (s *boundStream) finishHandler() {
	s.mu.Lock()
	s.returned = true
	finish := s.pending == 0
	s.mu.Unlock()
	if finish {
		s.finish()
	}
}
func (s *boundStream) RecvMsg(value any) error {
	return s.io(false, func() error { return s.ServerStream.RecvMsg(value) })
}
func (s *boundStream) SendMsg(value any) error {
	return s.io(true, func() error { return s.ServerStream.SendMsg(value) })
}
func (s *boundStream) io(send bool, operation func() error) error {
	if s.ctx.Err() != nil {
		return contextError(s.ctx)
	}
	s.mu.Lock()
	if s.returned || send && s.sending || !send && s.receiving {
		s.mu.Unlock()
		return runtimeError(codes.FailedPrecondition, "STREAM_OPERATION_ALREADY_ACTIVE")
	}
	if send {
		s.sending = true
	} else {
		s.receiving = true
	}
	s.pending++
	s.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		err := operation()
		s.mu.Lock()
		if send {
			s.sending = false
		} else {
			s.receiving = false
		}
		s.pending--
		finish := s.returned && s.pending == 0
		s.mu.Unlock()
		result <- err
		if finish {
			s.finish()
		}
	}()
	select {
	case <-s.ctx.Done():
		return contextError(s.ctx)
	case err := <-result:
		return err
	}
}
