package upload

import (
	"context"
	"io"
	"time"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

// RegistrarFactory is runtime.ManagerOptions.FileTransfer. It captures the real
// instance Authorizer, never a metadata identity. Construct one shared store per
// runtime; host quotas and the ownership lock must not be split among instances.
func (s *UploadStore) RegistrarFactory(services runtime.InstanceServices) (core.HelperRegistrar, error) {
	l, configured := services.Limits, s.config.Limits
	if services.Authorizer == nil || services.Principal.ModuleID == "" || services.Principal.InstanceID == "" || !sameManagement(services.ManagementDirectory, s.config.ManagementDirectory) || l.UploadRecordsPerInstance != configured.UploadRecordsPerInstance || l.UploadRecordsPerHost != configured.UploadRecordsPerHost || l.UploadFileNameMaxBytes != configured.UploadFileNameMaxBytes || l.UploadContentTypeMaxBytes != configured.UploadContentTypeMaxBytes || l.UploadDeadline != configured.UploadDeadline {
		return nil, invalid()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil, unavailable()
	}
	if _, exists := s.instances[services.Principal.InstanceID]; exists {
		return nil, invalid()
	}
	s.instances[services.Principal.InstanceID] = &instance{principal: services.Principal}
	server := &fileServer{store: s, services: services}
	return func(registrar grpc.ServiceRegistrar) error {
		wire.RegisterFileTransferServer(registrar, server)
		return nil
	}, nil
}

type fileServer struct {
	wire.UnimplementedFileTransferServer
	store    *UploadStore
	services runtime.InstanceServices
}

func (s *fileServer) authorize(ctx context.Context, operation string) (context.Context, context.CancelFunc, error) {
	p, err := s.services.Authorizer.Authorize(ctx, runtime.AccessRequest{Backend: "", Operation: operation, Scopes: []*wire.ResourceScope{{SelectorKind: &wire.ResourceScope_Selector{Selector: &wire.ResourceSelector{}}}}})
	if err != nil {
		return nil, nil, err
	}
	a, err := runtime.AdmissionFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if p != s.services.Principal || a.Principal() != p {
		a.Release()
		return nil, nil, core.NewError(codes.PermissionDenied, core.ReasonScopeDenied)
	}
	bounded, cancel := context.WithTimeout(a.Context(), time.Duration(s.services.Limits.UploadDeadline))
	return bounded, func() { cancel(); a.Release() }, nil
}

// receive does not join a blocked peer Recv before returning the handler. The
// runtime stream wrapper owns underlying worker/control-slot accounting and grpc
// cancels the real transport on handler return. The buffered result cannot block
// its sole worker even if the operation has already been canceled.
func receive(ctx context.Context, stream grpc.ClientStreamingServer[wire.UploadChunk, wire.UploadedFileRef]) (*wire.UploadChunk, error) {
	type result struct {
		value *wire.UploadChunk
		err   error
	}
	ready := make(chan result, 1)
	go func() { value, err := stream.Recv(); ready <- result{value, err} }()
	select {
	case <-ctx.Done():
		return nil, contextFailure(ctx)
	case result := <-ready:
		return result.value, result.err
	}
}

func (s *fileServer) Upload(stream grpc.ClientStreamingServer[wire.UploadChunk, wire.UploadedFileRef]) (result error) {
	ctx, finish, err := s.authorize(stream.Context(), "Upload")
	if err != nil {
		return err
	}
	defer finish()
	first, err := receive(ctx, stream)
	if err != nil {
		if err == io.EOF {
			return core.NewError(codes.InvalidArgument, core.ReasonUploadSequence)
		}
		return core.SafeRPCError(err)
	}
	metadata, ok := first.GetPart().(*wire.UploadChunk_Metadata)
	if !ok || metadata == nil || metadata.Metadata == nil {
		return core.NewError(codes.InvalidArgument, core.ReasonUploadSequence)
	}
	r, work, err := s.store.reserve(ctx, s.services.Principal, metadata.Metadata)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		r.cancel()
		s.store.mu.Lock()
		r.writing = false
		if !committed {
			r.retiring = true
		}
		if cleanup := s.store.reclaimLocked(r, time.Now()); cleanup != nil {
			result = cleanup
		}
		close(r.writerDone)
		s.store.mu.Unlock()
	}()
	writer, err := s.store.spool.create(r.name)
	if err != nil {
		return err
	}
	s.store.mu.Lock()
	r.storage = true
	s.store.mu.Unlock()
	closed := false
	defer func() {
		if !closed {
			if err := writer.Close(); err != nil {
				result = internal()
			}
		}
	}()
	var received uint64
	for {
		message, receiveErr := receive(work, stream)
		if receiveErr == io.EOF {
			break
		}
		if receiveErr != nil {
			return core.SafeRPCError(receiveErr)
		}
		if work.Err() != nil {
			return contextFailure(work)
		}
		part, ok := message.GetPart().(*wire.UploadChunk_Chunk)
		if !ok || part == nil || part.Chunk == nil {
			return core.NewError(codes.InvalidArgument, core.ReasonUploadSequence)
		}
		chunk := part.Chunk
		if chunk.Offset != received || len(chunk.Data) == 0 {
			return core.NewError(codes.InvalidArgument, core.ReasonUploadSequence)
		}
		if len(chunk.Data) > MaxChunkBytes {
			return core.NewError(codes.OutOfRange, core.ReasonChunkTooLarge)
		}
		if uint64(len(chunk.Data)) > r.size-received {
			return core.NewError(codes.InvalidArgument, core.ReasonUploadSizeMismatch)
		}
		n, writeErr := writer.Write(chunk.Data)
		if writeErr != nil || n != len(chunk.Data) {
			return internal()
		}
		received += uint64(n)
	}
	if work.Err() != nil {
		return contextFailure(work)
	}
	if received != r.size {
		return core.NewError(codes.InvalidArgument, core.ReasonUploadSizeMismatch)
	}
	// No writable descriptor survives commit, and the stored inode is read-only.
	if err := writer.Chmod(0400); err != nil {
		return internal()
	}
	err = writer.Close()
	closed = true
	if err != nil {
		return internal()
	}
	s.store.mu.Lock()
	if work.Err() != nil {
		s.store.mu.Unlock()
		return contextFailure(work)
	}
	if s.store.closing || r.owner.stopped || r.retiring {
		s.store.mu.Unlock()
		return unavailable()
	}
	r.committed = true
	r.expires = time.Now().Add(CompletionTTL)
	s.store.releaseSlotLocked(r)
	r.timer = time.AfterFunc(time.Until(r.expires), func() { s.store.expire(r) })
	ref := reference(r)
	committed = true
	s.store.mu.Unlock()
	// A lost response is not rolled back into an invalid partial success: the
	// unknown committed ref remains charged until its original TTL or stop.
	return core.SafeRPCError(stream.SendAndClose(ref))
}

func (s *fileServer) DeleteUpload(ctx context.Context, request *wire.DeleteUploadRequest) (*emptypb.Empty, error) {
	work, finish, err := s.authorize(ctx, "DeleteUpload")
	if err != nil {
		return nil, err
	}
	defer finish()
	if request == nil {
		return nil, invalid()
	}
	if err := s.store.Delete(work, s.services.Principal, request.File); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
