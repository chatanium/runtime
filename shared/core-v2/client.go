package corev2

import (
	"context"
	"io"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

type configClient struct {
	client wire.CoreClient
	limits JSONLimits
}

// NewCoreClient constructs a context-aware, instance-scoped config client.
// The returned JSONValue preserves exact bytes and is validated as an object.
func NewCoreClient(conn grpc.ClientConnInterface, limits JSONLimits) (CoreClient, error) {
	if conn == nil || limits.MaxBytes <= 0 || limits.MaxDepth <= 0 {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidLimits)
	}
	return &configClient{client: wire.NewCoreClient(conn), limits: limits}, nil
}

func (c *configClient) GetConfig(ctx context.Context) (*wire.JSONValue, error) {
	value, err := c.client.GetConfig(HelperContext(ctx), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, NewError(codes.Internal, ReasonInternal)
	}
	if err := ValidateConfigJSON(value, c.limits); err != nil {
		return nil, err
	}
	return value, nil
}

// HookClient is the host's complete context-aware module hook client. Closing it
// stops its owned reverse helper server, not the primary go-plugin connection.
// The host must additionally terminate/close the owning go-plugin instance.
type HookClient struct {
	client  wire.HookClient
	helpers *helperAcceptor
	options []grpc.CallOption
}

var _ ModuleHooks = (*HookClient)(nil)

func (c *HookClient) GetManifest(ctx context.Context) (*wire.ModuleManifest, error) {
	value, err := c.client.GetManifest(hookContext(ctx, false), &emptypb.Empty{}, c.options...)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, NewError(codes.Internal, ReasonInternal)
	}
	return value, nil
}
func (c *HookClient) GetStatus(ctx context.Context) (*wire.Status, error) {
	value, err := c.client.GetStatus(hookContext(ctx, false), &emptypb.Empty{}, c.options...)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, NewError(codes.Internal, ReasonInternal)
	}
	return value, nil
}
func (c *HookClient) OnStage(ctx context.Context, req *wire.StageRequest) error {
	if err := validateStage(req); err != nil {
		return err
	}
	value, err := c.client.OnStage(hookContext(ctx, false), req, c.options...)
	if err == nil && value == nil {
		return NewError(codes.Internal, ReasonInternal)
	}
	return err
}
func (c *HookClient) OnEvent(ctx context.Context, event *wire.EventEnvelope) error {
	if event == nil {
		return NewError(codes.InvalidArgument, ReasonInvalidArgument)
	}
	value, err := c.client.OnEvent(hookContext(ctx, true), event, c.options...)
	if err == nil && value == nil {
		return NewError(codes.Internal, ReasonInternal)
	}
	return err
}

// HelperErrors reports an unexpected reverse acceptor exit after readiness.
// P4 must fail the instance if this channel receives an error. It closes after
// normal shutdown. Readiness itself is awaited before Dispense returns.
func (c *HookClient) HelperErrors() <-chan error { return c.helpers.errors }

// Close forcibly stops helper RPCs, without waiting for untrusted handlers.
func (c *HookClient) Close() error { c.helpers.close(); return nil }

const (
	// MaxUploadChunkBytes is the normative per-chunk limit (256 KiB).
	MaxUploadChunkBytes = 256 * 1024
	// MaxUploadFileBytes is the storage limit, not a backend send guarantee.
	MaxUploadFileBytes uint64 = 500 * 1024 * 1024
)

// FileClient explicitly uploads local bytes; no Reader crosses the wire.
// There is no implicit upload or automatic retry after an ambiguous final reply.
type FileClient struct{ client wire.FileTransferClient }

// NewFileClient binds file operations to the authenticated helper connection.
func NewFileClient(conn grpc.ClientConnInterface) (*FileClient, error) {
	if conn == nil {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidArgument)
	}
	return &FileClient{client: wire.NewFileTransferClient(conn)}, nil
}

// Upload sends metadata followed by nonempty sequential chunks. Cancellation
// cancels the RPC and closes src if it implements io.ReadCloser, interrupting
// readers whose Close unblocks Read. Other Readers must return from Read in
// bounded time: Go cannot forcibly interrupt an arbitrary io.Reader. The SDK
// never starts an unbounded read goroutine and does not close src on success.
func (c *FileClient) Upload(ctx context.Context, meta *wire.UploadMetadata, src io.Reader) (*wire.UploadedFileRef, error) {
	if meta == nil || src == nil {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidArgument)
	}
	if meta.DeclaredSizeBytes > MaxUploadFileBytes {
		return nil, NewError(codes.OutOfRange, ReasonUploadTooLarge)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stopRead func() bool
	if closer, ok := src.(io.ReadCloser); ok {
		stopRead = context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer stopRead()
	}
	stream, err := c.client.Upload(HelperContext(ctx))
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&wire.UploadChunk{Part: &wire.UploadChunk_Metadata{Metadata: meta}}); err != nil {
		return nil, uploadSendError(stream, err)
	}
	var offset uint64
	for {
		if err := ctx.Err(); err != nil {
			return nil, SafeRPCError(err)
		}
		// grpc-go may retain sent messages for tracing/stats. Each chunk owns
		// its buffer; later reads must not mutate previously sent bytes.
		bufferSize := uint64(MaxUploadChunkBytes)
		if remaining := meta.DeclaredSizeBytes - offset; remaining < bufferSize {
			bufferSize = remaining + 1
		}
		buf := make([]byte, int(bufferSize))
		var n int
		var readErr error
		for emptyReads := 0; ; {
			if err := ctx.Err(); err != nil {
				return nil, SafeRPCError(err)
			}
			n, readErr = src.Read(buf)
			if err := ctx.Err(); err != nil {
				return nil, SafeRPCError(err)
			}
			if n < 0 || n > len(buf) {
				return nil, NewError(codes.InvalidArgument, ReasonSourceRead)
			}
			if n != 0 || readErr != nil {
				break
			}
			// io.Reader permits transient empty reads. Bound a non-progressing
			// source without reallocating or modifying any previously sent chunk.
			emptyReads++
			if emptyReads >= 100 {
				return nil, NewError(codes.InvalidArgument, ReasonSourceRead)
			}
		}
		if uint64(n) > meta.DeclaredSizeBytes-offset {
			return nil, NewError(codes.InvalidArgument, ReasonUploadSizeMismatch)
		}
		if n > 0 {
			if err := stream.Send(&wire.UploadChunk{Part: &wire.UploadChunk_Chunk{Chunk: &wire.FileChunk{Offset: offset, Data: buf[:n]}}}); err != nil {
				return nil, uploadSendError(stream, err)
			}
			offset += uint64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, NewError(codes.InvalidArgument, ReasonSourceRead)
		}
	}
	if offset != meta.DeclaredSizeBytes {
		return nil, NewError(codes.InvalidArgument, ReasonUploadSizeMismatch)
	}
	ref, err := stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}
	if ref == nil || ref.OpaqueId == "" || ref.SizeBytes != offset {
		return nil, NewError(codes.Internal, ReasonInternal)
	}
	return ref, nil
}

func uploadSendError(stream grpc.ClientStreamingClient[wire.UploadChunk, wire.UploadedFileRef], err error) error {
	if err == io.EOF {
		_, finalErr := stream.CloseAndRecv()
		if finalErr != nil {
			return finalErr
		}
		return NewError(codes.Internal, ReasonInternal)
	}
	return err
}

// DeleteUpload requests owned cleanup; the host enforces ownership and expiry.
func (c *FileClient) DeleteUpload(ctx context.Context, ref *wire.UploadedFileRef) error {
	if ref == nil || ref.OpaqueId == "" {
		return NewError(codes.InvalidArgument, ReasonInvalidArgument)
	}
	value, err := c.client.DeleteUpload(HelperContext(ctx), &wire.DeleteUploadRequest{File: ref})
	if err == nil && value == nil {
		return NewError(codes.Internal, ReasonInternal)
	}
	return err
}
