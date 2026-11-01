package corev2

import (
	"context"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

type moduleServer struct{ plugin *ModulePlugin }

var _ wire.HookServer = (*moduleServer)(nil)

func (s *moduleServer) GetManifest(ctx context.Context, _ *emptypb.Empty) (*wire.ModuleManifest, error) {
	ctx, cancel := s.plugin.callContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, SafeRPCError(err)
	}
	value, err := s.plugin.hooks.GetManifest(ctx)
	if err != nil {
		return nil, SafeRPCError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, SafeRPCError(err)
	}
	if value == nil {
		return nil, NewError(codes.Internal, ReasonInternal)
	}
	if value.ProtocolMajor != ProtocolMajor {
		return nil, NewError(codes.FailedPrecondition, ReasonProtocolMismatch)
	}
	return value, nil
}
func (s *moduleServer) GetStatus(ctx context.Context, _ *emptypb.Empty) (*wire.Status, error) {
	ctx, cancel := s.plugin.callContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, SafeRPCError(err)
	}
	value, err := s.plugin.hooks.GetStatus(ctx)
	if err != nil {
		return nil, SafeRPCError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, SafeRPCError(err)
	}
	if value == nil {
		return nil, NewError(codes.Internal, ReasonInternal)
	}
	switch value.Readiness {
	case wire.Readiness_READINESS_NOT_READY, wire.Readiness_READINESS_READY, wire.Readiness_READINESS_FAILED:
		return value, nil
	default:
		return nil, NewError(codes.Internal, ReasonInvalidStatus)
	}
}
func (s *moduleServer) OnStage(ctx context.Context, req *wire.StageRequest) (*emptypb.Empty, error) {
	ctx, cancel := s.plugin.callContext(ctx)
	defer cancel()
	if err := validateStage(req); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, SafeRPCError(err)
	}
	if req.Stage == wire.Stage_STAGE_INIT {
		if err := s.plugin.connectHelpers(ctx); err != nil {
			return nil, err
		}
	}
	if req.Stage == wire.Stage_STAGE_STOP {
		defer s.plugin.Close()
	}
	if err := s.plugin.hooks.OnStage(ctx, req); err != nil {
		if req.Stage == wire.Stage_STAGE_INIT {
			_ = s.plugin.Close()
		}
		return nil, SafeRPCError(err)
	}
	if err := ctx.Err(); err != nil {
		if req.Stage == wire.Stage_STAGE_INIT {
			_ = s.plugin.Close()
		}
		return nil, SafeRPCError(err)
	}
	return &emptypb.Empty{}, nil
}
func (s *moduleServer) OnEvent(ctx context.Context, event *wire.EventEnvelope) (*emptypb.Empty, error) {
	ctx, cancel := s.plugin.callContext(ctx)
	defer cancel()
	if event == nil {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return nil, SafeRPCError(err)
	}
	ctx, finish := deliveryContext(ctx)
	defer finish()
	if err := s.plugin.hooks.OnEvent(ctx, event); err != nil {
		return nil, SafeRPCError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, SafeRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

func validateStage(req *wire.StageRequest) error {
	if req == nil {
		return NewError(codes.InvalidArgument, ReasonInvalidStage)
	}
	switch req.Stage {
	case wire.Stage_STAGE_INIT:
		if req.InitContext == nil {
			return NewError(codes.InvalidArgument, ReasonInvalidStage)
		}
	case wire.Stage_STAGE_START, wire.Stage_STAGE_DRAIN, wire.Stage_STAGE_STOP:
		if req.InitContext != nil {
			return NewError(codes.InvalidArgument, ReasonInvalidStage)
		}
	default:
		return NewError(codes.InvalidArgument, ReasonInvalidStage)
	}
	return nil
}
