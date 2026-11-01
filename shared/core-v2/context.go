package corev2

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc/metadata"
)

type deliveryKey struct{}
type activeDelivery struct {
	ref    string
	active atomic.Bool
}

func deliveryContext(ctx context.Context) (context.Context, func()) {
	values := metadata.ValueFromIncomingContext(ctx, WorkRefMetadata)
	d := &activeDelivery{}
	if len(values) == 1 {
		d.ref = values[0]
	}
	d.active.Store(true)
	return context.WithValue(ctx, deliveryKey{}, d), func() { d.active.Store(false) }
}

// HelperContext strips all outgoing metadata and forwards only an active event
// work reference installed by the SDK. It never propagates claimed identities,
// authorization headers or arbitrary inbound metadata. A saved callback context
// loses its reference when that callback returns or is canceled. Host-side
// validation of the active reference is still required; it grants no authority.
func HelperContext(ctx context.Context) context.Context {
	md := metadata.MD{}
	if d, ok := ctx.Value(deliveryKey{}).(*activeDelivery); ok && d.active.Load() && ctx.Err() == nil && d.ref != "" {
		md.Set(WorkRefMetadata, d.ref)
	}
	return metadata.NewOutgoingContext(ctx, md)
}

// hookContext preserves only a host-issued work reference on event delivery.
// Lifecycle calls deliberately carry no reference.
func hookContext(ctx context.Context, event bool) context.Context {
	md := metadata.MD{}
	if event {
		if outgoing, ok := metadata.FromOutgoingContext(ctx); ok {
			values := outgoing.Get(WorkRefMetadata)
			if len(values) == 1 {
				md.Set(WorkRefMetadata, values[0])
			}
		}
	}
	return metadata.NewOutgoingContext(ctx, md)
}
