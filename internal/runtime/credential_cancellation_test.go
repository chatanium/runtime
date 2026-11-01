package runtime

import (
	"context"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
)

func TestCredentialIssueCancellationBeforePublication(t *testing.T) {
	for _, cancelDuringValidation := range []bool{false, true} {
		name := "already-canceled"
		if cancelDuringValidation {
			name = "canceled-under-publication-lock"
		}
		t.Run(name, func(t *testing.T) {
			m := regressionManager()
			instance := regressionInstance(t, m, "owner")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelDuringValidation {
				registration := m.backends[regressionBackend]
				validate := registration.ValidateSelector
				registration.ValidateSelector = func(resource *wire.ResourceSelector) error {
					if err := validate(resource); err != nil {
						return err
					}
					// Issue has passed its entry cancellation check and holds the
					// actual instance lock here. The operation expires before mint.
					cancel()
					return nil
				}
				m.backends[regressionBackend] = registration
			} else {
				cancel()
			}
			ref, err := m.credentials.Issue(ctx, instance.principal, CredentialBinding{
				BackendID:     regressionBackend,
				Purpose:       "respond",
				Resource:      regressionScope("group", "a").GetSelector(),
				ExpiresAt:     time.Now().Add(time.Minute),
				BackendHandle: &regressionCredentialKey{id: 1},
			})
			regressionError(t, err, codes.Canceled, "context canceled")
			if ref != nil {
				t.Fatal("canceled operation received a credential reference")
			}
			instance.mu.Lock()
			retained := len(instance.credentials)
			instance.mu.Unlock()
			if retained != 0 {
				t.Fatal("canceled operation published or charged a credential record")
			}
		})
	}
}
