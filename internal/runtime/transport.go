package runtime

import (
	"context"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin/runner"
	"github.com/thirdscam/chatanium/internal/host"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// go-plugin constructs its own background startup context. Preserve the actual
// single host startup deadline/cancellation rather than minting a second budget.
func bindRunnerStartup(factory *host.RunnerFactory, startup context.Context) func(hclog.Logger, *exec.Cmd, string) (runner.Runner, error) {
	return func(logger hclog.Logger, cmd *exec.Cmd, dir string) (runner.Runner, error) {
		if startup.Err() != nil {
			return nil, startup.Err()
		}
		inner, err := factory.RunnerFunc(logger, cmd, dir)
		if err != nil {
			return nil, err
		}
		return &startupRunner{Runner: inner, startup: startup}, nil
	}
}

type startupRunner struct {
	runner.Runner
	startup context.Context
}

func (r *startupRunner) Start(ctx context.Context) error {
	if r.startup.Err() != nil {
		return r.startup.Err()
	}
	bounded, cancel := context.WithDeadline(ctx, deadlineOf(r.startup))
	defer cancel()
	stop := context.AfterFunc(r.startup, cancel)
	defer stop()
	return r.Runner.Start(bounded)
}

func (i *Instance) newBrokerGuard() (*core.BrokerGuard, error) {
	guard, err := core.NewBrokerGuard(func(err error) {
		reason := "BROKER_PROTOCOL_VIOLATION"
		if status.Code(err) == codes.Unavailable {
			reason = "BROKER_TRANSPORT_LOST"
		}
		i.failTransport(reason)
	})
	if err != nil {
		return nil, err
	}
	i.mu.Lock()
	if i.state != Starting || i.startup.Err() != nil {
		i.mu.Unlock()
		guard.Close()
		return nil, runtimeError(codes.FailedPrecondition, "INSTANCE_NOT_RUNNING")
	}
	i.brokerGuard = guard
	i.mu.Unlock()
	return guard, nil
}

// beginTerminalCleanup linearizes expected transport shutdown with failure
// observers on the same authoritative lock. Admission is already closed and
// drain work has finished or expired before this transition.
func (i *Instance) beginTerminalCleanup() {
	i.mu.Lock()
	i.cancelStartup()
	for admission := range i.admissions {
		admission.cancel()
	}
	i.cancelLifetime()
	guard := i.brokerGuard
	i.mu.Unlock()
	if guard != nil {
		guard.Close()
	}
}

func (i *Instance) failTransport(reason string) {
	i.mu.Lock()
	// Expected terminal shutdown is not a new module failure. This check and
	// beginTerminalCleanup's cancellation share i.mu, so a late helper error
	// cannot race through after observing an obsolete live lifetime.
	if i.lifetime.Err() != nil {
		i.mu.Unlock()
		return
	}
	failed := i.failLocked(reason)
	i.mu.Unlock()
	if failed {
		i.manager.startStop(i, nil)
	}
}
