package host

import (
	"context"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/runner"
)

// RuntimeHost is the worker's entire sandbox authority. Engine handles and
// administrative operations do not cross this boundary.
type RuntimeHost interface {
	ImageManifest(context.Context, string) ([]byte, error)
	Acquire(context.Context, LaunchSpec) (Lease, error)
	SetEgress(context.Context, string, EgressPolicy) error
	Terminate(context.Context, string) error
	Release(context.Context, string) error
	Reconcile(context.Context) error
	NewRunnerTransport(Lease) RunnerTransport
}

// RunnerTransport separates breaking physical I/O from joining producers and
// closing resources. Manager joins go-plugin consumers between these phases.
type RunnerTransport interface {
	RunnerFunc(hclog.Logger, *exec.Cmd, string) (runner.Runner, error)
	SocketConfig() *plugin.UnixSocketConfig
	BeginCloseTransport(context.Context) error
	CloseTransport() error
}
