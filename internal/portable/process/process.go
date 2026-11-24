// Package process owns native children and their private local control channels.
package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// GuardianArg is the exact internal re-exec argument, dispatched before the CLI.
const GuardianArg = "__portable-process-guardian"

// ErrUnobserved means no positive proof that all native writers have exited.
var ErrUnobserved = errors.New("managed native process exit not observed")

// ErrOwnerBusy means another supervisor or its guardian owns the installation lock.
var ErrOwnerBusy = errors.New("portable process owner lock is held")

// Spec identifies a trusted native executable and its complete launch inputs.
// Nil standard streams go to the null device, not to the supervisor terminal.
// The caller retains ownership of all input files and can close its copies after Start.
// ExtraFiles become consecutive Unix descriptors starting at 3. On Windows,
// ExtraFileEnv explicitly supplies the environment names for their decimal HANDLEs.
// Env is otherwise exact: no inheritance, PATH lookup or implicit variables.
type Spec struct {
	Path, Dir             string
	Args, Env             []string
	Stdin, Stdout, Stderr *os.File
	ExtraFiles            []*os.File
	ExtraFileEnv          []string
	OwnerLock             *OwnerLock
}

// ExitError reports the main executable's nonzero exit, after its entire native
// process scope has exited. Code is -1 if a Unix signal killed the executable.
type ExitError struct {
	Code   int64
	Signal int
}

func (e *ExitError) Error() string {
	if e.Signal != 0 {
		return fmt.Sprintf("managed native process exited on signal %d", e.Signal)
	}
	return fmt.Sprintf("managed native process exited with code %d", e.Code)
}

// Child represents one native process scope. It cannot be constructed from a PID.
type Child struct {
	done      chan struct{}
	force     func()
	forceOnce sync.Once
	exit      error // published through closing done
	proof     error
}

// Start launches spec only with an active OS lifetime boundary.
// supervisorExecutable is the absolute path to the binary dispatching GuardianArg.
func Start(supervisorExecutable string, spec Spec) (*Child, error) {
	if !filepath.IsAbs(supervisorExecutable) || !launchString(supervisorExecutable) {
		return nil, errors.New("absolute supervisor executable required")
	}
	if !filepath.IsAbs(spec.Path) || !launchString(spec.Path) || (spec.Dir != "" && (!filepath.IsAbs(spec.Dir) || !launchString(spec.Dir))) {
		return nil, errors.New("absolute native executable and working directory required")
	}
	for _, arg := range spec.Args {
		if !launchString(arg) {
			return nil, errors.New("invalid native argument")
		}
	}
	if runtime.GOOS == "windows" && len(spec.ExtraFileEnv) != len(spec.ExtraFiles) || runtime.GOOS != "windows" && len(spec.ExtraFileEnv) != 0 {
		return nil, errors.New("extra file environment names are required for exactly the Windows extra handles")
	}
	if len(spec.ExtraFiles) > 65535 {
		return nil, errors.New("too many explicit native channels")
	}
	for _, f := range spec.ExtraFiles {
		if f == nil {
			return nil, errors.New("nil extra native file")
		}
	}
	names := make(map[string]struct{}, len(spec.Env)+len(spec.ExtraFileEnv))
	add := func(name string) bool {
		if runtime.GOOS == "windows" {
			name = strings.ToUpper(name)
		}
		if _, duplicate := names[name]; duplicate || name == "" {
			return false
		}
		names[name] = struct{}{}
		return true
	}
	for _, item := range spec.Env {
		name, _, hasValue := strings.Cut(item, "=")
		if !hasValue || !launchString(item) || !add(name) {
			return nil, errors.New("invalid or duplicate native environment entry")
		}
	}
	for _, name := range spec.ExtraFileEnv {
		if strings.Contains(name, "=") || !launchString(name) || !add(name) {
			return nil, errors.New("invalid or duplicate inherited handle environment name")
		}
	}
	return start(supervisorExecutable, spec)
}

func launchString(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }

// Done closes after the lifetime observer finishes. Check Observed before
// releasing anything that may still be writable by the scope.
func (c *Child) Done() <-chan struct{} { return c.done }

// Observed is true only with a positive, complete native exit observation.
func (c *Child) Observed() bool {
	select {
	case <-c.done:
		return c.proof == nil
	default:
		return false
	}
}

// Wait returns the original executable's exit status or a cleanup proof error.
func (c *Child) Wait() error {
	<-c.done
	if c.proof != nil {
		return c.proof
	}
	return c.exit
}

// Close forces scope termination and waits for positive native exit evidence.
// The executable's exit code does not affect the cleanup result.
func (c *Child) Close() error { return c.Stop(context.Background(), nil) }

// Stop optionally requests graceful termination, then forces termination if
// the scope does not exit. The callback must honor its context. If ctx expires
// before observation, the forced cleanup continues but Stop returns ErrUnobserved.
func (c *Child) Stop(ctx context.Context, graceful func(context.Context) error) error {
	select {
	case <-c.done:
		return c.proof
	default:
	}
	if graceful != nil && ctx.Err() == nil {
		period := 3 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			period = min(period, time.Until(deadline)/2)
		}
		grace, cancel := context.WithTimeout(ctx, period)
		if graceful(grace) == nil {
			select {
			case <-c.done:
				cancel()
				return c.proof
			case <-grace.Done():
			}
		}
		cancel()
	}
	c.forceOnce.Do(c.force)
	select {
	case <-c.done:
		return c.proof
	case <-ctx.Done():
		select {
		case <-c.done:
			return c.proof
		default:
		}
		return errors.Join(ErrUnobserved, ctx.Err())
	}
}

// OwnerLock holds exclusive installation liveness. The lock file is persistent:
// replacing or unlinking it would permit two independent owners.
// Acquiring a lock previously held by a crashed owner does not prove cleanup.
type OwnerLock struct {
	mu   sync.Mutex
	file *os.File
}

// Close drops this owner's handle. A Unix guardian may still hold the same lock
// until its managed scope has exited.
func (l *OwnerLock) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
