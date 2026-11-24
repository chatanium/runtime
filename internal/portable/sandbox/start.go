package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxipc"
	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

type stdio struct {
	input, output, diagnostics *os.File // supervisor handles
	stdin, stdout, stderr      *os.File // child handles
}

func openStdio() (_ *stdio, retErr error) {
	p := new(stdio)
	defer func() {
		if retErr != nil {
			p.closeChild()
			p.closeHost()
		}
	}()
	var err error
	if p.stdin, p.input, err = os.Pipe(); err != nil {
		return nil, err
	}
	if p.output, p.stdout, err = os.Pipe(); err != nil {
		return nil, err
	}
	if p.diagnostics, p.stderr, err = os.Pipe(); err != nil {
		return nil, err
	}
	return p, nil
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (p *stdio) closeChild()  { closeFiles(p.stdin, p.stdout, p.stderr) }
func (p *stdio) closeHost()   { closeFiles(p.input, p.output, p.diagnostics) }
func (p *stdio) closeBridge() { closeFiles(p.input, p.output) }

func (b *Backend) Open(ctx context.Context, id string, bootstrap []string) (_ []byte, _ io.ReadWriteCloser, retErr error) {
	defer annotateRPCError(&retErr)
	i, err := b.lookup(id)
	if err != nil {
		return nil, nil, err
	}
	i.startMu.Lock()
	if i.openAttempted {
		i.startMu.Unlock()
		return nil, nil, store.ErrState
	}
	i.openAttempted = true
	i.startupPhase = "validate-run"
	stopRequest := context.AfterFunc(ctx, func() { i.cancel(ctx.Err()) })
	handshake, err := b.start(i, bootstrap)
	stopRequest()
	if err == nil {
		err = context.Cause(i.ctx)
	}
	i.startupErr = err
	i.startMu.Unlock()
	if err != nil {
		i.cancel(err)
		// The supervisor continues cleanup independent of the RPC deadline.
		// If we can observe it here, include incomplete teardown in the result.
		if ctx.Err() == nil {
			err = errors.Join(err, b.awaitCleanup(ctx, i))
		}
		return nil, nil, err
	}
	return handshake, i.endpoint, nil
}

func (b *Backend) start(i *instance, bootstrap []string) ([]byte, error) {
	ctx := i.ctx
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	run, approval := i.run, i.run.Approval
	resources := i.module.Spec.Resources
	limits := gvxipc.Limits{ControlMessageMaxBytes: resources.ControlMessageMaxBytes, LogBufferBytes: resources.LogBufferBytes}
	persistent, err := localPath(run.Persistent.Path)
	if err != nil {
		return nil, err
	}
	runPath, err := localPath(run.InstancePath)
	if err != nil {
		return nil, err
	}
	if run.LogBytes <= ancillaryBytes || int64(resources.LogRetainedFiles) > run.LogBytes-ancillaryBytes {
		return nil, fmt.Errorf("%w: no finite sandbox log reservation", store.ErrBudgetExceeded)
	}
	maxLogFile := min(resources.LogFileMaxBytes, (run.LogBytes-ancillaryBytes)/int64(resources.LogRetainedFiles))
	root := b.opts.Root
	i.startupPhase = "verify-persistent-backing"
	before, err := observeVolume(root, persistent)
	if err != nil {
		return nil, err
	}
	if err = validateVolume(run.Persistent, before); err != nil {
		return nil, err
	}
	i.startupPhase = "verify-reviewed-image"
	image, err := i.module.Image.VerifiedLaunch(root, run.Image.EpochID)
	if err != nil {
		return nil, err
	}
	if image.Directory != filepath.Join(root.Name(), filepath.FromSlash(run.Image.Path)) || image.ExecutionRef != i.module.Image.ExecutionRef || image.RegistryURL != "https://chatanium.invalid" {
		return nil, store.ErrApprovalMismatch
	}
	i.startupPhase = "plan-engine"
	network, err := networkGrant(approval.Network)
	if err != nil {
		return nil, err
	}
	i.controlDir, err = controlDir(root, run)
	if err != nil {
		return nil, err
	}
	launch := engine.LaunchSpec{
		CacheDir: filepath.Join(root.Name(), runPath, cacheLeaf), ImageRef: image.ExecutionRef, HelperPath: b.opts.BridgePath,
		HelperArgs: []string{gvxcontract.BridgePortableArg},
		Endpoint:   engine.Endpoint{SocketPath: filepath.Join(i.controlDir, controlSocket), TokenPath: filepath.Join(i.controlDir, controlToken)},
		Environment: []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "TMPDIR=/tmp", "LANG=C", "LC_ALL=C",
			"CHATANIUM_GVX_STARTUP_TIMEOUT_NS=" + strconv.FormatInt(int64(b.opts.StartupTimeout), 10),
			"CHATANIUM_GVX_CONTROL_MAX_BYTES=" + strconv.FormatInt(resources.ControlMessageMaxBytes, 10),
			"CHATANIUM_GVX_LOG_BUFFER_BYTES=" + strconv.FormatInt(resources.LogBufferBytes, 10)},
	}
	for _, entry := range i.module.Image.ImageEnv {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, store.ErrApprovalMismatch
		}
		launch.ClearImageEnvironment = append(launch.ClearImageEnvironment, key)
	}
	if network.Mode == engine.NetworkPublicInternet {
		launch.DenyPolicyPath = filepath.Join(root.Name(), runPath, denyLeaf)
	}
	i.identity = engine.InstanceIdentity{InstallationID: b.opts.InstallationID, EpochID: run.Key.EpochID, InstanceID: run.InstanceID, ReviewDigest: approval.ReviewDigest}
	plan, err := engine.PlanRun(b.opts.Target, engine.ApprovedGrant{Identity: i.identity,
		Limits: engine.ResourceLimits{CPUMillicores: approval.CPUMillicores, MemoryBytes: approval.MemoryBytes, MaxPIDs: approval.MaxPIDs}, Network: network, Launch: launch,
	}, engine.VolumeLease{PersistentPath: filepath.Join(root.Name(), persistent), PersistentBytes: approval.PersistentBytes, ScratchBytes: approval.ScratchBytes})
	if err != nil {
		return nil, err
	}
	if digest := plan.EgressPolicyDigest(); digest != "" {
		i.policyDigest = "sha256:" + digest
	}
	if i.policyDigest != approval.Network.PolicyDigest {
		return nil, store.ErrApprovalMismatch
	}
	i.startupPhase = "compose-bridge-init"
	roots, err := gvxcontract.NewPortableRootManifest(gvxcontract.RootBinding{RuntimeInstallationID: b.opts.InstallationID, EpochID: run.Key.EpochID, InstanceID: run.InstanceID, IntentID: run.Key.ID, Nonce: run.ScratchID},
		gvxcontract.PortableRootLimits{MaxPIDs: approval.MaxPIDs, PersistentBytes: approval.PersistentBytes, ScratchBytes: approval.ScratchBytes}, approval.UID, approval.GID, !before.Exists)
	if err != nil {
		return nil, err
	}
	init, err := bridgeInit(i.module, bootstrap, roots, limits.Control())
	if err != nil {
		return nil, err
	}
	i.startupPhase = "begin-launch"
	if err = b.opts.Store.BeginLaunch(ctx, run.Key, before); err != nil {
		return nil, err
	}
	i.launchBegun = true
	i.startupPhase = "prepare-run-files"
	if err = privateParents(root, filepath.Dir(persistent), true); err != nil {
		return nil, err
	}
	if err = privateParents(root, filepath.Dir(runPath), true); err != nil {
		return nil, err
	}
	if err = root.Mkdir(runPath, 0700); err != nil {
		return nil, err
	}
	i.runDirOwned = true
	if err = process.ProtectPrivateDir(filepath.Join(root.Name(), runPath)); err != nil {
		return nil, err
	}
	if err = syncPath(root, filepath.Dir(runPath)); err != nil {
		return nil, err
	}
	workspace, err := root.OpenRoot(runPath)
	if err != nil {
		return nil, err
	}
	defer workspace.Close()
	for _, path := range []string{cacheLeaf, cwdLeaf, logLeaf, filepath.Join(cacheLeaf, engine.EphemeralVolumeDir)} {
		if err = workspace.Mkdir(path, 0700); err != nil {
			return nil, err
		}
	}
	i.startupPhase = "stage-reviewed-cache"
	if err = publishCache(ctx, root, runPath, i); err != nil {
		return nil, err
	}
	if raw := plan.DenyPolicyJSON(); raw != nil {
		if err = workspace.WriteFile(denyLeaf, raw, 0400); err != nil {
			return nil, err
		}
	}
	i.startupPhase = "create-control-endpoint"
	i.controlOwned, err = makeControl(workspace, run, i.controlDir)
	if err != nil {
		return nil, err
	}
	mounted := before
	if !run.Persistent.Initialized {
		i.startupPhase = "publish-persistent-backing"
		mounted, err = createPersistent(ctx, b.opts.Store, root, workspace, run, runPath, persistent)
		if err != nil {
			return nil, err
		}
	}
	i.startupPhase = "start-engine"
	i.pipes, err = openStdio()
	if err != nil {
		return nil, err
	}
	defer i.pipes.closeChild()
	startupIO := context.AfterFunc(ctx, i.pipes.closeBridge)
	defer startupIO()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	cwd := filepath.Join(workspace.Name(), cwdLeaf)
	i.child, err = process.Start(b.opts.SupervisorExecutable, process.Spec{
		Path: b.opts.EnginePath, Dir: cwd, Args: plan.Args(),
		Env:   []string{"HOME=" + cwd, "TMPDIR=" + cwd, "XDG_CACHE_HOME=" + cwd, "XDG_CONFIG_HOME=" + cwd, "XDG_STATE_HOME=" + cwd, "XDG_RUNTIME_DIR=" + cwd, "TEMP=" + cwd, "TMP=" + cwd, "USERPROFILE=" + cwd, "LOCALAPPDATA=" + cwd, "APPDATA=" + cwd},
		Stdin: i.pipes.stdin, Stdout: i.pipes.stdout, Stderr: i.pipes.stderr, OwnerLock: b.opts.OwnerLock,
	})
	i.pipes.closeChild()
	if err != nil {
		i.unobservedStart = errors.Is(err, process.ErrUnobserved)
		return nil, err
	}
	logs, err := workspace.OpenRoot(logLeaf)
	if err != nil {
		return nil, err
	}
	var diagnostics io.Reader = i.pipes.diagnostics
	if b.opts.Diagnostics != nil {
		i.startupLog = new(startupLog)
		diagnostics = io.TeeReader(diagnostics, i.startupLog)
	}
	i.logsDone = make(chan struct{})
	go func() {
		defer close(i.logsDone)
		err := drainLogs(logs, diagnostics, maxLogFile, resources.LogRetainedFiles)
		err = errors.Join(err, logs.Close())
		if err != nil && ctx.Err() == nil {
			i.cancel(err)
		}
	}()
	i.startupPhase = "authenticate-engine"
	i.adapter, err = engine.Connect(ctx, plan, engine.Peer{
		Done: i.child.Done(), Exited: i.child.Observed, Completing: i.completing.Load,
		Kill: func() error {
			deadline, cancel := context.WithTimeout(context.Background(), b.opts.CleanupTimeout)
			defer cancel()
			// Durably close the authorized generation before forcing the engine.
			// A ledger failure must not prevent the native kill.
			return errors.Join(b.opts.Store.StopRun(deadline, run.Key), i.child.Stop(deadline, nil))
		},
	})
	if err != nil {
		return nil, err
	}
	i.startupPhase = "record-engine"
	if err = b.opts.Store.RecordEngine(ctx, run.Key, plan.SandboxID()); err != nil {
		return nil, err
	}
	i.startupPhase = "initialize-guest-roots"
	codec, err := gvxipc.NewCodec(i.pipes.output, i.pipes.input, gvxipc.Host, limits)
	if err != nil {
		return nil, err
	}
	if _, err = gvxipc.PrepareHost(codec, init); err != nil {
		return nil, err
	}
	i.startupPhase = "commit-guest-roots"
	after, err := observeVolume(root, persistent)
	if err != nil {
		return nil, err
	}
	if !after.Exists || after.NativeID != mounted.NativeID || after.SizeBytes < store.MinVolumeBytes || after.SizeBytes > approval.PersistentBytes || after.SizeBytes%store.VolumeAlignmentBytes != 0 {
		return nil, errors.New("unexpected persistent backing after ROOTS_READY")
	}
	if err = b.opts.Store.RecordPersistent(ctx, run.Key, after); err != nil {
		return nil, err
	}
	if i.startupLog != nil {
		i.startupLog.stop()
	}
	if err = codec.Write(gvxipc.RootsCommit, nil); err != nil {
		return nil, err
	}
	i.startupPhase = "read-guest-handshake"
	handshake, err := gvxipc.ReadHandshake(codec, guestSocketDir)
	if err != nil {
		return nil, err
	}
	handshake = bytes.Clone(handshake) // The codec reuses its incoming frame slab.
	i.startupPhase = "open-guest-transport"
	if err = codec.Write(gvxipc.Open, nil); err != nil {
		return nil, err
	}
	typ, payload, err := codec.Read()
	if err != nil {
		return nil, err
	}
	if typ == gvxipc.Error {
		return nil, bridgeFailure(payload, limits.Control())
	}
	if typ != gvxipc.OpenOK {
		return nil, fmt.Errorf("%w: expected OPEN_OK", gvxipc.ErrInvalidFrame)
	}
	i.endpoint = newStream()
	i.startupPhase = "await-worker-authorization"
	b.watch(i, codec, limits.Control())
	return handshake, nil
}
