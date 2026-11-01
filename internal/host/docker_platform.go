package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

const ownershipLabel = "io.chatanium.flexmodule.owner"

type DockerConfig struct {
	Endpoint      string `json:"endpoint"`
	EngineVersion string `json:"engine_version"`
	RuntimeName   string `json:"runtime_name"`
	RunscPath     string `json:"runsc_path"`
	RunscVersion  string `json:"runsc_version"`
	RunscSHA256   string `json:"runsc_sha256"`
	// Exact per-file hashes of the complete release, including shim and gvisor-bin.
	RunscFiles          map[string]string `json:"runsc_files"`
	APIDeadline         time.Duration     `json:"api_deadline"`
	TerminationDeadline time.Duration     `json:"termination_deadline"`
	Network             NetworkConfig     `json:"network"`
}
type DockerPlatform struct {
	mu              sync.Mutex
	cfg             DockerConfig
	docker          *client.Client
	createDocker    *client.Client
	images          *client.Client
	imageTransport  *http.Transport
	createTransport *http.Transport
	instances       map[string]*dockerInstance
	network         *networkPolicy
	creates         CreateJournal
}
type dockerInstance struct {
	cleanup       sync.Mutex
	ownership     Ownership
	spec          LaunchSpec
	lease         Lease
	imageID       string
	attach        client.ContainerAttachResult
	collectorDone chan struct{}
	collectorErr  error
	stdout        *os.File
	logs          *logRotation
	network       *ownedNetwork
	stopping      atomic.Bool
}

func NewDockerPlatform(cfg DockerConfig) (*DockerPlatform, error) {
	if !strings.HasPrefix(cfg.Endpoint, "unix:///") || cfg.EngineVersion == "" || cfg.RuntimeName == "" || cfg.RunscVersion == "" || cfg.APIDeadline <= 0 || cfg.TerminationDeadline <= 0 {
		return nil, invalid("exact local Docker/runsc configuration and finite deadlines required")
	}
	// Keep the SDK's concrete base transport for bounded attach/hijack dialing.
	// Only create and network requests need the response-body receipt wrapper.
	cli, err := client.New(client.WithHost(cfg.Endpoint))
	if err != nil {
		return nil, err
	}
	createDocker, createTransport, err := newCreateClient(cfg.Endpoint)
	if err != nil {
		cli.Close()
		return nil, err
	}
	images, transport, err := newBoundedImageClient(cfg.Endpoint)
	if err != nil {
		cli.Close()
		createDocker.Close()
		createTransport.CloseIdleConnections()
		return nil, err
	}
	policy, err := newNetworkPolicy(createDocker, cfg.Network, cfg.APIDeadline)
	if err != nil {
		cli.Close()
		createDocker.Close()
		createTransport.CloseIdleConnections()
		images.Close()
		transport.CloseIdleConnections()
		return nil, err
	}
	return &DockerPlatform{cfg: cfg, docker: cli, createDocker: createDocker, images: images, imageTransport: transport, createTransport: createTransport, instances: make(map[string]*dockerInstance), network: policy}, nil
}
func (p *DockerPlatform) BindCreateJournal(j CreateJournal) error {
	if j == nil {
		return invalid("durable Docker create journal is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.creates != nil {
		return invalid("Docker create journal is already bound")
	}
	p.network.mu.Lock()
	defer p.network.mu.Unlock()
	p.creates = j
	p.network.creates = j
	return nil
}
func (p *DockerPlatform) Preflight(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.APIDeadline)
	defer cancel()
	info, err := p.docker.Info(ctx, client.InfoOptions{})
	if err != nil {
		return prerequisite(err)
	}
	if info.Info.ServerVersion != p.cfg.EngineVersion || info.Info.OSType != "linux" || info.Info.CgroupVersion != "2" || !info.Info.MemoryLimit || !info.Info.SwapLimit || !info.Info.PidsLimit || !info.Info.CPUCfsQuota {
		return prerequisite(errors.New("Docker version/cgroup hard-limit support mismatch"))
	}
	for _, s := range info.Info.SecurityOptions {
		if strings.Contains(s, "rootless") || strings.Contains(s, "userns") {
			return prerequisite(errors.New("rootful non-remapped deployment required"))
		}
	}
	rt, ok := info.Info.Runtimes[p.cfg.RuntimeName]
	if !ok || rt.Path != p.cfg.RunscPath {
		return prerequisite(errors.New("registered runsc executable mismatch"))
	}
	// Both phases must retain the OCI quota rather than runsc's elevated defaults.
	requiredArgs := []string{"--platform=systrap", "--host-uds=create", "--file-access-mounts=shared", "--overlay2=root:self", "--sandbox-creation-cpu-policy=1x", "--sandbox-lifecycle-cpu-policy=1x"}
	if info.Info.CgroupDriver == "systemd" {
		requiredArgs = append(requiredArgs, "--systemd-cgroup")
	} else if info.Info.CgroupDriver != "cgroupfs" {
		return prerequisite(errors.New("unsupported cgroup driver"))
	}
	for _, arg := range requiredArgs {
		if !slices.Contains(rt.Args, arg) {
			return prerequisite(errors.New("registered runsc isolation flags mismatch"))
		}
	}
	if len(rt.Args) != len(requiredArgs) {
		return prerequisite(errors.New("unapproved extra runsc arguments"))
	}
	if err := verifyPinnedExecutable(p.cfg.RunscPath, p.cfg.RunscSHA256); err != nil {
		return prerequisite(err)
	}
	if len(p.cfg.RunscFiles) < 3 {
		return prerequisite(errors.New("complete pinned runsc release manifest required"))
	}
	shim, sidecars := false, false
	for name, sum := range p.cfg.RunscFiles {
		if name == "containerd-shim-runsc-v1" {
			shim = true
		}
		if strings.HasPrefix(name, "gvisor-bin/") {
			sidecars = true
		}
		if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.HasPrefix(name, "../") {
			return invalid("invalid runsc release manifest path")
		}
		if err := verifyPinnedExecutable(filepath.Join(filepath.Dir(p.cfg.RunscPath), name), sum); err != nil {
			return prerequisite(err)
		}
	}
	if !shim || !sidecars {
		return prerequisite(errors.New("runsc shim and sidecar closure missing"))
	}
	if err := verifyRunscSidecars(filepath.Dir(p.cfg.RunscPath), p.cfg.RunscFiles); err != nil {
		return prerequisite(err)
	}
	out, err := boundedCommand(ctx, p.cfg.RunscPath, []string{"--version"}, nil, 4096)
	versionLine := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if err != nil || versionLine != "runsc version "+p.cfg.RunscVersion {
		return prerequisite(errors.New("runsc version mismatch"))
	}
	if err := p.network.preflight(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	live := make([]*dockerInstance, 0, len(p.instances))
	for _, i := range p.instances {
		live = append(live, i)
	}
	p.mu.Unlock()
	for _, i := range live {
		if err := p.preflightInstance(ctx, i); err != nil {
			return prerequisite(err)
		}
	}
	return nil
}
func (p *DockerPlatform) preflightInstance(ctx context.Context, i *dockerInstance) error {
	i.cleanup.Lock()
	defer i.cleanup.Unlock()
	c, err := p.inspect(ctx, i.ownership)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return p.recordFailure(i.ownership, PhaseRunning, err, FailureInspect)
	}
	if err := p.verifyContainer(c, i); err != nil {
		return p.recordFailure(i.ownership, PhaseRunning, err, FailureIsolation)
	}
	if c.State != nil && c.State.Running {
		select {
		case <-i.collectorDone:
			return p.recordFailure(i.ownership, PhaseRunning, classifiedFailure(FailureAttachEOF, nil), FailureAttachEOF)
		default:
		}
		if i.network != nil {
			if err := p.network.verifyEndpoint(ctx, i.network); err != nil {
				return p.recordFailure(i.ownership, PhaseRunning, err, FailureNetwork)
			}
		}
		return p.recordFailure(i.ownership, PhaseRunning, verifyCgroups(c.State.Pid, i.spec.Resources), FailureCgroupMembership)
	}
	return nil
}
func verifyPinnedExecutable(path, sum string) error {
	if !filepath.IsAbs(path) || len(sum) != 64 {
		return errors.New("absolute executable and SHA256 pin required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 {
		return errors.New("pinned executable must be root-owned and not writable by others")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, f); err != nil {
		return err
	}
	if hex.EncodeToString(digest.Sum(nil)) != strings.ToLower(sum) {
		return errors.New("pinned executable digest mismatch")
	}
	return nil
}
func verifyRunscSidecars(root string, manifest map[string]string) error {
	return filepath.WalkDir(filepath.Join(root, "gvisor-bin"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in pinned runsc sidecar closure")
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		if st.Uid != 0 || st.Mode&0022 != 0 {
			return errors.New("runsc sidecar closure is not administrator-owned")
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum, exists := manifest[relative]
		if !exists {
			return errors.New("unmanifested runsc sidecar")
		}
		return verifyPinnedExecutable(path, sum)
	})
}
func (p *DockerPlatform) Create(ctx context.Context, spec LaunchSpec, lease Lease, env []string, socketDir string) (*Container, error) {
	if err := p.Preflight(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.instances[lease.Ownership.InstanceID]; ok {
		return nil, invalid("instance already created")
	}
	if p.creates == nil {
		return nil, prerequisite(errors.New("durable Docker create journal is not bound"))
	}
	if spec.UID == 0 || spec.GID == 0 || len(spec.Entrypoint) == 0 || !filepath.IsAbs(spec.Entrypoint[0]) || spec.Resources.Pids <= 0 || spec.Resources.NanoCPUs <= 0 || spec.Resources.MemoryBytes <= 0 {
		return nil, invalid("invalid trusted process profile")
	}
	if _, err := collectorWorkspace(spec.Resources); err != nil {
		return nil, err
	}
	if filepath.Dir(socketDir) != lease.IPCPath {
		return nil, invalid("socket directory outside IPC lease")
	}
	if spec.InitialEgress != EgressNone && spec.InitialEgress != EgressPublicInternet {
		return nil, invalid("explicit initial egress candidate required")
	}
	api, cancel := context.WithTimeout(ctx, p.cfg.APIDeadline)
	defer cancel()
	image, err := p.inspectPinnedImage(api, spec.ImageDigest, spec.Resources.ControlMessageMaxBytes)
	if err != nil {
		return nil, err
	}
	if len(image.Config.Volumes) != 0 {
		return nil, prerequisite(errors.New("unapproved image volume declaration"))
	}
	for _, entry := range image.Config.Env {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PLUGIN_") || key == "FLEXMODULE_PLUGIN" || key == "TMPDIR" {
			return nil, invalid("image shadows reserved bootstrap environment")
		}
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		return nil, err
	}
	stderrW.Close()
	logs, err := newLogRotation(lease.LogPath, spec.Resources.LogFileMaxBytes, spec.Resources.LogRetainedFiles)
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		stderrR.Close()
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			stdoutR.Close()
			stdoutW.Close()
			stderrR.Close()
			logs.Close()
		}
	}()
	resolver, err := p.network.resolverFile(lease.LogPath)
	if err != nil {
		return nil, err
	}
	mounts := []mount.Mount{}
	for _, pair := range [][2]string{{lease.PersistentPath, GuestPersistentPath}, {lease.ScratchPath, GuestScratchPath}, {lease.IPCPath, GuestIPCPath}} {
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: pair[0], Target: pair[1], BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}})
	}
	mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: resolver, Target: "/etc/resolv.conf", ReadOnly: true, BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}})
	pids := spec.Resources.Pids
	mode := container.NetworkMode("none")
	var prepared *ownedNetwork
	var topology *network.NetworkingConfig
	if spec.InitialEgress == EgressPublicInternet {
		prepared, err = p.network.prepare(api, lease.Ownership)
		if err != nil {
			return nil, err
		}
		mode = container.NetworkMode(prepared.id)
		topology = &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{prepared.name: {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: prepared.ipv4, IPv6Address: prepared.ipv6, LinkLocalIPs: []netip.Addr{prepared.linkLocal6}}}}}
	}
	resolvers := make([]netip.Addr, len(p.cfg.Network.Resolvers))
	for index, address := range p.cfg.Network.Resolvers {
		resolvers[index] = netip.MustParseAddr(address)
	}
	if err := p.creates.SubmitCreate(api, lease.Ownership, CreateContainer, containerName(lease.Ownership)); err != nil {
		return nil, err
	}
	createAPI, receipt := createRequest(api, CreateContainer, containerName(lease.Ownership))
	result, err := p.createDocker.ContainerCreate(createAPI, client.ContainerCreateOptions{
		Name:   containerName(lease.Ownership),
		Config: &container.Config{Image: spec.ImageDigest, Entrypoint: spec.Entrypoint, Cmd: spec.Args, Env: env, User: fmt.Sprintf("%d:%d", spec.UID, spec.GID), WorkingDir: GuestScratchPath, Tty: false, AttachStdout: true, AttachStderr: true, Labels: ownershipLabels(lease.Ownership)},
		HostConfig: &container.HostConfig{
			Runtime: p.cfg.RuntimeName, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"},
			NetworkMode: mode, IpcMode: "none", CgroupnsMode: "private", GroupAdd: []string{strconv.FormatUint(uint64(lease.SocketGID), 10)},
			DNS: resolvers, DNSSearch: []string{"."},
			RestartPolicy: container.RestartPolicy{Name: "no"}, LogConfig: container.LogConfig{Type: "none"}, Mounts: mounts,
			Resources: container.Resources{NanoCPUs: spec.Resources.NanoCPUs, Memory: spec.Resources.MemoryBytes, MemorySwap: spec.Resources.MemoryBytes, PidsLimit: &pids, Ulimits: []*container.Ulimit{{Name: "nproc", Soft: pids, Hard: pids}}},
		},
		NetworkingConfig: topology,
	})
	if err != nil {
		return nil, recordCreateRejection(err, receipt, p.creates, lease.Ownership, p.cfg.APIDeadline)
	}
	own := lease.Ownership
	own.ContainerID = result.ID
	created, inspectErr := p.inspect(api, own)
	if inspectErr != nil {
		return nil, inspectErr
	}
	if created.ID != result.ID {
		return nil, errors.New("created container ID mismatch")
	}
	if err := p.creates.ObserveCreated(api, own, CreateContainer, containerName(own), result.ID); err != nil {
		return nil, err
	}
	if prepared != nil {
		p.network.bindContainer(prepared, own)
	}
	instance := &dockerInstance{ownership: own, spec: spec, lease: lease, imageID: image.ID, stdout: stdoutW, logs: logs, network: prepared, collectorDone: make(chan struct{})}
	p.instances[own.InstanceID] = instance
	attached, err := p.docker.ContainerAttach(api, result.ID, client.ContainerAttachOptions{Stream: true, Stdout: true, Stderr: true})
	if err != nil {
		close(instance.collectorDone)
		return nil, err
	}
	instance.attach = attached
	guestDir := filepath.Join(GuestIPCPath, filepath.Base(socketDir))
	go func() {
		err := collectDockerOutput(attached.Reader, stdoutW, logs, spec.Resources, guestDir)
		if closeErr := logs.Close(); err == nil && closeErr != nil {
			err = classifiedFailure(FailureLogSink, closeErr)
		}
		if err == nil && !instance.stopping.Load() {
			observation, stopObservation := context.WithTimeout(context.Background(), p.cfg.APIDeadline)
			c, inspectErr := p.inspect(observation, own)
			stopObservation()
			if inspectErr == nil && c.State != nil && c.State.Running {
				err = classifiedFailure(FailureAttachEOF, nil)
			} else if inspectErr != nil && !errdefs.IsNotFound(inspectErr) {
				err = classifiedFailure(FailureInspect, inspectErr)
			}
		}
		p.mu.Lock()
		instance.collectorErr = err
		p.mu.Unlock()
		// Persist the safe first cause before EOF or cleanup can trigger another
		// failure path. Expected attach closure during teardown is not a failure.
		if err != nil && !instance.stopping.Load() {
			err = p.recordFailure(own, PhaseAttach, err, FailureAttachRead)
		}
		stdoutW.Close()
		close(instance.collectorDone)
		if err != nil && !instance.stopping.Load() {
			cleanup, cancel := context.WithTimeout(context.Background(), p.cfg.TerminationDeadline)
			defer cancel()
			p.Terminate(cleanup, own)
		}
	}()
	failed = false
	return &Container{ID: result.ID, Stdout: stdoutR, Stderr: stderrR}, nil
}
func ownershipLabels(o Ownership) map[string]string {
	return map[string]string{ownershipLabel: "v2", "io.chatanium.flexmodule.installation": o.InstallationID, "io.chatanium.flexmodule.epoch": o.EpochID, "io.chatanium.flexmodule.instance": o.InstanceID}
}
func containerName(o Ownership) string {
	sum := sha256.Sum256([]byte(o.InstallationID + "\x00" + o.EpochID + "\x00" + o.InstanceID))
	return "flexmodule-" + hex.EncodeToString(sum[:16])
}
func verifyOwnership(c container.InspectResponse, o Ownership) error {
	if c.Config == nil {
		return errors.New("container has no ownership labels")
	}
	for key, value := range ownershipLabels(o) {
		if c.Config.Labels[key] != value {
			return errors.New("container ownership mismatch")
		}
	}
	return nil
}
func (p *DockerPlatform) inspect(ctx context.Context, o Ownership) (container.InspectResponse, error) {
	id := o.ContainerID
	if id == "" {
		id = containerName(o)
	}
	c, err := p.docker.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return container.InspectResponse{}, err
	}
	if err := verifyOwnership(c.Container, o); err != nil {
		return container.InspectResponse{}, err
	}
	return c.Container, nil
}
func (p *DockerPlatform) Start(ctx context.Context, o Ownership) error {
	p.mu.Lock()
	i := p.instances[o.InstanceID]
	p.mu.Unlock()
	if i == nil {
		return errors.New("bounded attach not prepared")
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.APIDeadline)
	defer cancel()
	c, err := p.inspect(ctx, o)
	if err != nil {
		return p.recordFailure(o, PhasePrestart, err, FailureInspect)
	}
	if err := p.verifyContainer(c, i); err != nil {
		return p.recordFailure(o, PhasePrestart, err, FailureIsolation)
	}
	if _, err := p.docker.ContainerStart(ctx, c.ID, client.ContainerStartOptions{}); err != nil {
		return p.recordFailure(o, PhaseStart, err, FailureStartAPI)
	}
	if i.network != nil {
		if err := p.network.verifyEndpoint(ctx, i.network); err != nil {
			return p.recordFailure(o, PhasePoststart, err, FailureNetwork)
		}
	}
	c, err = p.inspect(ctx, o)
	if err != nil {
		return p.recordFailure(o, PhasePoststart, err, FailureInspect)
	}
	if c.State == nil || !c.State.Running {
		return p.recordFailure(o, PhasePoststart, classifiedFailure(FailureNotRunning, nil), FailureNotRunning)
	}
	return p.recordFailure(o, PhasePoststart, verifyCgroups(c.State.Pid, i.spec.Resources), FailureCgroupMembership)
}
func (p *DockerPlatform) verifyContainer(c container.InspectResponse, i *dockerInstance) error {
	h := c.HostConfig
	r := i.spec.Resources
	expectedMode := container.NetworkMode("none")
	if i.network != nil {
		expectedMode = container.NetworkMode(i.network.id)
	}
	if h == nil || c.Config == nil || h.Runtime != p.cfg.RuntimeName || !h.ReadonlyRootfs || h.Privileged || h.LogConfig.Type != "none" || c.Config.Tty || h.NetworkMode != expectedMode || h.PidMode != "" || h.IpcMode != "none" || !slices.Equal(h.CapDrop, []string{"ALL"}) || len(h.CapAdd) != 0 || !slices.Contains(h.SecurityOpt, "no-new-privileges=true") || h.Memory != r.MemoryBytes || h.MemorySwap != r.MemoryBytes || h.NanoCPUs != r.NanoCPUs || h.PidsLimit == nil || *h.PidsLimit != r.Pids || len(h.Ulimits) != 1 || h.Ulimits[0].Name != "nproc" || h.Ulimits[0].Hard != r.Pids || h.Ulimits[0].Soft != r.Pids || len(c.Mounts) != 4 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.PortBindings) != 0 || h.PublishAllPorts || len(h.Tmpfs) != 0 {
		return classifiedFailure(FailureIsolation, nil)
	}
	if c.Config.User != fmt.Sprintf("%d:%d", i.spec.UID, i.spec.GID) || h.CgroupnsMode != "private" || !slices.Equal(h.GroupAdd, []string{strconv.FormatUint(uint64(i.lease.SocketGID), 10)}) || len(h.ExtraHosts) != 0 || len(h.Links) != 0 || len(h.VolumesFrom) != 0 || len(h.DeviceCgroupRules) != 0 || h.AutoRemove || h.RestartPolicy.Name != "no" {
		return classifiedFailure(FailureIdentity, nil)
	}
	if c.Image != i.imageID || c.Config.Image != i.spec.ImageDigest || !slices.Equal(c.Config.Entrypoint, i.spec.Entrypoint) || !slices.Equal(c.Config.Cmd, i.spec.Args) {
		return classifiedFailure(FailureImage, nil)
	}
	if len(h.DNS) != len(p.cfg.Network.Resolvers) || !slices.Equal(h.DNSSearch, []string{"."}) {
		return classifiedFailure(FailureDNS, nil)
	}
	for index, address := range p.cfg.Network.Resolvers {
		if h.DNS[index] != netip.MustParseAddr(address) {
			return classifiedFailure(FailureDNS, nil)
		}
	}
	expected := map[string]string{GuestPersistentPath: i.lease.PersistentPath, GuestScratchPath: i.lease.ScratchPath, GuestIPCPath: i.lease.IPCPath, "/etc/resolv.conf": filepath.Join(i.lease.LogPath, "resolv.conf")}
	for _, m := range c.Mounts {
		source, ok := expected[m.Destination]
		if !ok || source != m.Source || m.Type != mount.TypeBind || m.RW == (m.Destination == "/etc/resolv.conf") {
			return classifiedFailure(FailureMount, nil)
		}
		delete(expected, m.Destination)
	}
	if len(expected) != 0 {
		return classifiedFailure(FailureMount, nil)
	}
	if c.State != nil && c.State.Running {
		name := "none"
		if i.network != nil {
			name = i.network.name
		}
		if c.NetworkSettings == nil || len(c.NetworkSettings.Networks) != 1 || c.NetworkSettings.Networks[name] == nil {
			return classifiedFailure(FailureNetwork, nil)
		}
		endpoint := c.NetworkSettings.Networks[name]
		if i.network == nil {
			if endpoint.IPAddress.IsValid() || endpoint.GlobalIPv6Address.IsValid() {
				return classifiedFailure(FailureNetwork, nil)
			}
		} else if endpoint.NetworkID != i.network.id || endpoint.IPAddress != i.network.ipv4 || endpoint.GlobalIPv6Address != i.network.ipv6 {
			return classifiedFailure(FailureNetwork, nil)
		}
	}
	return nil
}
func verifyCgroups(pid int, r ResourceLimits) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return classifiedFailure(FailureCgroupMembership, err)
	}
	var relative string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::/") {
			relative = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if relative == "" || strings.Contains(relative, "..") {
		return classifiedFailure(FailureCgroupMembership, nil)
	}
	root := filepath.Join("/sys/fs/cgroup", relative)
	for _, check := range [...]struct {
		name, want     string
		read, mismatch FailureReason
	}{
		{"memory.max", strconv.FormatInt(r.MemoryBytes, 10), FailureCgroupMemoryRead, FailureCgroupMemory},
		{"memory.swap.max", "0", FailureCgroupSwapRead, FailureCgroupSwap},
		{"pids.max", strconv.FormatInt(r.Pids, 10), FailureCgroupPidsRead, FailureCgroupPids},
	} {
		got, err := os.ReadFile(filepath.Join(root, check.name))
		if err != nil {
			return classifiedFailure(check.read, err)
		}
		if strings.TrimSpace(string(got)) != check.want {
			return classifiedFailure(check.mismatch, nil)
		}
	}
	cpu, err := os.ReadFile(filepath.Join(root, "cpu.max"))
	if err != nil {
		return classifiedFailure(FailureCgroupCPURead, err)
	}
	fields := strings.Fields(string(cpu))
	if len(fields) != 2 {
		return classifiedFailure(FailureCgroupCPU, nil)
	}
	quota, e1 := strconv.ParseInt(fields[0], 10, 64)
	period, e2 := strconv.ParseInt(fields[1], 10, 64)
	if e1 != nil || e2 != nil || quota <= 0 || period <= 0 || quota*1000000000/period != r.NanoCPUs {
		return classifiedFailure(FailureCgroupCPU, nil)
	}
	return nil
}
func (p *DockerPlatform) Wait(ctx context.Context, o Ownership) (Exit, error) {
	c, err := p.inspect(ctx, o)
	if err != nil {
		return Exit{}, err
	}
	wait := p.docker.ContainerWait(ctx, c.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case <-ctx.Done():
		return Exit{}, ctx.Err()
	case err := <-wait.Error:
		return Exit{}, err
	case result := <-wait.Result:
		if result.Error != nil {
			return Exit{}, errors.New("Docker wait failed")
		}
		latest, err := p.inspect(ctx, o)
		if err != nil {
			return Exit{}, err
		}
		return Exit{Code: result.StatusCode, OOMKilled: latest.State != nil && latest.State.OOMKilled}, nil
	}
}
func (p *DockerPlatform) Terminate(ctx context.Context, o Ownership) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.TerminationDeadline)
	defer cancel()
	p.mu.Lock()
	i := p.instances[o.InstanceID]
	p.mu.Unlock()
	if i != nil {
		i.stopping.Store(true)
		i.cleanup.Lock()
		defer i.cleanup.Unlock()
	}
	var errs []error
	if p.creates == nil {
		return prerequisite(errors.New("durable Docker create journal is not bound"))
	}
	record, found, lookupErr := p.creates.LookupCreate(ctx, o, CreateContainer)
	if lookupErr != nil {
		errs = append(errs, lookupErr)
	} else if found && record.State == CreateObserved && o.ContainerID == "" {
		o.ContainerID = record.ObjectID
	}
	_, networkSubmitted, networkLookupErr := p.creates.LookupCreate(ctx, o, CreateNetwork)
	if networkLookupErr != nil {
		errs = append(errs, networkLookupErr)
	}
	// The supervisor holds the per-instance admission lock. With no durable
	// submission, no create was dispatched and none may start after this cleanup.
	// This is write-ahead evidence, not a point-in-time Docker absence check.
	if lookupErr == nil && !found {
		if i != nil {
			return errors.New("local container ownership has no submitted create")
		}
		if networkLookupErr != nil {
			return networkLookupErr
		}
		if !networkSubmitted {
			return nil
		}
		return errors.Join(p.network.revokeForCleanup(ctx, o), p.network.reconcile(ctx, o))
	}
	if networkLookupErr == nil && !networkSubmitted && i != nil && i.network != nil {
		errs = append(errs, errors.New("local network ownership has no submitted create"))
	}
	c, err := p.inspect(ctx, o)
	if err != nil && !errdefs.IsNotFound(err) {
		errs = append(errs, err)
	}
	var observationErr error
	if err == nil {
		observationErr = p.creates.ObserveCreated(ctx, o, CreateContainer, containerName(o), c.ID)
		if observationErr != nil {
			errs = append(errs, observationErr)
		}
		o.ContainerID = c.ID
	}
	if networkSubmitted {
		errs = append(errs, p.network.revokeForCleanup(ctx, o))
	}
	if err == nil {
		if c.State != nil && c.State.Running {
			if _, err := p.docker.ContainerKill(ctx, c.ID, client.ContainerKillOptions{Signal: "SIGKILL"}); err != nil && !errdefs.IsNotFound(err) {
				errs = append(errs, err)
			}
			_, err := p.Wait(ctx, o)
			errs = append(errs, err)
		}
		// Keep the object as durable-observation evidence if journaling failed.
		if observationErr == nil {
			if _, err := p.docker.ContainerRemove(ctx, c.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil && !errdefs.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
	}
	if i != nil {
		if i.attach.Conn != nil {
			i.attach.Close()
		}
		i.stdout.Close()
		select {
		case <-i.collectorDone:
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		}
	}
	// Topology is removed only after the process is proved absent. Revocation
	// above changes packets, not a running sentry's network configuration.
	if _, err := p.inspect(ctx, o); err == nil {
		return errors.Join(ErrCleanupIncomplete, errors.Join(errs...))
	} else if !errdefs.IsNotFound(err) {
		return errors.Join(err, errors.Join(errs...))
	}
	if err := requireCreateResolved(ctx, p.creates, o, CreateContainer, containerName(o)); err != nil {
		return errors.Join(err, errors.Join(errs...))
	}
	if networkSubmitted {
		if i != nil && i.network != nil {
			errs = append(errs, p.network.remove(ctx, i.network))
		} else {
			errs = append(errs, p.network.reconcile(ctx, o))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	p.mu.Lock()
	delete(p.instances, o.InstanceID)
	p.mu.Unlock()
	return nil
}
func (p *DockerPlatform) Reconcile(ctx context.Context, o Ownership) error {
	return p.Terminate(ctx, o)
}
func (p *DockerPlatform) SetEgress(ctx context.Context, o Ownership, policy EgressPolicy) error {
	p.mu.Lock()
	i := p.instances[o.InstanceID]
	p.mu.Unlock()
	if i == nil {
		return errors.New("unknown owned container")
	}
	i.cleanup.Lock()
	defer i.cleanup.Unlock()
	if policy == EgressNone {
		if i.network == nil {
			return nil
		}
		return p.network.disable(ctx, i.network)
	}
	if policy != EgressPublicInternet {
		return invalid("unknown egress policy")
	}
	if i.spec.InitialEgress != EgressPublicInternet || i.network == nil {
		return invalid("public egress cannot add an endpoint to initial NONE topology")
	}
	return p.network.enable(ctx, i.network)
}
func (p *DockerPlatform) Close() error {
	p.mu.Lock()
	owners := make([]Ownership, 0, len(p.instances))
	for _, i := range p.instances {
		owners = append(owners, i.ownership)
	}
	p.mu.Unlock()
	var errs []error
	for _, o := range owners {
		ctx, cancel := context.WithTimeout(context.Background(), p.cfg.TerminationDeadline)
		errs = append(errs, p.Terminate(ctx, o))
		cancel()
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	p.network.mu.Lock()
	watcher := p.network.watcher
	p.network.watcher = nil
	p.network.mu.Unlock()
	if watcher != nil {
		if err := watcher.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = append(errs, err)
		}
	}
	p.imageTransport.CloseIdleConnections()
	p.createTransport.CloseIdleConnections()
	errs = append(errs, p.images.Close(), p.createDocker.Close(), p.docker.Close())
	return errors.Join(errs...)
}
