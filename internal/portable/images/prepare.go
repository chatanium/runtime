package images

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/provision"
)

func verifyProgram(path, wantDigest, arch string) error {
	lstat, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !lstat.Mode().IsRegular() || !plainEntry(lstat) || lstat.Size() <= 0 || lstat.Size() > maxProgramBytes {
		return errors.New("portable program is not a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(info, lstat) {
		return errors.New("verified portable program changed identity")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, info.Size()+1))
	if err != nil || n != info.Size() || "sha256:"+hex.EncodeToString(h.Sum(nil)) != wantDigest {
		return errors.New("portable program digest mismatch")
	}
	if arch == "" {
		return nil
	}
	// Only after authenticating from the bundle is it safe to inspect ELF.
	e, err := elf.NewFile(f)
	if err != nil {
		return err
	}
	defer e.Close()
	machine := elf.EM_X86_64
	if arch == "arm64" {
		machine = elf.EM_AARCH64
	}
	if e.Class != elf.ELFCLASS64 || e.Data != elf.ELFDATA2LSB || e.Machine != machine || e.Type != elf.ET_EXEC && e.Type != elf.ET_DYN || runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0 {
		return errors.New("guest program is not an executable same-ISA Linux ELF64")
	}
	for _, seg := range e.Progs {
		if seg.Type == elf.PT_INTERP {
			return errors.New("trusted portable guest program cannot require an ELF interpreter")
		}
	}
	return nil
}

// GVX control credentials are generated as 64 hex digits. Neither registry
// credentials nor source bytes are sent to the engine during startup.
var controlCredential = regexp.MustCompile(`[a-fA-F0-9]{64,}`)

func withDiagnostic(reason error, label string, data []byte) error {
	if len(data) == 0 {
		return reason
	}
	text := controlCredential.ReplaceAllString(string(data), "[redacted]")
	return errors.Join(reason, fmt.Errorf("%s: %s", label, strconv.QuoteToASCII(text)))
}

// Prepare consumes approved bytes only after the owned engine reports its
// no-network state. On uncertain native exit the preparation reservation and
// its files survive for the caller's CLEANUP_PENDING recovery.
func (p Preparer) Prepare(ctx context.Context, plan Plan, offline io.Reader) (_ Generation, retErr error) {
	var zero Generation
	digest, err := plan.Digest()
	if err != nil {
		return zero, err
	}
	if err = p.validate(plan); err != nil {
		return zero, err
	}
	if plan.Source.Kind == "registry" && offline != nil || plan.Source.Kind != "registry" && offline == nil {
		return zero, errors.New("approved image source and supplied stream differ")
	}
	for _, program := range []struct{ path, digest, arch string }{{p.Engine, plan.EngineDigest, ""}, {p.GuestPreparer, plan.PreparerDigest, plan.Architecture}, {p.GuestCompiler, plan.CompilerDigest, plan.Architecture}} {
		if err = verifyProgram(program.path, program.digest, program.arch); err != nil {
			return zero, fmt.Errorf("verify installed preparation program: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, plan.Limits.Deadline)
	defer cancel()
	root := p.Root
	parent := filepath.Join("images", p.Epoch)
	for _, dir := range []string{"preparations", "images", parent} {
		if err = root.Mkdir(dir, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
			return zero, err
		}
		if err = directoryNoLinks(root, dir); err != nil {
			return zero, err
		}
	}
	final := generationPath(p.Epoch, p.GenerationID)
	if _, err = root.Lstat(final); !errors.Is(err, fs.ErrNotExist) {
		return zero, errors.Join(errors.New("portable image reservation is already published or inaccessible"), err, process.ErrUnobserved)
	}
	job := filepath.Join("preparations", p.PreparationID)
	if err = root.Mkdir(job, 0700); err != nil {
		return zero, err
	}
	var child PreparationProcess
	settled := true
	publish := filepath.Join(job, "publish")
	var pendingFiles []provision.FileIntegrity
	defer func() {
		if child != nil && !settled {
			stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			stopErr := child.Stop(stopCtx, nil)
			stopCancel()
			if errors.Is(stopErr, process.ErrUnobserved) || stopErr != nil {
				retErr = errors.Join(retErr, stopErr, process.ErrUnobserved)
				return
			}
			settled = true
		}
		if !settled {
			return
		}
		// The output directory may already have been atomically promoted.
		if _, err := root.Lstat(publish); err == nil {
			_ = root.Chmod(publish, 0700)
			if len(pendingFiles) > 0 {
				for _, f := range pendingFiles {
					_ = root.Chmod(filepath.Join(publish, f.Path), 0600)
				}
			}
		}
		if err := root.RemoveAll(job); err != nil {
			retErr = errors.Join(retErr, err, process.ErrUnobserved)
		}
	}()
	cache := filepath.Join(job, "bootstrap-cache")
	for _, dir := range []string{cache, publish} {
		if err = root.Mkdir(dir, 0700); err != nil {
			return zero, err
		}
	}
	inputR, inputW, err := os.Pipe()
	if err != nil {
		return zero, err
	}
	defer inputR.Close()
	defer inputW.Close()
	outputR, outputW, err := os.Pipe()
	if err != nil {
		return zero, err
	}
	defer outputR.Close()
	defer outputW.Close()
	diagR, diagW, err := os.Pipe()
	if err != nil {
		return zero, err
	}
	defer diagR.Close()
	defer diagW.Close()
	closeStreams := func() { inputW.Close(); outputR.Close(); diagR.Close() }
	stopWatch := context.AfterFunc(ctx, closeStreams)
	defer stopWatch()
	diagnostics := make(chan []byte, 1)
	go func() {
		const capBytes = 16 << 10
		data, err := io.ReadAll(io.LimitReader(diagR, capBytes+1))
		if len(data) > capBytes {
			cancel()
		}
		if len(data) > capBytes || err != nil && len(data) != 0 {
			// Drop the partial line so the byte cap cannot split a credential
			// and leave a long prefix outside the redaction pattern.
			const suffix = "[diagnostic truncated]\n"
			keep := bytes.LastIndexByte(data[:min(len(data), capBytes-len(suffix))], '\n') + 1
			data = append(data[:keep], suffix...)
		}
		diagnostics <- data
	}()
	launch := PreparationLaunch{Engine: p.Engine, GuestPreparer: p.GuestPreparer, GuestCompiler: p.GuestCompiler, Supervisor: p.Supervisor,
		Directory: filepath.Join(root.Name(), job), CacheDir: filepath.Join(root.Name(), cache), Architecture: plan.Architecture,
		InstallationID: p.InstallationID, Epoch: p.Epoch, JobID: p.PreparationID, PlanDigest: digest, Limits: plan.Limits, ScratchBytes: plan.scratchBytes(),
		Stdin: inputR, Stdout: outputW, Stderr: diagW}
	child, err = p.Start(ctx, launch)
	inputR.Close()
	outputW.Close()
	diagW.Close()
	if err != nil {
		settled = child == nil && !errors.Is(err, process.ErrUnobserved)
		if settled {
			err = withDiagnostic(err, "GVX startup diagnostic", <-diagnostics)
		}
		return zero, err
	}
	if child == nil {
		settled = false
		return zero, process.ErrUnobserved
	}
	settled = false
	prepErr := func(reason error) error {
		select {
		case b := <-diagnostics:
			reason = withDiagnostic(reason, "isolated guest diagnostic", b)
		default:
		}
		return errors.Join(reason, ctx.Err())
	}
	task := provision.PortableTask{Kind: plan.Source.Kind, Digest: plan.Source.Digest, PlanDigest: digest, Architecture: plan.Architecture, Limits: plan.Limits}
	if err = provision.WritePortableJSON(inputW, task, provision.TaskMaxBytes); err != nil {
		return zero, prepErr(err)
	}
	var offlineDone chan error
	if offline != nil {
		offlineDone = make(chan error, 1)
		go func() {
			h := sha256.New()
			n, err := io.Copy(io.MultiWriter(inputW, h), io.LimitReader(offline, plan.Limits.InputBytes+1))
			if err == nil && (n <= 0 || n > plan.Limits.InputBytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != plan.Source.Digest) {
				err = errors.New("offline source length or digest mismatch")
			}
			offlineDone <- errors.Join(err, inputW.Close())
		}()
	}
	output := bufio.NewReader(outputR)
	if err = readRequests(ctx, root, job, plan, output, inputW); err != nil {
		return zero, prepErr(err)
	}
	if offlineDone != nil {
		select {
		case err = <-offlineDone:
			if err != nil {
				return zero, prepErr(err)
			}
		case <-ctx.Done():
			return zero, ctx.Err()
		}
	} else {
		inputW.Close()
	}
	var record provision.PortableRecord
	if err = provision.ReadPortableJSON(output, &record, plan.Limits.JSONBytes*4); err != nil {
		return zero, prepErr(err)
	}
	if err = record.Validate(task); err != nil {
		return zero, err
	}
	format := cacheFormat()
	if record.CacheFormat != format {
		return zero, errors.New("guest compiler cache format is incompatible with the host engine")
	}
	block, err := provision.CacheBlockSize(format)
	if err != nil {
		return zero, err
	}
	name, ref, metadata, err := canonicalMetadata(plan.Architecture, format, record.Layers)
	if err != nil {
		return zero, err
	}
	remaining := plan.Limits.OutputBytes
	seen := make(map[string]bool, len(record.Layers))
	for _, layer := range record.Layers {
		if seen[layer.Digest] {
			continue
		}
		seen[layer.Digest] = true
		base := layerName(layer.Digest, format)
		n, err := provision.ReadPortableSize(output, remaining)
		if err != nil {
			return zero, prepErr(err)
		}
		if n < int64(block) || n%int64(block) != 0 {
			return zero, errors.New("invalid compiled EROFS length")
		}
		f, err := createFrozen(root, filepath.Join(publish, base), output, n)
		if err != nil {
			return zero, prepErr(err)
		}
		pendingFiles = append(pendingFiles, f)
		sum, err := freezeBytes(root, publish, base+".sum", []byte(fmt.Sprintf("%s %d %s\n", format, f.Size, f.Digest[7:])))
		if err != nil {
			return zero, err
		}
		pendingFiles = append(pendingFiles, sum)
		remaining -= n
	}
	if _, err = output.ReadByte(); err != io.EOF {
		return zero, prepErr(errors.New("unexpected trailing preparation output"))
	}
	wait := make(chan error, 1)
	go func() { wait <- child.Wait() }()
	select {
	case err = <-wait:
		if err != nil {
			return zero, prepErr(err)
		}
		settled = true
	case <-ctx.Done():
		return zero, ctx.Err()
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	jsonFile, err := freezeBytes(root, publish, name, metadata)
	if err != nil {
		return zero, err
	}
	pendingFiles = append(pendingFiles, jsonFile)
	sortInventory(pendingFiles)
	g := Generation{ID: p.GenerationID, Epoch: p.Epoch, PlanDigest: digest, SourceDigest: record.SourceDigest, ManifestDigest: record.ManifestDigest, DeclarationDigest: provision.Digest(record.Declaration), ExecutionRef: ref, Directory: final, Architecture: plan.Architecture, Format: format, Declaration: record.Declaration, ImageEnv: record.ImageEnv, Entrypoint: record.Entrypoint, Cmd: record.Cmd, Workdir: record.Workdir, Layers: record.Layers, Files: pendingFiles}
	if g.Digest, err = g.identity(); err != nil {
		return zero, err
	}
	// Keep the staging directory owner-writable through the cross-parent
	// rename: Linux updates its ".." entry. Its files are already read-only
	// and synced; the ledger cannot publish until final directory sealing.
	staged, err := imageDirectoryIdentity(root, publish)
	if err != nil {
		return zero, err
	}
	if err = syncDir(root, publish); err != nil {
		return zero, err
	}
	if err = renameImageNoReplace(root, publish, final); err != nil {
		e := &os.LinkError{Op: "publish image cache", Old: publish, New: final, Err: err}
		if _, statErr := root.Lstat(final); !errors.Is(statErr, fs.ErrNotExist) {
			return zero, errors.Join(e, statErr, process.ErrUnobserved)
		}
		return zero, e
	}
	moved, err := imageDirectoryIdentity(root, final)
	if err != nil || !os.SameFile(staged, moved) {
		return zero, errors.Join(errors.New("cache directory identity changed during promotion"), err, process.ErrUnobserved)
	}
	err = root.Chmod(final, 0555)
	if err == nil {
		err = errors.Join(syncDir(root, final), syncDir(root, parent), syncDir(root, "images"), syncDir(root, job), syncDir(root, "preparations"), syncDir(root, "."))
	}
	if err != nil {
		rollback := g.Remove(root, p.Epoch)
		if rollback == nil {
			rollback = syncDir(root, parent)
		}
		if rollback != nil {
			rollback = errors.Join(rollback, process.ErrUnobserved)
		}
		return zero, errors.Join(err, rollback)
	}
	return g, nil
}

func readRequests(ctx context.Context, root *os.Root, job string, plan Plan, output *bufio.Reader, input io.Writer) error {
	var registry *registrySource
	if plan.Source.Kind == "registry" {
		repo, err := parseRepository(plan.Source)
		if err != nil {
			return err
		}
		client, err := registryClient()
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		f, err := root.OpenFile(filepath.Join(job, "registry-object"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		registry = &registrySource{source: plan.Source, repo: repo, client: client, staging: f}
	}
	var requests int64
	remaining := plan.Limits.InputBytes
	limit := min(plan.Limits.Inodes, plan.Limits.DescriptorCount*3+2)
	for {
		kind, err := output.ReadByte()
		if err != nil {
			return err
		}
		if kind == provision.PortableResult {
			if registry != nil && requests == 0 {
				return errors.New("registry preparation omitted the approved source digest")
			}
			return nil
		}
		if registry == nil || kind != provision.PortableFetchBlob && kind != provision.PortableFetchManifest || requests >= limit {
			return errors.New("unexpected or over-budget preparer registry request")
		}
		bound := remaining
		if kind == provision.PortableFetchManifest {
			bound = min(bound, plan.Limits.JSONBytes)
		}
		digest, expected, err := provision.ReadPortableFetch(output, bound)
		if err != nil {
			return err
		}
		if requests == 0 && (kind != provision.PortableFetchManifest || digest != plan.Source.Digest || expected != 0) || requests > 0 && expected == 0 {
			return errors.New("preparer registry requests must begin with the approved manifest digest")
		}
		used, err := registry.fetch(ctx, kind, digest, expected, bound, input)
		if err != nil {
			return err
		}
		remaining -= used
		requests++
	}
}
