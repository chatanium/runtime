package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type quotaRoot struct {
	kind               string
	path               string
	owned              string
	file               *os.File
	written            int64
	allocated          int64
	allocationMeasured bool
	files              int
}

func (r *quotaRoot) snapshot() map[string]any {
	v := map[string]any{"target": r.kind, "path": r.path, "owned_directory": r.owned, "written_bytes": r.written, "created_files": r.files}
	if r.allocationMeasured {
		v["open_allocation_file_blocks_bytes"] = r.allocated
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(r.path, &fs); err == nil {
		v["statfs_available_blocks"], v["statfs_block_size"], v["statfs_free_inodes"] = fs.Bavail, fs.Bsize, fs.Ffree
	} else {
		v["statfs_outcome"], v["statfs_errno"] = safeOutcome(err)
	}
	return v
}

func quotaProbe(ctx context.Context, q *quotaConfig, p *probeSession) error {
	paths := map[string]string{"persistent": p.persistent, "scratch": p.scratch}
	kinds := []string{q.Target}
	if q.Operation == "combined-bytes" || q.Operation == "combined-inodes" {
		kinds = []string{"scratch", "ipc"}
	}
	if q.Operation == "cross-project-link" {
		kinds = []string{"persistent", "scratch", "ipc"}
	}
	for _, kind := range kinds {
		if kind == "ipc" {
			path, err := guestIPCDirectory()
			if err != nil {
				p.record("quota", "broker-directory-unavailable", err, nil)
				return err
			}
			if path == p.persistent || path == p.scratch {
				return errors.New("broker directory aliases data directory")
			}
			paths["ipc"] = path
		}
	}
	roots := make([]*quotaRoot, 0, len(kinds))
	defer func() {
		for _, r := range roots {
			if r.file != nil {
				p.record("quota", "close-owned-file", r.file.Close(), map[string]any{"target": r.kind})
			}
			if !q.RetainFiles {
				p.record("quota", "remove-owned-directory", os.RemoveAll(r.owned), map[string]any{"path": r.owned})
			} else {
				p.record("quota", "intentionally-retained-for-parent-cleanup", nil, map[string]any{"path": r.owned})
			}
		}
	}()
	for _, kind := range kinds {
		r := &quotaRoot{kind: kind, path: paths[kind]}
		p.record("quota", "before-allocation", nil, r.snapshot())
		owned, err := os.MkdirTemp(r.path, "probe-quota-")
		if err != nil {
			p.record("quota", "owned-directory-create", err, map[string]any{"target": kind})
			return err
		}
		r.owned = owned
		roots = append(roots, r)
	}
	p.record("quota", "allocation-intent", nil, map[string]any{"operation": q.Operation, "target_bytes": q.TargetBytes, "target_files": q.TargetFiles, "chunk_bytes": q.ChunkBytes, "retain_files": q.RetainFiles})
	var err error
	switch q.Operation {
	case "bytes", "combined-bytes", "held-file":
		err = quotaBytes(ctx, q, roots, p)
	case "inodes", "combined-inodes":
		err = quotaInodes(ctx, q, roots, p)
	case "cross-project-link":
		err = quotaLinks(ctx, roots, p)
	}
	for _, r := range roots {
		p.record("quota", "allocation-returned-not-project-accounting", err, r.snapshot())
	}
	// Holding is explicitly configured, not a readiness delay. It lets the parent
	// inspect real quota accounting or kill the instance with an open allocation.
	if q.HoldMS != 0 {
		p.record("quota", "holding-owned-allocation", err, map[string]any{"hold_ms": q.HoldMS, "unlink_held": q.UnlinkHeld})
		if holdErr := waitUntil(ctx, time.Now().Add(time.Duration(q.HoldMS)*time.Millisecond)); holdErr != nil {
			return holdErr
		}
	}
	return err
}

func quotaBytes(ctx context.Context, q *quotaConfig, roots []*quotaRoot, p *probeSession) error {
	for _, r := range roots {
		f, err := os.OpenFile(filepath.Join(r.owned, "allocation"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			p.record("quota", "allocation-file-create", err, map[string]any{"target": r.kind})
			return err
		}
		r.file, r.files = f, 1
	}
	block := make([]byte, q.ChunkBytes)
	// Write actual dense data, not truncate/fallocate assumptions. One combined
	// target is shared across scratch+IPC and alternates each bounded chunk.
	for i := range block {
		block[i] = 0xa5
	}
	var total int64
	turn := 0
	var result error
	for total < q.TargetBytes {
		if result = ctx.Err(); result != nil {
			break
		}
		r := roots[turn%len(roots)]
		n := int(min(int64(len(block)), q.TargetBytes-total))
		written, err := r.file.Write(block[:n])
		r.written += int64(written)
		total += int64(written)
		if err == nil && written != n {
			err = errors.New("short quota fixture write")
		}
		if err == nil {
			err = r.file.Sync()
		}
		if err != nil {
			p.record("quota", "write-or-sync-returned-error", err, map[string]any{"target": r.kind, "written_bytes": r.written})
			result = err
			break
		}
		turn++
	}
	for _, r := range roots {
		var stat unix.Stat_t
		if err := unix.Fstat(int(r.file.Fd()), &stat); err == nil {
			r.allocated = stat.Blocks * 512
			r.allocationMeasured = true
		} else {
			p.record("quota", "fstat-allocation", err, map[string]any{"target": r.kind})
		}
		if q.Operation == "held-file" && q.UnlinkHeld {
			err := os.Remove(r.file.Name())
			data := r.snapshot()
			data["unlinked_file"] = r.file.Name()
			p.record("quota", "unlink-while-open", err, data)
			if result == nil {
				result = err
			}
		}
	}
	return result
}

func quotaInodes(ctx context.Context, q *quotaConfig, roots []*quotaRoot, p *probeSession) error {
	for i := range q.TargetFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := roots[i%len(roots)]
		f, err := os.OpenFile(filepath.Join(r.owned, fmt.Sprintf("empty-%05d", i)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			p.record("quota", "empty-file-create-returned-error", err, map[string]any{"target": r.kind, "created_files": r.files})
			return err
		}
		r.files++
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func quotaLinks(ctx context.Context, roots []*quotaRoot, p *probeSession) error {
	// Three sources and exactly six directed link attempts: persistent<->scratch,
	// persistent<->IPC, scratch<->IPC. Success/EXDEV/EPERM are observations only.
	for _, r := range roots {
		f, err := os.OpenFile(filepath.Join(r.owned, "source"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write([]byte{0xa5})
		syncErr, closeErr := f.Sync(), f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("link fixture source I/O failed")
		}
		r.files, r.written = 1, 1
	}
	for i, from := range roots {
		for j, to := range roots {
			if i == j {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			err := os.Link(filepath.Join(from.owned, "source"), filepath.Join(to.owned, "link-from-"+from.kind))
			if err == nil {
				to.files++
			}
			p.record("quota", "hardlink-syscall-returned", err, map[string]any{"source": from.kind, "destination": to.kind})
		}
	}
	return nil
}
