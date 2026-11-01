package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlayerInitAcceptsAuthenticatedScratchDirectoryWithoutMountConvention(t *testing.T) {
	for _, path := range []string{"/var/lib/flexmodule/scratch", filepath.Join(t.TempDir(), "assigned-scratch")} {
		raw, init := playerConfigFixture(t)
		init.ScratchDirectory = path
		if _, err := decodeConfig(raw, init); err != nil {
			t.Fatalf("authenticated absolute scratch directory %q rejected: %v", path, err)
		}
	}
	for _, path := range []string{"", "relative-scratch"} {
		raw, init := playerConfigFixture(t)
		init.ScratchDirectory = path
		if _, err := decodeConfig(raw, init); err == nil {
			t.Fatalf("unauthenticated relative or missing scratch path %q accepted", path)
		}
	}
}

func TestPlayerScratchArtifactsAndCleanupStayInsideAssignedDirectory(t *testing.T) {
	base := t.TempDir()
	assigned := filepath.Join(base, "assigned-scratch")
	persistent := filepath.Join(base, "assigned-persistent")
	for _, path := range []string{assigned, persistent} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(assigned, "other-owner-data")
	retained := filepath.Join(persistent, "retained-settings")
	for _, path := range []string{unrelated, retained} {
		if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, init := playerConfigFixture(t)
	init.ScratchDirectory, init.PersistentDirectory = assigned, persistent
	if _, err := decodeConfig(raw, init); err != nil {
		t.Fatal(err)
	}
	scratch, err := openScratch(init.ScratchDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scratch.Close() })
	job, err := scratch.directory()
	if err != nil {
		t.Fatal(err)
	}
	jobClosed := false
	t.Cleanup(func() {
		if !jobClosed {
			_ = job.Close()
		}
	})
	file, handle, err := job.create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	if _, err := handle.WriteString("actual scratch bytes"); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(init.ScratchDirectory, file.path)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("artifact escaped authenticated scratch directory: path=%q relative=%q err=%v", file.path, relative, err)
	}
	if data, err := os.ReadFile(file.path); err != nil || string(data) != "actual scratch bytes" {
		t.Fatalf("artifact not stored at its assigned owned path: data=%q err=%v", data, err)
	}
	if err := job.Close(); err != nil {
		t.Fatal(err)
	}
	jobClosed = true
	if err := scratch.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scratch.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned instance scratch subtree remains: %v", err)
	}
	for _, path := range []string{unrelated, retained} {
		if data, err := os.ReadFile(path); err != nil || string(data) != "preserve" {
			t.Fatalf("cleanup touched unrelated/persistent data %q: data=%q err=%v", path, data, err)
		}
	}
}
