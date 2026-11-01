package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorageProbeUsesSuppliedGuestDirectories(t *testing.T) {
	persistent := t.TempDir()
	scratch := t.TempDir()
	if err := probeStorage(persistent, scratch); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(persistent, "probe-state")
	before, err := os.ReadFile(state)
	if err != nil || string(before) != "flexmodule-sandbox-probe-v2\n" {
		t.Fatal("persistent sentinel was not written in the supplied directory")
	}
	if err := probeStorage(persistent, scratch); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(state)
	if err != nil || string(after) != string(before) {
		t.Fatal("reopened persistent sentinel changed")
	}
	entries, err := os.ReadDir(scratch)
	if err != nil || len(entries) != 0 {
		t.Fatal("scratch probe left files in the supplied directory")
	}
}

func TestStorageProbeDoesNotReplaceCorruptPersistentState(t *testing.T) {
	persistent := t.TempDir()
	scratch := t.TempDir()
	state := filepath.Join(persistent, "probe-state")
	const corrupt = "not the probe sentinel\n"
	if err := os.WriteFile(state, []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	if err := probeStorage(persistent, scratch); err == nil {
		t.Fatal("corrupt persistent state accepted")
	}
	after, err := os.ReadFile(state)
	if err != nil || string(after) != corrupt {
		t.Fatal("corrupt persistent state was overwritten")
	}
}

func TestStorageProbeRejectsMissingOrRelativeMounts(t *testing.T) {
	persistent := t.TempDir()
	scratch := t.TempDir()
	for _, paths := range [][2]string{{"", scratch}, {persistent, ""}, {"relative", scratch}, {persistent, persistent}} {
		if err := probeStorage(paths[0], paths[1]); err == nil {
			t.Fatal("invalid authenticated mount paths accepted")
		}
	}
}
