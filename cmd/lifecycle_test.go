//go:build linux

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/provision"
)

func TestGvxPreparationPrivateInputs(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("operator-owned data"), 0644); err != nil {
		t.Fatal(err)
	}
	archive, err := install.OpenInput(path, false)
	if err != nil {
		t.Fatal(err)
	}
	archive.Close()
	if credential, err := install.OpenInput(path, true); err == nil {
		credential.Close()
		t.Fatal("world-readable task credential accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	credential, err := install.OpenInput(path, true)
	if err != nil {
		t.Fatal(err)
	}
	credential.Close()
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if archive, err := install.OpenInput(link, false); err == nil {
		archive.Close()
		t.Fatal("symlink preparation input accepted")
	}
	if archive, err := install.OpenInput(directory+"/missing/../input", false); err == nil {
		archive.Close()
		t.Fatal("noncanonical preparation input accepted")
	}
}

func TestGvxPreparationLimitsFileRequiresCompleteStrictBounds(t *testing.T) {
	limits := provision.PrepareLimits{NanoCPUs: 1_000_000_000, MemoryBytes: 256 << 20, Tasks: 64, InputBytes: 1 << 30, ExpandedBytes: 2 << 30, OutputBytes: 1 << 30, Inodes: 100_000, JSONBytes: 1 << 20, DescriptorCount: 1024, IndexDepth: 8, Deadline: time.Minute}
	raw, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readPreparationLimits(path)
	if err != nil || got != limits {
		t.Fatal("complete explicit preparation limits were not preserved")
	}
	var partial map[string]json.RawMessage
	if err := json.Unmarshal(raw, &partial); err != nil {
		t.Fatal(err)
	}
	delete(partial, "tasks")
	missing, err := json.Marshal(partial)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		string(missing),
		`{}`,
		strings.TrimSuffix(string(raw), "}") + `,"tasks":64}`,
		strings.TrimSuffix(string(raw), "}") + `,"unknown":1}`,
		string(raw) + `{}`,
		strings.Replace(string(raw), `"tasks":64`, `"tasks":0`, 1),
		strings.Replace(string(raw), `"nano_cpus":1000000000`, `"nano_cpus":1000000001`, 1),
		strings.Replace(string(raw), `"deadline":60000000000`, `"deadline":"1m"`, 1),
		strings.TrimSuffix(string(raw), "}") + `,"unknown":"` + strings.Repeat("x", 16<<10) + `"}`,
	} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := readPreparationLimits(path); err == nil || got != (provision.PrepareLimits{}) {
			t.Fatal("partial, ambiguous or unsafe limits received implicit defaults")
		}
	}
}
