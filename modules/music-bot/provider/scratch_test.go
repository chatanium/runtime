package provider

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestProviderScratchConsumersUseOwnedSubtree(t *testing.T) {
	const childMarker = "flexmodule-provider-owned-scratch-child"
	type writtenFile struct {
		Kind string
		Path string
	}
	contents := map[string]string{"temp": "temporary media bytes", "home": "home consumer bytes", "cache": "compiled cache bytes", "relative": "relative output bytes"}
	within := func(root, path string) bool {
		relative, err := filepath.Rel(root, path)
		return err == nil && !filepath.IsAbs(relative) && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	if marker := slices.Index(os.Args, childMarker); marker >= 0 {
		if marker+1 >= len(os.Args) {
			os.Exit(2)
		}
		owned := os.Args[marker+1]
		home, err := os.UserHomeDir()
		if err != nil {
			os.Exit(3)
		}
		working, err := os.Getwd()
		if err != nil {
			os.Exit(4)
		}
		cache := os.Getenv("DENO_DIR")
		// Guard fixture writes against a broken implementation pointing outside the
		// test tree. Actual consumer APIs below must then create and close real files.
		for _, directory := range []string{os.TempDir(), home, cache, working} {
			if !within(owned, directory) {
				os.Exit(5)
			}
		}
		files := make([]writtenFile, 0, 4)
		store := func(kind string, file *os.File) {
			if _, err := file.WriteString(contents[kind]); err != nil {
				file.Close()
				os.Exit(6)
			}
			if err := file.Close(); err != nil {
				os.Exit(7)
			}
			path, err := filepath.Abs(file.Name())
			if err != nil {
				os.Exit(8)
			}
			files = append(files, writtenFile{Kind: kind, Path: path})
		}
		temporary, err := os.CreateTemp("", "provider-temp-*")
		if err != nil {
			os.Exit(9)
		}
		store("temp", temporary)
		homeFile, err := os.CreateTemp(home, "provider-home-*")
		if err != nil {
			os.Exit(10)
		}
		store("home", homeFile)
		cacheDirectory, err := os.MkdirTemp(cache, "provider-cache-*")
		if err != nil {
			os.Exit(11)
		}
		cached, err := os.OpenFile(filepath.Join(cacheDirectory, "compiled-script"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(12)
		}
		store("cache", cached)
		relative, err := os.OpenFile("relative-output", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(13)
		}
		store("relative", relative)
		if err := json.NewEncoder(os.Stdout).Encode(files); err != nil {
			os.Exit(14)
		}
		os.Exit(0)
	}
	root := t.TempDir()
	scratch := filepath.Join(root, "authenticated-cache")
	if err := os.Mkdir(scratch, 0700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "preserved-sibling")
	if err := os.WriteFile(foreign, []byte("unrelated data"), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	provider := &Youtube{Limits: Limits{MaxOutputBytes: 4096}, CacheDirectory: scratch}
	// This explicit subprocess fixture exercises file consumers, not an env/argv
	// echo or production fallback. Parent inspects the bytes it actually created.
	raw, err := provider.run(ctx, executable, "-test.run=^TestProviderScratchConsumersUseOwnedSubtree$", "--", childMarker, scratch)
	if err != nil {
		t.Fatal(err)
	}
	var files []writtenFile
	if err = json.Unmarshal(raw, &files); err != nil {
		t.Fatal(err)
	}
	if len(files) != len(contents) {
		t.Fatalf("missing consumer artifacts: %+v", files)
	}
	seen := map[string]bool{}
	for _, file := range files {
		want, known := contents[file.Kind]
		if !known || seen[file.Kind] || !within(scratch, file.Path) {
			t.Fatalf("consumer artifact escaped or duplicated: %+v", file)
		}
		seen[file.Kind] = true
		data, err := os.ReadFile(file.Path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Fatalf("%s consumer did not persist its actual bytes: %q", file.Kind, data)
		}
	}
	if err = os.RemoveAll(scratch); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if _, err := os.Stat(file.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("consumer artifact survived owned cleanup: %q: %v", file.Path, err)
		}
	}
	data, err := os.ReadFile(foreign)
	if err != nil || string(data) != "unrelated data" {
		t.Fatalf("owned cleanup damaged sibling storage: %q %v", data, err)
	}
}
