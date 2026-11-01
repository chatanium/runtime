// Package scaffold creates independent modules using Chatanium's public v2 SDK.
package scaffold

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

//go:embed templates/*
var templates embed.FS

var moduleName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,49}$`)
var importPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~/-]*$`)

type Options struct {
	Name       string
	ModulePath string
	Directory  string
	SDKPath    string
}

// Create refuses an existing destination rather than replacing user sources.
// SDKPath points at this repository's checkout, not a published v2 release.
func Create(opts Options) (string, error) {
	if !moduleName.MatchString(opts.Name) {
		return "", errors.New("module name must be 1–50 lowercase letters, digits or hyphens, starting with a letter")
	}
	if opts.ModulePath == "" {
		opts.ModulePath = "example.com/" + opts.Name
	}
	if !importPath.MatchString(opts.ModulePath) || strings.Contains(opts.ModulePath, "//") || strings.Contains(opts.ModulePath, "..") {
		return "", errors.New("invalid Go module import path")
	}
	if opts.Directory == "" {
		opts.Directory = filepath.Join("modules", opts.Name)
	}
	if opts.SDKPath == "" {
		opts.SDKPath = "."
	}
	sdk, err := filepath.Abs(opts.SDKPath)
	if err != nil {
		return "", err
	}
	mod, err := os.ReadFile(filepath.Join(sdk, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read SDK checkout go.mod: %w", err)
	}
	if !strings.Contains(string(mod), "module github.com/thirdscam/chatanium\n") {
		return "", errors.New("--sdk-path must point at a github.com/thirdscam/chatanium v2 checkout")
	}
	if _, err := os.Stat(filepath.Join(sdk, "shared", "core-v2", "plugin.go")); err != nil {
		return "", fmt.Errorf("SDK checkout lacks the public v2 module transport: %w", err)
	}
	dir, err := filepath.Abs(opts.Directory)
	if err != nil {
		return "", err
	}
	data := struct {
		Name, ModulePath, SDKPath, DiscordPath string
	}{opts.Name, opts.ModulePath, strconv.Quote(filepath.ToSlash(sdk)), strconv.Quote(filepath.ToSlash(filepath.Join(sdk, ".tools", "deps", "discordgo")))}
	// Render everything before creating the output directory.
	files := make(map[string][]byte)
	for _, name := range []string{"main.go", "main_test.go", "manifest.json", "go.mod", "README.md", "Dockerfile", ".gitignore", ".dockerignore", "config.example.json"} {
		source, err := templates.ReadFile("templates/" + name + ".tmpl")
		if err != nil {
			return "", err
		}
		t, err := template.New(name).Parse(string(source))
		if err != nil {
			return "", err
		}
		var out bytes.Buffer
		if err := t.Execute(&out, data); err != nil {
			return "", err
		}
		files[name] = out.Bytes()
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return "", fmt.Errorf("create new module directory: %w", err)
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
	}
	return dir, nil
}
