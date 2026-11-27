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
var buildPath = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

type Template string

const (
	Local   Template = "local"
	Discord Template = "discord"
)

type Options struct {
	Name       string
	ModulePath string
	Directory  string
	SDKPath    string
	Template   Template
}

// Destination resolves the path shown in the prompt without writing anything.
func Destination(name, directory string) (string, error) {
	if !moduleName.MatchString(name) {
		return "", errors.New("module name must be 1–50 lowercase letters, digits or hyphens, starting with a letter")
	}
	if directory == "" {
		directory = filepath.Join("modules", name)
	}
	return filepath.Abs(directory)
}

// BuildTarget returns the repo-relative path for make modules, or "" if it
// cannot be shown as a make command.
func BuildTarget(sdk, directory string) string {
	if sdk == "" {
		sdk = "."
	}
	root, err := filepath.Abs(sdk)
	if err != nil {
		return ""
	}
	relative, err := filepath.Rel(root, directory)
	if err != nil {
		return ""
	}
	target := filepath.ToSlash(relative)
	if strings.HasPrefix(target, "../") || !strings.Contains(target, "/") || !buildPath.MatchString(target) {
		return ""
	}
	return target
}

// Create refuses an existing destination rather than replacing user sources.
// SDKPath points at this repository's checkout, not a published v2 release.
func Create(opts Options) (string, error) {
	dir, err := Destination(opts.Name, opts.Directory)
	if err != nil {
		return "", err
	}
	switch opts.Template {
	case "":
		opts.Template = Local
	case Local, Discord:
	default:
		return "", fmt.Errorf("unknown starter template %q", opts.Template)
	}
	if opts.ModulePath == "" {
		opts.ModulePath = "example.com/" + opts.Name
	}
	if !importPath.MatchString(opts.ModulePath) || strings.Contains(opts.ModulePath, "//") || strings.Contains(opts.ModulePath, "..") {
		return "", errors.New("invalid Go module import path")
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
	discordPath := ""
	if opts.Template == Discord {
		discordPath = filepath.Join(sdk, ".tools", "deps", "discordgo")
		if relative, err := filepath.Rel(dir, discordPath); err == nil {
			discordPath = filepath.ToSlash(relative)
			if !strings.HasPrefix(discordPath, "../") {
				discordPath = "./" + discordPath
			}
		}
	}
	data := struct {
		Name, ModulePath, SDKPath, DiscordPath, BuildTarget string
		Discord                                           bool
	}{
		Name: opts.Name, ModulePath: opts.ModulePath,
		SDKPath:     strconv.Quote(filepath.ToSlash(sdk)),
		DiscordPath: strconv.Quote(filepath.ToSlash(discordPath)),
		BuildTarget: BuildTarget(sdk, dir),
		Discord:     opts.Template == Discord,
	}
	main, tests := "local.go.tmpl", "local_test.go.tmpl"
	if data.Discord {
		main, tests = "main.go.tmpl", "main_test.go.tmpl"
	}
	sources := map[string]string{
		"main.go": main, "main_test.go": tests,
		"manifest.json": "manifest.json.tmpl",
		"go.mod":        "go.mod.tmpl",
		"go.sum":        "go.sum.tmpl",
		"README.md":     "README.md.tmpl",
		".gitignore":    ".gitignore.tmpl",
	}
	// Render everything before creating the output directory.
	files := make(map[string][]byte, len(sources))
	for name, sourceName := range sources {
		source, err := templates.ReadFile("templates/" + sourceName)
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
