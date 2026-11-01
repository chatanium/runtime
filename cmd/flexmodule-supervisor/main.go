// flexmodule-supervisor is the privileged, independently supervised host
// service. Its configuration contains host policy only, never backend secrets.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

type configuration struct {
	Supervisor host.SupervisorConfig `json:"supervisor"`
	Platform   host.DockerConfig     `json:"platform"`
}

func run() (result error) {
	configPath := flag.String("config", "", "absolute root-owned supervisor JSON configuration (required)")
	flag.Parse()
	if *configPath == "" || !filepath.IsAbs(*configPath) || filepath.Clean(*configPath) != *configPath || flag.NArg() != 0 {
		return errors.New("canonical absolute -config is required; positional arguments are not accepted")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, *configPath, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "supervisor-configuration")
	defer file.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 {
		return errors.New("supervisor configuration must be a root-owned non-writable regular file")
	}
	// The operator-owned regular file's exact finite length bounds decoding.
	decoder := json.NewDecoder(io.NewSectionReader(file, 0, stat.Size))
	decoder.DisallowUnknownFields()
	var config configuration
	if err = decoder.Decode(&config); err != nil {
		return err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing configuration JSON")
	}
	platform, err := host.NewDockerPlatform(config.Platform)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, platform.Close()) }()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	startup, finish := context.WithTimeout(ctx, config.Supervisor.OperationTimeout)
	supervisor, err := host.NewSupervisor(startup, config.Supervisor, platform)
	finish()
	if err != nil {
		return err
	}
	serveErr := supervisor.Serve(ctx)
	// Shutdown revokes old authority and cleans all transient owned resources.
	// An error remains fatal; the service manager must preserve/restart cleanup.
	return errors.Join(serveErr, supervisor.Close())
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "flexmodule-supervisor:", err)
		os.Exit(1)
	}
}
