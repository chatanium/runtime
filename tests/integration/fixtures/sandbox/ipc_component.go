package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// These endpoints belong only to this fixture's leased mounts. Serve still
// supplies the genuine AutoMTLS handshake; no bootstrap line is forged.
func ipcComponentBootstrap() {
	dir, err := guestIPCDirectory()
	if err != nil {
		os.Exit(87)
	}
	gid, err := strconv.Atoi(os.Getenv("PLUGIN_UNIX_SOCKET_GROUP"))
	if err != nil || gid <= 0 {
		os.Exit(87)
	}
	const persistent = "/var/lib/flexmodule/data"
	const scratch = "/var/lib/flexmodule/scratch"
	if probeStorage(persistent, scratch) != nil {
		os.Exit(87)
	}
	p, err := newProbeSession(persistent, scratch)
	if err != nil {
		os.Exit(87)
	}
	listen := func(path string) *net.UnixListener {
		l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil || os.Chown(path, -1, gid) != nil || os.Chmod(path, 0660) != nil {
			os.Exit(87)
		}
		l.SetUnlinkOnClose(false)
		_ = l.SetDeadline(time.Now().Add(90 * time.Second))
		return l
	}
	primary := filepath.Join(dir, "original")
	original := listen(primary)
	outside := listen(filepath.Join(scratch, "outside"))
	control := listen(filepath.Join(dir, "control"))
	serve := func(l *net.UnixListener, identity string) {
		defer l.Close()
		for range 4 {
			c, e := l.AcceptUnix()
			if e != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = fmt.Fprintln(c, identity)
			_ = c.Close()
			p.record("ipc-component", "endpoint-accepted", nil, map[string]any{"endpoint": identity})
		}
	}
	go serve(original, "original")
	go serve(outside, "outside")
	go func() {
		defer control.Close()
		c, e := control.AcceptUnix()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		r := bufio.NewScanner(c)
		r.Buffer(make([]byte, 512), 512)
		if !r.Scan() {
			return
		}
		line := r.Text()
		// The supplied path is the exact host-visible counterpart of our own
		// scratch endpoint, not a pathname selected by the guest or an outsider.
		parts := strings.Split(line, " ")
		if len(parts) != 2 || parts[0] != "replace" || !filepath.IsAbs(parts[1]) || filepath.Base(parts[1]) != "outside" {
			return
		}
		if os.Rename(primary, primary+".retained") != nil || os.Symlink(parts[1], primary) != nil {
			return
		}
		p.record("ipc-component", "pathname-replaced", nil, map[string]any{"original_retained": true})
		if _, e = fmt.Fprintln(c, "replaced"); e != nil {
			return
		}
		if r.Scan() && r.Text() == "complete" {
			p.record("ipc-component", "returned-not-policy-proof", nil, nil)
			_, _ = fmt.Fprintln(c, "complete")
		}
	}()
}
