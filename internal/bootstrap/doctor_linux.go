//go:build linux

package bootstrap

import (
	"context"
	"github.com/thirdscam/chatanium/internal/bundle"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func Doctor(ctx context.Context) (DoctorReport, error) {
	report := DoctorReport{}
	add := func(name, state, detail string) {
		report.Checks = append(report.Checks, DoctorCheck{Name: name, State: state, Detail: detail})
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		add("platform", "supported", "linux/amd64 observed")
	} else {
		add("platform", "unsupported", "runtime requires linux/amd64")
	}
	source, e := configuredSource()
	if e != nil {
		add("bundle manifest", "unknown", "no injected bundle source")
	} else {
		raw, e := source.Manifest()
		if e != nil {
			add("bundle manifest", "unknown", "manifest unavailable")
		} else if _, e = bundle.VerifyManifest(raw); e != nil {
			add("bundle manifest", "unsupported", "manifest fails pinned compatibility or integrity checks")
		} else {
			add("bundle manifest", "supported", "pinned manifest verified; payload neither extracted nor executed")
		}
	}
	if raw, e := os.ReadFile("/etc/os-release"); e != nil {
		add("native ABI", "unknown", "OS release unavailable")
	} else {
		fields := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				fields[parts[0]] = strings.Trim(parts[1], "\"'")
			}
		}
		if fields["PLATFORM_ID"] == "platform:el9" {
			add("native ABI", "supported", "EL9 host release observed")
		} else {
			add("native ABI", "unsupported", "pinned native closure requires EL9")
		}
	}
	if raw, e := os.ReadFile("/proc/cpuinfo"); e != nil {
		add("CPU baseline", "unknown", "CPU flags unavailable")
	} else {
		seen, supported := false, true
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) != "flags" {
				continue
			}
			seen = true
			flags := map[string]bool{}
			for _, flag := range strings.Fields(parts[1]) {
				flags[flag] = true
			}
			for _, flag := range []string{"cx16", "lahf_lm", "popcnt", "pni", "ssse3", "sse4_1", "sse4_2"} {
				supported = supported && flags[flag]
			}
		}
		if !seen {
			add("CPU baseline", "unknown", "amd64 feature flags not exposed")
		} else if supported {
			add("CPU baseline", "supported", "amd64-v2 flags observed on every exposed processor")
		} else {
			add("CPU baseline", "unsupported", "amd64-v2 CPU features missing")
		}
	}
	if raw, e := os.ReadFile("/proc/1/comm"); e != nil {
		add("PID1", "unknown", "PID1 identity unavailable")
	} else if strings.TrimSpace(string(raw)) == "systemd" {
		if info, e := os.Stat("/run/systemd/private"); e == nil && info.Mode()&os.ModeSocket != 0 {
			add("PID1", "supported", "systemd PID1 and private socket observed; no connection attempted")
		} else {
			add("PID1", "unknown", "systemd private socket unavailable")
		}
	} else {
		add("PID1", "unsupported", "PID1 is not systemd")
	}
	var filesystem unix.Statfs_t
	if e = unix.Statfs("/sys/fs/cgroup", &filesystem); e != nil {
		add("cgroup v2", "unknown", "cgroup filesystem unavailable")
	} else if filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		add("cgroup v2", "unsupported", "unified cgroup filesystem required")
	} else if raw, e := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); e != nil {
		add("cgroup v2", "unknown", "controller list unavailable")
	} else {
		controllers := map[string]bool{}
		for _, name := range strings.Fields(string(raw)) {
			controllers[name] = true
		}
		if controllers["cpu"] && controllers["memory"] && controllers["pids"] {
			add("cgroup v2", "supported", "cpu/memory/pids controllers available; effective job ceilings not probed")
		} else {
			add("cgroup v2", "unsupported", "required cpu/memory/pids controllers unavailable")
		}
	}
	for _, namespace := range []string{"user", "mnt", "pid", "net"} {
		if _, e := os.Stat("/proc/self/ns/" + namespace); e == nil {
			add(namespace+" namespace", "supported", "kernel namespace interface observed")
		} else if os.IsNotExist(e) {
			add(namespace+" namespace", "unsupported", "required namespace interface absent")
		} else {
			add(namespace+" namespace", "unknown", "namespace identity unavailable")
		}
	}
	if raw, e := os.ReadFile("/proc/sys/user/max_user_namespaces"); e != nil {
		add("user namespace limit", "unknown", "kernel limit unavailable")
	} else if value, e := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); e != nil {
		add("user namespace limit", "unknown", "kernel limit not understood")
	} else if value == 0 {
		add("user namespace limit", "unsupported", "user namespace creation disabled")
	} else {
		add("user namespace limit", "supported", "positive kernel namespace ceiling observed; no namespace created")
	}
	for _, name := range []string{"systrap startup", "PID1 descriptor transport and effective ceilings", "private namespace cleanup", "XFS project quota enforcement and bounded backing", "PUBLIC route/filter/conntrack enforcement"} {
		add(name, "needs_privileged_check", "requires approved finite initialization; no extraction, helper execution, namespace, mount, account, service, firewall or sysctl mutation performed")
	}
	return report, ctx.Err()
}
