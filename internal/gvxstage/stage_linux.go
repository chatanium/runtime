//go:build linux

// Package gvxstage implements the static, nonroot, one-shot gate before rungv.
package gvxstage

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

const MaxConfigBytes = 256 << 10
const MaxMessageBytes = 4096

type Config struct {
	Version               uint32   `json:"version"`
	RuntimeInstallationID string   `json:"runtime_installation_id"`
	EpochID               string   `json:"epoch_id"`
	InstanceID            string   `json:"instance_id"`
	Generation            string   `json:"generation"`
	GatePath              string   `json:"gate_path"`
	RungvPath             string   `json:"rungv_path"`
	RungvDigest           string   `json:"rungv_digest"`
	Workdir               string   `json:"workdir"`
	Argv                  []string `json:"argv"`
	Env                   []string `json:"env"`
	DeadlineBootNS        int64    `json:"deadline_boot_ns"`
}
type Message struct {
	Version    uint32 `json:"version"`
	Type       string `json:"type"`
	EpochID    string `json:"epoch_id"`
	InstanceID string `json:"instance_id"`
	Generation string `json:"generation"`
	Error      string `json:"error,omitempty"`
}

func BootNS() (int64, error) {
	var t unix.Timespec
	e := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t)
	return t.Nano(), e
}
func Deadline(c Config) (time.Time, error) {
	now, e := BootNS()
	if e != nil {
		return time.Time{}, e
	}
	remaining := c.DeadlineBootNS - now
	if remaining <= 0 || remaining > int64(time.Hour) {
		return time.Time{}, errors.New("expired or excessive stage deadline")
	}
	return time.Now().Add(time.Duration(remaining)), nil
}
func cleanAbsolute(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsRune(s, 0)
}
func Validate(c Config) error {
	if c.Version != 1 || c.RuntimeInstallationID == "" || c.EpochID == "" || c.InstanceID == "" || c.Generation == "" || !cleanAbsolute(c.GatePath) || !cleanAbsolute(c.RungvPath) || !cleanAbsolute(c.Workdir) || len(c.Argv) < 2 || c.Argv[0] != c.RungvPath || c.Argv[1] != "run" || len(c.RungvDigest) != 71 || !strings.HasPrefix(c.RungvDigest, "sha256:") {
		return errors.New("invalid stage configuration")
	}
	if _, e := hex.DecodeString(c.RungvDigest[7:]); e != nil {
		return e
	}
	if len(c.Argv) > 512 || len(c.Env) > 128 {
		return errors.New("stage argument bound")
	}
	for _, a := range c.Argv {
		if strings.ContainsRune(a, 0) {
			return errors.New("NUL in stage argument")
		}
	}
	seen := map[string]bool{}
	for _, v := range c.Env {
		k, _, ok := strings.Cut(v, "=")
		if !ok || seen[k] || strings.ContainsRune(v, 0) {
			return errors.New("invalid stage environment")
		}
		seen[k] = true
		switch k {
		case "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL":
		default:
			return errors.New("unexpected stage environment key")
		}
	}
	_, e := Deadline(c)
	return e
}
func WriteMessage(w io.Writer, m Message) error {
	if e := validateMessage(m); e != nil {
		return e
	}
	raw, e := json.Marshal(m)
	if e != nil {
		return e
	}
	if len(raw) > MaxMessageBytes {
		return errors.New("stage control bound")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if e = writeAll(w, header[:]); e != nil {
		return e
	}
	return writeAll(w, raw)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func ReadMessage(r io.Reader) (Message, error) {
	var m Message
	var header [4]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return m, e
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxMessageBytes {
		return m, errors.New("stage control bound")
	}
	raw := make([]byte, n)
	if _, e := io.ReadFull(r, raw); e != nil {
		return m, e
	}
	if e := gvxcontract.DecodeStrict(raw, MaxMessageBytes, 4, &m); e != nil {
		return m, e
	}
	return m, validateMessage(m)
}
func validateMessage(m Message) error {
	if m.Version != 1 || m.EpochID == "" || m.InstanceID == "" || m.Generation == "" {
		return errors.New("invalid stage control identity")
	}
	switch m.Type {
	case "READY", "START":
		if m.Error != "" {
			return errors.New("unexpected stage error")
		}
	case "ERROR":
		if m.Error == "" || len(m.Error) > 512 {
			return errors.New("invalid stage error")
		}
	default:
		return errors.New("unknown stage message")
	}
	return nil
}
func Matches(m Message, c Config) bool {
	return m.Version == 1 && m.EpochID == c.EpochID && m.InstanceID == c.InstanceID && m.Generation == c.Generation
}
func protectedParents(path string) error {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if e := unix.Lstat(p, &st); e != nil {
			return e
		}
		if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
			return fmt.Errorf("unprotected stage parent %s", p)
		}
		if p == "/" {
			return nil
		}
	}
}
func ReadConfig(path string) (Config, error) {
	var c Config
	if e := readProtectedConfig(path, &c); e != nil {
		return c, e
	}
	return c, Validate(c)
}

func readProtectedConfig(path string, value any) error {
	if !cleanAbsolute(path) {
		return errors.New("absolute config path required")
	}
	if e := protectedParents(path); e != nil {
		return e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return e
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0222 != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > MaxConfigBytes {
		return errors.New("unprotected stage configuration")
	}
	raw, e := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if e != nil {
		return e
	}
	return gvxcontract.DecodeStrict(raw, MaxConfigBytes, 8, value)
}
func awaitStart(ctx context.Context, deadline time.Time, c Config) error {
	if e := protectedParents(c.GatePath); e != nil {
		return e
	}
	var gate unix.Stat_t
	if e := unix.Lstat(c.GatePath, &gate); e != nil {
		return e
	}
	if gate.Uid != 0 || gate.Mode&unix.S_IFMT != unix.S_IFSOCK || gate.Mode&0007 != 0 {
		return errors.New("unprotected stage gate")
	}
	dialer := net.Dialer{Deadline: deadline}
	conn, e := dialer.DialContext(ctx, "unix", c.GatePath)
	if e != nil {
		return e
	}
	defer conn.Close()
	peer := conn.(*net.UnixConn)
	if e = peer.SetDeadline(deadline); e != nil {
		return e
	}
	raw, e := peer.SyscallConn()
	if e != nil {
		return e
	}
	var credentials *unix.Ucred
	var peerErr error
	if e = raw.Control(func(fd uintptr) {
		credentials, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); e != nil {
		return e
	}
	if peerErr != nil {
		return peerErr
	}
	if credentials.Uid != 0 {
		return errors.New("gate peer is not root")
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if e = WriteMessage(conn, Message{Version: 1, Type: "READY", EpochID: c.EpochID, InstanceID: c.InstanceID, Generation: c.Generation}); e != nil {
		return e
	}
	message, e := ReadMessage(conn)
	if e != nil {
		return e
	}
	if !Matches(message, c) || message.Type != "START" {
		return errors.New("gate refused executable start")
	}
	return conn.Close()
}

func Run(ctx context.Context, configPath string) error {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return errors.New("stage must start nonroot")
	}
	c, e := ReadConfig(configPath)
	if e != nil {
		return e
	}
	deadline, e := Deadline(c)
	if e != nil {
		return e
	}
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	executable, e := openVerifiedExecutable(c.RungvPath, c.RungvDigest)
	if e != nil {
		return e
	}
	defer executable.Close()
	if e = awaitStart(ctx, deadline, c); e != nil {
		return e
	}
	if _, e = Deadline(c); e != nil {
		return e
	}
	if e = os.Chdir(c.Workdir); e != nil {
		return e
	}
	now, e := BootNS()
	if e != nil {
		return e
	}
	remaining := c.DeadlineBootNS - now
	if remaining <= 0 {
		return errors.New("stage startup deadline expired")
	}
	prefix := "--env=CHATANIUM_GVX_STARTUP_TIMEOUT_NS="
	found := false
	for index, arg := range c.Argv {
		if strings.HasPrefix(arg, prefix) {
			if found {
				return errors.New("duplicate bridge startup budget")
			}
			original, parseErr := strconv.ParseInt(strings.TrimPrefix(arg, prefix), 10, 64)
			if parseErr != nil || original <= 0 {
				return errors.New("invalid bridge startup budget")
			}
			if remaining < original {
				c.Argv[index] = prefix + strconv.FormatInt(remaining, 10)
			}
			found = true
		}
	}
	if !found {
		return errors.New("bridge startup budget missing")
	}
	// /proc/self/fd names the verified, still-open inode rather than a mutable path.
	return unix.Exec(fmt.Sprintf("/proc/self/fd/%d", executable.Fd()), c.Argv, c.Env)
}
