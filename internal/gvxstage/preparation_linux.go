//go:build linux

package gvxstage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

const PreparationPurpose = "PREPARER"
const LoadPurpose = "RUNGv_LOAD"

const PreparationReady = "READY"
const PreparationArm = "ARM"
const PreparationFilterReady = "FILTER_READY"
const PreparationStart = "START"
const PreparationError = "ERROR"

// PreparationConfig authorizes one fixed executable, released only after the
// controller observes both the unarmed process and its installed writer filter.
type PreparationConfig struct {
	Version               uint32   `json:"version"`
	WriterDomainVersion   uint32   `json:"writer_domain_version"`
	FilterVersion         uint32   `json:"filter_version"`
	Purpose               string   `json:"purpose"`
	RuntimeInstallationID string   `json:"runtime_installation_id"`
	Generation            string   `json:"generation"`
	GatePath              string   `json:"gate_path"`
	Executable            string   `json:"executable"`
	ExecutableDigest      string   `json:"executable_digest"`
	Workdir               string   `json:"workdir"`
	Argv                  []string `json:"argv"`
	Env                   []string `json:"env"`
	DeadlineBootNS        int64    `json:"deadline_boot_ns"`
}

func (c PreparationConfig) Binding() Config {
	return Config{Version: c.Version, RuntimeInstallationID: c.RuntimeInstallationID, EpochID: c.RuntimeInstallationID, InstanceID: c.Generation, Generation: c.Generation, GatePath: c.GatePath, DeadlineBootNS: c.DeadlineBootNS}
}

type PreparationMessage struct {
	Version             uint32 `json:"version"`
	Type                string `json:"type"`
	EpochID             string `json:"epoch_id"`
	InstanceID          string `json:"instance_id"`
	Generation          string `json:"generation"`
	WriterDomainVersion uint32 `json:"writer_domain_version"`
	FilterVersion       uint32 `json:"filter_version"`
	Error               string `json:"error,omitempty"`
}

func preparationMessage(c PreparationConfig, kind string) PreparationMessage {
	return PreparationMessage{
		Version: c.Version, Type: kind, EpochID: c.RuntimeInstallationID,
		InstanceID: c.Generation, Generation: c.Generation,
		WriterDomainVersion: c.WriterDomainVersion, FilterVersion: c.FilterVersion,
	}
}

func WritePreparationMessage(w io.Writer, m PreparationMessage) error {
	if e := validatePreparationMessage(m); e != nil {
		return e
	}
	raw, e := json.Marshal(m)
	if e != nil {
		return e
	}
	if len(raw) > MaxMessageBytes {
		return errors.New("preparation control bound")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if e = writeAll(w, header[:]); e != nil {
		return e
	}
	return writeAll(w, raw)
}

func ReadPreparationMessage(r io.Reader) (PreparationMessage, error) {
	var m PreparationMessage
	var header [4]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return m, e
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxMessageBytes {
		return m, errors.New("preparation control bound")
	}
	raw := make([]byte, n)
	if _, e := io.ReadFull(r, raw); e != nil {
		return m, e
	}
	if e := gvxcontract.DecodeStrict(raw, MaxMessageBytes, 4, &m); e != nil {
		return m, e
	}
	return m, validatePreparationMessage(m)
}

func validatePreparationMessage(m PreparationMessage) error {
	if m.Version != gvxcontract.PreparationWriterProtocolVersion || m.WriterDomainVersion != gvxcontract.PreparationWriterDomainVersion || m.FilterVersion != gvxcontract.PreparationWriterFilterVersion || m.EpochID == "" || m.InstanceID == "" || m.Generation == "" {
		return errors.New("invalid preparation control identity")
	}
	switch m.Type {
	case PreparationReady, PreparationArm, PreparationFilterReady, PreparationStart:
		if m.Error != "" {
			return errors.New("unexpected preparation error")
		}
	case PreparationError:
		if m.Error == "" || len(m.Error) > 512 {
			return errors.New("invalid preparation error")
		}
	default:
		return errors.New("unknown preparation message")
	}
	return nil
}

func MatchesPreparation(m PreparationMessage, c PreparationConfig) bool {
	return validatePreparationMessage(m) == nil &&
		c.Version == gvxcontract.PreparationWriterProtocolVersion &&
		c.WriterDomainVersion == gvxcontract.PreparationWriterDomainVersion &&
		c.FilterVersion == gvxcontract.PreparationWriterFilterVersion &&
		m.Version == c.Version && m.WriterDomainVersion == c.WriterDomainVersion &&
		m.FilterVersion == c.FilterVersion && m.EpochID == c.RuntimeInstallationID &&
		m.InstanceID == c.Generation && m.Generation == c.Generation
}

func ValidatePreparation(c PreparationConfig) error {
	if e := validatePreparationDeclaration(c); e != nil {
		return e
	}
	_, e := Deadline(c.Binding())
	return e
}

func validatePreparationDeclaration(c PreparationConfig) error {
	if c.Version != gvxcontract.PreparationWriterProtocolVersion || c.WriterDomainVersion != gvxcontract.PreparationWriterDomainVersion || c.FilterVersion != gvxcontract.PreparationWriterFilterVersion || c.RuntimeInstallationID == "" || c.Generation == "" || !cleanAbsolute(c.GatePath) || !cleanAbsolute(c.Executable) || !strings.HasPrefix(c.Executable, "/chatanium/base/") || !cleanAbsolute(c.Workdir) || len(c.ExecutableDigest) != 71 || !strings.HasPrefix(c.ExecutableDigest, "sha256:") || len(c.Argv) == 0 || len(c.Argv) > 512 || c.Argv[0] != c.Executable || len(c.Env) > 128 {
		return errors.New("invalid preparation gate configuration")
	}
	if _, e := hex.DecodeString(c.ExecutableDigest[7:]); e != nil {
		return e
	}
	switch c.Purpose {
	case PreparationPurpose:
		if len(c.Argv) != 1 {
			return errors.New("preparer accepts only its framed input")
		}
	case LoadPurpose:
		if len(c.Argv) < 2 || c.Argv[1] != "load" {
			return errors.New("only bounded rungv load is permitted")
		}
	default:
		return errors.New("unknown preparation gate purpose")
	}
	for _, arg := range c.Argv {
		if strings.ContainsRune(arg, 0) {
			return errors.New("NUL preparation argument")
		}
	}
	seen := map[string]bool{}
	for _, entry := range c.Env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || seen[key] || strings.ContainsAny(entry, "\x00\r\n") || strings.HasPrefix(key, "LD_") || strings.HasPrefix(key, "GVX_") {
			return errors.New("invalid preparation environment")
		}
		seen[key] = true
	}
	if c.DeadlineBootNS <= 0 {
		return errors.New("missing preparation deadline")
	}
	return nil
}

func ReadPreparationConfig(path string) (PreparationConfig, error) {
	var c PreparationConfig
	if e := readProtectedConfig(path, &c); e != nil {
		return c, e
	}
	return c, ValidatePreparation(c)
}

// ReadPreparationDeclaration is recovery-only: it does not authorize execution.
// RunPreparation separately enforces the original, still-live boot deadline.
func ReadPreparationDeclaration(path string) (PreparationConfig, error) {
	var c PreparationConfig
	if e := readProtectedConfig(path, &c); e != nil {
		return c, e
	}
	return c, validatePreparationDeclaration(c)
}

func RunPreparation(ctx context.Context, path string) error {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return errors.New("preparation gate must start nonroot")
	}
	c, e := ReadPreparationConfig(path)
	if e != nil {
		return e
	}
	deadline, e := Deadline(c.Binding())
	if e != nil {
		return e
	}
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	executable, e := openVerifiedExecutable(c.Executable, c.ExecutableDigest)
	if e != nil {
		return e
	}
	defer executable.Close()
	if e = awaitPreparationStart(ctx, deadline, c); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if _, e = Deadline(c.Binding()); e != nil {
		return e
	}
	if e = os.Chdir(c.Workdir); e != nil {
		return e
	}
	return unix.Exec(fmt.Sprintf("/proc/self/fd/%d", executable.Fd()), c.Argv, c.Env)
}

func openVerifiedExecutable(path, digest string) (*os.File, error) {
	if e := protectedParents(path); e != nil {
		return nil, e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		file.Close()
		return nil, e
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0222 != 0 {
		file.Close()
		return nil, errors.New("unprotected gate executable")
	}
	hash := sha256.New()
	if _, e = io.Copy(hash, file); e != nil {
		file.Close()
		return nil, e
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
		file.Close()
		return nil, errors.New("gate executable digest mismatch")
	}
	return file, nil
}

func awaitPreparationStart(ctx context.Context, deadline time.Time, c PreparationConfig) error {
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
	if e = exchangePreparation(conn, c, confinePreparation); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return conn.Close()
}

// exchangePreparation is deliberately stream-only. The stage has no data-side
// authority until both fixed barriers have been accepted on this connection.
func exchangePreparation(conn io.ReadWriter, c PreparationConfig, confine func() error) error {
	if e := WritePreparationMessage(conn, preparationMessage(c, PreparationReady)); e != nil {
		return e
	}
	message, e := ReadPreparationMessage(conn)
	if e != nil {
		return e
	}
	if !MatchesPreparation(message, c) || message.Type != PreparationArm {
		return errors.New("gate refused preparation arm")
	}
	if e = confine(); e != nil {
		return e
	}
	if e = WritePreparationMessage(conn, preparationMessage(c, PreparationFilterReady)); e != nil {
		return e
	}
	message, e = ReadPreparationMessage(conn)
	if e != nil {
		return e
	}
	if !MatchesPreparation(message, c) || message.Type != PreparationStart {
		return errors.New("gate refused preparation start")
	}
	return nil
}
