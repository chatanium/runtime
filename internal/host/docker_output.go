package host

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const GuestPersistentPath = "/var/lib/flexmodule/data"
const GuestScratchPath = "/var/lib/flexmodule/scratch"
const GuestIPCPath = "/run/flexmodule/ipc"

// logRotation has no in-memory queue and never opens a second unbounded sink.
// Writes backpressure attach; active and archived files share the retention cap.
type logRotation struct {
	dir   string
	limit int64
	count int
	size  int64
	file  *os.File
}

func newLogRotation(dir string, limit int64, count int) (*logRotation, error) {
	if limit <= 0 || count <= 0 {
		return nil, invalid("finite log retention required")
	}
	f, err := os.OpenFile(filepath.Join(dir, "output.0"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return &logRotation{dir: dir, limit: limit, count: count, file: f}, nil
}
func (l *logRotation) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		if l.size == l.limit {
			if err := l.file.Close(); err != nil {
				return total, err
			}
			if err := os.Remove(filepath.Join(l.dir, "output."+strconv.Itoa(l.count-1))); err != nil && !errors.Is(err, os.ErrNotExist) {
				return total, err
			}
			for i := l.count - 2; i >= 0; i-- {
				if err := os.Rename(filepath.Join(l.dir, "output."+strconv.Itoa(i)), filepath.Join(l.dir, "output."+strconv.Itoa(i+1))); err != nil && !errors.Is(err, os.ErrNotExist) {
					return total, err
				}
			}
			f, err := os.OpenFile(filepath.Join(l.dir, "output.0"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return total, err
			}
			l.file = f
			l.size = 0
		}
		n := len(p)
		if int64(n) > l.limit-l.size {
			n = int(l.limit - l.size)
		}
		written, err := l.file.Write(p[:n])
		l.size += int64(written)
		total += written
		p = p[written:]
		if err != nil {
			return total, err
		}
		if written != n {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (l *logRotation) Close() error { return l.file.Close() }

// Docker's stdcopy allocates an entire frame based on its length header. This
// streaming implementation uses the same framing but never trusts a frame size
// as an allocation request. The budget includes the untouched handshake,
// field parsing copy, DER decode workspace, Docker's buffered attach reader,
// and go-plugin's bounded 64KiB handshake Scanner.
func collectorWorkspace(limits ResourceLimits) (int, error) {
	const transportOverhead = 65536 + 4096 + 256
	if limits.ControlMessageMaxBytes <= 0 || limits.ControlMessageMaxBytes > (limits.LogBufferBytes-transportOverhead)/3 {
		return 0, invalid("log buffer cannot contain bootstrap parsing and transport buffers")
	}
	size := limits.LogBufferBytes - 3*limits.ControlMessageMaxBytes - transportOverhead
	if size <= 0 {
		return 0, invalid("log buffer has no attach streaming workspace")
	}
	if size > 32768 {
		size = 32768
	}
	return int(size), nil
}
func collectDockerOutput(src io.Reader, handshake *os.File, logs *logRotation, limits ResourceLimits, guestSocketDir string) error {
	slabSize, err := collectorWorkspace(limits)
	if err != nil {
		return err
	}
	slab := make([]byte, slabSize)
	line := make([]byte, 0, int(limits.ControlMessageMaxBytes))
	ready := false
	var header [8]byte
	for {
		_, err := io.ReadFull(src, header[:])
		if err != nil {
			if err == io.EOF && ready {
				return nil
			}
			if !ready && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
				return classifiedFailure(FailureBootstrapEOF, err)
			}
			return classifiedFailure(FailureAttachRead, err)
		}
		if header[1] != 0 || header[2] != 0 || header[3] != 0 || (header[0] != 1 && header[0] != 2) {
			return classifiedFailure(FailureAttachFrame, nil)
		}
		remaining := int64(binary.BigEndian.Uint32(header[4:]))
		for remaining > 0 {
			n := int64(len(slab))
			if n > remaining {
				n = remaining
			}
			if _, err := io.ReadFull(src, slab[:int(n)]); err != nil {
				return classifiedFailure(FailureAttachRead, err)
			}
			remaining -= n
			p := slab[:int(n)]
			if header[0] == 1 && !ready {
				end := bytes.IndexByte(p, '\n')
				take := len(p)
				if end >= 0 {
					take = end + 1
				}
				if int64(len(line)+take) > limits.ControlMessageMaxBytes {
					return classifiedFailure(FailureBootstrapLimit, nil)
				}
				line = append(line, p[:take]...)
				p = p[take:]
				if end >= 0 {
					if _, err := validateDockerHandshake(line, guestSocketDir); err != nil {
						if _, logErr := logs.Write(line); logErr != nil {
							return errors.Join(err, classifiedFailure(FailureLogSink, logErr))
						}
						return err
					}
					if _, err := handshake.Write(line); err != nil {
						return classifiedFailure(FailureBootstrapForward, err)
					}
					ready = true
					line = nil
				}
			}
			if len(p) > 0 {
				if _, err := logs.Write(p); err != nil {
					return classifiedFailure(FailureLogSink, err)
				}
			}
		}
	}
}

func validateDockerHandshake(line []byte, guestSocketDir string) (string, error) {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return "", classifiedFailure(FailureBootstrapFormat, nil)
	}
	fields := strings.SplitN(string(line[:len(line)-1]), "|", 8)
	if len(fields) != 7 {
		return "", classifiedFailure(FailureBootstrapFormat, nil)
	}
	if fields[0] != "1" || fields[1] != "2" || fields[4] != "grpc" {
		return "", classifiedFailure(FailureBootstrapProtocol, nil)
	}
	if fields[2] != "unix" {
		return "", classifiedFailure(FailureBootstrapNetwork, nil)
	}
	if fields[6] != "true" {
		return "", classifiedFailure(FailureBootstrapMux, nil)
	}
	name := fields[3]
	if filepath.Dir(name) != guestSocketDir || filepath.Base(name) == "." || strings.ContainsAny(name, "\x00\r\n") {
		return "", classifiedFailure(FailureBootstrapSocket, nil)
	}
	cert, err := base64.RawStdEncoding.DecodeString(fields[5])
	if err != nil {
		return "", classifiedFailure(FailureBootstrapTLS, err)
	}
	// Check the bounded DER certificate envelope without recursively allocating
	// x509 objects from untrusted ASN.1. go-plugin AutoMTLS parses the complete
	// certificate and authenticates the peer before any application RPC.
	var envelope, tbs, algorithm, signature asn1.RawValue
	rest, err := asn1.Unmarshal(cert, &envelope)
	if err != nil || len(rest) != 0 || envelope.Tag != 16 || !envelope.IsCompound {
		return "", classifiedFailure(FailureBootstrapTLS, err)
	}
	rest, err = asn1.Unmarshal(envelope.Bytes, &tbs)
	if err != nil || tbs.Tag != 16 || !tbs.IsCompound {
		return "", classifiedFailure(FailureBootstrapTLS, err)
	}
	rest, err = asn1.Unmarshal(rest, &algorithm)
	if err != nil || algorithm.Tag != 16 || !algorithm.IsCompound {
		return "", classifiedFailure(FailureBootstrapTLS, err)
	}
	rest, err = asn1.Unmarshal(rest, &signature)
	if err != nil || len(rest) != 0 || signature.Tag != 3 || len(signature.Bytes) < 2 {
		return "", classifiedFailure(FailureBootstrapTLS, err)
	}
	return name, nil
}
