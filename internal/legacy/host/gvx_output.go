//go:build linux

package host

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

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
