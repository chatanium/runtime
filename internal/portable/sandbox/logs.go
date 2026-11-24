package sandbox

import (
	"errors"
	"io"
	"os"
	"strconv"

	"github.com/thirdscam/chatanium/internal/gvxipc"
)

// drainLogs retains at most count files, each at most maxBytes. The caller
// charges that full peak plus the engine's fixed-size control/policy files
// before creating the run directory. Nothing forwards unbounded diagnostics
// to the worker or supervisor output.
func drainLogs(root *os.Root, input io.Reader, maxBytes int64, count int) (retErr error) {
	name := func(i int) string { return "log." + strconv.Itoa(i) }
	var file *os.File
	defer func() {
		if file != nil {
			retErr = errors.Join(retErr, file.Close())
		}
	}()
	size := maxBytes
	var slab [gvxipc.LogSlab]byte
	for {
		n, readErr := input.Read(slab[:])
		for p := slab[:n]; len(p) != 0; {
			if size == maxBytes {
				if file != nil {
					closeErr := file.Close()
					file = nil
					if closeErr != nil {
						return closeErr
					}
					if err := root.Remove(name(count - 1)); err != nil && !errors.Is(err, os.ErrNotExist) {
						return err
					}
					for i := count - 2; i >= 0; i-- {
						if err := root.Rename(name(i), name(i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
							return err
						}
					}
				}
				var err error
				file, err = root.OpenFile(name(0), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					return err
				}
				size = 0
			}
			step := int(min(int64(len(p)), maxBytes-size))
			written, err := file.Write(p[:step])
			if err != nil {
				return err
			}
			if written != step {
				return io.ErrShortWrite
			}
			size += int64(written)
			p = p[written:]
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}
