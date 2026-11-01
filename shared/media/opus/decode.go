package opus

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// Decoder reads raw DCA frames or DCA1 files from previous module encodings.
// Headers are bounded to 1MiB and individual packets to the signed DCA limit.
type Decoder struct {
	r       *bufio.Reader
	started bool
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: bufio.NewReader(r)}
}

func (d *Decoder) OpusFrame(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !d.started {
		d.started = true
		magic, err := d.r.Peek(4)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if len(magic) >= 3 && string(magic[:3]) == "DCA" {
			if string(magic) != "DCA1" {
				return nil, fmt.Errorf("unsupported DCA header")
			}
			d.r.Discard(4)
			var size [4]byte
			if _, err := io.ReadFull(d.r, size[:]); err != nil {
				return nil, unexpectedEOF(err)
			}
			n := binary.LittleEndian.Uint32(size[:])
			if n > 1<<20 {
				return nil, fmt.Errorf("DCA metadata exceeds 1MiB")
			}
			if _, err := io.CopyN(io.Discard, d.r, int64(n)); err != nil {
				return nil, unexpectedEOF(err)
			}
		}
	}
	var size [2]byte
	if _, err := io.ReadFull(d.r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint16(size[:]))
	if n == 0 || n > 32767 {
		return nil, fmt.Errorf("invalid DCA frame size %d", n)
	}
	packet := make([]byte, n)
	if _, err := io.ReadFull(d.r, packet); err != nil {
		return nil, unexpectedEOF(err)
	}
	return packet, nil
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
