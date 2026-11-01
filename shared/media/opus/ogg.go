package opus

import (
	"encoding/binary"
	"fmt"
	"io"
)

// oggReader handles a single logical Opus stream, including packets continued
// across pages. Page and packet storage are bounded independently of input size.
type oggReader struct {
	r                io.Reader
	page             [65307]byte
	packet           []byte
	segments         []byte
	data             []byte
	index            int
	offset           int
	serial           uint32
	sequence         uint32
	started          bool
	end              bool
	headers          int
	maxPacketBytes   int // Zero uses the inherent single-frame Opus bound.
	maxMetadataBytes int
	finished         bool
}

func (r *oggReader) next() ([]byte, error) {
	for {
		if r.index == len(r.segments) {
			if r.end {
				if len(r.packet) != 0 || r.headers != 2 {
					return nil, fmt.Errorf("incomplete Ogg Opus stream")
				}
				if !r.finished {
					var trailing [1]byte
					n, err := io.ReadFull(r.r, trailing[:])
					if n != 0 {
						return nil, fmt.Errorf("trailing data after Ogg EOS")
					}
					if err != io.EOF {
						return nil, err
					}
					r.finished = true
				}
				return nil, io.EOF
			}
			if err := r.readPage(); err != nil {
				return nil, err
			}
		}
		for r.index < len(r.segments) {
			n := int(r.segments[r.index])
			r.index++
			limit := 1275 // Maximum size of a single encoded Opus frame.
			if r.maxPacketBytes > 0 && r.maxPacketBytes < limit {
				limit = r.maxPacketBytes
			}
			switch r.headers {
			case 0:
				limit = 19
			case 1:
				limit = 1 << 20
				if r.maxMetadataBytes > 0 && r.maxMetadataBytes < limit {
					limit = r.maxMetadataBytes
				}
			}
			if n > limit-len(r.packet) {
				return nil, fmt.Errorf("Ogg Opus packet exceeds %d bytes", limit)
			}
			// Grow explicitly: append's capacity rounding must not allocate past
			// the metadata/partial-packet limit before the packet is complete.
			if need := len(r.packet) + n; need > cap(r.packet) {
				capacity := max(need, 2*cap(r.packet))
				if capacity > limit {
					capacity = limit
				}
				packet := make([]byte, len(r.packet), capacity)
				copy(packet, r.packet)
				r.packet = packet
			}
			r.packet = append(r.packet, r.data[r.offset:r.offset+n]...)
			r.offset += n
			if n == 255 {
				continue
			}
			packet := r.packet
			r.packet = r.packet[:0]
			switch r.headers {
			case 0:
				if len(packet) != 19 || string(packet[:8]) != "OpusHead" || packet[8] != 1 || packet[9] != 2 || binary.LittleEndian.Uint32(packet[12:16]) != 48000 || packet[18] != 0 {
					return nil, fmt.Errorf("expected 48kHz stereo mapping-family-zero OpusHead")
				}
				r.headers++
			case 1:
				if err := validateTags(packet); err != nil {
					return nil, err
				}
				r.headers++
			default:
				if err := validatePacket(packet); err != nil {
					return nil, err
				}
				return packet, nil
			}
		}
	}
}

func (r *oggReader) readPage() error {
	header := r.page[:27]
	if _, err := io.ReadFull(r.r, header); err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF // A successful stream must include EOS.
		}
		return err
	}
	if string(header[:4]) != "OggS" || header[4] != 0 || header[5]&^byte(7) != 0 {
		return fmt.Errorf("invalid Ogg page header")
	}
	flags := header[5]
	serial := binary.LittleEndian.Uint32(header[14:18])
	sequence := binary.LittleEndian.Uint32(header[18:22])
	if !r.started {
		if flags&2 == 0 || flags&1 != 0 || sequence != 0 {
			return fmt.Errorf("invalid first Ogg page")
		}
		r.serial = serial
		r.started = true
	} else if flags&2 != 0 || serial != r.serial || sequence != r.sequence+1 {
		return fmt.Errorf("discontinuous or multiplexed Ogg stream")
	}
	if (flags&1 != 0) != (len(r.packet) != 0) {
		return fmt.Errorf("invalid Ogg packet continuation")
	}
	r.sequence = sequence
	r.end = flags&4 != 0
	n := int(header[26])
	r.segments = r.page[27 : 27+n]
	if _, err := io.ReadFull(r.r, r.segments); err != nil {
		return unexpectedEOF(err)
	}
	size := 0
	for _, segment := range r.segments {
		size += int(segment)
	}
	r.data = r.page[27+n : 27+n+size]
	if _, err := io.ReadFull(r.r, r.data); err != nil {
		return unexpectedEOF(err)
	}
	page := r.page[:27+n+size]
	want := binary.LittleEndian.Uint32(page[22:26])
	clear(page[22:26])
	var crc uint32
	for _, b := range page {
		crc = crc<<8 ^ oggCRC[byte(crc>>24)^b]
	}
	if crc != want {
		return fmt.Errorf("Ogg page checksum mismatch")
	}
	r.index, r.offset = 0, 0
	return nil
}

var oggCRC = func() (table [256]uint32) {
	for i := range table {
		v := uint32(i) << 24
		for range 8 {
			if v&0x80000000 != 0 {
				v = v<<1 ^ 0x04c11db7
			} else {
				v <<= 1
			}
		}
		table[i] = v
	}
	return table
}()

// validateTags walks lengths without allocating vendor/comment strings. The
// packet itself has already been bounded while assembling continued pages.
func validateTags(packet []byte) error {
	if len(packet) < 16 || string(packet[:8]) != "OpusTags" {
		return fmt.Errorf("expected OpusTags")
	}
	vendor := uint64(binary.LittleEndian.Uint32(packet[8:12]))
	if vendor > uint64(len(packet)-16) {
		return fmt.Errorf("truncated OpusTags vendor")
	}
	offset := 12 + int(vendor)
	count := binary.LittleEndian.Uint32(packet[offset : offset+4])
	offset += 4
	if uint64(count) > uint64((len(packet)-offset)/4) {
		return fmt.Errorf("truncated OpusTags comments")
	}
	for ; count > 0; count-- {
		if len(packet)-offset < 4 {
			return fmt.Errorf("truncated OpusTags comment length")
		}
		size := uint64(binary.LittleEndian.Uint32(packet[offset : offset+4]))
		offset += 4
		if size > uint64(len(packet)-offset) {
			return fmt.Errorf("truncated OpusTags comment")
		}
		offset += int(size)
	}
	return nil // RFC 7845 permits padding after the comments.
}

// validatePacket checks RFC 6716 framing and a total duration of exactly 960
// samples at the fixed 48kHz Opus clock. It does not pretend to decode audio.
func validatePacket(packet []byte) error {
	invalid := func() error { return fmt.Errorf("invalid or non-20ms Opus packet") }
	if len(packet) == 0 {
		return invalid()
	}
	config := packet[0] >> 3
	samples := 0
	switch {
	case config >= 16:
		samples = 120 << (config & 3)
	case config >= 12:
		samples = 480 << (config & 1)
	default:
		samples = [...]int{480, 960, 1920, 2880}[config&3]
	}
	code := packet[0] & 3
	count, offset, end := 1, 1, len(packet)
	vbr := false
	switch code {
	case 1:
		count = 2
	case 2:
		count, vbr = 2, true
	case 3:
		if len(packet) < 2 {
			return invalid()
		}
		control := packet[1]
		count, offset, vbr = int(control&63), 2, control&128 != 0
		if control&64 != 0 {
			for {
				if offset >= end {
					return invalid()
				}
				padding := int(packet[offset])
				offset++
				if padding == 255 {
					end -= 254
				} else {
					end -= padding
					break
				}
				if offset > end {
					return invalid()
				}
			}
		}
	}
	if count == 0 || samples*count != 960 || offset > end {
		return invalid()
	}
	if !vbr {
		if (end-offset)%count != 0 || (end-offset)/count > 1275 {
			return invalid()
		}
		return nil
	}
	remaining := end - offset
	for range count - 1 {
		if offset >= end {
			return invalid()
		}
		size := int(packet[offset])
		offset++
		remaining--
		if size >= 252 {
			if offset >= end {
				return invalid()
			}
			size += 4 * int(packet[offset])
			offset++
			remaining--
		}
		if size > 1275 || size > remaining {
			return invalid()
		}
		remaining -= size
	}
	if remaining < 0 || remaining > 1275 {
		return invalid()
	}
	return nil
}
