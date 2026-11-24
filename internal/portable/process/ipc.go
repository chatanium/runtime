package process

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
)

// ErrEndpointNotReady identifies an authorized endpoint whose startup has
// not yet published its final socket permissions or completed its token write.
var ErrEndpointNotReady = errors.New("private native endpoint is not ready")

func readToken(r io.Reader) ([]byte, error) {
	const size = 64 // 256-bit token, hexadecimal on disk
	raw, err := io.ReadAll(io.LimitReader(r, size+3))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, ErrEndpointNotReady
	}
	token := bytes.TrimSpace(raw)
	var decoded [size / 2]byte
	if len(raw) > size+2 || len(token) != size {
		return nil, errors.New("invalid native engine token length")
	}
	if _, err := hex.Decode(decoded[:], token); err != nil {
		return nil, errors.New("invalid native engine token encoding")
	}
	return token, nil
}
