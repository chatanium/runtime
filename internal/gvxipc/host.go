package gvxipc

import (
	"encoding/json"
	"fmt"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

// PrepareHost exchanges magic, sends INIT and verifies the actual guest
// ROOTS_READY. The host owns cancellation of the stream and must durably
// confirm the result before it sends ROOTS_COMMIT.
func PrepareHost(c *Codec, init gvxcontract.BridgeInit) (gvxcontract.RootInitResult, error) {
	var result gvxcontract.RootInitResult
	roots, err := ValidateInit(init, c.max)
	if err != nil {
		return result, err
	}
	payload, err := json.Marshal(init)
	if err != nil {
		return result, err
	}
	if len(payload) > c.max {
		return result, fmt.Errorf("%w: INIT exceeds control frame limit", ErrInvalidFrame)
	}
	if err = c.SendMagic(); err != nil {
		return result, err
	}
	if err = c.ReadMagic(); err != nil {
		return result, err
	}
	if err = c.Write(Init, payload); err != nil {
		return result, err
	}
	ready, err := readStartupFrame(c, RootsReady)
	if err != nil {
		return result, err
	}
	if err = gvxcontract.DecodeStrict(ready, c.max, 16, &result); err != nil {
		return gvxcontract.RootInitResult{}, fmt.Errorf("%w: ROOTS_READY: %v", ErrInvalidFrame, err)
	}
	if err = validateRootResult(init.Roots.Digest, roots, result); err != nil {
		return gvxcontract.RootInitResult{}, fmt.Errorf("%w: ROOTS_READY: %v", ErrInvalidFrame, err)
	}
	return result, nil
}

// ReadHandshake receives and validates the core-v2 AutoMTLS handshake after
// ROOTS_COMMIT. The returned bytes belong to c until its next Read.
func ReadHandshake(c *Codec, socketDir string) ([]byte, error) {
	line, err := readStartupFrame(c, Handshake)
	if err != nil {
		return nil, err
	}
	if _, err = ValidateHandshake(line, socketDir); err != nil {
		return nil, fmt.Errorf("%w: HANDSHAKE: %v", ErrInvalidFrame, err)
	}
	return line, nil
}

func readStartupFrame(c *Codec, want byte) ([]byte, error) {
	typ, payload, err := c.Read()
	if err != nil {
		return nil, err
	}
	if typ == Error {
		p, err := DecodeError(payload, c.max)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("guest bridge %s: %s", p.Code, p.Message)
	}
	if typ != want {
		return nil, fmt.Errorf("%w: expected startup frame %d, received %d", ErrInvalidFrame, want, typ)
	}
	return payload, nil
}
