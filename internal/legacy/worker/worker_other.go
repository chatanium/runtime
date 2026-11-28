//go:build !linux

package worker

import (
	"context"
	"errors"
	"io"
)

func Run(context.Context, io.Reader, io.Writer, io.Writer) error {
	return errors.New("legacy worker is Linux-only; portable INIT required")
}
