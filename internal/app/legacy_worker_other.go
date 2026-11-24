//go:build !linux

package app

import (
	"context"
	"errors"
	"io"
)

func runLegacyWorker(context.Context, io.Reader, io.Writer, io.Writer) error {
	return errors.New("legacy worker is Linux-only; portable INIT required")
}
