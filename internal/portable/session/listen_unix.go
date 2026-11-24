//go:build !windows

package session

import (
	"net"

	"github.com/thirdscam/chatanium/internal/portable/process"
)

func listenPlugin(path string) (net.Listener, error) { return process.Listen(path) }
