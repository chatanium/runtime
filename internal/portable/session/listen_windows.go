package session

import (
	"net"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/portable/process"
)

func listenPlugin(path string) (net.Listener, error) {
	// go-plugin's mux dials a net.Addr directly. The worker uses Windows'
	// native filesystem AF_UNIX support, not the supervisor's named pipe
	// and not a competing local TCP endpoint.
	if err := process.CheckPrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
}
