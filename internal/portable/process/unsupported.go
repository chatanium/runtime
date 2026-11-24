//go:build !(((linux && !android) || windows) && (amd64 || arm64)) && !(darwin && arm64 && !ios)

package process

import (
	"context"
	"errors"
	"net"
	"os"
)

var errUnsupported = errors.New("portable native process ownership is unavailable for this host target")

func start(string, Spec) (*Child, error)                   { return nil, errUnsupported }
func RunGuardian() error                                   { return errUnsupported }
func BootIdentity() (string, error)                        { return "", errUnsupported }
func SelfIdentity() (string, error)                        { return "", errUnsupported }
func OwnerIdentity() (string, error)                       { return "", errUnsupported }
func EnsurePrivateDir(string) error                        { return errUnsupported }
func CheckPrivateDir(string) error                         { return errUnsupported }
func ProtectPrivateDir(string) error                       { return errUnsupported }
func CheckPrivateFileACL(*os.File) error                   { return errUnsupported }
func Listen(string) (net.Listener, error)                  { return nil, errUnsupported }
func Dial(context.Context, string) (net.Conn, error)       { return nil, errUnsupported }
func DialEngine(context.Context, string) (net.Conn, error) { return nil, errUnsupported }
func ReadEngineToken(string) ([]byte, error)               { return nil, errUnsupported }
func Lock(string) (*OwnerLock, error)                      { return nil, errUnsupported }
