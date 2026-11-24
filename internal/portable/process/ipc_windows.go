//go:build windows && (amd64 || arm64)

package process

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func ownerSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

// OwnerIdentity identifies the Windows token user, not the display name.
func OwnerIdentity() (string, error) {
	sid, err := ownerSID()
	if err != nil {
		return "", err
	}
	return "sid:" + sid.String(), nil
}

// CheckPrivateFileACL checks the owner and DACL of the already open handle.
// The caller must open with READ_CONTROL and verify type and path binding.
func CheckPrivateFileACL(file *os.File) error {
	owner, err := ownerSID()
	if err != nil {
		return err
	}
	err = checkOwnerACL(windows.Handle(file.Fd()), owner, false)
	runtime.KeepAlive(file)
	return err
}

func localWindowsPath(path string) bool {
	volume := filepath.VolumeName(path)
	return len(volume) == 2 && volume[1] == ':' && filepath.IsAbs(path) && filepath.Clean(path) == path && launchString(path) && !strings.Contains(path[2:], ":")
}

func localWindowsLeaf(path string) bool {
	return localWindowsPath(path) && filepath.Dir(path) != path
}

func ownerSDDL(owner *windows.SID, flags, access string) string {
	sid := owner.String()
	return "O:" + sid + "D:P(A;" + flags + ";" + access + ";;;" + sid + ")"
}

func checkOwnerACL(handle windows.Handle, owner *windows.SID, inherit bool) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	actual, _, err := sd.Owner()
	if err != nil || actual == nil || !actual.Equals(owner) {
		return errors.Join(errors.New("Windows native endpoint has a different owner SID"), err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return errors.Join(errors.New("Windows native endpoint lacks a private DACL"), err)
	}
	const propagation = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	ownerInherits := false
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(owner) {
			return errors.New("Windows native endpoint DACL is not restricted to the owner SID")
		}
		if ace.Header.AceFlags&(propagation|windows.INHERIT_ONLY_ACE|windows.NO_PROPAGATE_INHERIT_ACE) == propagation {
			ownerInherits = true
		}
	}
	if inherit && !ownerInherits {
		return errors.New("Windows native directory lacks inheritable owner-only access")
	}
	return nil
}

// Pinned rungv v0.22 creates a protected DACL with unqualified full access
// for the token user and, separately, LocalSystem. The latter is accepted
// only for a GVX token, never for Chatanium IPC or installation ownership.
func checkGVXTokenACL(handle windows.Handle, owner *windows.SID) error {
	const fileAllAccess = 0x1f01ff
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	actual, _, err := sd.Owner()
	if err != nil || actual == nil || !actual.Equals(owner) {
		return errors.Join(errors.New("GVX token file has a different owner SID"), err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.Join(errors.New("GVX token file DACL is not protected"), err)
	}
	wantSystem := !owner.Equals(system)
	wantCount := uint16(1)
	if wantSystem {
		wantCount++
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != wantCount {
		return errors.Join(errors.New("GVX token file has an unexpected DACL"), err)
	}
	var seenOwner, seenSystem bool
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
			(ace.Mask != fileAllAccess && ace.Mask != windows.GENERIC_ALL) {
			return errors.New("GVX token file has an unexpected permission")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case !seenOwner && sid.Equals(owner):
			seenOwner = true
		case wantSystem && !seenSystem && sid.Equals(system):
			seenSystem = true
		default:
			return errors.New("GVX token file authorizes an unexpected SID")
		}
	}
	if !seenOwner || seenSystem != wantSystem {
		return errors.New("GVX token file is missing the expected owner or LocalSystem access")
	}
	return nil
}

// openWindowsDirChain pins all path components without delete sharing, rejecting
// junctions, symlinks and other reparse points. The caller must close every pin.
func openWindowsDirChain(path string, finalAccess uint32) ([]windows.Handle, error) {
	if !localWindowsPath(path) {
		return nil, errors.New("absolute, clean local Windows directory required")
	}
	volume := filepath.VolumeName(path)
	root := volume + `\`
	rootName, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	const driveRemovable, driveFixed = 2, 3
	if drive := windows.GetDriveType(rootName); drive != driveFixed && drive != driveRemovable {
		return nil, errors.New("Windows native endpoint requires a local filesystem drive")
	}
	var parts []string
	if path != root {
		parts = strings.Split(path[len(root):], `\`)
	}
	pins := make([]windows.Handle, 0, len(parts)+1)
	for i := range len(parts) + 1 {
		if i > 0 {
			root = filepath.Join(root, parts[i-1])
		}
		access := uint32(windows.FILE_READ_ATTRIBUTES)
		if i == len(parts) {
			access |= finalAccess
		}
		h, err := openWindowsPath(root, access, windows.OPEN_EXISTING, nil)
		if err != nil {
			closeWindowsPins(pins)
			return nil, err
		}
		pins = append(pins, h)
		var info windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(h, &info)
		if err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != windows.FILE_ATTRIBUTE_DIRECTORY {
			closeWindowsPins(pins)
			return nil, &os.PathError{Op: "verify non-reparse Windows directory", Path: root, Err: errors.Join(errors.New("not a normal directory"), err)}
		}
	}
	return pins, nil
}

func closeWindowsPins(pins []windows.Handle) {
	for _, h := range pins {
		windows.CloseHandle(h)
	}
}

func openPrivateWindowsDir(path string) ([]windows.Handle, *windows.SID, error) {
	if !localWindowsLeaf(path) {
		return nil, nil, errors.New("local private Windows directory required")
	}
	owner, err := ownerSID()
	if err != nil {
		return nil, nil, err
	}
	pins, err := openWindowsDirChain(path, windows.READ_CONTROL)
	if err != nil {
		return nil, nil, err
	}
	if err = checkOwnerACL(pins[len(pins)-1], owner, true); err != nil {
		closeWindowsPins(pins)
		return nil, nil, &os.PathError{Op: "verify private native directory", Path: path, Err: err}
	}
	return pins, owner, nil
}

// EnsurePrivateDir creates a leaf with a private, inheritable DACL or verifies
// the existing private leaf. It does not follow reparse points.
func EnsurePrivateDir(path string) error {
	if !localWindowsLeaf(path) {
		return errors.New("local private Windows directory required")
	}
	parent, err := openWindowsDirChain(filepath.Dir(path), 0)
	if err != nil {
		return err
	}
	defer closeWindowsPins(parent)
	owner, err := ownerSID()
	if err != nil {
		return err
	}
	sa, err := privateWindowsSecurity(owner, "OICI")
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return &os.PathError{Op: "create private native directory", Path: path, Err: err}
	}
	return CheckPrivateDir(path)
}

// CheckPrivateDir verifies the owner's DACL and the link-free path to it.
func CheckPrivateDir(path string) error {
	pins, _, err := openPrivateWindowsDir(path)
	closeWindowsPins(pins)
	return err
}

// ProtectPrivateDir installs a private DACL on a directory already created by
// this owner. Call it before publishing files in the directory.
func ProtectPrivateDir(path string) error {
	if !localWindowsLeaf(path) {
		return errors.New("local private Windows directory required")
	}
	pins, err := openWindowsDirChain(path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer closeWindowsPins(pins)
	owner, err := ownerSID()
	if err != nil {
		return err
	}
	h := pins[len(pins)-1]
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	actual, _, err := sd.Owner()
	if err != nil || actual == nil || !actual.Equals(owner) {
		return errors.Join(errors.New("cannot protect another Windows owner's directory"), err)
	}
	sa, err := privateWindowsSecurity(owner, "OICI")
	if err != nil {
		return err
	}
	dacl, _, err := sa.SecurityDescriptor.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	return checkOwnerACL(h, owner, true)
}

func privateWindowsSecurity(owner *windows.SID, flags string) (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(ownerSDDL(owner, flags, "FA"))
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func openWindowsPath(path string, access, action uint32, sa *windows.SecurityAttributes) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa,
		action, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, &os.PathError{Op: "open native path", Path: path, Err: err}
	}
	return h, nil
}

func pipeName(path string, owner *windows.SID) string {
	digest := sha256.Sum256([]byte(owner.String() + "\x00" + strings.ToUpper(path)))
	return fmt.Sprintf(`\\.\pipe\chatanium-portable-%x`, digest)
}

// Listen makes a local-only named pipe with an owner-only DACL and atomically
// refuses to bind a name already occupied by another server.
func Listen(path string) (net.Listener, error) {
	if !localWindowsLeaf(path) {
		return nil, errors.New("local Windows management endpoint path required")
	}
	pins, owner, err := openPrivateWindowsDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer closeWindowsPins(pins)
	return winio.ListenPipe(pipeName(path, owner), &winio.PipeConfig{SecurityDescriptor: ownerSDDL(owner, "", "GA")})
}

// Dial authenticates the server's owner and DACL before sending any bytes.
func Dial(ctx context.Context, path string) (net.Conn, error) {
	if !localWindowsLeaf(path) {
		return nil, errors.New("local Windows management endpoint path required")
	}
	pins, owner, err := openPrivateWindowsDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer closeWindowsPins(pins)
	conn, err := winio.DialPipeContext(ctx, pipeName(path, owner))
	if err != nil {
		return nil, err
	}
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		conn.Close()
		return nil, errors.New("cannot inspect Windows management pipe handle")
	}
	if err := checkOwnerACL(windows.Handle(pipe.Fd()), owner, false); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// DialEngine connects to pinned GVX's local AF_UNIX control transport, not
// the Chatanium named pipe. Its HELLO requires the separately protected token.
func DialEngine(ctx context.Context, path string) (net.Conn, error) {
	if !localWindowsLeaf(path) {
		return nil, errors.New("local Windows engine socket path required")
	}
	pins, _, err := openPrivateWindowsDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer closeWindowsPins(pins)
	h, err := openWindowsPath(path, windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	var tag struct{ Attributes, ReparseTag uint32 }
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return nil, err
	}
	const afUnixTag = 0x80000023 // IO_REPARSE_TAG_AF_UNIX
	if tag.Attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || tag.ReparseTag != afUnixTag {
		return nil, errors.New("Windows engine endpoint is not an AF_UNIX socket")
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

// ReadEngineToken verifies the GVX token's protected DACL and reads only the
// expected bounded hexadecimal token.
func ReadEngineToken(path string) ([]byte, error) {
	f, err := openPrivateWindowsFile(path, windows.GENERIC_READ, windows.OPEN_EXISTING, checkGVXTokenACL)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		// Metadata-only opens can succeed while the writer has denied data
		// sharing. Retry only after authorizing the exact file independently.
		if metadata, authErr := openPrivateWindowsFile(path, 0, windows.OPEN_EXISTING, checkGVXTokenACL); authErr == nil {
			metadata.Close()
			return nil, ErrEndpointNotReady
		}
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readToken(f)
}

// Lock holds an exclusive file range until the owner handle closes. A later
// acquisition is not used alone as evidence of native Job cleanup.
func Lock(path string) (*OwnerLock, error) {
	f, err := openPrivateWindowsFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.OPEN_ALWAYS,
		func(h windows.Handle, owner *windows.SID) error { return checkOwnerACL(h, owner, false) })
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrOwnerBusy
		}
		return nil, err
	}
	return &OwnerLock{file: f}, nil
}

func openPrivateWindowsFile(path string, access, action uint32, checkACL func(windows.Handle, *windows.SID) error) (*os.File, error) {
	if !localWindowsLeaf(path) {
		return nil, errors.New("local private Windows file required")
	}
	pins, owner, err := openPrivateWindowsDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer closeWindowsPins(pins)
	var sa *windows.SecurityAttributes
	if action != windows.OPEN_EXISTING {
		sa, err = privateWindowsSecurity(owner, "")
		if err != nil {
			return nil, err
		}
	}
	h, err := openWindowsPath(path, access|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, action, sa)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &info)
	if err == nil && (info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1) {
		err = errors.New("private Windows file must be singly linked and not a reparse point")
	}
	if err == nil {
		err = checkACL(h, owner)
	}
	if err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "verify private native file", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
