package discordbackend

import (
	"errors"
	"os"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"golang.org/x/sys/windows"
)

const ownershipReadFlags = 0

func checkOwnershipDirectory(path string, _ os.FileInfo) error {
	return process.CheckPrivateDir(path)
}

func checkOwnershipFile(file *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return errors.New("Discord ownership file is linked, reparsed, or not regular")
	}
	return process.CheckPrivateFileACL(file)
}
