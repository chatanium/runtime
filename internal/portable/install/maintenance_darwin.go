package install

import (
	"errors"
	"os"
	"syscall"
)

func checkMaintenanceMount(parent *os.Root, child *os.File) error {
	p, err := parent.Stat(".")
	if err != nil {
		return err
	}
	c, err := child.Stat()
	if err != nil {
		return err
	}
	a, aOK := p.Sys().(*syscall.Stat_t)
	b, bOK := c.Sys().(*syscall.Stat_t)
	if !aOK || !bOK || a.Dev != b.Dev {
		return errors.New("refusing to cross an unverified installation mount")
	}
	return nil
}
