//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func validAccountName(name string) bool {
	if name == "" || len(name) > 31 {
		return false
	}
	for index, c := range name {
		if !(c >= 'a' && c <= 'z' || c == '_' || index > 0 && (c >= '0' && c <= '9' || c == '-')) {
			return false
		}
	}
	return true
}
func unknownUser(e error) bool  { var unknown user.UnknownUserError; return errors.As(e, &unknown) }
func unknownGroup(e error) bool { var unknown user.UnknownGroupError; return errors.As(e, &unknown) }
func validateGroupOnly(p host.ProvisionProperties) error {
	group, e := user.LookupGroup(p.Name)
	if e != nil {
		return e
	}
	if !validAccountName(p.Name) || p.GID == 0 || group.Gid != strconv.FormatUint(uint64(p.GID), 10) {
		return errors.New("dedicated group identity mismatch")
	}
	return validateUnsharedGroup(p.Name, group.Gid)
}
func accountRemovalState(p host.ProvisionProperties) error {
	if !validAccountName(p.Name) || p.GID == 0 {
		return errors.New("invalid recorded account identity")
	}
	if p.Source != "group" {
		account, e := user.Lookup(p.Name)
		if e == nil {
			if account.Uid != strconv.FormatUint(uint64(p.UID), 10) || account.Gid != strconv.FormatUint(uint64(p.GID), 10) {
				return errors.New("account identity was replaced")
			}
		} else if !unknownUser(e) {
			return e
		}
	}
	group, e := user.LookupGroup(p.Name)
	if e == nil {
		if group.Gid != strconv.FormatUint(uint64(p.GID), 10) {
			return errors.New("group identity was replaced")
		}
		return validateUnsharedGroup(p.Name, group.Gid)
	}
	if !unknownGroup(e) {
		return e
	}
	return nil
}
func removeAccount(ctx context.Context, s *ownedSession, record host.ProvisionRecord) error {
	var p host.ProvisionProperties
	if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return e
	}
	if !record.ProductCreated || record.ExistedBefore {
		return errors.New("account was not product-created")
	}
	if e := accountRemovalState(p); e != nil {
		return e
	}
	uid, gid := strconv.FormatUint(uint64(p.UID), 10), strconv.FormatUint(uint64(p.GID), 10)
	processes, e := os.ReadDir("/proc")
	if e != nil {
		return e
	}
	for _, process := range processes {
		if _, e = strconv.Atoi(process.Name()); e != nil {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("/proc", process.Name(), "status"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			check := ""
			switch fields[0] {
			case "Uid:":
				if p.Source != "group" {
					check = uid
				}
			case "Gid:", "Groups:":
				check = gid
			}
			if check != "" {
				for _, id := range fields[1:] {
					if id == check {
						return errors.New("product account/group has live processes")
					}
				}
			}
		}
	}
	passwd, e := os.ReadFile("/etc/passwd")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[3] == gid && fields[0] != p.Name {
			return errors.New("product group is shared")
		}
	}
	if p.Source != "group" {
		if _, e = user.Lookup(p.Name); e == nil {
			if _, e = s.systemd.RunHelper(ctx, s.owner, bundle.ProgramID("userdel"), []string{p.Name}, nil, 65536); e != nil {
				return e
			}
		} else if !unknownUser(e) {
			return e
		}
	}
	if _, e = user.LookupGroup(p.Name); e == nil {
		if _, e = s.systemd.RunHelper(ctx, s.owner, bundle.ProgramID("groupdel"), []string{p.Name}, nil, 65536); e != nil {
			return e
		}
	} else if !unknownGroup(e) {
		return e
	}
	if _, e = user.LookupGroup(p.Name); !unknownGroup(e) {
		return errors.Join(errors.New("group removal is not established"), e)
	}
	if p.Source != "group" {
		if _, e = user.Lookup(p.Name); !unknownUser(e) {
			return errors.Join(errors.New("account removal is not established"), e)
		}
	}
	return nil
}
