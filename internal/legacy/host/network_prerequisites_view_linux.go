//go:build linux

package host

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"

	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

type networkPrerequisiteInterface struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
	MTU  uint32 `json:"mtu"`
	Up   bool   `json:"up"`
	Kind string `json:"kind"`
}
type networkPrerequisiteAddress struct {
	Interface string `json:"interface"`
	Family    string `json:"family"`
	Prefix    string `json:"prefix"`
	Scope     uint8  `json:"scope"`
	Active    bool   `json:"active"`
}
type networkPrerequisiteRoute struct {
	Family          string `json:"family"`
	Source          string `json:"source"`
	Target          string `json:"target"`
	Interface       string `json:"interface"`
	MAC             string `json:"mac"`
	Gateway         string `json:"gateway"`
	Via             string `json:"via"`
	PreferredSource string `json:"preferred_source"`
}
type networkPrerequisiteInventory struct {
	Profile    sharedhost.NetworkProfile                 `json:"profile"`
	Forwarding []networkReadScalar            `json:"forwarding"`
	Interfaces []networkPrerequisiteInterface `json:"interfaces"`
	Addresses  []networkPrerequisiteAddress   `json:"addresses"`
	Routes     []networkPrerequisiteRoute     `json:"routes"`
}

func networkReadUint32(attrs []networkReadAttribute, kind uint16) (uint32, error) {
	value := networkReadAttributeValue(attrs, kind)
	if len(value) == 0 {
		return 0, nil
	}
	if len(value) != 4 {
		return 0, errors.New("invalid semantic network integer width")
	}
	return binary.NativeEndian.Uint32(value), nil
}
func networkReadFamily(family int) (string, error) {
	switch family {
	case unix.AF_INET:
		return "ipv4", nil
	case unix.AF_INET6:
		return "ipv6", nil
	}
	return "", errors.New("unsupported semantic network address family")
}
func networkReadIP(attrs []networkReadAttribute, kind uint16, family int) (string, error) {
	value := networkReadAttributeValue(attrs, kind)
	if len(value) == 0 {
		return "", nil
	}
	address, err := networkReadAddress(family, value)
	if err != nil {
		return "", err
	}
	return address.String(), nil
}
func networkReadVia(attrs []networkReadAttribute) (string, error) {
	value := networkReadAttributeValue(attrs, unix.RTA_VIA)
	if len(value) == 0 {
		return "", nil
	}
	if len(value) < 2 {
		return "", errors.New("invalid semantic route via")
	}
	family := int(binary.NativeEndian.Uint16(value[:2]))
	address, err := networkReadAddress(family, value[2:])
	if err != nil {
		return "", err
	}
	label, err := networkReadFamily(family)
	if err != nil {
		return "", err
	}
	return label + " " + address.String(), nil
}

// This is the semantic subset actually required by preflight: configured
// uplinks, their active selected source addresses, and effective route lookups
// for the existing fixed/public-resolver targets. Native identifiers, dump
// headers, statistics, cache metrics, lifetimes and unrelated host links are
// deliberately not approval authority.
func networkSemanticInventory(cfg NetworkConfig, raw networkReadInventory) (networkPrerequisiteInventory, error) {
	out := networkPrerequisiteInventory{Profile: cfg.Profile, Forwarding: raw.Forwarding, Interfaces: []networkPrerequisiteInterface{}, Addresses: []networkPrerequisiteAddress{}, Routes: []networkPrerequisiteRoute{}}
	if out.Forwarding == nil {
		out.Forwarding = []networkReadScalar{}
	}
	if cfg.Profile == sharedhost.NetworkNone {
		out.Forwarding = []networkReadScalar{}
		return out, nil
	}
	links := make(map[int]networkPrerequisiteInterface, len(raw.Links))
	for _, row := range raw.Links {
		if len(row.Header) != unix.SizeofIfInfomsg {
			return out, errors.New("invalid semantic link header")
		}
		index := int(int32(binary.NativeEndian.Uint32(row.Header[4:8])))
		link := networkPrerequisiteInterface{Name: strings.TrimRight(string(networkReadAttributeValue(row.Attributes, unix.IFLA_IFNAME)), "\x00"), MAC: net.HardwareAddr(networkReadAttributeValue(row.Attributes, unix.IFLA_ADDRESS)).String(), Up: binary.NativeEndian.Uint32(row.Header[8:12])&unix.IFF_UP != 0}
		var err error
		link.MTU, err = networkReadUint32(row.Attributes, unix.IFLA_MTU)
		if err != nil {
			return out, err
		}
		if value := networkReadAttributeValue(row.Attributes, unix.IFLA_LINKINFO); len(value) > 0 {
			info, err := networkReadNormalize(value, 0, func(kind uint16) bool { return kind == 1 })
			if err != nil {
				return out, err
			}
			link.Kind = strings.TrimRight(string(networkReadAttributeValue(info.Attributes, 1)), "\x00")
		}
		links[index] = link
		out.Interfaces = append(out.Interfaces, link)
	}
	slices.SortFunc(out.Interfaces, func(a, b networkPrerequisiteInterface) int { return strings.Compare(a.Name, b.Name) })
	for bindingIndex, binding := range []struct{ name, source string }{{cfg.Uplink4, cfg.Source4}, {cfg.Uplink6, cfg.Source6}} {
		if bindingIndex == 1 && cfg.Profile != sharedhost.NetworkPublicDual {
			continue
		}
		if binding.source == "" {
			continue
		}
		selected := netip.MustParseAddr(binding.source)
		if selected.Is6() && cfg.Profile != sharedhost.NetworkPublicDual {
			continue
		}
		for _, row := range raw.Addresses {
			if len(row.Header) != unix.SizeofIfAddrmsg {
				return out, errors.New("invalid semantic address header")
			}
			link, found := links[int(binary.NativeEndian.Uint32(row.Header[4:8]))]
			if !found || link.Name != binding.name {
				continue
			}
			family := int(row.Header[0])
			if selected.Is4() && family != unix.AF_INET || selected.Is6() && family != unix.AF_INET6 {
				continue
			}
			value := networkReadAttributeValue(row.Attributes, unix.IFA_LOCAL)
			if len(value) == 0 {
				value = networkReadAttributeValue(row.Attributes, unix.IFA_ADDRESS)
			}
			address, err := networkReadAddress(family, value)
			if err != nil {
				return out, err
			}
			if address != selected {
				continue
			}
			label, err := networkReadFamily(family)
			if err != nil {
				return out, err
			}
			flags := uint32(row.Header[2])
			if len(networkReadAttributeValue(row.Attributes, unix.IFA_FLAGS)) > 0 {
				flags, err = networkReadUint32(row.Attributes, unix.IFA_FLAGS)
				if err != nil {
					return out, err
				}
			}
			prefix := netip.PrefixFrom(address, int(row.Header[1]))
			if !prefix.IsValid() {
				return out, errors.New("invalid selected source prefix")
			}
			out.Addresses = append(out.Addresses, networkPrerequisiteAddress{link.Name, label, prefix.String(), row.Header[3], flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DEPRECATED|unix.IFA_F_DADFAILED) == 0})
		}
	}
	slices.SortFunc(out.Addresses, func(a, b networkPrerequisiteAddress) int {
		if a.Interface != b.Interface {
			return strings.Compare(a.Interface, b.Interface)
		}
		if a.Family != b.Family {
			return strings.Compare(a.Family, b.Family)
		}
		return strings.Compare(a.Prefix, b.Prefix)
	})
	for _, selection := range raw.Selections {
		index, err := networkReadUint32(selection.Route.Attributes, unix.RTA_OIF)
		if err != nil {
			return out, err
		}
		link, found := links[int(index)]
		if !found {
			return out, errors.New("effective route has no observed selected uplink")
		}
		family := unix.AF_INET
		if selection.Family == "ipv6" {
			family = unix.AF_INET6
		}
		route := networkPrerequisiteRoute{Family: selection.Family, Source: selection.Source, Target: selection.Target, Interface: link.Name, MAC: link.MAC}
		route.Gateway, err = networkReadIP(selection.Route.Attributes, unix.RTA_GATEWAY, family)
		if err != nil {
			return out, err
		}
		route.PreferredSource, err = networkReadIP(selection.Route.Attributes, unix.RTA_PREFSRC, family)
		if err != nil {
			return out, err
		}
		route.Via, err = networkReadVia(selection.Route.Attributes)
		if err != nil {
			return out, err
		}
		out.Routes = append(out.Routes, route)
	}
	return out, nil
}
