//go:build linux

package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type networkReadAttribute struct {
	Type  uint16 `json:"type"`
	Value []byte `json:"value"`
}
type networkReadRow struct {
	Header     []byte                 `json:"header"`
	Attributes []networkReadAttribute `json:"attributes"`
}
type networkReadScalar struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}
type networkReadSelection struct {
	Family string         `json:"family"`
	Source string         `json:"source"`
	Target string         `json:"target"`
	Route  networkReadRow `json:"route"`
}
type networkReadInventory struct {
	Forwarding []networkReadScalar    `json:"forwarding"`
	Links      []networkReadRow       `json:"links"`
	Addresses  []networkReadRow       `json:"addresses"`
	Selections []networkReadSelection `json:"selections"`
}

const networkReadBudget = 8 << 20

func networkPolicyDigest(cfg NetworkConfig) (string, error) {
	// These operational fields have independent installation/limit approvals and
	// do not change the network prerequisite being observed by a readonly planner.
	cfg.RunRoot = ""
	cfg.OperationTimeout = 0
	if cfg.Resolvers == nil {
		cfg.Resolvers = []string{}
	}
	if cfg.HostPublicAddresses == nil {
		cfg.HostPublicAddresses = []string{}
	}
	if cfg.InternalPrefixes == nil {
		cfg.InternalPrefixes = []string{}
	}
	if cfg.MetadataPrefixes == nil {
		cfg.MetadataPrefixes = []string{}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	if len(raw) > 64<<10 {
		return "", invalid("network policy observation exceeds bound")
	}
	return networkDigest([]byte("chatanium-network-policy-v1"), raw), nil
}
func networkPrerequisiteDigest(o NetworkPrerequisiteObservation) string {
	return networkDigest([]byte("chatanium-network-prerequisite-v1"), []byte(o.Profile), []byte(o.ConfigurationDigest), o.Inventory)
}
func readNetworkScalar(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 129))
	err = errors.Join(err, f.Close())
	if err != nil {
		return "", err
	}
	if len(raw) > 128 {
		return "", errors.New("network scalar observation exceeds bound")
	}
	return strings.TrimSpace(string(raw)), nil
}

// ObserveNetworkPrerequisites performs no helper execution, owner registration,
// lease acquisition, packet probe, filesystem creation, or configuration write.
func ObserveNetworkPrerequisites(ctx context.Context, cfg NetworkConfig) (NetworkPrerequisiteObservation, error) {
	if err := validateNetworkConfig(cfg); err != nil {
		return NetworkPrerequisiteObservation{}, err
	}
	policy, err := networkPolicyDigest(cfg)
	if err != nil {
		return NetworkPrerequisiteObservation{}, err
	}
	observation := NetworkPrerequisiteObservation{Version: 1, Profile: cfg.Profile, ConfigurationDigest: policy}
	timeout := cfg.OperationTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var inventory networkReadInventory
	if err = networkHostNamespaces(); err != nil {
		return observation, err
	}
	if cfg.Profile != NetworkNone {
		paths := []string{"/proc/sys/net/ipv4/ip_forward"}
		if cfg.Profile == NetworkPublicDual {
			paths = append(paths, "/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv6/conf/"+cfg.Uplink6+"/forwarding")
		}
		for _, path := range paths {
			value, e := readNetworkScalar(path)
			if e != nil {
				return observation, e
			}
			inventory.Forwarding = append(inventory.Forwarding, networkReadScalar{path, value})
			if value != "1" {
				return observation, prerequisite(fmt.Errorf("required forwarding is not enabled at %s", path))
			}
		}
		fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
		if e != nil {
			return observation, e
		}
		defer unix.Close(fd)
		if e = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
			return observation, e
		}
		reader := networkReadSocket{fd: fd}
		names := []string{cfg.Uplink4}
		if cfg.Profile == NetworkPublicDual && cfg.Uplink6 != cfg.Uplink4 {
			names = append(names, cfg.Uplink6)
		}
		for _, name := range names {
			link, e := reader.link(bounded, name)
			if e != nil {
				return observation, e
			}
			inventory.Links = append(inventory.Links, link)
		}
		inventory.Addresses, e = reader.dump(bounded, unix.RTM_GETADDR, unix.AF_UNSPEC, unix.SizeofIfAddrmsg, func(kind uint16) bool { return kind != unix.IFA_CACHEINFO })
		if e != nil {
			return observation, e
		}
		if e = networkReadValidateSources(cfg, inventory.Links, inventory.Addresses); e != nil {
			return observation, e
		}
		for _, binding := range []struct {
			family       int
			name, source string
		}{{unix.AF_INET, cfg.Uplink4, cfg.Source4}, {unix.AF_INET6, cfg.Uplink6, cfg.Source6}} {
			if binding.family == unix.AF_INET6 && cfg.Profile != NetworkPublicDual {
				continue
			}
			index := networkReadInterfaceIndex(inventory.Links, binding.name)
			targets := []string{"1.1.1.1"}
			label := "ipv4"
			if binding.family == unix.AF_INET6 {
				targets = []string{"2606:4700:4700::1111"}
				label = "ipv6"
			}
			for _, resolver := range cfg.Resolvers {
				if netip.MustParseAddr(resolver).Is4() == (binding.family == unix.AF_INET) {
					targets = append(targets, resolver)
				}
			}
			targets = slices.Compact(targets)
			for _, target := range targets {
				route, e := reader.selection(bounded, binding.family, netip.MustParseAddr(binding.source), netip.MustParseAddr(target))
				if e != nil {
					return observation, e
				}
				if len(route.Header) != unix.SizeofRtMsg || route.Header[7] != unix.RTN_UNICAST {
					return observation, errors.New("selected network route is not unicast")
				}
				out := networkReadAttributeValue(route.Attributes, unix.RTA_OIF)
				if len(out) != 4 || int(binary.NativeEndian.Uint32(out)) != index {
					return observation, errors.New("selected uplink conflicts with effective source route")
				}
				for _, kind := range []uint16{unix.RTA_PREFSRC, unix.RTA_SRC} {
					value := networkReadAttributeValue(route.Attributes, kind)
					if len(value) == 0 {
						continue
					}
					address, e := networkReadAddress(binding.family, value)
					if e != nil || address != netip.MustParseAddr(binding.source) {
						return observation, errors.New("effective route source differs from selected network source")
					}
				}
				inventory.Selections = append(inventory.Selections, networkReadSelection{label, binding.source, target, route})
			}
		}
	}
	semantic, err := networkSemanticInventory(cfg, inventory)
	if err != nil {
		return observation, err
	}
	observation.Inventory, err = json.Marshal(semantic)
	if err != nil {
		return observation, err
	}
	if len(observation.Inventory) > NetworkPrerequisiteInventoryMaxBytes {
		return observation, errors.New("network prerequisite snapshot exceeds bound")
	}
	observation.Digest = networkPrerequisiteDigest(observation)
	return observation, nil
}
func VerifyNetworkPrerequisites(ctx context.Context, cfg NetworkConfig, approved NetworkPrerequisiteObservation) error {
	if approved.Version != 1 || approved.Profile != cfg.Profile || len(approved.Inventory) == 0 || len(approved.Inventory) > NetworkPrerequisiteInventoryMaxBytes || approved.Digest == "" || approved.Digest != networkPrerequisiteDigest(approved) {
		return invalid("invalid approved network prerequisite observation")
	}
	current, err := ObserveNetworkPrerequisites(ctx, cfg)
	if err != nil {
		return err
	}
	if current.ConfigurationDigest != approved.ConfigurationDigest || current.Digest != approved.Digest {
		return errors.New("network prerequisites changed since explicit approval")
	}
	return nil
}

func networkReadLinkAttribute(kind uint16) bool {
	switch kind {
	case unix.IFLA_IFNAME, unix.IFLA_ADDRESS, unix.IFLA_MTU, unix.IFLA_LINKINFO:
		return true
	}
	return false
}
func networkReadRouteAttribute(kind uint16) bool {
	return kind != unix.RTA_CACHEINFO && kind != unix.RTA_EXPIRES
}
func networkReadAttributeValue(attrs []networkReadAttribute, kind uint16) []byte {
	for _, attr := range attrs {
		if attr.Type&0x3fff == kind {
			return attr.Value
		}
	}
	return nil
}
func networkReadAddress(family int, raw []byte) (netip.Addr, error) {
	if family == unix.AF_INET && len(raw) == 4 {
		return netip.AddrFrom4([4]byte(raw)), nil
	}
	if family == unix.AF_INET6 && len(raw) == 16 {
		return netip.AddrFrom16([16]byte(raw)), nil
	}
	return netip.Addr{}, errors.New("invalid native network address width")
}
func networkReadInterfaceIndex(links []networkReadRow, name string) int {
	for _, link := range links {
		value := networkReadAttributeValue(link.Attributes, unix.IFLA_IFNAME)
		if strings.TrimRight(string(value), "\x00") == name && len(link.Header) == unix.SizeofIfInfomsg {
			return int(int32(binary.NativeEndian.Uint32(link.Header[4:8])))
		}
	}
	return 0
}
func networkReadValidateSources(cfg NetworkConfig, links, addresses []networkReadRow) error {
	blocked := append([]netip.Prefix{}, specialPurposePrefixes...)
	for _, value := range append(append(append(append([]string{}, cfg.HostPublicAddresses...), cfg.InternalPrefixes...), cfg.MetadataPrefixes...), cfg.IPv4Pool, cfg.IPv6Pool) {
		if value != "" {
			prefix, err := parseAddressPrefix(value)
			if err != nil {
				return err
			}
			blocked = append(blocked, prefix)
		}
	}
	for _, row := range addresses {
		if len(row.Header) != unix.SizeofIfAddrmsg {
			return errors.New("invalid address observation header")
		}
		family := int(row.Header[0])
		if family != unix.AF_INET && family != unix.AF_INET6 {
			continue
		}
		value := networkReadAttributeValue(row.Attributes, unix.IFA_LOCAL)
		if len(value) == 0 {
			value = networkReadAttributeValue(row.Attributes, unix.IFA_ADDRESS)
		}
		address, err := networkReadAddress(family, value)
		if err != nil {
			return err
		}
		blocked = append(blocked, netip.PrefixFrom(address, address.BitLen()))
	}
	for bindingIndex, binding := range []struct{ name, source string }{{cfg.Uplink4, cfg.Source4}, {cfg.Uplink6, cfg.Source6}} {
		if bindingIndex == 1 && cfg.Profile != NetworkPublicDual {
			continue
		}
		if binding.source == "" {
			continue
		}
		index := networkReadInterfaceIndex(links, binding.name)
		up := false
		for _, link := range links {
			if len(link.Header) == unix.SizeofIfInfomsg && int(int32(binary.NativeEndian.Uint32(link.Header[4:8]))) == index && binary.NativeEndian.Uint32(link.Header[8:12])&unix.IFF_UP != 0 {
				up = true
			}
		}
		if index <= 0 || !up {
			return errors.New("selected network uplink is not active")
		}
		selected := netip.MustParseAddr(binding.source)
		found := false
		for _, row := range addresses {
			if int(binary.NativeEndian.Uint32(row.Header[4:8])) != index {
				continue
			}
			family := int(row.Header[0])
			if selected.Is4() != (family == unix.AF_INET) {
				continue
			}
			value := networkReadAttributeValue(row.Attributes, unix.IFA_LOCAL)
			if len(value) == 0 {
				value = networkReadAttributeValue(row.Attributes, unix.IFA_ADDRESS)
			}
			address, err := networkReadAddress(family, value)
			if err != nil {
				continue
			}
			flags := uint32(row.Header[2])
			extended := networkReadAttributeValue(row.Attributes, unix.IFA_FLAGS)
			if len(extended) == 4 {
				flags = binary.NativeEndian.Uint32(extended)
			}
			if address == selected && flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DEPRECATED|unix.IFA_F_DADFAILED) == 0 {
				found = true
			}
		}
		if !found {
			return errors.New("selected network source is not an active uplink address")
		}
	}
	for _, resolver := range cfg.Resolvers {
		address := netip.MustParseAddr(resolver)
		for _, prefix := range blocked {
			if prefix.Contains(address) {
				return errors.New("resolver conflicts with host or exclusion inventory")
			}
		}
	}
	return nil
}

type networkReadSocket struct {
	fd       int
	sequence uint32
	bytes    int
}

func (reader *networkReadSocket) request(ctx context.Context, kind uint16, dump bool, payload []byte) ([][]byte, error) {
	switch kind {
	case unix.RTM_GETLINK, unix.RTM_GETADDR, unix.RTM_GETROUTE:
	default:
		return nil, errors.New("network observation request is not readonly")
	}
	reader.sequence++
	sequence := reader.sequence
	var message [128]byte
	size := unix.NLMSG_HDRLEN + len(payload)
	if size > len(message) {
		return nil, errors.New("network observation request exceeds bound")
	}
	binary.NativeEndian.PutUint32(message[:4], uint32(size))
	binary.NativeEndian.PutUint16(message[4:6], kind)
	flags := uint16(unix.NLM_F_REQUEST)
	if dump {
		flags |= unix.NLM_F_DUMP
	}
	binary.NativeEndian.PutUint16(message[6:8], flags)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	copy(message[unix.NLMSG_HDRLEN:], payload)
	if err := unix.Sendto(reader.fd, message[:size], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var rows [][]byte
	var buffer [65536]byte
	requestBytes := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		poll := []unix.PollFd{{Fd: int32(reader.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, errors.New("readonly network observation socket lost authority")
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		count, _, receivedFlags, from, err := unix.Recvmsg(reader.fd, buffer[:], nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || receivedFlags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return nil, errors.New("untrusted or truncated network observation")
		}
		raw := buffer[:count]
		for len(raw) > 0 {
			if len(raw) < unix.NLMSG_HDRLEN {
				return nil, errors.New("network observation header truncated")
			}
			length := int(binary.NativeEndian.Uint32(raw[:4]))
			if length < unix.NLMSG_HDRLEN || length > len(raw) {
				return nil, errors.New("network observation length invalid")
			}
			if binary.NativeEndian.Uint32(raw[8:12]) != sequence {
				return nil, errors.New("network observation sequence mismatch")
			}
			response := binary.NativeEndian.Uint16(raw[4:6])
			responseFlags := binary.NativeEndian.Uint16(raw[6:8])
			body := raw[unix.NLMSG_HDRLEN:length]
			if responseFlags&unix.NLM_F_DUMP_INTR != 0 || response == unix.NLMSG_OVERRUN {
				return nil, errors.New("network observation dump lost consistency")
			}
			if response == unix.NLMSG_ERROR {
				if len(body) < 4 {
					return nil, errors.New("network observation error truncated")
				}
				code := int32(binary.NativeEndian.Uint32(body))
				if code != 0 {
					if code > 0 {
						return nil, errors.New("invalid network observation errno")
					}
					return nil, unix.Errno(-code)
				}
			} else if response == unix.NLMSG_DONE {
				if len(body) >= 4 && int32(binary.NativeEndian.Uint32(body)) != 0 {
					return nil, errors.New("network observation dump failed")
				}
				return rows, nil
			} else {
				if response != kind-2 {
					return nil, errors.New("unexpected network observation response")
				}
				reader.bytes += len(body)
				requestBytes += len(body)
				if reader.bytes > networkReadBudget || requestBytes > 1<<20 {
					return nil, errors.New("native network inventory exceeds bound")
				}
				rows = append(rows, append([]byte(nil), body...))
				if !dump && responseFlags&unix.NLM_F_MULTI == 0 {
					return rows, nil
				}
			}
			next := (length + 3) &^ 3
			if next > len(raw) {
				if length == len(raw) {
					raw = nil
				} else {
					return nil, errors.New("network observation padding truncated")
				}
			} else {
				raw = raw[next:]
			}
		}
	}
}
func networkReadNormalize(payload []byte, header int, include func(uint16) bool) (networkReadRow, error) {
	if len(payload) < header {
		return networkReadRow{}, errors.New("native network fact header truncated")
	}
	row := networkReadRow{Header: payload[:header]}
	raw := payload[header:]
	for len(raw) > 0 {
		if len(raw) < 4 {
			return row, errors.New("native network attribute truncated")
		}
		length := int(binary.NativeEndian.Uint16(raw))
		if length < 4 || length > len(raw) {
			return row, errors.New("native network attribute length invalid")
		}
		kind := binary.NativeEndian.Uint16(raw[2:4])
		if include(kind & 0x3fff) {
			row.Attributes = append(row.Attributes, networkReadAttribute{kind, raw[4:length]})
		}
		next := (length + 3) &^ 3
		if next > len(raw) {
			if length == len(raw) {
				raw = nil
			} else {
				return row, errors.New("native network attribute padding truncated")
			}
		} else {
			raw = raw[next:]
		}
	}
	slices.SortFunc(row.Attributes, func(a, b networkReadAttribute) int {
		if a.Type < b.Type {
			return -1
		}
		if a.Type > b.Type {
			return 1
		}
		return bytes.Compare(a.Value, b.Value)
	})
	for index := 1; index < len(row.Attributes); index++ {
		if row.Attributes[index-1].Type == row.Attributes[index].Type {
			return row, errors.New("duplicate native network attribute")
		}
	}
	return row, nil
}
func (reader *networkReadSocket) dump(ctx context.Context, kind uint16, family, header int, include func(uint16) bool) ([]networkReadRow, error) {
	payload := make([]byte, header)
	payload[0] = byte(family)
	raw, err := reader.request(ctx, kind, true, payload)
	if err != nil {
		return nil, err
	}
	rows := make([]networkReadRow, 0, len(raw))
	for _, message := range raw {
		row, err := networkReadNormalize(message, header, include)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b networkReadRow) int {
		if order := bytes.Compare(a.Header, b.Header); order != 0 {
			return order
		}
		for index := 0; index < len(a.Attributes) && index < len(b.Attributes); index++ {
			if a.Attributes[index].Type < b.Attributes[index].Type {
				return -1
			}
			if a.Attributes[index].Type > b.Attributes[index].Type {
				return 1
			}
			if order := bytes.Compare(a.Attributes[index].Value, b.Attributes[index].Value); order != 0 {
				return order
			}
		}
		return len(a.Attributes) - len(b.Attributes)
	})
	return rows, nil
}
func (reader *networkReadSocket) selection(ctx context.Context, family int, source, target netip.Addr) (networkReadRow, error) {
	var payload [64]byte
	size := unix.SizeofRtMsg
	payload[0] = byte(family)
	payload[1] = byte(target.BitLen())
	payload[2] = byte(source.BitLen())
	add := func(kind uint16, value []byte) {
		length := 4 + len(value)
		binary.NativeEndian.PutUint16(payload[size:size+2], uint16(length))
		binary.NativeEndian.PutUint16(payload[size+2:size+4], kind)
		copy(payload[size+4:], value)
		size += (length + 3) &^ 3
	}
	add(unix.RTA_DST, target.AsSlice())
	add(unix.RTA_SRC, source.AsSlice())
	var rootUID [4]byte
	add(unix.RTA_UID, rootUID[:])
	raw, err := reader.request(ctx, unix.RTM_GETROUTE, false, payload[:size])
	if err != nil {
		return networkReadRow{}, err
	}
	if len(raw) != 1 {
		return networkReadRow{}, errors.New("ambiguous selected network route")
	}
	return networkReadNormalize(raw[0], unix.SizeofRtMsg, networkReadRouteAttribute)
}
func (reader *networkReadSocket) link(ctx context.Context, name string) (networkReadRow, error) {
	var payload [unix.SizeofIfInfomsg + 4 + 16]byte
	size := unix.SizeofIfInfomsg
	length := 4 + len(name) + 1
	if !networkInterfaceName(name) || length > 20 {
		return networkReadRow{}, invalid("invalid selected uplink name")
	}
	binary.NativeEndian.PutUint16(payload[size:size+2], uint16(length))
	binary.NativeEndian.PutUint16(payload[size+2:size+4], unix.IFLA_IFNAME)
	copy(payload[size+4:], name)
	size += (length + 3) &^ 3
	rows, err := reader.request(ctx, unix.RTM_GETLINK, false, payload[:size])
	if err != nil {
		return networkReadRow{}, err
	}
	if len(rows) != 1 {
		return networkReadRow{}, errors.New("ambiguous selected uplink observation")
	}
	return networkReadNormalize(rows[0], unix.SizeofIfInfomsg, networkReadLinkAttribute)
}
