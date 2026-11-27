//go:build linux

package host

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// Only an event confined to another durable, already peer-excluded allocation
// is irrelevant. Unknown attributes, global rules, lost events and foreign
// mutations all close authority before any expensive inventory revalidation.
func (n *Network) notificationRelevant(data []byte, target *networkAllocation, firewall bool) bool {
	if len(data) == 0 {
		return false
	}
	allocations, err := networkAllocations()
	if err != nil {
		return true
	}
	otherInterfaces := make(map[int]bool)
	var otherChains [][]byte
	ownF, ownI, ownN := networkChains(target.Record)
	for _, a := range allocations {
		if a.Record.Generation == target.Record.Generation || a.Record.State == "CLEANED" {
			continue
		}
		if a.Record.HostIfIndex != 0 {
			otherInterfaces[a.Record.HostIfIndex] = true
		}
		if a.Record.PeerIfIndex != 0 {
			otherInterfaces[a.Record.PeerIfIndex] = true
		}
		f, i, nat := networkChains(a.Record)
		for _, chain := range []string{f, i, nat} {
			otherChains = append(otherChains, []byte(chain+"\x00"))
		}
	}
	for len(data) > 0 {
		if len(data) < unix.NLMSG_HDRLEN {
			return true
		}
		size := int(binary.NativeEndian.Uint32(data))
		if size < unix.NLMSG_HDRLEN || size > len(data) {
			return true
		}
		kind := binary.NativeEndian.Uint16(data[4:6])
		payload := data[unix.NLMSG_HDRLEN:size]
		relevant := true
		if firewall {
			// NFT_MSG_NEWGEN contains no authority itself; its table/chain/rule
			// mutations are separately delivered on the same subscribed socket.
			if kind == uint16(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWGEN) || kind == 0x10 || kind == 0x11 {
				relevant = false
			} else {
				own := false
				for _, chain := range []string{ownF, ownI, ownN} {
					if bytes.Contains(payload, []byte(chain+"\x00")) {
						own = true
					}
				}
				if !own {
					for _, chain := range otherChains {
						if bytes.Contains(payload, chain) {
							relevant = false
							break
						}
					}
				}
			}
		} else {
			index := 0
			switch kind {
			case unix.RTM_NEWLINK, unix.RTM_DELLINK:
				if len(payload) >= unix.SizeofIfInfomsg {
					index = int(binary.NativeEndian.Uint32(payload[4:8]))
				}
			case unix.RTM_NEWADDR, unix.RTM_DELADDR:
				if len(payload) >= unix.SizeofIfAddrmsg {
					index = int(binary.NativeEndian.Uint32(payload[4:8]))
				}
			case unix.RTM_NEWNEIGH, unix.RTM_DELNEIGH:
				if len(payload) >= 12 {
					index = int(binary.NativeEndian.Uint32(payload[4:8]))
					if index != target.Record.HostIfIndex && index != target.Record.PeerIfIndex {
						relevant = false
					}
				}
			case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
				if len(payload) >= unix.SizeofRtMsg {
					attrs := payload[unix.SizeofRtMsg:]
					for len(attrs) >= 4 {
						length := int(binary.NativeEndian.Uint16(attrs))
						if length < 4 || length > len(attrs) {
							return true
						}
						attr := binary.NativeEndian.Uint16(attrs[2:4]) & 0x3fff
						if attr == unix.RTA_OIF && length == 8 {
							index = int(binary.NativeEndian.Uint32(attrs[4:8]))
						}
						aligned := (length + 3) &^ 3
						if aligned > len(attrs) {
							break
						}
						attrs = attrs[aligned:]
					}
				}
			}
			if index != 0 && otherInterfaces[index] {
				relevant = false
			}
		}
		if relevant {
			return true
		}
		aligned := (size + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if aligned > len(data) {
			return size != len(data)
		}
		data = data[aligned:]
	}
	return false
}
