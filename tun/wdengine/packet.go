//go:build windows

package wdengine

import (
	"encoding/binary"
	"net/netip"
)

// IP protocol numbers we decode. TCP is what we NAT; UDP is only inspected for
// the QUIC (UDP/443) block.
const (
	protoTCP = 6
	protoUDP = 17
)

// parsed holds the fields extracted from a captured IP packet, plus the offsets
// needed to rewrite it in place (transparent-proxy NAT).
type parsed struct {
	proto    uint8
	isIPv4   bool
	srcIP    netip.Addr
	dstIP    netip.Addr
	srcPort  uint16
	dstPort  uint16
	l4Off    int // offset of the L4 (TCP/UDP) header within the packet buffer
	tcpFlags uint8
	ok       bool
}

// parsePacket decodes an IPv4 or IPv6 packet far enough to make a routing/NAT
// decision. It never allocates beyond slicing into buf.
func parsePacket(buf []byte) parsed {
	if len(buf) < 1 {
		return parsed{}
	}
	switch buf[0] >> 4 {
	case 4:
		return parseIPv4(buf)
	case 6:
		return parseIPv6(buf)
	default:
		return parsed{}
	}
}

func parseIPv4(buf []byte) parsed {
	if len(buf) < 20 {
		return parsed{}
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl {
		return parsed{}
	}
	p := parsed{proto: buf[9], isIPv4: true, l4Off: ihl}
	p.srcIP, _ = netip.AddrFromSlice(buf[12:16])
	p.dstIP, _ = netip.AddrFromSlice(buf[16:20])
	return parseL4(p, buf)
}

func parseIPv6(buf []byte) parsed {
	if len(buf) < 40 {
		return parsed{}
	}
	// Only the fixed header is handled; extension headers are uncommon for the
	// TCP traffic we redirect and are treated as unparseable (passed through).
	p := parsed{proto: buf[6], l4Off: 40}
	p.srcIP, _ = netip.AddrFromSlice(buf[8:24])
	p.dstIP, _ = netip.AddrFromSlice(buf[24:40])
	return parseL4(p, buf)
}

func parseL4(p parsed, buf []byte) parsed {
	l4 := buf[p.l4Off:]
	switch p.proto {
	case protoTCP:
		if len(l4) < 20 {
			return parsed{}
		}
		p.srcPort = binary.BigEndian.Uint16(l4[0:2])
		p.dstPort = binary.BigEndian.Uint16(l4[2:4])
		p.tcpFlags = l4[13]
		p.ok = true
	case protoUDP:
		if len(l4) < 8 {
			return parsed{}
		}
		p.srcPort = binary.BigEndian.Uint16(l4[0:2])
		p.dstPort = binary.BigEndian.Uint16(l4[2:4])
		p.ok = true
	default:
		p.ok = true // known IP, other L4 — still a valid parse (passed through)
	}
	return p
}

// tcpRST is the RST flag bit; a reset lets us release the NAT mapping early.
const tcpRST = 0x04

// --- in-place rewrite helpers -------------------------------------------------
// These mutate buf directly; callers must recompute checksums afterwards via
// windivert.CalcChecksums. The source/destination address fields sit at fixed
// offsets: IPv4 src 12:16 / dst 16:20, IPv6 src 8:24 / dst 24:40.

func setSrcIP(buf []byte, isIPv4 bool, ip netip.Addr) {
	if isIPv4 {
		a := ip.As4()
		copy(buf[12:16], a[:])
		return
	}
	a := ip.As16()
	copy(buf[8:24], a[:])
}

func setDstIP(buf []byte, isIPv4 bool, ip netip.Addr) {
	if isIPv4 {
		a := ip.As4()
		copy(buf[16:20], a[:])
		return
	}
	a := ip.As16()
	copy(buf[24:40], a[:])
}

func setSrcPort(buf []byte, l4Off int, port uint16) {
	binary.BigEndian.PutUint16(buf[l4Off:l4Off+2], port)
}

func setDstPort(buf []byte, l4Off int, port uint16) {
	binary.BigEndian.PutUint16(buf[l4Off+2:l4Off+4], port)
}
