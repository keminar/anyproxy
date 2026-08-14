//go:build windows

package wdengine

import (
	"encoding/binary"
	"log"
	"net/netip"
	"time"

	"github.com/keminar/anyproxy/tun/windivert"
	"github.com/keminar/anyproxy/utils/cache"
	"github.com/keminar/anyproxy/utils/dnsutil"
)

// hijackDNS answers an outbound IPv4 DNS query per the hosts config. On a hit it
// builds the response, injects it back to the app as an inbound packet, and
// returns true so the caller drops the original query. A miss (no matching host,
// or a matched host with no ip / non-A type without an ip mapping) returns false,
// letting the query flow out to the system resolver unchanged.
//
// This mirrors the gVisor path's handleDNS (tun/udp.go) but re-injects via
// WinDivert instead of writing to a TUN device. Only IPv4 transport is handled;
// DNS over IPv6 is passed through (callers gate on p.isIPv4).
func (e *Engine) hijackDNS(pkt []byte, p parsed, addr *windivert.Address) bool {
	// UDP payload starts after the IPv4 header (p.l4Off) + 8-byte UDP header.
	start := p.l4Off + 8
	if start > len(pkt) {
		return false
	}
	payload := pkt[start:]

	domain, qtype := dnsutil.ParseQuery(payload)
	if domain == "" {
		return false
	}
	hostIP, deny, matched := dnsutil.MatchHostDNS(domain)
	if !matched {
		return false
	}

	var resp []byte
	switch {
	case deny:
		resp = dnsutil.BuildNXDomain(payload)
		log.Printf("dns hijack NXDOMAIN: %s (deny)", domain)
	case hostIP != "" && qtype == dnsutil.TypeA:
		resp = dnsutil.BuildResponse(payload, domain, hostIP)
		log.Printf("dns hijack: %s -> %s", domain, hostIP)
		// 记录 ip->域名，供后续该 IP 的 TCP 连接在嗅探不到域名时还原真实域名
		// (proto.ForwardTCP 里的 cache.SniffName.Lookup)。
		cache.SniffName.Store(hostIP, domain, 10*time.Minute)
	case hostIP != "" && qtype == dnsutil.TypeAAAA:
		// 域名已配 IPv4，对 AAAA 返回 NOERROR 空应答让客户端回退到 A 记录，
		// 不转发真实 DNS(内网域名会拿到 NXDOMAIN 污染解析)。
		resp = dnsutil.BuildEmpty(payload)
		log.Printf("dns hijack AAAA empty: %s", domain)
	default:
		// 命中规则但无 ip 映射(如 target=remote)：不拦截，放行走正常解析。
		return false
	}
	if resp == nil {
		return false
	}

	// 构造入站响应包: src=解析器(原 dst), dst=客户端(原 src), 端口互换。
	reply := buildUDPv4Reply(p.dstIP, p.srcIP, p.dstPort, p.srcPort, resp)

	// 翻转方向为入站, 让协议栈把它当作解析器的回包交给应用。
	addr.SetOutbound(false)
	addr.SetLoopback(false)
	if err := windivert.CalcChecksums(reply, addr); err != nil {
		log.Printf("dns hijack checksum: %v", err)
		return false
	}
	if _, err := e.h.Send(reply, addr); err != nil {
		log.Printf("dns hijack send: %v", err)
	}
	return true
}

// buildUDPv4Reply builds a minimal IPv4+UDP packet (no IP options). The IP and
// UDP checksums are left zero for windivert.CalcChecksums to fill in.
func buildUDPv4Reply(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	b := make([]byte, total)

	// IPv4 header (20 bytes, IHL=5).
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[8] = 64 // TTL
	b[9] = 17 // UDP
	sa := src.As4()
	da := dst.As4()
	copy(b[12:16], sa[:])
	copy(b[16:20], da[:])

	// UDP header (8 bytes) + payload.
	binary.BigEndian.PutUint16(b[20:22], srcPort)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	binary.BigEndian.PutUint16(b[24:26], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}
