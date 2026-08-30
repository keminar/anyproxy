//go:build windows

// Package wdengine is the Windows transparent redirector built on WinDivert.
//
// It captures outbound HTTP/HTTPS TCP at the NETWORK layer, NATs each connection
// onto a local listener, and hands the accepted connection (with its recovered
// original destination) to proto.ForwardTCP — reusing anyproxy's own routing,
// SNI/Host sniffing and upstream logic. It also hijacks outbound DNS (UDP/53) to
// answer per the hosts config, and drops hijacked-IP QUIC (UDP/443) so those
// flows fall back to the proxied TCP path.
//
// See redirect.go (WinDivert loop + NAT rewrite), nat.go (connection table),
// proxy.go (local listener → ForwardTCP) and dns.go (DNS hijack).
package wdengine

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/keminar/anyproxy/proto"
	"github.com/keminar/anyproxy/tun/windivert"
	"github.com/keminar/anyproxy/utils/dnsutil"
)

const (
	// NAT source-port pool (proxy-side identifiers). Kept below the Windows
	// default dynamic port range (49152-65535) so these fabricated loopback
	// source ports never contend with the OS's ephemeral ports for real outbound
	// connections (e.g. anyproxy's own dials to a direct server / upstream proxy).
	natLo         = 10000
	natHi         = 40000
	natIdle       = 10 * time.Minute // fallback reclaim for flows whose teardown we missed
	natCloseGrace = 10 * time.Second // reclaim after the proxy connection ends (post-FIN handshake)
)

// Engine ties together the WinDivert capture loop, the NAT table and the local
// forwarding proxy.
type Engine struct {
	cfg   *Config
	nat   *natTable
	proxy *proxyServer
	guard *socksGuard // excludes anyproxy's own egress ports (nil = disabled)
	h     *windivert.Handle
}

// New starts the local proxy (which fixes cfg.ProxyPort if it was 0), opens a
// WinDivert session with a filter derived from that port, and returns a ready
// engine.
func New(cfg *Config) (*Engine, error) {
	nat := newNatTable(natLo, natHi)

	proxy, err := startProxy(cfg, nat)
	if err != nil {
		return nil, fmt.Errorf("start local proxy: %w", err)
	}

	h, err := openWithFallback(cfg)
	if err != nil {
		proxy.Close()
		return nil, err
	}

	// anyproxy makes its own outbound connections for direct/upstream targets from
	// this same process; without excluding its egress source ports they loop back
	// into the redirector. The guard learns the family from whoever owns the
	// listener port (anyproxy itself) and excludes its egress. Always on.
	guard := startSocksGuard(true, cfg.ProxyPort, cfg.SocksProcessNames)

	return &Engine{cfg: cfg, nat: nat, proxy: proxy, guard: guard, h: h}, nil
}

// openWithFallback tries the candidate filters from most- to least-optimized,
// using the first one WinDivert accepts. A rejected filter (invalid-filter, i.e.
// this WinDivert build doesn't support some token) is skipped; any other error
// (access denied, driver missing) is returned immediately. Correctness never
// depends on which filter wins — process() re-applies every decision in Go.
func openWithFallback(cfg *Config) (*windivert.Handle, error) {
	candidates := candidateFilters(cfg)
	for i, f := range candidates {
		h, err := windivert.Open(f, windivert.LayerNetwork, 0, 0)
		if err == nil {
			log.Printf("WinDivert filter: %s", f)
			return h, nil
		}
		if isInvalidFilter(err) && i < len(candidates)-1 {
			if reason, pos, ok := windivert.CompileFilter(f, windivert.LayerNetwork); !ok {
				log.Printf("filter rejected: %q at char %d (…%s…); falling back", reason, pos, filterSnippet(f, pos))
			} else {
				log.Printf("filter rejected by Open yet compiles; falling back: %s", f)
			}
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("no usable WinDivert filter")
}

func isInvalidFilter(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == syscall.Errno(87) // ERROR_INVALID_PARAMETER
}

// filterSnippet returns a small window of the filter around pos, to show which
// token WinDivert choked on.
func filterSnippet(f string, pos int) string {
	if pos < 0 || pos > len(f) {
		return f
	}
	start := pos - 20
	if start < 0 {
		start = 0
	}
	end := pos + 20
	if end > len(f) {
		end = len(f)
	}
	return f[start:end]
}

// candidateFilters returns filter strings from most- to least-optimized. The
// first one WinDivert accepts is used; the last is the minimal filter using only
// tokens known to compile everywhere. process() re-applies every decision, so any
// candidate is correct — the richer one just moves work into the kernel.
//
// We capture outbound TCP on the redirect ports plus our own return path
// (srcPort == ProxyPort), and outbound UDP/53 (DNS hijack) plus UDP/443 (QUIC
// drop) when enabled. Everything is "outbound"; our inbound re-injections carry a
// different direction and are not recaptured.
func candidateFilters(cfg *Config) []string {
	var tcpClause string
	if !cfg.AllPorts {
		dst := make([]string, 0, len(cfg.RedirectPorts))
		for _, p := range cfg.RedirectPorts {
			dst = append(dst, fmt.Sprintf("tcp.DstPort == %d", p))
		}
		tcpClause = fmt.Sprintf("tcp and ((%s) or tcp.SrcPort == %d)", strings.Join(dst, " or "), cfg.ProxyPort)
	} else {
		tcpClause = "tcp"
	}

	udpPorts := []string{"udp.DstPort == 53"}
	if cfg.BlockQUIC {
		udpPorts = append(udpPorts, "udp.DstPort == 443")
	}
	udpClause := fmt.Sprintf("udp and (%s)", strings.Join(udpPorts, " or "))

	full := fmt.Sprintf("outbound and ((%s) or (%s))", tcpClause, udpClause)
	minimal := "outbound and (tcp or udp)"
	return []string{full, minimal}
}

func containsPort(ports []uint16, p uint16) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// Close releases the WinDivert handle and the local proxy listener.
func (e *Engine) Close() error {
	e.proxy.Close()
	e.guard.Close()
	return e.h.Close()
}

// Run processes packets until Close is called (which makes Recv fail).
func (e *Engine) Run() error {
	go e.gcLoop()

	buf := make([]byte, 65535)
	for {
		n, addr, err := e.h.Recv(buf)
		if err != nil {
			return err
		}
		pkt := buf[:n]
		if e.process(pkt, addr) {
			if _, err := e.h.Send(pkt, addr); err != nil {
				log.Printf("send: %v", err)
			}
		}
		// process==false → drop by not re-injecting.
	}
}

// process rewrites the packet in place and reports whether to (re)inject it.
func (e *Engine) process(pkt []byte, addr *windivert.Address) bool {
	// Our own re-injections come back flagged as impostor; pass them through
	// untouched to avoid a capture loop.
	if addr.Impostor() {
		return true
	}
	p := parsePacket(pkt)
	if !p.ok {
		return true
	}

	if p.proto == protoUDP {
		// DNS hijack: answer per hosts config and inject the reply inbound; drop the
		// original query. Unmatched queries pass through to the system resolver.
		if p.dstPort == dnsutil.Port && p.isIPv4 {
			if e.hijackDNS(pkt, p, addr) {
				return false // handled: reply injected, drop the outbound query
			}
			return true
		}
		// QUIC block: drop outbound UDP/443 whose destination IP is a hosts-hijacked
		// IP, forcing the browser to fall back to TCP+TLS (which we proxy). Other
		// QUIC keeps flowing.
		if p.dstPort == 443 && dnsutil.BlockQUICEnabled() && dnsutil.HostBlocksUDP(p.dstIP.String()) {
			return false
		}
		return true
	}
	if p.proto != protoTCP {
		return true // e.g. IPv6 with extension headers we don't decode
	}

	// Return path first: only our proxy owns srcPort == ProxyPort.
	if p.srcPort == e.cfg.ProxyPort {
		return e.rewriteReturn(pkt, p, addr)
	}

	// Our own injected forward packet (or anything else headed straight at the
	// proxy over loopback) — deliver as-is, never re-NAT.
	if addr.Loopback() && p.dstPort == e.cfg.ProxyPort {
		return true
	}

	// anyproxy's own connection to an upstream proxy (either leg) must go out
	// untouched, or we'd redirect it back into ourselves.
	if e.isUpstream(p) {
		return true
	}

	// Explicitly-excluded destinations (tun.bypassIPs) go direct — e.g. a
	// co-resident OpenVPN server endpoint that would otherwise loop.
	if e.isExcludedIP(p.dstIP) || e.isExcludedIP(p.srcIP) {
		return true
	}

	// anyproxy's own direct-egress connections must also go out untouched.
	// Capturing them would loop: app→proxy→anyproxy-egress→captured→proxy→…
	//
	// Primary, deterministic identification: the Windows dialer binds every
	// anyproxy egress connection's source port into a dedicated band
	// (proto.EgressPortLo..Hi), so any captured packet from that band is our own.
	// This is happens-before the SYN and IP-version-agnostic, so it catches IPv6
	// direct — which the SOCKET-layer guard below races and misses.
	if p.srcPort >= proto.EgressPortLo && p.srcPort <= proto.EgressPortHi {
		return true
	}
	// Backstop for the rare unbound fallback dial and for extra helper processes
	// (SocksProcessNames): the guard identifies egress by source port via the
	// SOCKET layer.
	if e.guard.ownsPort(p.srcPort) {
		return true
	}

	// Anything we don't redirect (bypassed destination, skip port, out-of-scope
	// port) goes out untouched.
	if !e.shouldRedirect(p) {
		return true
	}

	// In scope but IPv6 with IPv6 disabled: drop so it cannot bypass the proxy.
	if !p.isIPv4 && !e.cfg.IPv6 {
		return false
	}
	return e.rewriteForward(pkt, p, addr)
}

// isDirect reports whether a destination is always sent direct (never proxied):
// loopback, a skip port, or — when BypassPrivate is set — a private/LAN address.
func (e *Engine) isDirect(dstIP netip.Addr, dstPort uint16) bool {
	if dstIP.IsLoopback() {
		return true
	}
	// 黑洞哨兵 IP 必须进引擎(强制走代理), 不受 SkipPorts / BypassPrivate 影响。
	// 即便用户把哨兵配成私网地址, 也仍拦截进引擎, 由转发层强制 remote+remote 出去。
	if e.cfg.BlackholeIP.IsValid() && dstIP == e.cfg.BlackholeIP {
		return false
	}
	if containsPort(e.cfg.SkipPorts, dstPort) {
		return true
	}
	return e.cfg.BypassPrivate && isPrivateOrLinkLocal(dstIP)
}

// shouldRedirect reports whether an outbound packet's destination should be
// proxied. In all-ports mode everything not sent direct is proxied, otherwise
// only the configured RedirectPorts.
func (e *Engine) shouldRedirect(p parsed) bool {
	if e.isDirect(p.dstIP, p.dstPort) {
		return false
	}
	if e.cfg.AllPorts {
		return true
	}
	return containsPort(e.cfg.RedirectPorts, p.dstPort)
}

func isPrivateOrLinkLocal(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast()
}

// isUpstream reports whether a packet belongs to anyproxy's own connection to an
// upstream proxy server (either direction), which must never be redirected.
func (e *Engine) isUpstream(p parsed) bool {
	ip, port := e.cfg.SocksExcludeIP, e.cfg.SocksExcludePort
	if !ip.IsValid() {
		return false
	}
	return (p.dstIP == ip && p.dstPort == port) || (p.srcIP == ip && p.srcPort == port)
}

// isExcludedIP reports whether an address falls in one of the configured
// ExcludeIPs prefixes (tun.bypassIPs) and must go direct, never redirected.
func (e *Engine) isExcludedIP(a netip.Addr) bool {
	if len(e.cfg.ExcludeIPs) == 0 || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, pfx := range e.cfg.ExcludeIPs {
		if pfx.Contains(a) {
			return true
		}
	}
	return false
}

// rewriteForward turns an outbound app→server packet into a loopback packet to
// the local proxy: src port → unique natPort, dst → this host, dst port → proxy.
func (e *Engine) rewriteForward(pkt []byte, p parsed, addr *windivert.Address) bool {
	ent, _ := e.nat.forward(p.srcIP, p.srcPort, p.dstIP, p.dstPort, addr.IfIdx(), addr.SubIfIdx())
	if ent == nil {
		log.Printf("NAT pool exhausted; dropping %s:%d", p.dstIP, p.dstPort)
		return false
	}

	setSrcPort(pkt, p.l4Off, ent.natPort)
	setDstIP(pkt, p.isIPv4, p.srcIP) // loop back to this host
	setDstPort(pkt, p.l4Off, e.cfg.ProxyPort)
	addr.SetLoopback(true)

	if err := windivert.CalcChecksums(pkt, addr); err != nil {
		log.Printf("checksum(forward): %v", err)
		return false
	}
	if p.tcpFlags&tcpRST != 0 {
		e.nat.release(ent.natPort)
	}
	return true
}

// rewriteReturn turns a proxy→app packet back into one that appears to come from
// the real server, then injects it inbound on the app's original NIC.
func (e *Engine) rewriteReturn(pkt []byte, p parsed, addr *windivert.Address) bool {
	ent, ok := e.nat.lookupNat(p.dstPort)
	if !ok {
		return false // unknown natPort — drop rather than leak the loopback packet
	}

	setSrcIP(pkt, p.isIPv4, ent.dstIP) // appear to come from the real server
	setSrcPort(pkt, p.l4Off, ent.dstPort)
	setDstPort(pkt, p.l4Off, ent.clientPort) // dst IP is already this host
	addr.SetLoopback(false)
	addr.SetOutbound(false) // deliver to the app as an inbound packet
	addr.SetIfIdx(ent.ifIdx)
	addr.SetSubIfIdx(ent.subIfIdx)

	if err := windivert.CalcChecksums(pkt, addr); err != nil {
		log.Printf("checksum(return): %v", err)
		return false
	}
	if p.tcpFlags&tcpRST != 0 {
		e.nat.release(ent.natPort)
	}
	return true
}

func (e *Engine) gcLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		e.nat.gc(natIdle, natCloseGrace)
		e.proxy.rl.cleanup(2 * time.Minute)
	}
}
