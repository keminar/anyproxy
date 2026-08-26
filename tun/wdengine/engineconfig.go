//go:build windows

package wdengine

import "net/netip"

// Config holds the WinDivert engine's runtime options. It is a trimmed cousin of
// the standalone example's config: the upstream is anyproxy's own ForwardTCP
// engine (not a SOCKS5 client), so the SOCKS client fields are gone. tun_windows.go
// fills this in from the anyproxy config.
type Config struct {
	// ProxyPort is the local listener port redirected traffic is folded onto.
	// 0 means "pick an ephemeral port"; it is filled in once the listener binds.
	ProxyPort uint16

	// RedirectPorts are the outbound TCP destination ports to intercept when
	// AllPorts is false (default 80, 443).
	RedirectPorts []uint16

	// AllPorts redirects every outbound TCP port (minus SkipPorts and bypassed
	// destinations) instead of just RedirectPorts.
	AllPorts bool

	// SkipPorts are destination ports that always go direct (never proxied).
	SkipPorts []uint16

	// BypassPrivate sends traffic to private/LAN and link-local ranges direct.
	// Loopback (127.0.0.0/8, ::1) is always bypassed regardless of this flag.
	BypassPrivate bool

	// BlackholeIP is the sentinel destination (e.g. 192.0.0.0) that a domain is
	// mapped to — in the system hosts file or anyproxy's own hosts config — so the
	// domain is unreachable without a proxy yet forced through the proxy (with
	// remote DNS) when the engine is up. Traffic to it must always be captured
	// (never bypassed by BypassPrivate/SkipPorts). Zero value (invalid) disables it.
	BlackholeIP netip.Addr

	// BlockQUIC makes the WinDivert filter also capture outbound UDP/443 so
	// process() can drop QUIC to hosts-hijacked IPs (forcing TCP+TLS fallback).
	BlockQUIC bool

	// IPv6 enables NAT/redirection of IPv6 traffic too. When false, IPv6 traffic
	// that would be proxied is dropped so it cannot bypass the proxy.
	IPv6 bool

	// SocksExcludeIP / SocksExcludePort exclude anyproxy's own connection to an
	// upstream proxy server from capture, preventing a loop. Set when the upstream
	// proxy address resolves to an IPv4 address.
	SocksExcludeIP   netip.Addr
	SocksExcludePort uint16

	// ExcludeIPs are destination IPs/CIDRs that must never be captured/redirected,
	// regardless of port. Traffic to (or back from) these goes direct. Use it to
	// escape a co-resident tunnel's transport endpoint — e.g. an OpenVPN server on
	// tcp/443 whose packets would otherwise loop (openvpn→server:443 captured →
	// anyproxy re-dials via the VPN default route → openvpn re-sends → …). Fed from
	// tun.bypassIPs.
	ExcludeIPs []netip.Prefix

	// MaxConnPerDomainPerSec caps how many new redirected connections a single
	// destination IP may start per second, protecting the ephemeral-port pool from
	// a single site's connection storms. 0 disables the limit.
	MaxConnPerDomainPerSec int

	// SocksProcessNames are additional executable base names (lowercase) whose
	// outbound connections must never be redirected. The listener-owning process
	// (anyproxy itself) is auto-detected; use this for extra helper processes.
	SocksProcessNames []string

	// Verbose logs every redirect decision.
	Verbose bool
}
