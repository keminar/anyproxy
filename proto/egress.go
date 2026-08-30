package proto

// Egress source-port band.
//
// On Windows the WinDivert redirector captures outbound TCP 80/443 and folds it
// into the local proxy. anyproxy's OWN outbound connections (direct to a server,
// or to an upstream proxy) leave from this same host on those same ports, so
// without a way to tell them apart the redirector recaptures them and folds them
// back in too — an endless loop: app→proxy→egress→recaptured→proxy→… The loop
// was observed specifically for IPv6 direct connections, where the SOCKET-layer
// loop guard loses the race against the outbound SYN and never excludes the
// egress port in time.
//
// To make the exclusion deterministic and IP-version-agnostic, the Windows
// dialer binds every anyproxy egress connection's local source port into this
// band, and the redirector passes any captured packet whose source port is in
// the band straight through. The band sits ABOVE the engine's NAT source-port
// pool (10000-40000) and BELOW the Windows dynamic/ephemeral range (49152-65535),
// so it collides with neither the proxy's fabricated loopback ports nor real
// application traffic.
//
// Used by proto (Windows dialer, tunDial) and tun/wdengine (redirect.process).
const (
	EgressPortLo uint16 = 40001
	EgressPortHi uint16 = 49151
)
