# anyproxy documentation

## Getting started & overview

- [quickstart.md](quickstart.md) — Quick start: local startup, tunneld, forwarding to upstream proxy, graceful restart, Docker.
- [overview.md](overview.md) — Overview and architecture: what it does, data chain, the processing flow of one connection, run-mode overview, process model.
- [usage.md](usage.md) — Client access and usage: same-port auto-detected HTTP+SOCKS5 proxy, transparent proxy, global (TUN/WinDivert) three access methods, and how to point the client at it.

## Reference manual

- [cli.md](cli.md) — Command-line arguments in detail, and priority vs. config file.
- [configuration.md](configuration.md) — `router.yaml` full configuration reference, explained section by section.
- [hot-reload.md](hot-reload.md) — `watcher: true` config hot reload: which config changes take effect immediately, which need restart or SIGHUP, and the judgment mechanism.
- [config-examples.md](config-examples.md) — Complete config examples by scenario: global proxy, domain-based routing, Windows+OpenVPN, macOS inbound SSH, iptables, tunneld, tcpcopy, intranet penetration, same-host dual instances.
- [routing.md](routing.md) — Routing and proxy rules: domain matching, `target`/`proxy`/`dns`/`ip`/`port`/`allowIP`, multi-proxy `local`/`deny`, priority.
- [proxy-decision.md](proxy-decision.md) — Proxy decision logic in detail: `target`(local/remote/auto/deny) × `proxy`(multi-proxy + local/deny suffix) full decision order, host/global fallback chain, hot reload, unavailable cache.
- [modes.md](modes.md) — Run modes: proxy / tunnel(tunneld) / tun / bypass(Linux only) / tcpcopy port forwarding / websocket intranet penetration.
- [websocket.md](websocket.md) — websocket intranet penetration in detail: server/subscriber roles, two forwarding paths (HTTP header subscription, raw TCP port forwarding), `forward`/`subscribe` fields, auth handshake, whitelist and common pitfalls.
- [deployment.md](deployment.md) — Deployment and operations: build, background, graceful restart, iptables global proxy, Docker, Windows notes, performance tuning.
- [build.md](build.md) — Build and cross-compilation: `build.sh`/`build.bat` targets, router MIPS (big/little-endian, softfloat), Windows WinDivert, manual cross-compilation (ARM, etc.).

## Topics

- [geo.md](geo.md) — geoip/geosite routing: match by country IP range / domain category using `geoip.dat`/`geosite.dat`(protobuf) or text lists (`name: geoip:cn` / `geosite:cn`), `-geo-extract` offline extraction of small file, zero-dependency protobuf parsing, only Domain+Full used.
- [caching.md](caching.md) — In-process caches: DNS resolution cache (10min, domains with `ip` configured don't use cache), auto direct-fail cache (20s), sniffed-domain cache (10min, saves domain matching in preconnect scenarios); upstream proxy connectivity cache removed (now real-dial each time).
- [tun-features.md](tun-features.md) — TUN global proxy features: cross-platform (Linux/Windows/macOS utun), auto-route `autoRoute`, QUIC(UDP443) interception `blockQUIC`, UDP forwarding behavior, `target`/`proxy` priority.
- [tun-dns-resolution.md](tun-dns-resolution.md) — DNS resolution priority under TUN: which of system hosts / anyproxy config hosts / DoH-DoT three paths wins; resolution phase (UDP53 hijack) vs. forwarding phase (re-query config by SNI, `host.IP` override, TUN does no local DNS re-resolution); where DoH bypass and `ip:` are the only ways to force rewrite; and the private/LAN target `BypassPrivate` (Windows default true) exception that goes direct at capture stage, not entering the engine.
- [blackhole-sentinel.md](blackhole-sentinel.md) — **Blackhole sentinel IP topic** (`default.blackholeIP`, default 192.0.0.0): point a domain at an unroutable sentinel IP to solve at once both "block a domain locally when proxy is off" and "access that domain via the downstream proxy's remote resolution when anyproxy is on"; includes why the sentinel must be 192.0.0.0 (not loopback/private), the two-phase principle (capture forces into engine + forwarding forces remote+remote), detection by dstIP/SNI only to recover the domain, system hosts vs config hosts (whether effective for DoH), full example and FAQ.
- [multi-instance-loop.md](multi-instance-loop.md) — Same-host multi-instance (A with tun + B normal) loop protection: `mode=bypass` root fix (Linux only), `loopGuard` circuit breaker fallback, macOS/Windows alternatives.
- [direct-punch-order.md](direct-punch-order.md) — NAT direct hole-punch ordering topic: when crossing "carrier CGNAT home broadband ↔ public cloud host", the residential/CGNAT side must send the first packet, otherwise the NAT mapping is poisoned and both directions die; includes the origin of `direct.punchFirst` config and a troubleshooting checklist.
- [direct-relay-design.md](direct-relay-design.md) — VPS blind-relay (TURN-style direct relay) design: when both ends are behind CGNAT, relay via a public VPS, QUIC/TLS end-to-end, VPS only blind-forwards opaque UDP; signaling/auth/data plane/failure semantics.
- [tun-dns-vpn-coexist.md](tun-dns-vpn-coexist.md) — TUN and VPN (OpenVPN/TAP) coexistence three kinds of reply-failure: ① VPN intranet DNS /32 route lost; ② Windows (WinDivert) VPN transport loop and `excludeProcs`/`bypassIPs` escape; ③ inbound connection reply packets sucked in by TUN (external SSH drops) — Linux source policy routing (automatic), macOS `pf reply-to` (`inboundPorts`).
- [windows-winDivert.md](windows-winDivert.md) — Windows WinDivert runtime dependencies: `WinDivert.dll`/`.sys` placement, administrator privileges, driver-load issues with space/Chinese paths, bypass mode removed on Windows.
- [todo.md](todo.md) — Todo / pending confirmation: items left unhandled during PR #22 review (transparent proxy sniff `Peek(1)` no timeout + implementation fork, `HostBlocksUDP` linear scan on hot path).
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — Windows WinDivert redirect principle: the full chain of packet capture → NAT rewrite → local proxy → restore destination forwarding; NAT table, dual-stack listening, loop protection.
- [windows-windivert-escape.md](windows-windivert-escape.md) — Windows WinDivert escape mechanism (loop-protection topic): how anyproxy's own outbound escapes capture to avoid self-loop; the SOCKS-layer Guard race defect (IPv4 escapes, IPv6 stably self-loops) and the egress source-port-range root fix.
