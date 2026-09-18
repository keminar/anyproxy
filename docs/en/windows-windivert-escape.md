# Windows WinDivert escape mechanism (loop protection)

This document specifically explains how anyproxy makes its own outbound connections on Windows **escape WinDivert capture**,
avoid self-loops, and why IPv4 and IPv6 are handled differently.

Companion documents:
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — the main redirect chain (capture→NAT→local proxy→forward)
- [windows-winDivert.md](windows-winDivert.md) — runtime dependencies (driver placement, admin privileges)

## The problem: anyproxy's own outbound also gets captured

WinDivert intercepts all outbound TCP 80/443 at the NETWORK layer and folds them into the local proxy. But
**anyproxy's own dialed-out connections (Leg 2)** are also local outbound, also 80/443, indistinguishable
from normal app traffic. If nothing is done:

```
App → WinDivert capture → local proxy → anyproxy outbound (Leg 2)
                                        ↓
                              WinDivert captures again → local proxy → outbound → …
                                        ↓ infinite loop
```

This is the "self-loop": `app→proxy→egress→re-capture→proxy→…`, until the port pool is exhausted and connections RST.
Historically this loop was **stably reproduced only for IPv6 direct connections**, while IPv4 worked fine — this article explains
the cause and the root fix.

## Escape methods overview (in process() decision order)

`Engine.process()` (`redirect.go`) releases each captured packet layer by layer:

| Layer | Mechanism | Release condition | Code location |
|----|------|----------|----------|
| impostor | self-injected return packet | `addr.Impostor()` | redirect.go:197 |
| return | proxy → app | `srcPort == ProxyPort` | redirect.go:227 |
| loopback | straight to local proxy | loopback and `dstPort == ProxyPort` | redirect.go:233 |
| upstream exclude | connection to upstream proxy | matches `SocksExcludeIP:Port` | redirect.go:239 |
| IP exclude | target matched by `tun.bypassIPs` | `isExcludedIP` | redirect.go:245 |
| **egress segment** | **anyproxy outbound dedicated source-port range** | **`srcPort ∈ [40001, 49151]`** | **redirect.go:257** |
| SOCKS Guard | fallback: fallback dial / external proxy process | `guard.ownsPort(srcPort)` | redirect.go:263 |
| isDirect | loopback/skipPort/private net | `isDirect` | redirect.go:296 |

> The first two layers (impostor, return) solve re-capture of the "**redirect injection itself**";
> the later layers solve the self-loop of "**anyproxy's own dialing**". This article focuses on the latter.

## Old solution: SOCKS-layer process Guard (the IPv4-escaping implementation)

Network-layer packets carry no process identity, so the old solution borrowed WinDivert's **SOCKET layer** (`LayerSocket`
+ `SNIFF|RECV_ONLY`) — this layer reports a **PID** for each TCP connection event:

1. the guard opens the SOCKET layer and listens for connection events (the `loop()` in `socksguard.go`)
2. **LISTEN/ACCEPT happens on the proxy port `:ProxyPort`** → learns the executable file name of that process
   into `family` (by process name not PID, to be compatible with proxy suites that separate GUI and core)
3. **CONNECT comes from a process in the family** → records the connection's **local source port** into the `egress` map
4. when the NETWORK layer `process()` captures a packet: `guard.ownsPort(p.srcPort)` matches → release as-is

Timing-wise, this chain relies on an implicit assumption: **the SOCKET-layer CONNECT event must be processed by the guard
before the SYN is captured by the NETWORK layer**. This holds in practice on IPv4, so it can escape.

## Why IPv6 fails with the same approach

The root of the race is the speed difference between the two processing paths:

```
                anyproxy initiates connect()
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
 NETWORK layer (sync)          SOCKET layer (async)
 SYN captured → judge now      CONNECT event → queued
        │                                │
        ▼                                ▼
 process() checks ownsPort()    guard checks PID → resolves name
 (egress table may be empty)    → writes egress[srcPort]
        │                                │
        ▼                                ▼
  ┌──────────┴─────────┐        ┌──────────┴─────────┐
  │IPv4: guard finishes│        │IPv6: SYN arrives   │
  │first → hits        │        │first → misses       │
  │→ released          │        │→ redirect self-loop │
  └────────────────────┘        └─────────────────────┘
```

- **NETWORK layer sync**: the instant `Recv()` captures the SYN, `process()` immediately runs `ownsPort`
- **SOCKET layer async**: the event first enters the WinDivert queue; the guard goroutine blocks on `RecvSocket()`
  and after reading the event still must `QueryFullProcessImageName` to resolve the process name (a syscall), **then**
  writes to the `egress` map

Which path finishes first is inherently uncertain. Measured result (verbatim comment in `proto/egress.go`):

> The loop was observed **specifically for IPv6 direct connections**, where the
> SOCKET-layer loop guard **loses the race against the outbound SYN and never
> excludes the egress port in time**.

Note the **never** — on IPv6 it's not a probabilistic miss but a **systematic loss of the race**: the IPv6
CONNECT event always arrives at the guard later than the SYN is captured by the NETWORK layer
(Windows reports IPv6 connection events with different timing than IPv4; the exact kernel details aren't recorded in code,
but the phenomenon is stable and reproducible). As a result `ownsPort` misses → `rewriteForward` folds the SYN
back to the proxy → the proxy dials again → captured again → infinite loop.

## New solution: egress source-port segment (deterministic identification)

Introduced in commit `4a5eec4 "ipv6请求连接逃逸问题"`. The idea shifts from "**passive recording**" (waiting for events to discover
ports) to "**active declaration**" (pin the source port into a dedicated segment before dialing):

### Port space layout

```
0 ────────── 10000 ──────── 40000 ─── 40001 ────── 49151 ── 49152 ────── 65535
│ fixed/system │ NAT pool  │ Egress seg │ Windows dynamic ports (real app traffic) │
                (engine-faked  (anyproxy
                 loopback src)  own outbound)
```

| Range | Purpose | Conflict? |
|------|------|--------|
| `[10000, 40000]` | NAT pool: loopback source ports the engine fakes for redirected connections | no overlap with egress segment |
| `[40001, 49151]` | **Egress segment**: anyproxy's own outbound dedicated source ports | deliberately avoids both sides |
| `[49152, 65535]` | Windows dynamic/ephemeral ports (normal app outbound) | no overlap with egress segment |

### Three coordinated parts

**1. Bind before dialing (`tunDial` in `proto/dialer_windows.go`)**

```go
d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{Port: int(nextEgressPort())}}
conn, err := d.Dial(network, addr)
```

- `nextEgressPort()` rotates within `[40001, 49151]` (constant in `egress.go`)
- binding happens **before** `connect` sends the SYN, so the source port is fixed the moment the packet goes out
- `LocalAddr.IP` is nil → binds the wildcard address of that protocol family (`0.0.0.0` / `::`),
  **one code path works for both tcp4/tcp6**
- bind conflict (WSAEADDRINUSE) → try the next slot, up to 16 times; only after the whole segment is exhausted does it fall back
  to normal dialing (that one may self-loop, but is caught by the per-target rate limiter)

**2. Recognized instantly by the NETWORK layer (`process()` in `redirect.go`)**

```go
if p.srcPort >= proto.EgressPortLo && p.srcPort <= proto.EgressPortHi {
    return true // anyproxy's own outbound, release
}
```

It reads the source port from the TCP header for a **pure numeric comparison**, needs no async state, and can be judged the instant the packet arrives.

**3. SOCKS Guard downgraded to fallback**

It only catches two cases: ① unbound fallback dialing when the egress segment is exhausted; ② external proxy processes configured via `tun.windows.excludeProcs`
(configured through anyproxy's dialer; the config field is named `excludeProcs`, which the engine internally fills into
`SocksProcessNames` for SOCKS Guard to match).

### Why this is a root fix

| Dimension | Old: SOCKET Guard | New: egress source-port segment |
|------|------------------|---------------------|
| Source port origin | OS randomly assigns, "discovered" via async events | anyproxy actively binds to dedicated segment |
| Recognition timing | depends on event arriving before SYN | bound before connect; port fixed when SYN goes out |
| Recognition method | look up process → look up map (async state) | `srcPort ∈ [40001,49151]` pure numeric check |
| IP version | depends on SOCKET-layer event timing (IPv6 reliably fails) | IP-version-independent, identical for IPv4/IPv6 |

In one sentence: the old solution relied on the luck of "SOCKET event arriving just in time", which reliably fails on IPv6; the new solution
turns recognition into a deterministic port-segment check, independent of any timing, so the IPv6 self-loop is eradicated.

## Key code index

| File | Responsibility |
|------|------|
| `proto/egress.go` | `EgressPortLo=40001` / `EgressPortHi=49151` constants, and design notes |
| `proto/dialer_windows.go` | `tunDial`: bind source port into egress segment before connect, swap slot on conflict |
| `tun/wdengine/redirect.go` | `process()`: source-port segment check (primary) + `ownsPort` (fallback) |
| `tun/wdengine/socksguard.go` | SOCKET-layer process guard: record/release proxy-family outbound source ports |
| `tun/wdengine/pidtable.go` | `GetExtendedTcpTable` port→PID snapshot (for diagnostics) |
| `tun/wdengine/procimage.go` | PID → executable file name resolution (cache + TTL) |

## Related commit

- `4a5eec4 "ipv6请求连接逃逸问题"` — introduced the egress source-port segment, root-fixing the IPv6 direct-connection self-loop
