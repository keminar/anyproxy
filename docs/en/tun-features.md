# TUN Mode Features and Routing/Proxy Rule Semantics

This document summarizes several features and rule semantics related to anyproxy's TUN global proxy:
cross-platform support, automatic routing, QUIC(UDP443) interception, UDP forwarding behavior, and the
priority between `target` and `proxy`.

Loop protection for same-machine A+B (multiple instances) is documented separately in [multi-instance-loop.md](multi-instance-loop.md).

## 1. Cross-Platform TUN Support

| Platform | Implementation | Notes |
|------|------|------|
| Linux | `/dev/net/tun` (`IFF_TUN\|IFF_NO_PI`) + gVisor user-space stack | reads/writes raw IP packets |
| macOS | native utun (`AF_SYSTEM` control socket) + gVisor user-space stack | self-implemented, no external dependencies |
| Windows | **WinDivert** network-layer redirection (**not a virtual network interface, not gVisor**) | requires `WinDivert.dll` + `WinDivert64.sys`, see [windows-winDivert.md](windows-winDivert.md) |

- **Linux/macOS**: create a TUN virtual network interface (TUN device); packets enter the gVisor user-space protocol stack, which parses out TCP and reuses the proxy logic.
  macOS opens utun via `Socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` + `IoctlCtlInfo`;
  the interface name is like `utun4` (set `tun.name: utunN` to specify the unit; leaving blank lets the kernel pick one). Each utun packet carries a 4-byte address-family header, which the Device layer strips/re-adds automatically and is transparent to the upper gVisor layer. Both share the same gVisor stack, so behavior is identical.
- **Windows**: does not create a virtual network interface; it uses WinDivert to capture outbound TCP 80/443 at the network layer and NAT-redirect them to the local listening port,
  then reuses the same proxy routing logic. Therefore virtual-network-interface parameters such as `tun.name/addr/mtu/autoRoute` are ignored on Windows.

Startup (identical on all three platforms, requires admin/root):
```
# Enable via command line (default IP 10.9.0.1/24)
sudo ./anyproxy -mode tun -p 'socks5://127.0.0.1:10000'

# Network interface name and interface address are specified via tun.name / tun.addr
sudo ./anyproxy -mode tun

# Or enable tun.enable: true in conf/router.yaml and start directly
sudo ./anyproxy
```

## 2. Automatic Routing autoRoute (enabled by default)

`tun.autoRoute` controls whether global routes are automatically added at startup. When **not configured, the default is true** (three-state `*bool`;
you must explicitly set `false` to disable it).

| Config | Behavior |
|------|------|
| `autoRoute` not written | **true** — at startup automatically add `0.0.0.0/1`+`128.0.0.0/1` routes plus bypass exceptions; cleaned up on exit |
| `autoRoute: true` | same as above |
| `autoRoute: false` | only print the route commands for you to run manually |

Implemented on all three platforms (Linux `ip route` / Windows `route add if` / macOS `route add -interface`).

> The default of true means enabling `mode=tun` takes over the default route. The upstream proxy MUST be direct (egress) and must NOT go through the TUN, otherwise a routing loop will cut off the network.
> **An upstream proxy specified by IP is automatically added to the direct exception** (`tun.bypassIPs`; autoRoute adds a `/32` direct route);
> only an upstream proxy specified by **domain name** requires you to manually fill its IP into `tun.bypassIPs`.

With `autoRoute: false`, startup only prints the commands; you must take over manually per the prompt (requires admin/root):

```
# Linux: before taking over the default route, make sure to add a direct exception for the upstream proxy's egress IP, otherwise a loop will cut off the network
sudo ip route add <upstream proxy IP>/32 via <original gateway> dev <original interface>
sudo ip route add 0.0.0.0/1 dev anytun0
sudo ip route add 128.0.0.0/1 dev anytun0

# Windows: likewise add a direct exception for the upstream proxy IP first
route add <upstream proxy IP> mask 255.255.255.255 <original gateway>
route add 0.0.0.0 mask 128.0.0.0 10.9.0.1
route add 128.0.0.0 mask 128.0.0.0 10.9.0.1
```

## 3. QUIC(UDP 443) Interception blockQUIC (enabled by default)

### Problem

In TUN mode all UDP is forwarded directly and **does not go through the proxy chain** (see Section 4). This causes domains whose `ip:` is configured in hosts (intranet hijacking) to have their QUIC/HTTP3 (UDP 443) go directly to the Internet with the hijacked IP, bypassing the TCP+SNI proxy path that should have taken effect.

### Solution

`tun.blockQUIC` (**default true**, three-state `*bool`): directly drop UDP 443 packets whose destination IP exactly equals some `host.ip`. QUIC is designed to gracefully fall back, so when the client's UDP 443 is unreachable it automatically downgrades to TCP 443 → goes through the existing
TCP+SNI proxy chain, and the hosts rules take effect as usual.

- **Matching uses only the exact `dstIP == host.ip` check** (deterministic, unique). No IP→domain reverse lookup: one IP can map to multiple
  domains (CDN/shared IP), so reverse lookup is non-unique and cannot be used as the basis for a decision.
- **No QUIC packet parsing**: it reuses the `ip` configuration already known from DNS hijacking, no QUIC Initial decryption needed.
- To disable: `tun.blockQUIC: false`.

### Coverage and Boundaries

- ✅ Covered: domains whose hosts have `ip:` configured (including `target=remote`+`ip`).
- ⚪ `deny` domains need no handling here: the DNS layer already returns NXDOMAIN, the client gets no IP, and naturally sends no QUIC.
- ⚠️ Not covered: domains with `target=remote` but **no `ip` configured** (they use real DNS/real IP, and the machine has no reliable domain signal).
  If you need to intercept them, just configure `ip:` for that domain to bring it into scope.
- ⚠️ Clients that use DoH/DoT to bypass the local DNS hijack are not affected by this mechanism (they never get the hijacked IP).

The risk of false blocking is extremely low: blocking UDP 443 downgrades HTTP3 to HTTP2/TCP, pages still open normally, only losing the QUIC performance optimization.
This is an industry-standard practice (Clash/sing-box also do this by default).

## 4. UDP Forwarding Behavior

- **All UDP (any port) is intercepted before entering gVisor and forwarded directly**, going out via the physical network interface (binding source IP + `SO_BINDTODEVICE`
  to escape the TUN, see Section 6), **not going through the upstream proxy** (tunnel/socks5 cannot handle UDP).
- **DNS(53)** additionally does a layer of local hosts hijacking: domains matching a configured `ip` get answered locally with that IP directly; `deny` domains get
  NXDOMAIN; unmatched ones are forwarded directly as usual to the real DNS.
- **QUIC(443)** see Section 3. All other UDP is NAT-forwarded directly.

## 5. Priority Between target and proxy

Semantics when `hosts[].target` and `hosts[].proxy` are combined (handshake in `proto/tunnel.go`):

| target | proxy | Result |
|--------|-------|------|
| `local` | present | **local direct connection**, proxy is ignored (explicit local has highest priority) |
| `remote` | present | use this custom proxy; if the proxy fails and there is no `local` fallback, error, no direct connection |
| `auto` | present | **try direct connection first**, fall back to this proxy if unreachable (local preferred, not forced through proxy) |
| `remote`/`auto` | absent | use global proxy / auto selection |
| `deny` | — | abort the request |

Key point: `target: local` has the highest priority — even with a proxy configured it goes direct; `auto` always prefers local and will not force the proxy just because a proxy is configured.
The full decision logic (multiple proxies, `local`/`deny` fallback, host/global fallback, caching) is in [proxy-decision.md](proxy-decision.md).

## 6. How Local Egress Escapes the TUN (Linux)

After the TUN takes over all global traffic, anyproxy's own outbound connections (to direct targets, or to the upstream proxy) **must escape the TUN**, otherwise
the outbound packets get captured again by its own `anytun0`, the source address becomes `10.9.0.1`, and gVisor treats it as a new connection and processes it again → **routing loop**.

On Linux, **policy routing** (`tun/route_linux.go`, automatically effective when `autoRoute=true`) distinguishes "local egress" from "traffic entering the TUN":

| ip rule | Effect |
|---------|------|
| `pref 100  from <physical NIC IP> lookup main` | packets with **source IP = physical NIC IP** look up main → go via the physical NIC default route (escape the TUN) |
| `pref 110  from all lookup main suppress_prefixlength 0` | use main's **specific** routes (LAN/loopback/upstream-proxy `/32`), but ignore the default route |
| `pref 120  from all lookup <tun table>` | the rest (those that should take the default route) enter `anytun0` and are taken over by gVisor |

Key point: **`pref 100` matches by "source IP", not by network interface**. So for local egress to escape the TUN, the connection's
**source IP must be the physical NIC IP from the start**. For this reason, `tunDial` (TCP, `proto/dialer_linux.go`) and `listenUDP`
(UDP, `tun/udp_dial_linux.go`) do two things simultaneously for IPv4 targets **outside the local direct subnet**:

1. **Bind source IP = physical NIC IP** (`LocalAddr` / `bind`) — the **primary** means of hitting `pref 100`, determines whether escape succeeds.
2. **`SO_BINDTODEVICE` to bind the physical NIC** — fallback, forces egress from that NIC (when the source IP cannot be obtained, or in a **one-NIC-multiple-IP** scenario, guarantees the correct egress).

> Why binding source IP is primary and binding NIC is secondary: `SO_BINDTODEVICE` does **not set the source IP** at the kernel routing-decision stage, so on its own
> it cannot match `pref 100` (which matches by source IP) and falls into `pref 120` → enters the TUN → loop. Binding the NIC only guarantees "which NIC to egress from",
> not "which source IP to use", and the escape criterion is precisely the source IP.
>
> **One NIC with multiple IPs**: `pref 100` adds a rule for **each** IPv4 of that NIC, so binding any one of them matches. We bind
> `physIPv4s(dev)[0]` (the first IPv4 of that NIC), then stack `SO_BINDTODEVICE` to lock the NIC, so multi-IP scenarios are also correct.

Startup log `TUN bypass: device="enp3s0" ip="192.168.1.100" ...`: escape is
ready only when both `device` and `ip` are non-empty. If `ip=""` (a symptom in older versions) then the source IP was not bound, and local direct connections to the public Internet will loop.

### Troubleshooting: recurring `direct to <IP>` — loop or normal telemetry?

Symptom: the same domain (commonly QQ/Tencent **telemetry/beacon** domains such as `otheve.beacon.qq.com`) keeps flooding the log with
`direct to <IP>`, especially **when traffic comes from a Windows VM behind the TUN**. This is **usually not a loop**, but rather
an app in the VM reporting telemetry at high frequency, creating a new connection each time. When **escape is normal**, these are real direct connections of "connect → send → close".

To tell whether it's a loop (either of the two diagnoses it):

```bash
# 1) Any local outbound connection with source=10.9.0.1? Present = did not escape TUN = hard proof of loop; empty = normal.
sudo ss -tnp | grep anyproxy | grep 10.9.0.1

# 2) Sample for a few seconds: does the connection count to that IP only grow / is some IP's connection count abnormally high (dozens or hundreds)?
sudo ss -tnp | grep anyproxy | grep -oE '[0-9.]+:(443|80)' | sort | uniq -c | sort -rn | head
```

- All outbound sources are physical NIC IPs (e.g. `192.168.1.100%enp3s0`), no `10.9.0.1`, single-digit connection counts per target → **normal**, just noisy telemetry.
- A `10.9.0.1` source appears, or some IP's connection count spikes → real loop; check whether the startup log `TUN bypass:` `ip` is empty, and whether `ip rule` has `pref 100`.

To silence the noise: configure `target: deny` for that telemetry domain to cut it off directly (does not affect normal business):

```yaml
hosts:
  - name: otheve.beacon.qq.com
    match: contain
    target: deny
```

> Note: manually running `ip route add <IP> via <gateway> dev <physical NIC>` can also make the log disappear, but that lets the VM's traffic
> **pass through directly at `pref 110`, bypassing anyproxy** (`/32` is a specific route and is not suppressed), which does not mean
> there was a loop before, and is not the recommended approach. After confirming escape is normal you should delete such manual `/32` routes and use `deny` or just ignore the telemetry noise.

## Configuration Quick Reference

| Config | Default | Notes |
|--------|------|------|
| `mode` | `proxy` | `tun` builds a virtual network interface for global proxy (all three platforms) |
| `tun.name` | platform default | Linux `anytun0` / Windows `AnyProxy` / macOS `utunN` (kernel picks) |
| `tun.autoRoute` | **true** | if not configured, routes are added automatically; `false` only prints commands |
| `tun.bypassIPs` | empty | direct exceptions (upstream proxies specified by IP are merged automatically; domain proxies require manual IP) |
| `tun.blockQUIC` | **true** | drop UDP443 of domains with ip configured, forcing QUIC to fall back to TCP; `false` disables |
