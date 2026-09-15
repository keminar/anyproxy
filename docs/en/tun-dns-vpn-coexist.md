# DNS Troubleshooting When TUN Coexists with a VPN (OpenVPN/TAP)

This document records a real incident: **when anyproxy's TUN global proxy and OpenVPN Connect run on the same machine, deleting a `/32` route manually caused all domains not hijacked by hosts to time out on resolution.**

## Symptom

```
> nslookup baidu.com
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  10.18.0.1        # resolver points to the OpenVPN tunnel's intranet DNS
*** Request to UnKnown timed out
```

Domains matching anyproxy's `hosts` config resolved fine (anyproxy constructs the answer locally), but everything else timed out.

## Topology

Two layers of tunnel run on the same machine:

- **anyproxy TUN**: `autoRoute` installed `0.0.0.0/1` + `128.0.0.0/1`, taking over almost all traffic.
- **OpenVPN Connect TAP**: `TAP-Windows Adapter V9`, IP `10.18.0.70/30` (mask `255.255.255.252`, the local direct segment contains only `10.18.0.68 ~ 10.18.0.71`), DNS server `10.18.0.1`, **no default gateway**.

Key point: **DNS `10.18.0.1` is NOT in the TAP's `/30` direct segment** — it is at the tunnel peer and can only be reached via a `10.18.0.1/32 → TAP` route that OpenVPN installs.

## Root Cause

Windows routing uses **longest-prefix-match first**, so `/32` always beats anyproxy's `/1`:

- **/32 present**: queries to `10.18.0.1` go straight into the TAP → go through the VPN's DNS → normal, anyproxy never participates.
- **/32 deleted**: the only route to `10.18.0.1` left is anyproxy's `0/1` → the packet is sucked into anyproxy's TUN → anyproxy has no way to send it back to the TAP:
  - force-bind the physical NIC (`IP_UNICAST_IF`) → there is no `10.18.0.1` on the physical network → **blackhole**;
  - normal dial (no interface binding) → the system again selects `0/1` by the routing table → feeds back into anyproxy → **routing loop**.

### Why `isLocalNet` Cannot Patch This

`isLocalNet` / `dstInBypassNet` (`proto/dialer_*.go`, `tun/udp.go`) **only judge "local direct subnet"** (`config.TUNBypassNets`, collected by `initBypassNets` from each NIC's direct segment), **with no RFC1918 check**. `10.18.0.1` does not belong to any local direct subnet (the TAP only gave `/30`), so `isLocalNet(10.18.0.1) == false`.

Even changing it to return true for private ranges is useless — it only swaps "blackhole" for "routing loop": after deleting the /32, the only route to `10.18.0.1` in the system is anyproxy's `0/1`, and a normal dial still loops back to itself. **The source of truth is the routing table**; code-level judgments cannot conjure a route to someone else's tunnel.

## Fix

1. **Don't delete that /32 (easiest)**: reconnect OpenVPN Connect to let it push again, or add it manually:
   ```cmd
   :: Find the TAP interface index
   netsh interface ip show interfaces
   :: Pin 10.18.0.1 back to the TAP (net30 topology peer is usually .69; using the interface index is safest)
   route add 10.18.0.1 mask 255.255.255.255 10.18.0.69 if <TAP Idx> metric 1
   ```
   As long as anyproxy is not fed this packet, it is naturally correct.

2. **Catch the VPN segment at the code level (to be implemented, option B)**: add a direct-exception config for "binding to a specified interface ifindex by destination subnet" (`tun.bypassRoutes`, unrelated to mode=bypass). When TCP `tunDial` and UDP `listenUDP` match, they point `IP_UNICAST_IF` to **the TAP's index** (instead of the physical NIC), so anyproxy can actively send VPN intranet traffic (including DNS) back to the TAP even without the system /32:
   ```yaml
   tun:
     bypassRoutes:
       - net: 10.18.0.0/24     # or precisely 10.18.0.1/32
         dev: "TAP-Windows Adapter V9 for OpenVPN Connect"
   ```

## Troubleshooting Commands

### 1. Check whether the /32 exception route exists (is VPN DNS / upstream still correctly directed?)

```powershell
Get-NetRoute -AddressFamily IPv4 |
    ? { $_.DestinationPrefix -match '/32$' -and $_.NextHop -in '192.168.1.1','10.18.0.69' } |
    Sort-Object NextHop,DestinationPrefix |
    Format-Table DestinationPrefix,NextHop,ifIndex,RouteMetric
```

- If `10.18.0.1/32` (next hop pointing to the TAP, e.g. `10.18.0.69`) is **not in the list**, the route to the VPN DNS is lost and DNS gets swallowed by anyproxy's `0/1`.
- Also verify that the /32 exception for the upstream proxy / gateway is still there (next hop `192.168.1.1`).

To check which ifIndex is the TAP / physical NIC:

```powershell
Get-NetAdapter | Format-Table Name,ifIndex,Status
```

### 2. Query different DNS servers separately to locate "routing problem" vs "resolution problem"

```cmd
:: Use the current default resolver (may be 10.18.0.1)
nslookup baidu.com

:: Explicitly specify the VPN intranet DNS to verify the /32 route sent it into the TAP
nslookup baidu.com 10.18.0.1

:: Explicitly specify the physical network's real DNS as a control
nslookup baidu.com 192.168.1.1
```

Interpretation:

- `10.18.0.1` times out, `192.168.1.1` works → the /32 route to the VPN DNS is lost (this incident).
- Both time out → a deeper problem (anyproxy did not escape the TUN, `TUNBypassIfIndex=0`, etc., see the startup log `TUN bypass:` line).
- Both work → DNS has recovered.

## VPN Transport Routing Loop (Windows/WinDivert) and Escape Config

The above is about the VPN **intranet DNS** routing problem. Another independent failure is the **VPN transport's own routing loop** — which only occurs on Windows (WinDivert model).

### Cause

When OpenVPN uses **TCP transport** (e.g. `tcp/443`, commonly used to penetrate firewalls) and has redirect-gateway enabled (default route points to the VPN):

```
openvpn.exe → VPN server:443 (TCP transport)
   → WinDivert captures (443 is a redirect port) → NAT to anyproxy local listener
   → anyproxy calls back VPN server:443 (anyproxy's own egress binds to the egress source-port range, deterministically allowed, no longer captured)
   → but default route = VPN tunnel → openvpn.exe re-encapsulates and sends to VPN server:443
   → captured by WinDivert again → …… routing loop
```

Root: **the transport packets OpenVPN itself sends to the VPN server get captured by WinDivert**. UDP transport (default 1194/UDP, or udp/443) is outside the capture scope (only TCP 80/443 and UDP 53/443 are captured, and UDP443 only drops hosts-hijacked IPs), so it is unaffected.

### Escape Config (pick one or stack both)

1. **Exclude by process name (preferred, IP-independent)**: add the OpenVPN process to `tun.excludeProcs`, and all its outbound connections are not redirected. Covers server changes / multiple servers / failover, most robust.
   ```yaml
   tun:
     excludeProcs:
       - openvpn.exe
   ```
2. **Exclude by destination IP (supplementary)**: fill the VPN server IP/CIDR into `tun.bypassIPs`, and traffic to that address skips capture and goes direct.
   ```yaml
   tun:
     bypassIPs:
       - 203.0.113.10       # VPN server public IP
   ```

After taking effect, the startup log prints `tun(windivert): exclude procs=[openvpn.exe] ips=[...]`.

> **Reliability difference between the two exclusions**: `bypassIPs` (by destination IP) matches at the packet-capture layer, **deterministic, no race condition**; `excludeProcs` (by process name) relies on WinDivert's **SOCKET-layer events** recording that process's outbound source port, and this event and the network-layer SYN belong to two separate paths, **so there is a race condition** (in extreme cases the first few packets may not be excluded), and it requires a fairly recent WinDivert (if the SOCKET layer is unavailable, `excludeProcs` fails completely and the startup log warns). So: **prefer process-name exclusion for maintainability, but if the VPN transport is occasionally still captured, switch to / stack `bypassIPs` with the server IP for maximum reliability.**
>
> (Note: anyproxy's own direct egress now uses the **egress source-port range** for deterministic allowance and no longer relies on the SOCKET guard, which also root-fixed the IPv6 direct self-loop — see the "Loop Protection" section of [windows-windivert-redirect.md](windows-windivert-redirect.md). The SOCKET guard now only serves external processes like `excludeProcs`.)

> Why not auto-scan the routing table to identify the VPN server: OpenVPN's `<server>/32 via physical gateway` is detectable, but `/32` routes are not only added by it, so heuristics easily misfire/miss; explicit config is more controllable.
>
> Note the distinction between two types of failure: this section is about **the transport layer being captured by WinDivert** (Windows-specific); the above is about **the VPN intranet DNS /32 route being lost** (a cross-platform routing problem). The two are independent and may coexist.

## Inbound Connection Reply Packets Sucked Into the TUN (external service / external SSH drops)

Another reply-packet failure: **an external party actively connects into this machine** (e.g. external SSH login); the local service (sshd) replies with source = physical NIC IP, destination = external client IP, which matches the TUN's `0.0.0.0/1`+`128.0.0.0/1` → gets sucked into the TUN → treated as a new outbound → cannot return, handshake stalls. The gVisor TUN on all three platforms (Linux/macOS) has this problem (Windows uses the WinDivert centralized-capture model, a different mechanism).

### Linux: source policy routing (built-in, automatic)

Linux uses `ip rule` source-address policy routing to root-fix this: the TUN default route is moved to a separate table, and `ip rule from <physical IP> lookup main` makes "reply packets with source = physical IP" look up the main table and go via the physical NIC, while the rest enter the TUN. Automatically effective when `autoRoute=true`, no config needed. Details in `tun/route_linux.go`.

### macOS: pf reply-to (requires explicit enable)

macOS has **no** Linux-style source policy routing / multiple routing tables, so it uses pf's `reply-to` to make inbound connection reply packets return along the incoming NIC. Just configure the inbound ports to allow (needs root, installed together with the route when `autoRoute=true`):

```yaml
tun:
  inboundPorts:
    - 22        # external SSH
    - 443       # external https service
```

Startup log when effective: `inboundPF: 已放行入站端口 22 的回包(pf reply-to via en0 <gw>)` (allowed reply packets for inbound port 22 via pf reply-to on en0 <gw>). The principle is to add a rule to the `com.apple/anyproxy` sub-anchor (macOS's main ruleset ships with the wildcard `anchor "com.apple/*"`, which is evaluated automatically):

```
pass in quick on en0 reply-to (en0 <gateway>) inet proto tcp from any to (en0) port { 22 } flags S/SA keep state
```

On exit, that anchor is automatically flushed and the pf enable reference released (`pfctl -X <token>`), without affecting other system pf rules.

Verify / manual troubleshooting:

```bash
sudo pfctl -a com.apple/anyproxy -sr      # view the loaded reply-to rules
```

> Note: `inboundPorts` is only installed together with the TUN route when `autoRoute=true` (default); if you manually add `0/1` routes (autoRoute:false), you must also add an equivalent pf rule. If your macOS uses a custom `/etc/pf.conf` that removed `anchor "com.apple/*"`, the sub-anchor will not be evaluated and this mechanism will silently fail — confirm with the `pfctl -sr` above.

**Implementation dependencies and verification status** (as of 2026-08-11):

- Code is in [tun/pf_darwin.go](../tun/pf_darwin.go) + [tun/route_darwin.go](../tun/route_darwin.go); it compiles on all three platforms, but **the pf part has not yet been verified on a real macOS machine**.
- Two environmental prerequisites: ① depends on the `anchor "com.apple/*"` in the system main ruleset (present by default on macOS); ② installed only when `autoRoute=true`.
- On first real-machine run, keep a session that does not go through this link (local terminal / screen sharing), and confirm external SSH connects before relying on it; if the `pass in ... reply-to ...` rule syntax differs on your macOS version, adjust based on `pfctl -a com.apple/anyproxy -sr` / system logs.

## Related

- Loop protection for two anyproxy instances on the same machine: see [multi-instance-loop.md](./multi-instance-loop.md).
- TUN routing and bypass mechanism: see [routing.md](./routing.md), [tun-features.md](./tun-features.md).
