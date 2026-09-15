# Domain Resolution Priority in TUN Mode (System hosts / DoH / Configured hosts)

This article answers a common confusion: **On Windows with TUN enabled (WinDivert) but no system proxy set, when the browser visits a domain,
does it go through the system `hosts` file, get taken over by anyproxy's UDP DNS hijack, or go through DoH? Which IP does it finally connect to?**

Conclusion up front: you must look at **two independent stages** — the **DNS resolution stage** decides "which IP is obtained", and the **TCP forwarding stage**
anyproxy re-queries its own config once more by SNI domain, which may override the IP from the previous step. The two are not equivalent, and each has blind spots.

Also distinguish the two things both called "hosts":

| Name | What it is | Who uses it |
|------|--------|--------|
| **System hosts** | `C:\Windows\System32\drivers\etc\hosts` | OS resolver (DNS Client / dnscache) |
| **anyproxy config hosts** | the `hosts:` section in `router.yaml` (`name`/`ip`/`target`/`dns` …) | anyproxy's DNS hijack and TCP forwarding routing |

anyproxy **does not read the system hosts file**; it only recognizes its own `hosts:` in config.

---

## 1. Resolution Stage: Three Paths

anyproxy's DNS hijack only intercepts **plaintext UDP/53**: the WinDivert filter captures `outbound and udp.DstPort == 53`
(the `candidateFilters` in [`tun/wdengine/redirect.go`](../tun/wdengine/redirect.go)), and once captured, `hijackDNS`
([`tun/wdengine/dns.go`](../tun/wdengine/dns.go)) answers per the configured hosts. There are three cases:

### ① Domain is in the system hosts → system hosts wins, UDP hijack cannot intercept

Windows DNS Client's resolution order is to **check the system hosts file first**; on a match it returns immediately and **never sends a UDP/53 packet to the network**.
No outbound UDP packet → WinDivert has nothing to capture → `hijackDNS` does not fire. **anyproxy's config hosts, fake-ip, and AAAA
suppression all fail at this step**, and the browser gets the IP written in the system hosts.

### ② Domain not in system hosts, uses plaintext UDP/53 → anyproxy hijack takes effect

The outbound UDP/53 is captured by WinDivert, and `hijackDNS` matches against the configured hosts (`dnsutil.MatchHostDNS`):

- Match with `ip:` configured and the query is an A record → directly construct an answer returning **the configured ip** (and record `ip→domain` for later TCP domain restoration).
- Match and it is AAAA → return NOERROR empty answer, forcing the client to fall back to A record (to avoid real DNS polluting intranet domains).
- Match `deny` → return NXDOMAIN.
- Match but no `ip` configured (e.g. `target=remote` without `ip`) → **not intercepted**, let it go through normal resolution.

### ③ Client uses DoH/DoT → both resolution layers are bypassed

DoH wraps the DNS query into HTTPS and sends it to the DoH server over **TCP/443**. This TCP connection **is captured by WinDivert**
(`tcp.DstPort == 443`), but it is **encrypted**: anyproxy can only sniff the SNI (e.g. `dns.google`) and proxy-forward it as-is,
**cannot see or change the domain queried inside**. And `hijackDNS` only knows plaintext UDP/53. So:

- The system hosts is bypassed (DoH does not query the local hosts);
- anyproxy's DNS-layer hijack is also bypassed (no plaintext query obtained);
- The DoH server returns the domain's **real public IP**.

> DoT (DNS over TLS, TCP/853) is the same: encrypted, does not go through UDP/53, anyproxy's DNS layer cannot intercept it.
> Document [tun-features.md](tun-features.md) Section 3 also marks this boundary.

---

## 2. Forwarding Stage: anyproxy re-queries the config once more by SNI domain

After obtaining the IP, the browser initiates TCP 80/443 to that IP, which WinDivert redirects into anyproxy's `ForwardTCP`
([`proto/forward.go`](../proto/forward.go)). Here it **sniffs the domain from the first packet** (TLS SNI / HTTP Host),
then before the handshake uses `findHost(dstName, dstIP)` to re-query the config. The core logic is in
[`proto/tunnel.go`](../proto/tunnel.go)'s `handshake`:

```go
host := findHost(dstName, dstIP)   // match the configured hosts by sniffed domain or dstIP
...
if host.IP != "" {
    dstIP = host.IP                        // ← ip configured, override the IP resolved in the previous step
} else if dstName != "" && confDNS != "remote" && !s.req.TUN {
    dstIP, state = s.lookup(dstName, dstIP) // ← local DNS re-resolution: TUN traffic does not reach here
}
```

Two key rules:

- **`host.IP != ""`: unconditionally override the target IP with the configured ip.** This step does not distinguish the source; the real IP obtained via DoH
  is changed back to the configured value here.
- **The local DNS re-resolution branch has a `!s.req.TUN` gate.** A TUN connection has `req.TUN == true`
  (set `TUN: true` when `ForwardTCP` builds the `Request` in [`proto/forward.go`](../proto/forward.go)),
  **so the branch is skipped** — even with `dns: local` configured it will not re-resolve. Reason: the TUN target IP is pinned by the kernel routing,
  re-resolving by domain may yield an IP inconsistent with the client and cause errors instead; a resolution timeout would also hang pointlessly.

### Which IP does it finally connect to in the DoH scenario (key conclusion)

Even if DoH bypassed everything in the resolution stage and obtained the real public IP, **the forwarding stage still re-queries the config by SNI domain**:

| This domain is in anyproxy's config hosts | Final connected IP |
|---|---|
| `ip:` configured | **the configured ip** (overrides the DoH result, i.e. DoH queried for nothing) |
| only `dns: local` configured (no `ip:`) | **DoH's real IP** (TUN does not re-resolve, `dns: local` has no effect on TUN) |
| nothing configured | **DoH's real IP** |

So: **to force a domain to a specified IP in the DoH scenario, the only reliable means is to explicitly configure `ip:` for it**; relying on `dns: local` or
on the local hosts does not work.

### Prerequisite: the SNI domain must be sniffable

`findHost` needs the domain from SNI/Host to match a `name` rule. If the domain cannot be sniffed (**ECH-encrypted ClientHello**,
non-TLS/HTTP protocol, server-speaks-first protocol, etc.), `dstName` is empty and `findHost` degrades to **matching by dstIP** —
a `name`-based rule will not match, `host.IP` will not take effect, and it connects directly using the IP at hand (DoH's real IP).

> Fallback: when `dstName` is empty, `ForwardTCP` first reverse-looks-up the domain in the DNS hijack records by dstIP
> (`cache.SniffName.Lookup`). But that record is only written **when plaintext UDP/53 is hijacked**; the DoH path does not write it, so it cannot be recovered.

---

## 3. Exceptions to Note: These Targets Never Enter Forwarding (Direct)

The "re-query config by SNI in the forwarding stage, `host.IP` override" described in the first two sections has a big prerequisite — **this TCP must first be redirected into anyproxy by WinDivert**.
But several categories of targets are judged as direct at the **capture stage** (`isDirect` / `shouldRedirect`,
[`tun/wdengine/redirect.go`](../tun/wdengine/redirect.go)) and **never enter the engine**,
so the SNI re-query, `host.IP` override, and proxy routing **all do not happen**, and the client connects directly to that IP:

| Exception | Judgment | Default |
|------|------|------|
| **Private/LAN/link-local IP** | `BypassPrivate && isPrivateOrLinkLocal(dstIP)` | **default true** on Windows |
| **loopback** (`127.0.0.0/8`, `::1`) | `dstIP.IsLoopback()` | always direct, cannot be disabled |
| **SkipPorts** (configured skipped ports) | `containsPort(SkipPorts, dstPort)` | per config |
| **tun.bypassIPs** (`ExcludeIPs`) | `isExcludedIP(dstIP)` | per config (e.g. upstream proxy / VPN endpoint IP) |
| **anyproxy's own egress** (egress source-port range / guard) | escape, prevents self-loop | automatic |

### ⚠️ `BypassPrivate` is on by default and is the easiest to trip over

On Windows `tun.windows.bypassPrivate` **defaults to `true` if not configured**
([`tun/tun_windows.go`](../tun/tun_windows.go), [`utils/conf/router.go`](../utils/conf/router.go)):
any target that is a **private/LAN/link-local address (including VM subnets) is always direct and does not enter the engine**.

This collides frequently with "hosts hijacking intranet domains":

- If you configure domain A's `ip:` as a **private address** (common for intranet services), after the client resolves to that private IP and initiates TCP,
  **it is judged direct at the capture stage** — it does not go through anyproxy, so there is no "re-query by SNI / `target=remote` go via proxy".
  Wanting the intranet domain to reach the intranet service directly is the expected behavior; but **if the intent was to send it through the upstream proxy, this default rule blocks it**.
- When you need private targets to also enter the engine and be processed by router rules, explicitly configure `tun.windows.bypassPrivate: false`
  (then private 80/443 enters the engine; loopback still always direct).

> Note the difference from Section 2: the `host.IP` override happens in the **forwarding stage** (already in the engine); the `BypassPrivate` direct connection happens
> in the **capture stage** (not yet in the engine). The former can rewrite the IP; the latter directly lets the connection bypass anyproxy.

### This exception generally does not trigger in the DoH scenario

DoH obtains a **real public IP** (not private), so `BypassPrivate` usually does not apply to DoH results — DoH's TCP
still enters the engine and is still re-queried by SNI. `BypassPrivate` mainly affects scenarios that **resolve to a private IP**
(system hosts / configured hosts with a private ip / plaintext DNS resolving to intranet).

---

## 4. One Table to See It All

Assume domain A:

| Client resolution method | A in system hosts | A has `ip:` in config hosts | IP obtained by resolution | Final connected IP in anyproxy forwarding |
|---|---|---|---|---|
| Plaintext UDP/53 | yes | — | system hosts' IP | if config also has `ip`, change to config ip; otherwise system hosts' IP |
| Plaintext UDP/53 | no | yes | **config ip** (DNS hijack returns directly) | config ip |
| Plaintext UDP/53 | no | no | real DNS's IP | real IP (TUN does not re-resolve) |
| DoH/DoT | yes | yes | real public IP (hosts bypassed) | **config ip** (SNI re-query override) |
| DoH/DoT | yes | no | real public IP | real IP (system hosts also cannot recover) |
| DoH/DoT + ECH | — | yes | real public IP | real IP (SNI not sniffable, `host.IP` cannot match) |

> The "Final connected IP in forwarding" column **assumes the connection entered the engine**. If **the resolved IP is private/LAN** (Windows default
> `BypassPrivate=true`), it is direct at the capture stage and does not enter the engine, so this column does not apply — it connects directly to the resolved private IP (see Section 3).

One sentence: **resolution is resolution, forwarding is forwarding**. DoH can bypass the system hosts and anyproxy's UDP hijack at the resolution layer,
but as long as the SNI is sniffable and the domain has `ip:` in config, the forwarding layer changes the IP back; `dns: local` has no effect on TUN traffic.
Going further back, private/LAN targets are direct at the capture stage by default and never enter the engine (`BypassPrivate`).

---

## 5. Blackhole Sentinel IP: Solving the "System hosts + Proxy" Coexistence Problem

The previous sections exposed a dilemma: you want to use **hosts to block a domain locally**, but once the proxy is on, you also want this domain to **be accessible normally through the proxy**.
Hardcoding a single IP cannot do both. The **blackhole sentinel IP** (default `192.0.0.0`) is the solution — point the domain at it:

```
# hosts: C:\Windows\System32\drivers\etc\hosts or /etc/hosts
192.0.0.0 example.com
```

- **Proxy off**: `192.0.0.0` is not routable → connecting to it must fail → the domain is blocked locally on the machine.
- **anyproxy on (tun/WinDivert)**: the connection is intercepted into the engine → the real domain is restored from SNI/Host → forced
  `target=remote`+`dns=remote` → the downstream proxy resolves the real IP and connects out → normal access.

Key point: **detection relies on `dstIP` (the sentinel is always the destination the browser actually connects to), and SNI is only used to restore the real domain for the downstream resolver**;
the sentinel **must use `192.0.0.0`** — using `127.0.0.1` (loopback does not enter TUN) or a private address (may be bypassed) will not work.

> 📖 Full topic (motivation, two-stage principle, config, cross-platform, examples, troubleshooting FAQ) is in
> **[blackhole-sentinel.md](blackhole-sentinel.md)**.

## Related Documents

- [blackhole-sentinel.md](blackhole-sentinel.md) — **Blackhole Sentinel IP topic**: one sentinel IP simultaneously achieves "local block when no proxy" + "remote downstream resolution access when proxy is on".

- [tun-features.md](tun-features.md) — TUN feature overview, DNS hijack and `blockQUIC` (QUIC/UDP443 drop for domains with `ip` configured).
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — the WinDivert capture→NAT→local proxy→restore destination forwarding chain.
- [routing.md](routing.md) — semantics and priority of routing fields such as `target`/`proxy`/`dns`/`ip`.
