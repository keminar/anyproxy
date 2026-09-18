# Blackhole sentinel IP topic

> A single sentinel IP solves both the seemingly contradictory needs of
> "**locally block a domain when no proxy is on**" and "**still access that domain normally when the anyproxy proxy is on**".

## 1. The problem to solve

Using **system hosts** to block a domain is the easiest approach — point `example.com` to an unreachable address and the browser can't open it.
But once anyproxy's global proxy is on (TUN / Windows WinDivert), you often want **this very domain to be accessible via the proxy**
(e.g. it's polluted/blocked on the local network and only reachable through a downstream proxy).

Writing a fixed IP in hosts can't satisfy both:

| hosts entry | proxy off | proxy on |
|---|---|---|
| **Real public IP** | connects (not blocked) | connects, but bypasses the "route by domain to proxy" intent |
| **Fake IP** (e.g. `192.0.2.10`) | can't connect (blocked ✓) | the proxy **dials this fake IP directly** and also fails ✗ |
| **`127.0.0.1`** | connects to localhost (not blocking, weird behavior) | loopback **never enters the proxy**, connects to local port 80 ✗ |

The **blackhole sentinel IP** is designed for this dilemma: point the domain to an **unroutable sentinel address** (default `192.0.0.0`),
once anyproxy detects "the target is a sentinel", it doesn't dial it directly but **recovers the real domain from the traffic and forces it to the downstream proxy for remote resolution**.

## 2. TL;DR

```
# system hosts (C:\Windows\System32\drivers\etc\hosts or /etc/hosts)
192.0.0.0 example.com
```

- **anyproxy proxy off**: `192.0.0.0` is unroutable → connecting to it inevitably fails → `example.com` is blocked locally.
- **anyproxy on (tun / WinDivert, no system proxy set)**: the connection is intercepted into the engine → recovered from SNI/Host
  `example.com` → **enforced `target=remote` + `dns=remote`** → downstream proxy resolves the real IP and connects out → normal access.
- Works out of the box (the default `default.blackholeIP` is already `192.0.0.0`); the "accessible" effect only appears when a downstream proxy is configured,
  with no downstream proxy it's pure blocking.

## 3. Configuration

The only switch is `default.blackholeIP`:

```yaml
default:
  # blackhole sentinel IP; if unset defaults to 192.0.0.0; set off/none/disable to disable
  #blackholeIP: 192.0.0.0
```

- **Unset = default `192.0.0.0`** (feature on by default, but only triggers when traffic actually targets that IP; no effect otherwise).
- Can be changed to another sentinel address (must meet the "routable into the engine" condition in section 4).
- Set `off` / `none` / `disable` to fully disable.

A sentinel can come from **two places**, with consistent semantics and mixable:

| Source | Form | Traits |
|---|---|---|
| **System hosts** | `192.0.0.0 example.com` | simplest; but a **DoH client doesn't consult hosts**, so it's ineffective (see section 7) |
| **anyproxy config hosts** | `- name: example.com` + `ip: 192.0.0.0` | goes through anyproxy's DNS-layer hijack, **also effective for DoH**; can also be covered by `blockQUIC` |

## 4. Why the sentinel must be 192.0.0.0 (can't use 127.0.0.1 / private networks)

The prerequisite for a sentinel to work is that **the target IP is routed into the TUN / captured by the engine**. This is the easiest pitfall:

- **`127.0.0.1` (loopback) — cannot be intercepted.** The kernel uses the built-in route `127.0.0.0/8 dev lo` (/8) to send it to loopback,
  which is **more specific and always takes priority** over the TUN autoRoute `0.0.0.0/1` + `128.0.0.0/1` (/1), and the kernel specifically routes 127/8 only to lo,
  never outside. As a result **the packet never enters the TUN**, anyproxy can't see it and logs nothing; and no one listens on local `127.0.0.1:80`,
  so it immediately gets `Connection refused`. Typical symptom: `curl` fails in **a few milliseconds** (via TUN through proxy it should be tens to hundreds of ms).
- **Private/LAN (`10.x` / `192.168.x` / `172.16.x`, etc.) — unstable.** Windows defaults to `bypassPrivate=true`
  which goes direct at capture stage and doesn't enter the engine; on Linux, if the address falls within a local directly-connected subnet it's also bypassed.
- **`192.0.0.0` — the correct choice.** It's an IANA special-use address (IETF Protocol Assignments), won't collide with a real business target,
  and is unroutable; it falls in `128.0.0.0/1` so gets routed into the TUN; under WinDivert the sentinel rule forces it into the engine.

| Sentinel candidate | Enters TUN/engine? | Conclusion |
|---|---|---|
| `127.0.0.1` (loopback) | ❌ goes to lo, not TUN | can't capture, refuses in seconds |
| `10.x` / `192.168.x` (private) | △ may be bypassed direct | unstable |
| **`192.0.0.0`** | ✅ enters TUN; WinDivert forces into engine | **correct (default)** |

## 5. How it works (two stages)

```
Browser → example.com (hosts→192.0.0.0) → TCP 192.0.0.0:443
      → [capture stage] TUN/WinDivert intercepts (sentinel forced into engine)
      → [forward stage] anyproxy sniffs SNI=example.com → enforces remote+remote
      → downstream proxy resolves real IP by domain → connects
```

### Capture stage: force into engine

- **Windows (WinDivert)**: the `isDirect` in [`tun/wdengine/redirect.go`](../tun/wdengine/redirect.go) marks the sentinel IP
  as **must enter the engine**, **unaffected by `bypassPrivate` / `SkipPorts`** (even if someone configures the sentinel as a private address it's still intercepted).
- **Linux / macOS (gVisor)**: the sentinel is a normal routable address; autoRoute's `0/1`+`128/1` already imports it into the TUN,
  so it naturally enters the stack, no extra handling needed.

### Forward stage: enforce remote + remote (shared across all three platforms)

The `handshake` in [`proto/tunnel.go`](../proto/tunnel.go): when **destination IP == sentinel** it's judged a blackhole connection,
**enforcing `target=remote` + `dns=remote`** — never dialing `192.0.0.0` directly, but handing the **domain** to the downstream proxy,
which resolves the real IP remotely and connects out.

> **Detection relies on `dstIP`, not SNI.** The sentinel IP is the **actual destination the browser connects to** (hosts resolves `example.com` to
> `192.0.0.0`, so the browser initiates a connection to `192.0.0.0`); after capture and reconstruction `dstIP` is exactly that — this signal is **always present**,
> judging blackhole doesn't need SNI. SNI is an **independent secondary signal**, used only to reconstruct "which real domain is behind it", so the domain can be handed to the downstream
> proxy for remote resolution (`192.0.0.0` itself can't be dialed or reverse-looked-up — multiple domains can point to the same sentinel, so reverse lookup is ambiguous).

| What to determine | Signal source | Always present? |
|---|---|---|
| Is it a blackhole connection | `dstIP` (from kernel routing / capture) | **Always** |
| The real domain behind it | SNI / Host first packet | May be un-sniffable (ECH, non-TLS, no first packet) |

This also explains why anyproxy's gVisor (Linux/macOS) path works the same: TCP connections are handed by
[`tun/stack.go`](../tun/stack.go) `handleTCP` to the shared `proto.ForwardTCP` (`TUN=true`),
which goes through exactly the same `handshake` blackhole judgment.

## 6. Complete examples

### Example A: Windows + system hosts (most common)

```
# C:\Windows\System32\drivers\etc\hosts
192.0.0.0 blocked-but-proxyable.com
```

```yaml
# router.yaml
mode: tun            # Windows uses WinDivert
default:
  proxy: socks5://127.0.0.1:1080   # downstream proxy (resolves and accesses the target)
  #blackholeIP: 192.0.0.0          # defaults to this, can be omitted
```

- Without anyproxy running: the browser can't open the domain (blocked).
- After starting: the domain is normally accessed via the `127.0.0.1:1080` downstream proxy; the log shows `blackhole ip 192.0.0.0 -> force remote dns for ...`.

### Example B: config hosts (also effective for DoH clients)

```yaml
# router.yaml
default:
  proxy: socks5://127.0.0.1:1080
hosts:
  - name: blocked-but-proxyable.com
    ip: 192.0.0.0        # DNS-layer hijack into sentinel; same effect as system hosts, but DoH also gets the sentinel
```

## 7. Edge cases and troubleshooting (FAQ)

- **Sentinel set but domain can't be sniffed → deny.** There are real cases of "no domain even though `dstIP==192.0.0.0`": the browser has
  **ECH** (encrypted ClientHello) and still gets `192.0.0.0` from hosts and connects, but SNI is encrypted; also non-TLS/HTTP,
  non-80/443 with no first packet, etc. Here we know it's a blackhole connection but don't know which domain to have the downstream resolve, and we must never dial the sentinel directly — so we can only **deny**
  (log `blackhole ip ... but no domain to proxy`).
  - Exception: if the sentinel comes from **config hosts**, the DNS hijack has already recorded `192.0.0.0→domain` in `cache.SniffName`, so even without SNI
    it can reverse-look-up the domain and doesn't trigger denial. **Only system-hosts sentinel + no SNI** actually lands in the deny branch.
- **No usable downstream proxy → judged failed directly.** When it reaches the forward stage with still no usable proxy, it won't vainly dial `192.0.0.0` waiting for timeout,
  but fails directly (log `blackhole ip ... requires an upstream proxy`). Equivalent to "no proxy means inaccessible".
- **Explicit `deny` takes priority.** If a config rule already judges the domain as `deny`, the sentinel logic doesn't override it (still denied).
- **Port range.** Windows WinDivert capture is constrained by filter ports (default 80/443); the sentinel mainly targets web domains,
  other ports won't take effect if not included in capture.
- **DoH/DoT client + system-hosts sentinel: effect ① fails.** DoH resolution doesn't consult system hosts, so it gets the real public IP (not the sentinel),
  and the local-blocking half is gone. Countermeasure: use **config hosts** (Example B) to have the DNS layer hijack into the sentinel, or block the DoH server to force fallback to
  plaintext DNS. See [tun-dns-resolution.md](tun-dns-resolution.md).
- **"No capture log at all / `curl` refused in a few milliseconds"** — almost certainly the sentinel was written as `127.0.0.1` or a private net.
  Change it back to `192.0.0.0` (see section 4).

## Related documents

- [tun-dns-resolution.md](tun-dns-resolution.md) — Full picture of DNS resolution priority under TUN: system hosts / config hosts / DoH
  three paths, resolution stage vs forward stage, `BypassPrivate` direct exception. The blackhole sentinel is the solution to the "hosts + proxy" dilemma.
- [routing.md](routing.md) — semantics of the `target` / `dns` / `proxy` / `ip` fields (the sentinel enforces exactly `target=remote`+`dns=remote`).
- [tun-features.md](tun-features.md) — TUN feature overview, DNS hijack and `blockQUIC`.
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — WinDivert capture→NAT→local proxy→restore-destination forward chain.
