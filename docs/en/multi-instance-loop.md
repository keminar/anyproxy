# Same-host multiple-instance loop protection

This document explains the cause, root fix, and fallback for the infinite loop when two anyproxy instances are deployed on the same host.

## Scenario and cause

Deploying two anyproxy instances on the same host:

- **A**: runs `mode=tun`, acts as global proxy, forwards requests to upstream B
- **B**: normal mode, acts as egress

```
Client ──▶ A(TUN global proxy) ──▶ B(egress) ──▶ Internet
                 ▲                          │
                 └──── B's outbound re-captured by A's TUN ─┘   ← infinite loop
```

A's TUN sucks in all traffic of `0.0.0.0/1` and `128.0.0.0/1`. A's own outbound already escapes the
TUN by binding the physical network interface, but **B's outbound traffic didn't escape**, gets re-captured by A's TUN → A → B → … infinite loop, fds keep piling up.

> Same-host source IPs are identical, so you can't distinguish B's traffic by "source IP=B" or `ip rule from`; and HTTPS/CONNECT can't stuff
> a loop-detection header. So the same-host scenario can only rely on the two layers below.

## First layer (root fix): B uses mode=bypass (Linux only)

Run B with `mode=bypass`; B's outbound connections bind the physical network interface and escape A's TUN route, root-fixing the loop at the routing layer.
**bypass mode is Linux only**; macOS/Windows have removed it (see "Platform differences" at the end).

```yaml
# B's conf/router.yaml
mode: bypass
tun:
  linux:
    # manually specify if auto-detection can't find a physical NIC
    device: eth0
```

**Be sure to check B's startup log**:

```
bypass-only: device="eth0" ip="192.168.1.10" exclude=[...]
```

`device` and `ip` non-empty means bypass is active. If empty, auto-detection failed and bypass will **silently fall back to normal dialing and fail**,
so you must manually specify the NIC name with `tun.linux.device`.

## Second layer (fallback): loopGuard circuit breaker

As a last line of defense, it prevents bypass failure from exhausting the machine's fds. The judgment is based on the **in-flight connection ratio**, not requests per second:

- **Cheap gate**: checks are enabled only once the whole process's in-flight connection count reaches `minActive`; normally it's just one `int` comparison, zero extra cost
- **Ratio judgment**: once the gate is open, if some `host:port`'s in-flight connections exceed `total * ratio%` (fds all piled on one target = loop signature), reject its new connections
- **Self-heal**: after rejecting new connections, upstream B's connections to that target fail because A rejects them, the loop unwinds, in-flight connections drain, and the gate automatically re-opens — no breaker timer needed

```yaml
loopGuard:
  minActive: 1000  # ratio check enabled only when global in-flight connections reach this; 0=built-in default 1000 (on by default); <0=off
  ratio: 80        # percentage threshold for a single target's share of global in-flight connections (e.g. 80=80%); <=0 uses default 80
```

When triggered, the log looks like:

```
loopguard: circuit open for example.com:443 (in-flight 960/1000, suspected proxy loop)
```

loopGuard is a fallback, not the main solution — the loop's root fix still depends on B's `mode=bypass` actually taking effect.

### Relationship between minActive and ulimit -n (important)

In a loop, traffic is almost 100% concentrated on one target, so the loop is cut **right when the global in-flight count just crosses `minActive`** —
`minActive` roughly equals "the maximum in-flight connections piled up before the loop is cut". Each proxy connection takes about **2 file descriptors**
(client side + upstream side), so:

> **`minActive × 2` must be far smaller than `ulimit -n`**, otherwise the process hits `too many open files` first,
> and the circuit breaker never gets a chance to trigger — becoming useless.

- anyproxy recommends `ulimit -n 65535` (see `-h` help). Under this premise the default `minActive=1000` (~2000 fds) leaves ample headroom,
  and raises the false-positive threshold to "single-target concurrency 800", so normal bulk downloads/crawling rarely trigger it.
- **If ulimit is still the default 1024**: `minActive=1000` will exhaust fds at ~512 concurrency, so be sure to lower `minActive`
  (e.g. to 200), or first raise ulimit as recommended.

## Platform differences

### loopGuard — identical across all three platforms

`proto/loopguard.go` is pure Go, no build tags, no syscalls, and its mount points are also cross-platform files. Windows / Mac /
Linux behave identically and are on by default.

(`transferConn` is the TUN path; Mac can't create a TUN NIC so it's not reached; but the normal proxy path `transfer` still counts,
so loopGuard still works on Mac.)

### bypass — Linux only; macOS/Windows removed

| Platform | bypass mode | Alternative |
|------|------------|----------|
| **Linux** | ✅ supported. `SO_BINDTODEVICE` hard-binds by NIC name, most reliable; auto-detects `ip route show default` | — |
| **macOS** | ❌ removed | inbound service reply packets sucked into TUN → `mode=tun` + `tun.inboundPorts` (pf reply-to) |
| **Windows** | ❌ removed | WinDivert model has no 0/1 route concept; escape relies on the TUN process's `tun.windows.excludeProcs`/`bypassIPs` + egress source-port segment (see [windows-windivert-escape.md](windows-windivert-escape.md)) |

> On Linux, if auto-detection fails (`bypass-only: device=""`), use `tun.linux.device` to specify the NIC name manually.
> Also, on Windows/macOS B's (anyproxy process) outbound is still captured/routed by A: on macOS without 0/1 routes it doesn't apply;
> on Windows B's outbound is naturally released by A via the egress source-port segment (when both are anyproxy), so no bypass mode is needed.

## Configuration quick reference

| Config item | Default | Notes |
|--------|------|------|
| `mode` | `proxy` | `proxy` / `tunnel` / `tun` / `bypass` (bypass Linux only) / `tcpcopy`; same-host A uses tun, B uses bypass |
| `tun.linux.device` | empty (auto-detect) | manually specify physical NIC name (Linux only, mode=bypass) |
| `tun.linux.excludeNics` | platform default TUN name | NIC names excluded when collecting direct subnets (Linux only, mode=bypass) |
| `loopGuard.minActive` | 1000 | in-flight connection gate; `<0` to disable |
| `loopGuard.ratio` | 80 | single-target ratio threshold (%) |
