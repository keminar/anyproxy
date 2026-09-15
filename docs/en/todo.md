# Todo / pending confirmation

Source: code review before merging PR #22 (todo → master). The following are review findings that were **not handled in that pass and are waiting for confirmation before changing**. Each gives location, impact, suggested fix and current status.

> Handled review items are not listed here (e.g. sniffing timeout tiering, `-mode` help adding `tcpcopy`, etc. already changed).

---

## 1. Transparent proxy (iptables) path first-packet sniffing: `Peek(1)` has no read timeout

- **Location**: [proto/stream.go](../proto/stream.go) `sniffPeekDomain` (the `r.Peek(1)` line, ~line 47)
- **Impact (correctness)**: the first `r.Peek(1)` in `sniffPeekDomain` **has no read timeout** (the timeout is only set after confirming it's TLS `0x16`). If iptables redirects a "server-speaks-first" protocol (SSH:22 / SMTP:25 / MySQL:3306 / IMAP, etc.) on **all ports** to anyproxy, the client waits for the server banner and doesn't send data first, so `Peek(1)` blocks forever and the proxy never dials the backend → **connection hangs**.
  - Narrow trigger surface: documented iptables only redirects 80/443 (client-speaks-first), so normal deployments don't hit it; only "all-port transparent proxy + server-speaks-first protocol" triggers it.
- **Suggested fix**: follow the TUN path's [proto/forward.go](../proto/forward.go) `sniffClientHead` — **`SetReadDeadline` before reading**, fall back to IP forwarding on timeout. See item 2's unified approach below, which solves both at once.
- **Status**: pending confirmation.

---

## 2. Two first-packet sniffing implementations diverged; the `bufio` variant is fragile

- **Location**: [proto/stream.go](../proto/stream.go) `sniffPeekDomain` (bufio `Peek` variant) vs [proto/forward.go](../proto/forward.go) `sniffClientHead` (read into buffer then re-send, robust)
- **Impact (architecture/correctness)**: the same "sniff first packet for SNI/Host" feature has two implementations:
  - TUN path `forward.go`: set timeout first → `Read` the first packet → then **re-send** the first packet to the server. Robust.
  - Transparent path `stream.go`: `Peek` on the shared `bufio.Reader`, and the timeout is "postponed".
  - Besides the blocking in item 1, there's another hazard: on ClientHello fragmentation/slowness the `Peek` times out and caches an i/o timeout error inside the `bufio.Reader`; later, the first real read of forwarded data returns it once, which may **harm the connection**.
  - Also, the transparent path hasn't gotten the target port yet during sniffing (the port comes later from `GetOriginalDstAddr`), so it can't use a long timeout for 80/443 like the TUN path — 443 sniffing is currently fixed at 200ms.
- **Suggested fix**: unify `stream.go`'s sniffing to `forward.go`'s "set timeout first → read first packet → re-send" approach. One change removes both item 1 (blocking) and this item (bufio cached error + implementation fork), and lets the transparent path also use long/short timeouts per port.
- **Status**: pending confirmation (relatively large change, touching the transparent path's read/re-send timing).

---

## 3. `HostBlocksUDP` linearly scans hosts on the QUIC hot path

- **Location**: [utils/dnsutil/dns.go](../utils/dnsutil/dns.go) `HostBlocksUDP` (~line 189); call site [tun/wdengine/redirect.go](../tun/wdengine/redirect.go) `process()` (~line 216)
- **Impact (efficiency)**: every outbound UDP/443 packet **linearly iterates** `conf.RouterConfig.Hosts` doing string comparison, to decide whether to drop that QUIC. With a large hosts list + dense QUIC traffic, this is per-packet overhead on the capture fast path.
- **Suggested fix**: at startup/config hot reload, pre-build a `map[string]struct{}` (the set of IPs of hosts configured with `ip`), and change `HostBlocksUDP` to O(1) lookup.
- **Status**: pending confirmation (performance optimization, not a functional issue; negligible impact when hosts is small).

---

## Remarks

- Items 1 and 2 are essentially the same code (the transparent proxy path's sniffing); suggested to merge into one change.
- After confirming which to change, remove the corresponding entries from this file.
