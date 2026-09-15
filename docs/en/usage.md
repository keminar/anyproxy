# Client access and usage

anyproxy has three ways to "hand traffic to it". The first two use the same listening port under `mode: proxy` (default); the third is global capture.

## 1. Explicit proxy (same-port HTTP + SOCKS5, auto-detected)

On the listening port (default `:3000`), anyproxy **auto-detects the protocol per first packet** ([proto/request.go](../proto/request.go)):

1. **HTTP proxy**: recognizes standard methods (`GET/POST/PUT/HEAD/OPTIONS/DELETE/TRACE` and `CONNECT`). HTTPS goes via `CONNECT` tunnel.
2. **SOCKS5 proxy**: recognizes the SOCKS5 handshake.
3. Neither → fall back to **raw TCP** (for transparent proxy/TUN, see below).

In other words, **the same `:3000` is both an HTTP proxy and a SOCKS5 proxy**; clients just pick whichever they need.

### How to point the client at it

```bash
# Environment variables (common to most CLI tools)
export http_proxy=http://127.0.0.1:3000
export https_proxy=http://127.0.0.1:3000
export all_proxy=socks5://127.0.0.1:3000

# curl (HTTP proxy / SOCKS5 proxy, pick one)
curl -x http://127.0.0.1:3000   https://example.com
curl -x socks5://127.0.0.1:3000 https://example.com

# git
git config --global http.proxy http://127.0.0.1:3000

# Docker pull official images (configure proxy for dockerd, or use env vars)
# See README use case 1
```

Browser/system proxy: point the HTTP(S) proxy or SOCKS5 proxy at `127.0.0.1:3000` (Chrome can use a plugin like SwitchyOmega to switch by domain).

> Access control: inbound is constrained by `allowIP` (global) and `hosts[].allowIP` (per domain), see [routing.md](routing.md#allowip-access-control). Local loopback and TUN's own traffic are allowed by default.

### HTTP/1.1 keep-alive multi-domain reuse

On one HTTP keep-alive connection, a client may send multiple requests for **different domains** (common in browsers/IE). anyproxy routes each request by its actual target, rather than pinning the whole connection to the first domain ([proto/keep.go](../proto/keep.go), [proto/http.go](../proto/http.go)).

## 2. Transparent proxy (Linux iptables)

Without changing client config, use iptables to REDIRECT the host's outbound traffic to anyproxy's listening port; anyproxy gets the real target from `SO_ORIGINAL_DST` and sniffs the first packet's TLS SNI / HTTP Host to recover the domain. Config see [deployment.md](deployment.md#linux-iptables-global-proxy).

## 3. Global capture (TUN / WinDivert)

`mode: tun`: Linux/macOS create a TUN virtual NIC, Windows uses WinDivert network-layer redirect, capturing almost all TCP. No per-client config needed. See [tun-features.md](tun-features.md), [windows-winDivert.md](windows-winDivert.md).

## Which to choose?

| method | client config needed? | suitable for |
|------|----------------|------|
| Explicit proxy (HTTP/SOCKS5) | yes (point at `:3000`) | single app/browser, container, CLI tool |
| Transparent proxy (iptables) | no | whole Linux server / one user's outbound |
| Global (TUN/WinDivert) | no | whole desktop global proxy (needs admin/root) |

All three methods hit the same `default`/`hosts` routing rules ([routing.md](routing.md), [proxy-decision.md](proxy-decision.md)), with consistent behavior.
