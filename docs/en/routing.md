# Routing and Proxy Rules

This page explains how anyproxy decides the egress for a connection. The core logic is in the handshake stage of `proto/tunnel.go`.

## Matching Flow

1. Obtain the target domain (a normal request has it directly; transparent proxy/TUN sniffs TLS SNI / HTTP Host from the first packet; if it cannot be sniffed, use the IP).
2. Traverse `hosts` in order, comparing the domain against each entry's `name` using that entry's `match` method; **the first match** is adopted as the rule.
3. If no `hosts` match, use `default`.
4. Use the matched rule's `target` / `proxy` / `dns` / `ip` / `port` to decide the egress.

## Domain Comparison Methods

It is recommended to use a leading/trailing `*` wildcard in `name`, with no need to configure `match` (the part without the star is denoted X):

| `name` form | Meaning | Example (X=`google.com`) |
|----|------|------|
| `google.com` | exact equality | only `google.com` |
| `*google.com` | suffix match | `www.google.com` matches; `www.google.com.hk` does not |
| `google.com*` | prefix match | `google.com` / `google.com.hk` match; `www.google.com` does not |
| `*google.com*` | substring contain | any position containing `google.com` matches |

> YAML values starting with `*` must be quoted, e.g. `name: "*google.com"`.

`name` also supports matching by **geo dataset** (requires `geo.ip` / `geo.site` to load `.dat`; see [geo.md](geo.md) for details):

| `name` form | Meaning |
|----|------|
| `geoip:cn` | target **IP** matches geoip category `cn` |
| `geosite:cn` | target **domain** matches geosite category `cn` (uses only Domain suffix + Full exact, drops keyword/regex) |

You can also write `match` explicitly (legacy form, `name` is taken literally without parsing stars, for compatibility with existing configs):

| `match` | Meaning |
|----|------|
| `contain` | domain contains the `name` keyword |
| `equal` | domain exactly equals `name` |

Priority: explicit `match` > `name` leading/trailing `*` > `default.match` > `equal`.
`hosts[].match` and `name` both without stars use `default.match` (default `equal`).

## target (egress policy)

HTTP uses `hosts[].target` (falls back to `default.target`, default `auto`); plain TCP uses `default.tcpTarget` (default `remote`).

| Value | Meaning |
|----|------|
| `local` | local direct connection (egress from current environment). **Highest priority** — direct even if `proxy` is configured |
| `remote` | go via proxy (global proxy or this entry's `proxy`) |
| `auto` | dial local first; if it connects, use local; if not, fall back to remote (and force remote DNS). Suitable for "IP not pingable" optimization |
| `deny` | abort the request, forbid access |
| `localport` | only usable for `tcpTarget`: ports matching `default.localPort` go local direct, the rest go via proxy |

### Details of auto

`auto` is **local-preferred**: dial local first (2s timeout); if it connects, reuse that connection and go local; if not, switch to remote (and force remote DNS), and mark the domain as "direct failed" with a **short 20s cache** (subsequent requests within the window skip direct and go via proxy directly; after expiry it retries direct to recover). Some "IP reachable but no data received" cases cannot be judged by auto and must be written explicitly as `remote` in the rule.

> The **full decision logic** for `target` with `proxy`, multiple proxies, and `local`/`deny` fallback is in [proxy-decision.md](proxy-decision.md).

### Default ports for localport

When `tcpTarget: localport` and `default.localPort` is not configured, the default local-direct ports are **21(ftp) / 22(ssh)**. Once `localPort` is configured, it is taken entirely as configured (overrides, does not append).

```yaml
default:
  tcpTarget: localport
  localPort:
    - 22
    - 3306
```

## dns (resolution source)

| Value | Meaning |
|----|------|
| `local` | resolve using the local machine DNS (default) |
| `remote` | resolved by the remote proxy end. **Only valid when `target=remote`** |

Use: the IP resolved locally for some domains is unreachable; switch to remote DNS to obtain a proxy-reachable IP.

> The TUN connection's target IP is already determined by kernel routing, so it is not re-resolved locally.

## ip (replace IP)

When `hosts[].ip` is non-empty, it forcibly replaces the target IP with that value, equivalent to a local hosts binding. Used when the locally resolved IP is unreachable and remote DNS is unavailable, to specify manually:

```yaml
hosts:
  - name: golang.org
    match: contain
    ip: 216.239.37.1   # locally resolved 180.97.235.30 is unreachable, manually switch to a reachable IP
```

> `ip` is also the decision basis for `blockQUIC` in TUN mode: domains with `ip` configured have their UDP443 (QUIC) dropped to force the client to fall back to TCP. See [tun-features.md](tun-features.md).

## port (replace port)

`hosts[].port` is a `{from, to}` list; when the target port equals a `from`, rewrite it to the corresponding `to`:

```yaml
hosts:
  - name: dev.example.com
    ip: 127.0.0.1
    port:
      - from: 80
        to: 88
```

## proxy field

Specifies which proxy this rule uses, overriding the global proxy. Three protocols are supported; **without a `://` prefix it defaults to `tunnel://`**:

- `tunnel://host:port` (default)
- `socks5://host:port`
- `http://host:port`

### Multiple proxies and suffix operations

- **Comma-separated multiple proxies**: take the first reachable one in order:
  ```yaml
  proxy: http://127.0.0.1:8888, http://127.0.0.1:7777
  ```
- **Suffix `local`**: when all custom proxies are unreachable, go local direct (clear the proxy):
  ```yaml
  proxy: http://127.0.0.1:8888, http://127.0.0.1:7777 local
  ```
- **Suffix `deny`**: abort the request when all are unreachable:
  ```yaml
  proxy: http://127.0.0.1:8888 deny
  ```

> The global proxy (`default.proxy` and command-line `-p`) also supports the identical "multiple proxies + `local`/`deny` suffix" syntax.
> A normal single-proxy global proxy takes the no-probe fast path; once configured as multiple proxies or with a suffix, each request selects by reachability (including a 200ms dial probe), consistent with per-domain `proxy` behavior.
>
> **Each proxy selection is probed live and does not cache unavailability**: every proxy selection does a 200ms dial probe once, and a down proxy is still probed next time. The benefit is that **after a proxy restarts and recovers, the next request is immediately usable** and is not blocked by an old failure cache with no response; the cost is that while a proxy is down for a long time, each request spends up to 200ms probing. See [caching.md](caching.md) and [proxy-decision.md](proxy-decision.md).

### Priority between target and proxy

| target | proxy | Result |
|--------|-------|------|
| `local` | present | **local direct connection**, proxy is ignored (explicit local has highest priority) |
| `remote` | present | use this custom proxy |
| `auto` | usable proxy present | **try direct first**, fall back to this proxy if direct fails (local preferred) |
| `remote`/`auto` | absent | use global proxy / auto selection |
| `deny` | — | abort the request |

Key point: `auto`, whether the proxy is configured on the host or globally, is "try direct first, go via proxy if it fails", and will not force the proxy just because a proxy is configured; to force the proxy use `target: remote`. The `proxy` field only answers "which proxy to use when going via proxy".

## allowIP (access control)

- Top-level `allowIP`: globally allowed client IPs (empty = no restriction), supports CIDR.
- `hosts[].allowIP`: restricts which client IPs can access this domain.

## A Comprehensive Example

```yaml
default:
  dns: local
  target: auto        # HTTP default auto
  tcpTarget: remote   # plain TCP default via proxy
  match: equal
  proxy:              # global proxy left empty

hosts:
  # go via local 8888 proxy, direct if unreachable
  - name: github
    match: contain
    target: remote
    dns: remote
    proxy: http://127.0.0.1:8888 local

  # dial succeeds → local, fails → remote
  - name: golang.org
    match: contain
    target: auto
    dns: remote

  # directly forbid
  - name: google
    match: contain
    target: deny

  # replace IP + replace port, only allow a specific client
  - name: dev.example.com
    ip: 127.0.0.1
    port:
      - from: 80
        to: 88
    allowIP:
      - 172.17.0.12
```
