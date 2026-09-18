# Proxy decision logic (target / proxy / local / deny / auto)

This page explains the complete decision of whether a connection goes local-direct, through which proxy, or is denied.
The implementation lives in the handshake stage of `proto/tunnel.go`.

Two orthogonal dimensions:

- **`target`**: egress policy — local-direct / via proxy / auto / deny.
- **`proxy`**: which proxy to use when going via proxy (supports multiple proxies and the `local`/`deny` suffix).

`target` decides "whether / when to use a proxy"; `proxy` only answers "which proxy to use".

---

## 1. target values

HTTP uses `hosts[].target`, defaulting to `default.target`; pure TCP defaults to `default.tcpTarget`. When neither is configured, the default is `auto`.

| Value | Meaning |
|----|------|
| `local` | **Local direct** (egress from the current environment). Highest priority; any `proxy` that is set is ignored |
| `remote` | **Via proxy** (the `proxy` on that entry, or the global proxy if none). If the proxy is unavailable and there is no `local` fallback, it **errors out** instead of going direct |
| `auto` | **Local-first**: try direct first; fall back to proxy only if direct fails. Same whether the proxy is set per-host or globally |
| `deny` | **Deny** the request |
| `localport` | Only for `tcpTarget`: ports matching `default.localPort` go local, the rest go via proxy |

> Note: `proxy` is also treated as a synonym for `remote` (any value other than `local`/`auto`/`deny`/`localport` is handled as "go via proxy"). Using `remote` is recommended.

---

## 2. proxy values

Overrides the global proxy. Protocol prefixes: `tunnel://` (default; omitting the prefix means this) / `socks5://` / `http://`.

The three forms are **identical** for `default.proxy` (and command-line `-p`) and `hosts[].proxy`:

```yaml
proxy: socks5://127.0.0.1:1080                              # single proxy
proxy: http://127.0.0.1:8888, http://127.0.0.1:7777        # multiple proxies: comma-separated
proxy: http://127.0.0.1:8888, http://127.0.0.1:7777 local  # multiple proxies + fallback suffix
```

### Multiple proxies

Multiple proxies separated by commas — **probed one by one in order (200ms dial each), using the first one that connects**.

### Suffix `local` / `deny`

Written at the **end** of the whole string, controls "what to do when none of the listed proxies connect":

| Suffix | When all proxies are unavailable |
|------|------------------|
| (no suffix) | host proxy: fall back to **global proxy**; global proxy: see the "Fallback" section below |
| `local` | ignore the proxy, **go local-direct** |
| `deny` | **deny** the request |

---

## 3. Complete decision order

For each connection (already matched to a host rule or default), **route by target; the proxy is only resolved/probed on demand**:

1. `target == deny` → deny directly.
2. `target == localport` → if it hits a local port treat as `local`, otherwise as `remote`.
3. `target == local` → **local-direct; never resolves/probes the proxy at all** (also unaffected by the global proxy's `deny` suffix).
4. `target == auto` → **local-first: try direct first (2s timeout), proxy not touched yet**:
   - direct succeeds → use direct, done (proxy never probed once).
   - direct fails → record a "direct-failed" short cache (see the cache section) → downgrade to `remote`, continue to step 5.
5. `target == remote`/`proxy` (including downgraded from the previous step) → **select proxy** (see "Proxy selection flow"):
   - a usable proxy is selected → go via proxy.
   - all proxies unavailable: if there is a `local` fallback → local-direct; otherwise → **error out** (no silent direct).

> Key order: the direct attempt for `auto` happens **before proxy resolution** — if direct works, the proxy is never probed, and a hung proxy won't slow it down. Only a direct failure triggers proxy resolution/probing.

### Proxy selection flow (host first, global fallback)

```
if host.proxy is set:
    select from host.proxy using "multiple proxies + suffix":
        usable proxy selected   -> use it
        all down + suffix local -> go local-direct
        all down + suffix deny  -> deny
        all down + no suffix    -> fall back to global proxy (the part below)
else or needs fallback:
    select from global proxy (-p / default.proxy) using "multiple proxies + suffix":
        usable proxy selected   -> use it
        all down + suffix local -> go local-direct
        all down + suffix deny  -> deny
        all down + no suffix    -> no higher-level fallback
```

Key points:

- **Host proxy is tried before the global proxy**; when the host proxy matches, the global proxy is never probed (no wasted dials).
- **`auto` is always local-first**; configuring a proxy won't skip direct — to force proxy use `target: remote`.
- **Without the `local` suffix, an unreachable proxy won't silently go direct**. When `target` is to use a proxy (`remote`/`proxy`), a proxy is configured but all are down, and there is no `local` fallback → error out. To have a hung proxy fall back to local, you must explicitly write ` local`.

---

## 4. Global proxy values and hot reload

The global proxy is read **live** on each request, with priority: command-line `-p` (fixed; unchanged for the process lifetime) > config `default.proxy` (**hot-reloadable**; edits to the config file take effect immediately).

Performance: a normal **single** global proxy takes the "no-probe fast path" and adds no dial per request; only when configured as **multiple proxies or with a suffix** does it probe each for connectivity (same as the host proxy).

---

## 5. Proxy probing and short cache

**Before using any upstream proxy, a `200ms` dial actually probes connectivity** (with multiple proxies, the first one that connects is used). **Unavailable proxies are not cached** — a dead proxy is still probed next time, so **after a proxy restarts and recovers, the next request can use it immediately**, not blocked by a stale failure cache.

> Early on there was an "unavailable proxy cache" (skip probing within 20s of failure, log `proxy ... unavailable (cached)`); it was **removed** because it caused "proxy already recovered but still judged dead by cache". The cost is that while a proxy stays down for a long time, each request spends up to 200ms probing, in exchange for instant availability on recovery. See [caching.md](caching.md).

One short cache is still kept (affects only route selection, not external service availability):

| Cache | Effect | Duration |
|------|------|------|
| **auto direct-fail cache** | After an `auto` direct failure, subsequent requests within the TTL skip direct and go straight to proxy (avoids a burst of concurrency each retrying the same just-failed direct connection) | `autoDirectFailTTL` = 20s |

Intentionally short: a single transient direct failure won't pin the domain to the proxy for long; after expiry it retries direct to recover promptly.

---

## 6. Quick reference of common combinations

| target | proxy config | proxy available | all proxies down |
|--------|-----------|---------|---------|
| `local` | any | local-direct | local-direct |
| `auto` | set | direct first, proxy if fails | direct (proxy is fallback; if fallback also gone, still direct) |
| `remote` | no suffix | via proxy | fall back to global; if global also down → **error out** |
| `remote` | ` local` | via proxy | **local-direct** |
| `remote` | ` deny` | via proxy | **deny** |
| `deny` | — | deny | deny |

---

## 7. Configuration examples

```yaml
default:
  target: auto                     # default local-first
  # global proxy: multiple proxies + local fallback; hot-reloadable
  proxy: socks5://192.168.1.11:10808, socks5://192.168.1.33:10808 local

hosts:
  # force via proxy; if this proxy dies, don't fall back to global, deny directly
  - name: "*google.com"
    target: remote
    proxy: socks5://192.168.1.8:10808 deny

  # local-first: direct first, use this proxy only if it fails
  - name: "*github.com"
    target: auto
    proxy: http://127.0.0.1:8888

  # force via proxy; if proxy dies, fall back to local-direct
  - name: "*example.com"
    target: remote
    proxy: http://127.0.0.1:8888 local

  # deny directly
  - name: "*doubleclick.net"
    target: deny
```

---

## 8. Common pitfalls

- **Only `proxy` set without `target`**: `target` defaults to `auto` (local-first), so sites that can connect directly won't use the proxy. To force proxy use, set `target: remote`.
- **`remote` + proxy down thinking it auto-goes-direct**: it won't; it errors out. To fall back to local, explicitly add the ` local` suffix.
- **Suffix position**: `local`/`deny` must be at the **end** of the whole string, separated by a space before it, e.g. `... :7777 local`.
- **"Usable" = can connect**: multiple-proxy selection is based on whether the 200ms dial probe connects, not merely valid format.

See also: field overview in [routing.md](routing.md); global proxy and command line in [cli.md](cli.md).
