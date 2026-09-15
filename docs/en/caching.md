# Caching mechanism

anyproxy has a few **in-process memory caches** ([utils/cache/cache.go](../utils/cache/cache.go)) that need no config, are lost when the process exits, and have very short TTLs; config hot reload does not actively clear them (they expire naturally soon). They affect observable behavior and are worth knowing for troubleshooting.

> All are **process-private in-memory state, not persisted, not cross-process**. Once anyproxy restarts, all caches reset to zero — so "stale cache" can only happen in the window where anyproxy does **not restart** but the outside (upstream proxy / upstream DNS) changes.

## 1. DNS resolution cache (ResolveLookup)

- **Contents**: domain → IPv4, plus a dial state (normal / failed).
- **TTL**: successful resolution cached for **10 minutes**; under `auto` mode, records of local dial failure cached for **20 seconds** (`autoDirectFailTTL`).
- **Effect**:
  - Reduces repeated DNS resolution of the same domain;
  - Speeds up `auto` decision — when local dial of a domain fails, within 20 seconds it goes remote directly as "failed", instead of retrying local dial every time and waiting idle (see [proxy-decision.md](proxy-decision.md)).
- Capacity cap ~65536 entries, ring-overwrites the oldest when full.

> **Domains with `hosts[].ip` configured do not use this cache**: such domains read the fixed IP directly from config ([proto/tunnel.go](../proto/tunnel.go) `if host.IP != "" { dstIP = host.IP }`), neither querying nor writing the resolution cache. So **changing `ip` in the config takes effect immediately on hot reload, no need to wait 10 minutes**. What really eats this 10-minute cache is only domains that rely on real DNS resolution without a configured `ip`.

## 2. auto direct-fail cache (reuses ResolveLookup's StateFail)

- **Contents**: under `auto` mode, a "domain → StateFail" mark for locally-failed direct connections.
- **TTL**: **20 seconds** (`autoDirectFailTTL`).
- **Mechanism**: `target=auto` dials direct first; on failure it records this short mark, and within its validity subsequent requests **skip direct and go straight to proxy**, instead of letting each concurrently-requested page retry the just-failed direct dial and each wait one timeout idle. After expiry it retries direct, to detect recovery promptly.
- **Nature**: only affects **route choice** (direct ↔ proxy), not a "service unavailable" judgment; both paths usually work, worst case a bit more proxy traffic within 20 seconds.

## 3. Sniffed-domain cache (SniffName)

- **Contents**: domains configured with `ip` in `hosts`, their `ip → domain` mapping (recorded on DNS hijack).
- **TTL**: **10 minutes**.
- **Effect**: under TUN/WinDivert, browser **preconnect** opens TCP but sends no data, so the TCP first packet can't sniff SNI/Host. Then we reverse-lookup the domain from this table by target IP to recover the real domain the client just resolved, so **domain-based rules still take effect** (otherwise it degrades to IP matching).
- The key is always the fixed `hosts.ip` from config; entry count is bounded by config size (usually a few dozen), expired entries lazily deleted. Even if stale within 10 minutes it's harmless — the key is your hardcoded config IP, and every DNS hijack overwrites it.

## 4. Upstream proxy connectivity: no longer cached (removed)

Early versions cached "unavailable" for upstream proxies (`ProxyDial`, skipping probe for 20 seconds after failure, log `proxy ... unavailable (cached)`). **This cache has been removed**: it caused "after the upstream proxy restarts and recovers, anyproxy still judges it dead within the old failure-cache window", leaving requests unresponsive.

Current behavior ([proto/tunnel.go](../proto/tunnel.go) `getProxyServer`):

- **Probes with a real dial before each use of the upstream proxy** (returns on 200ms connect), no more failure cache;
- If the proxy is down the request fails/falls back that time; once the proxy recovers the **next request is immediately usable**, no TTL wait.

> Trade-off: without the cache, if the upstream proxy is down for a long time, each proxied request during that period spends up to 200ms probing. In return, "recover on restart, no longer blocked by cache" is the better trade-off for this project.

## Notes

- The caches above are all in-memory, process-private, not persisted, not cross-process; the new process after graceful restart starts from an empty cache.
- To see config/network change effects immediately, restart the process; otherwise wait for the TTL (10 minutes / 20 seconds) to expire naturally. **Note**: domains with `ip` configured and the upstream proxy are both **unaffected by the cache** (the former on hot reload, the latter on every real dial).
- Debug level `-debug 3` prints the DNS resolution cache's HIT/MISS/EXPIRED, handy for "why still the old IP / old decision" troubleshooting.

> There are also a few **platform-specific** short-lived runtime maps (not general caches): Windows WinDivert's pid→exe name (30s, guard against PID reuse misjudgment), port→pid (25ms), NAT connection table (reclaimed by idle/close); TUN's UDP negative cache (2s), in-flight DNS (5s). They serve their own subsystems, see [windows-windivert-redirect.md](windows-windivert-redirect.md) and other corresponding docs.
