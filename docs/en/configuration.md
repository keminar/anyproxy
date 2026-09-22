# Configuration file reference (router.yaml)

The default config path is `conf/router.yaml` (specifiable with `-c`). Search order: current working directory `conf/` → program directory `conf/` → source directory `conf/`.

`default` and `hosts` support hot reload (changing the file takes effect when `watcher: true`); other items require a restart.

This page explains each config section in turn. Routing semantics (`target`/`proxy`/`match`/`dns`, etc.) are detailed in [routing.md](routing.md); TUN/bypass/loopGuard are in [tun-features.md](tun-features.md) and [multi-instance-loop.md](multi-instance-loop.md).

## Top level

| Field | Type | Default | Description |
|------|------|------|------|
| `listen` | string | `:3000` | Listen address:port; lower priority than `-l`. Set to `off` (or `none`/`-`) to **disable the proxy listener**, running only background services like websocket/tun (pure intranet-penetration scenario, no local proxy port needed). After disabling, the websocket "HTTP header subscription" path stops working (it depends on the local proxy); the "raw TCP forward" is unaffected |
| `network` | string | `tcp` | Listen protocol: `tcp` (v4+v6) / `tcp4` / `tcp6` |
| `watcher` | bool | false | Whether to watch config file changes and hot-reload `default`/`hosts` |
| `token` | string | — | Encryption key for communicating with tunneld; any length works as long as both ends match (internally normalized into a 16-byte AES key) |
| `allowIP` | []string | empty = unrestricted | Client IPs allowed to access, supports CIDR |
| `mode` | string | `proxy` | Run mode (mutually exclusive): `proxy` / `tunnel` / `tun` / `bypass` (Linux only) / `tcpcopy`; lower priority than `-mode`. websocket intranet penetration is not a `mode` value — it is an independent switch coexisting with any mode |

## log

| Field | Default | Description |
|------|------|------|
| `log.dir` | `./logs/` | Log directory |

## firstLine (HTTP first-line domain handling)

For non-CONNECT HTTP requests, whether to strip the first-line domain when the first-line domain matches the Host header. Generally a local vue project should set the domain to `off`.

| Field | Default | Description |
|------|------|------|
| `firstLine.host` | `on` | Whether to include Host: `on` includes / `off` excludes |
| `firstLine.custom` | — | Per-domain override: `on`/`off`, others use default. **Note**: the colon between domain and port becomes a dot, e.g. `localhost:5173` is written as `localhost.5173` |

```yaml
firstLine:
  host: on
  custom:
    localhost.5173: off
```

## tcpcopy (port-forward mode)

Enabled with `mode: tcpcopy` (one of the run modes, mutually exclusive with proxy/tunnel/tun/bypass). Once enabled, **the hosts domain proxy rules no longer take effect**, but `allowIP` still applies. See [modes.md](modes.md#tcpcopy-port-forwarding).

| Field | Default | Description |
|------|------|------|
| `mode` | `proxy` | Set to `tcpcopy` to enable port forwarding |
| `tcpcopy.ip` | — | Forward target IP |
| `tcpcopy.port` | — | Forward target port |
| `tcpcopy.enable` | false | **deprecated**, use `mode: tcpcopy`; for backward compatibility when true (equivalent to `mode: tcpcopy`) |

```yaml
mode: tcpcopy
tcpcopy:
  ip: 10.0.0.2
  port: 3306
```

## geo (geoip/geosite dataset)

Top-level `geoip:` / `geosite:` are each a **file list**; only when configured are `hosts`' `geoip:xx` / `geosite:xx` matches enabled. Files are distinguished by extension: `.dat` (protobuf dataset, one file with multiple categories, `cats` empty = all) or plain-text list (the whole file is one category, `cats` must be exactly one). **The same category can be merged from multiple files taking the union** (e.g. `geosite.dat`'s `cn` + `direct-list.txt`'s `cn`; `geosite:cn` matches the sum of both contents; duplicates deduped, merged in list order, category name case-insensitive). See [geo.md](geo.md).

| Field | Type | Description |
|------|------|------|
| `geoip[].file` | string | geoip data file (`.dat` or CIDR plain-text list) |
| `geoip[].cats` | []category | Categories loaded from this file; `.dat` empty = all, plain-text list must be exactly one |
| `geosite[].file` | string | geosite data file (`.dat` or domain plain-text list, e.g. `direct-list.txt`) |
| `geosite[].cats` | []category | same as above |

```yaml
geoip:
  - file: ./geoip.dat         # .dat one file multiple categories, parsed only once
    cats: [cn]                # empty loads all categories in that .dat
geosite:
  - file: ./direct-list.txt   # plain-text domain list, whole file is one category
    cats: [cn]
hosts:
  - name: geoip:cn
    target: local        # domestic IP direct
  - name: geosite:cn
    target: local        # domestic domain direct
```

## default (default route, hot-reloadable)

Used when no `hosts` entry matches.

| Field | Default | Description |
|------|------|------|
| `default.target` | `auto` | HTTP default egress: `local`/`remote`/`deny`/`auto` |
| `default.tcpTarget` | `remote` | TCP default egress: `auto`/`local`/`remote`/`deny`/`localport` |
| `default.localPort` | empty (default 21/22) | Port list for local direct when `tcpTarget=localport`; **once configured it is authoritative (overrides rather than appends)** |
| `default.dns` | `local` | DNS server: `local` current environment / `remote` remote (only valid when `target=remote`) |
| `default.match` | `equal` | Default domain comparison method: `contain`/`equal` (only effective when `name` has no asterisk and `match` is not explicitly set) |
| `default.proxy` | empty | Global upstream proxy server, lower priority than `-p`; supports multiple proxies and `local`/`deny` suffixes, see [routing.md](routing.md#proxy-field) |
| `default.blackholeIP` | `192.0.0.0` | Blackhole sentinel IP: point a domain (system hosts or this config) to it to achieve "no proxy → locally unreachable = blocked; with proxy → force proxy and remote resolution". Connections hitting this IP force `target=remote`+`dns=remote`; under Windows WinDivert it forces interception into the engine (not affected by `bypassPrivate`). Set `off`/`none`/`disable` to disable. See [blackhole-sentinel.md](blackhole-sentinel.md) for the dedicated topic |

## hosts (domain rule list, hot-reloadable)

Compared entry by entry in order; the first match is used. Field meaning is detailed in [routing.md](routing.md).

| Field | Description |
|------|------|
| `name` | Domain keyword; leading/trailing `*` wildcard (`*X` suffix / `X*` prefix / `*X*` contain / no asterisk exact), see [routing.md](routing.md) |
| `match` | Optional, explicitly specify comparison method: `contain` contains / `equal` exact equality (when set, `name` is used verbatim without asterisk parsing, for backward compatibility) |
| `target` | `local`/`remote`/`deny`/`auto` (same as default.target) |
| `dns` | `local`/`remote`, only valid when `target=remote` |
| `ip` | Local resolution IP: on match force the target IP to this value (swap IP) |
| `port` | Target port translation list, elements are `{from, to}` |
| `proxy` | Specify upstream proxy server, supports multiple values and `local`/`deny` suffixes, see [routing.md](routing.md#proxy-field) |
| `allowIP` | Client IP list allowed to access this domain |

```yaml
hosts:
  - name: github
    match: contain
    target: remote
    dns: remote
    proxy: http://127.0.0.1:8888, http://127.0.0.1:7777 local
  - name: dev.example.com
    ip: 127.0.0.1
    port:
      - from: 80
        to: 88
    allowIP:
      - 172.17.0.12
```

## tun (effective when mode=tun)

Windows and Linux/macOS use two different underlying engines (Windows = WinDivert redirect, no virtual network interface; Linux/macOS = gVisor virtual network interface), so the effective scope of fields differs. **Recommended to write per-system blocks**: under `tun.linux` / `tun.darwin` / `tun.windows` fill only the fields that system needs; the program takes the corresponding block for the current system (the whole block overrides the top-level flat fields).

```yaml
tun:
  linux:
    addr: 10.9.0.1/24
    autoRoute: true
    bypassIPs: [192.168.199.1]
  darwin:
    addr: 10.9.0.1/24
    inboundPorts: [22]        # allow external SSH reply packets (pf)
    bypassIPs: [192.168.199.1]
  windows:
    excludeProcs: [openvpn.exe]  # escape same-machine OpenVPN loop
    bypassIPs: [203.0.113.10]
```

> **Compatibility**: the old flat style (writing `name/addr/...` directly under `tun:`, common to all three platforms) is still valid; when a corresponding system block is configured, the system block takes precedence.

### Fields and effective platforms

| Field | Default | Effective platform | Description |
|------|------|----------|------|
| `enable` | false | — | **deprecated**, use top-level `mode: tun` |
| `name` | platform default | Linux/macOS | NIC name (Linux `anytun0` / macOS `utunN`); Windows has no NIC, ignored |
| `addr` | `10.9.0.1/24` | Linux/macOS | Interface address CIDR; Windows ignores |
| `mtu` | 1500 | Linux/macOS | MTU; Windows ignores |
| `autoRoute` | **true** | Linux/macOS | Auto add/clean routes; `false` only prints commands; Windows ignores |
| `bypassIPs` | empty | all three | These targets are direct (Linux/macOS add `/32` routes; Windows excludes from capture). **An upstream proxy specified by IP (`-p`/`default.proxy`/`hosts[].proxy`) is auto-merged, no need to fill manually**; only a proxy or VPN server IP specified by domain needs to be listed here manually |
| `blockQUIC` | **true** | all three | drop UDP443 for domains matching hosts (with ip), forcing QUIC to fall back to TCP |
| `bypassPrivate` | **true** | **Windows only** | Private/LAN/link-local (including VM network segments, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`) are all direct, not entering the engine. Explicit `false` lets private 80/443 enter the engine and follow router rules; `loopback` is always direct. Linux/macOS direct subnets are naturally direct via routes, no such item needed |
| `excludeProcs` | empty | **Windows only** | These processes (exe name) are not redirected outbound, escaping same-machine tunnels (e.g. `openvpn.exe`) loops |
| `inboundPorts` | empty | **macOS only** | pf reply-to allows inbound service reply packets (e.g. external SSH 22). Linux automatic, Windows not needed |
| `windivertDir` | empty (same dir as exe) | **Windows only** | Directory of `WinDivert.dll`+`WinDivert64.sys`. Can place the driver in a clean path with no spaces/Chinese (e.g. `C:\wd`), leaving the exe in place, to avoid driver load failures caused by Chinese/space paths |

See [tun-features.md](tun-features.md); for VPN coexistence see [tun-dns-vpn-coexist.md](tun-dns-vpn-coexist.md).

## tun.linux (effective when mode=bypass, Linux only)

`mode=bypass` (physical NIC bypass) reuses the two fields under `tun.linux`, paired with `mode=bypass`.

| Field | Default | Description |
|------|------|------|
| `tun.linux.device` | empty (auto-detect) | Manually specify the bound physical NIC name (e.g. `eth0`) |
| `tun.linux.excludeNics` | platform default TUN name | NIC names excluded when collecting direct subnets (usually fill the other instance's TUN NIC name) |

macOS/Windows have removed bypass mode: macOS inbound reply uses `tun.inboundPorts`; Windows escape relies on
`tun.windows.excludeProcs`/`bypassIPs`. See [multi-instance-loop.md](multi-instance-loop.md).

## loopGuard (loop fallback circuit breaker)

Under the same-machine A(tun)+B(bypass, Linux only) scenario, the last line of defense when bypass fails. Enabled by default.

| Field | Default | Description |
|------|------|------|
| `loopGuard.minActive` | 1000 | Global in-flight connection count must reach this to enable the ratio check; `0` = default 1000; `<0` = disabled. Requires `ulimit -n` far greater than 2× this |
| `loopGuard.ratio` | 80 | Percentage threshold of a single target's share of global in-flight connections; `<=0` uses default 80 |

See [multi-instance-loop.md](multi-instance-loop.md#second-layer-fallback-loopguard-circuit-breaker).

## websocket (intranet penetration)

Config is split by role into `server` (server side) / `client` (client side) blocks. The server needs `server.listen`/`users`; the client needs `client.connect`/`user`/`email` (missing any prevents initiating connection). See [modes.md](modes.md#websocket-intranet-penetration).

| Field | Description |
|------|------|
| `websocket.server.listen` | Server-side listen address:port |
| `websocket.server.users` | Authentication account array, each `{user, pass, disable}`, verifies connecting subscribers; `disable: true` can temporarily disable an account |
| `websocket.server.allowIP` | Allowed client IP whitelist (CIDR/single IP), empty = unrestricted; judged by real TCP source, loopback always allowed |
| `websocket.server.forward` | Server-side raw TCP forward entry list, elements are `{listen, email, tag}`; `tag` pairs with the subscriber's `client.forward[].tag` to decide which of its forward rules a connection lands on |
| `websocket.client.connect` | Client connection address:port |
| `websocket.client.host` | connect's domain |
| `websocket.client.proxy` | The subscriber reconnects to server B **via upstream HTTP/SOCKS5 proxy**, format `scheme://host:port`: `socks5://` (via SOCKS5) / `http://`, `https://` (via HTTP CONNECT); other schemes error out directly, not silently degraded to direct. Used when `connect` is an intranet/loopback address that the local machine cannot reach directly — connect to this reachable proxy first, which forwards to `connect`. Not configured = direct (original behavior). Like `connect`/`forward`, **it is read only once at startup / each reconnect, not part of hot reload** |
| `websocket.client.user` / `.pass` | Client authentication username / password (sent to server) |
| `websocket.client.email` | Used to locate the user, not for authentication |
| `websocket.client.subscribe` | Subscribed header info list, elements are `{key, val}` |
| `websocket.client.forward` | Subscriber raw TCP forward target list, elements are `{tag, target}`; `tag` must match the server's `server.forward[].tag` to pair, unmatched connections are rejected |
| `websocket.client.uuid` | This subscriber's identity credential, used only by both file-transfer sender and receiver; **not written in config**, auto-generated at startup and persisted to a same-name hidden file `.router.uuid`, unchanged across restarts | — |
| `websocket.client.direct.accept` | When `true`, start QUIC listening and advertise the endpoint to the server, allowing other subscribers to connect to self directly (path C) | — |
| `websocket.client.direct.rules` | Local QUIC direct-entry rule array, each `{listen, forward: {email, tag}, via}`; `listen` may carry `tcp://` (default) / `udp://` / `both://` prefix; `forward.tag` (formerly `forwardPort`, now a string) picks which rule in the peer's `forward[]` to use, not a port number | — |
| `websocket.client.direct.encrypt` | When `true`, hole-punch control packets get extra AES-256-GCM encryption to prevent operators dropping packets by plaintext features; default `false`, applies to both `direct.rules[]` and `-send`/`-recv` | — |
| `websocket.client.direct.portmap` | When `true`, direct candidate collection tries UPnP/PCP/NAT-PMP port mapping; default `false` | — |
| `websocket.client.direct.punchFirst` | `true` declares this machine is behind restrictive CGNAT and, when actively connecting directly, must send the first packet first (letting the peer acceptor delay its punch); set when home broadband connecting to public cloud host fails | — |
| `websocket.client.direct.relay` | When `true`, this machine (public VPS) allows acting as the A↔C blind-forward relay; no need to configure `forward`/`direct` per pair, the target is specified by the initiator's `direct.rules[].via` | — |
| `websocket.client.direct.relayAllow` | Tightens `direct.relay`: only allows these source emails to use this machine's relay; empty = unrestricted | — |
| `websocket.client.direct.relayPublic` | Optional public relay address array. If every entry is a bare IP, each binding uses a random port advertised on all IPs; if every entry is `IP:port`, fixed-port mode is used. The two forms cannot be mixed | — |
| `websocket.client.direct.plainUdp` | Overrides the command-line `-direct-plain-udp` default for this connection, three-state: not set follows global value, explicit `true`/`false` affects only this one | `-direct-plain-udp` |
| `websocket.client.direct.lanAddrs` | Manually fill this machine's LAN/intranet IP array (no port), extra candidates for hole-punch/QUIC-dial racing | — |
| `websocket.client.receive` | File-transfer receive config `{dir, allow[], readonly}`; each `allow` is `{email, uuid, wol, dir}`, `readonly: true` is send-only, `wol: true` (default `false`) is required for that email to use `-wol` to have this machine broadcast on its behalf, and a non-empty `dir` overrides where that email's uploads land (default: the shared `dir`) | — |
| `websocket.client.sendRecvOnly` | When `true`, force this config to only fetch credentials for `-send`/`-recv`; the resident process does not initiate a connection for it | — |

> The full semantics, authentication, and examples of `websocket.client`'s direct/relay/file-transfer fields (the `direct*` / `receive` / `sendRecvOnly` in the table above) are in [websocket.md](websocket.md#file-transfer--send---recv--receive); `-genkey` generating `key` is also on that page.
