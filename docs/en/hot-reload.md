# Config hot reload (watcher)

With `watcher: true` set at the config top level, anyproxy watches the **directory** containing `router.yaml` for file changes and auto-reloads on change. This doc lists which configs support hot reload and which require a restart.

## Mechanism

The hot-reload implementation is simple: on file change, it re-runs `LoadRouterConfig` and **replaces the `RouterConfig` pointer wholesale** (the `reload` in [utils/conf/config.go](../utils/conf/config.go)). Therefore there is only one criterion:

- **Consumers that read `conf.RouterConfig.X` live on every request/connection → hot reload takes effect**
- **Consumers that read once at startup, capturing the value into a variable or for initialization → no effect (need restart)**

It watches the directory, not the file itself, to be compatible with editors' atomic "write temp file then rename over" save (otherwise the inode change under Linux would break the watch). Multiple events in a short time are debounced with a 200ms merge, reloading only once.

> Reload only affects **requests/connections created afterward**; in-flight connections are unaffected.

## Supports hot reload (takes effect from the next request/connection)

| config | reference location |
|------|----------|
| `hosts` (all rules: name/target/dns/proxy/ip/port/allowIP/match) | `proto/tunnel.go`, `utils/dnsutil/dns.go` |
| `default.target` / `dns` / `tcpTarget` / `match` / `localPort` | `proto/tunnel.go`, `proto/websocket.go` |
| `default.proxy` | `proto/tunnel.go` (**only if `-p` was not given at startup**; if `-p` was used it is fixed, CLI wins) |
| `allowIP` (top-level, proxy client whitelist) | `isAllowed` in `proto/tunnel.go` |
| `loopGuard.minActive` / `ratio` | `proto/loopguard.go` (read live on every `allow()`) |
| `firstLine.host` / `custom` | `proto/http.go` |
| `token` | `proto/request.go` |
| `tcpcopy.ip` / `port` / `enable` | `proto/request.go`, `proto/tcpcopy.go` (reload re-normalizes `mode: tcpcopy`) |
| `tun.blockQUIC` | `utils/dnsutil/dns.go` (takes effect on new DNS queries) |
| `websocket.server.users` (incl. each entry's `disable`) / `allowIP` | `nat/conn.go` (auth for **newly accepted connections** reads live, `LookupUser` looks up `users` by user; connected ones unchanged — changing/disabling an account only affects its later new connections) |
| `websocket.client.user` / `pass` / `host` / `email` / `subscribe` (incl. same-named fields inside the `clients[]` array) | `liveAuthCfg` in `nat/handler.go` (takes effect on **next reconnect**; `clients[]` is located by index, so **do not change the array order** after reload, or it may read another server's account) |

## Does not support hot reload (determined at startup, needs restart)

| config | reason |
|------|------|
| `listen` / `network` | bound at startup. Change takes effect via **`kill -HUP` (SIGHUP graceful restart)**; watcher itself does not re-bind |
| `log.dir` | log initialized at startup |
| `mode` | proxy/tunnel/tun/bypass/tcpcopy selected at startup |
| `tun.*` (except `blockQUIC`: name/addr/mtu/autoRoute/bypassIPs/bypassPrivate/excludeProcs/inboundPorts/windivertDir/excludeNics/device) | builds TUN / bypass at startup |
| `geo` / `geoip` / `geosite` | `loadGeo()` runs once at startup; swap `.dat` → restart |
| `websocket.server.listen` / `client.connect` / `clients[].connect` (whether to start / which server to connect to) | decides which connections to spin up at startup; adding/removing entries or changing `connect` address needs restart (internal auth params are hot, see above) |
| `websocket.server.forward` / `client.forward` (incl. `clients[].forward`) | `StartForward` / `buildForward` each run once at startup |
| `watcher` itself | decides whether to enable watching at startup |

## Three easily-confused points

1. **`listen` is "SIGHUP restart", not "watcher hot reload".** They are different paths: after changing `listen` you need `kill -HUP <pid>` to trigger a graceful restart (new process takes over listening, old exits); watcher only swaps the config pointer, not the bound port.
2. **websocket's "params" are hot, "whether to start" is cold.** `users`/`allowIP` take effect on new connections/reconnect, but changing `listen`/`connect` from empty to a value won't auto-spin up the service — needs restart.
3. **Hot reload only affects new connections**; in-flight connections keep the config from when they were established.
