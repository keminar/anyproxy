# Run modes

anyproxy's run mode is decided by a single `-mode` (or config `mode`), and the values are **mutually exclusive**: `proxy` (default) / `tunnel` / `tun` / `bypass` (Linux only) / `tcpcopy`.

`websocket` (intranet penetration) is **not** a `-mode` value, but an independent switch — the server is enabled via `websocket.server.listen` (or `-ws-listen`); the client is enabled via `websocket.client.connect` / `websocket.clients[]` (no CLI equivalent, config file only). It starts before the mode decision, and **coexists in the same process as any mode** (usually paired with the default proxy).

## proxy mode (default)

Client / proxy mode. Listens on a port for traffic, then routes locally direct or forwards to the upstream proxy (tunnel/socks5/http) per the rules in [routing.md](routing.md).

```bash
./anyproxy                         # Read conf/router.yaml
./anyproxy -p 'socks5://127.0.0.1:10000'
```

Paired capture methods:
- Linux iptables transparent proxy, see [deployment.md](deployment.md#linux-iptables-global-proxy).
- Full-platform TUN virtual network interface, see [tun-features.md](tun-features.md).

## tunnel mode (tunneld server)

`-mode tunnel` starts tunneld, deployed on a server, accepts anyproxy requests and proxies them out, or forwards to the next-level tunneld. **With token authentication, non-anyproxy requests are all rejected**. Used for cross-intranet access to resources.

```bash
./anyproxy -mode tunnel
```

- `token`: the key for communicating with the client anyproxy; both ends must match and the **length must be 16 characters**.
- The client points to it with `-p 'tunnel://<tunneld-ip>:3001'` or `hosts[].proxy: tunnel://...`.
- Multi-level chaining is supported: anyproxy → tunneld A → tunneld B → Internet.

## tun mode (TUN global proxy)

On Linux/macOS a TUN virtual network interface is created to capture global traffic, and gVisor's user-space protocol stack parses the TCP internally before routing through the proxy rules, equivalent to tun2socks. **Windows exception**: instead of creating a virtual network interface, it uses **WinDivert** to hijack and redirect at the network layer, requiring `WinDivert.dll` + `WinDivert64.sys` (see [windows-winDivert.md](windows-winDivert.md)). Both require administrator/root. Cross-platform features, autoRoute, QUIC interception, UDP behavior see [tun-features.md](tun-features.md).

```bash
sudo ./anyproxy -mode tun -p 'socks5://127.0.0.1:10000'
```

## bypass mode (physical NIC bypass, Linux only)

Creates no NIC, only binds this process's outbound connections to the physical NIC. Used when **there is already another anyproxy TUN process on the same host**, so that this process's `target=local` requests can escape the other's TUN `0/1` routes and avoid a loop. **Linux only** (removed on macOS/Windows: macOS handles inbound reply via `tun.inboundPorts`, Windows uses WinDivert's `tun.windows.excludeProcs/bypassIPs`). See [multi-instance-loop.md](multi-instance-loop.md).

```yaml
mode: bypass
tun:
  linux:
    device: eth0   # Leave empty to auto-detect the default-route NIC
```

## tcpcopy (port forwarding)

Bridges connections on a locally listened port verbatim to another address:port. **Once enabled, all hosts domain proxy rules become ineffective**; `allowIP` still applies.

Typical use: the host is on the 192 subnet and the container is on the 10 subnet, accessing the container's TCP service (e.g. mysql) via the host's port.

Enable with `mode: tcpcopy` (one of the run modes, mutually exclusive with proxy/tunnel/tun/bypass).

```yaml
# conf/tcpcopy.yaml
watcher: true
listen: 192.168.1.2:3306
allowIP:
  - 192.168.1.2
mode: tcpcopy
tcpcopy:
  ip: 10.0.0.2
  port: 3306
```

```bash
./anyproxy -c conf/tcpcopy.yaml
# Or specify the mode on the command line
./anyproxy -c conf/tcpcopy.yaml -mode tcpcopy
```

> The old form `tcpcopy.enable: true` is still supported (equivalent to `mode: tcpcopy`).

## websocket (intranet penetration)

Brings traffic from the public network back to the intranet over a websocket long connection, with the intranet side actively reconnecting. Split into server and subscriber roles, can coexist in the same process as proxy mode. There are two paths: **HTTP header subscription forwarding** (limited to non-CONNECT HTTP requests) and **raw TCP port forwarding** (intranet penetration / exposing any intranet TCP service). Principles and field details see [websocket.md](websocket.md).

- **Server**: configure `websocket.server.{listen,users}` (or `-ws-listen`). `users` is an array, each entry `{user,pass,disable}`, supporting multiple subscribers each with their own account, and the ability to disable a single account. Receives public-side traffic. For raw TCP forwarding also configure `server.forward[].{listen,email}`.
- **Subscriber**: configure `websocket.client.{connect,user,pass,email}` (to subscribe to multiple servers at once use `websocket.clients[]`, see [websocket.md](websocket.md)). If `connect`/`user`/`email` are not configured, no connection is initiated. For raw TCP forwarding also configure `client.forward[].{port,target}`.
- Server `users[].user`/`pass` must **correspond and match** the subscriber's `client.user`/`pass` (`pass` participates in the token); `email` is used to locate/identify the subscriber and does not participate in the token; `subscribe` is the subscription header for the HTTP path.

```yaml
websocket:
  server:                     # Server
    listen: :3002
    users:
      - user: someuser
        pass: somepass
  client:                     # Client (another host / another process)
    connect: ws-server-ip:3002
    host: ws.example.com
    user: someuser
    pass: somepass
    email: user@example.com
    subscribe:
      - key: X-Env
        val: test
```

> Typical case (HTTPS packet capture): the public network sends the https request to the server; the server decrypts the certificate, adds a specific header and forwards to the anyproxy websocket server; locally start another websocket client to receive and forward the HTTP request to Charles. See [README](../README.md) use case 3.
