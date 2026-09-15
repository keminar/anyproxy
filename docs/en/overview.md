# Overview and architecture

anyproxy is a cross-platform TCP traffic forwarder / proxy. It routes each connection by domain name: either direct locally, or forwarded to the next-level proxy (tunneld / socks5 / http). It can act as a transparent proxy client under Linux (with iptables or a TUN NIC), and also as a server (tunneld) accepting requests from other anyproxy instances.

Companion docs:

- [Command-line arguments](cli.md)
- [Configuration reference router.yaml](configuration.md)
- [Routing and proxy rules](routing.md)
- [Run modes (proxy / tunnel / tcpcopy / websocket)](modes.md)
- [Deployment and operations](deployment.md)
- [TUN global proxy features](tun-features.md)
- [Same-host multi-instance loop protection](multi-instance-loop.md)

## What it does

- **Domain-based routing**: different domains use different egress (local direct / upstream proxy / forbidden).
- **Multi-level forwarding**: anyproxy → tunneld → socks5 → Internet, any chaining.
- **Transparent proxy**: Linux uses iptables redirect, or full-platform TUN virtual network interface (tun2socks equivalent) to capture global traffic.
- **Domain sniffing**: transparent proxy only gets the target IP, the program sniffs the first packet's TLS SNI / HTTP Host to recover the domain so domain rules take effect.
- **Intranet penetration**: bring HTTP requests from the public network back to the intranet via websocket (see [modes.md](modes.md)).
- **Port forwarding (tcpcopy)**: bridge a local port to another address:port (e.g. connect to in-container mysql).
- **Traffic statistics**: count upstream and downstream separately.

## Data chain

```
+----------+      +----------+      +----------+
| Computer | <==> | anyproxy | <==> | Internet |
+----------+      +----------+      +----------+

# Egress via tunneld server (cross-intranet access)
+----------+      +----------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | tunneld | <==> | Internet |
+----------+      +----------+      +---------+      +----------+

# Forward to socks5
+----------+      +----------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | socks5  | <==> | Internet |
+----------+      +---------+      +----------+      +----------+

# Chaining
+----------+   +----------+   +---------+   +---------+   +----------+
| Computer |=> | anyproxy |=> | tunneld |=> | socks5  |=> | Internet |
+----------+   +----------+   +---------+   +---------+   +----------+

# websocket intranet penetration
+----------+   +---------+   +-----------+  ws  +-----------+   +---------+
| Computer |=> | Nginx A |=> | anyproxy S|  ==> | anyproxy C|=> | Nginx B |
+----------+   +---------+   +-----------+      +-----------+   +---------+
```

## Processing flow of one connection

1. **Ingress**: the connection enters from the listening port (normal/transparent proxy) or the TUN virtual network interface (gVisor user-space protocol stack).
2. **Get target**: a normal request resolves the target domain/IP; transparent proxy/TUN has only the target IP, the program sniffs the first packet's TLS SNI / HTTP Host to recover the domain, falling back to IP matching if it can't sniff.
3. **Match rule**: compare domains against `hosts` one by one (`match` decides the comparison method); on a hit use that rule, otherwise use `default`.
4. **Decide egress**: `target` / `proxy` / `dns` / `ip` / `port` decide local direct, which proxy, which DNS, whether to rewrite IP/port — see [routing.md](routing.md).
5. **Forward**: establish the connection to the egress, copy bidirectionally and count upstream/downstream traffic.

## Run mode overview

The mode is decided by a single `-mode` (or config `mode`), mutually exclusive:

| value | meaning |
|------|------|
| `proxy` (default) | client/proxy mode, only takes traffic on the listening port |
| `tunnel` | tunneld server, with token auth, only processes anyproxy requests |
| `tun` | create TUN virtual NIC for global proxy (Windows uses WinDivert; requires admin/root) |
| `bypass` | no NIC, only binds outbound connections to the physical NIC (escape another instance's TUN on the same host; **Linux only**) |
| `tcpcopy` | port forwarding, each connection re-routed to `tcpcopy.ip:port` (hosts rules become ineffective once enabled) |

There is also an independent switch `websocket` (intranet penetration) that can coexist with the modes above, see [modes.md](modes.md).

## Process model (important)

- **Foreground**: starts directly in the foreground, logs go to both stdout and the log file.
- **Daemonize `-daemon`**: the program forks a child process and the parent exits immediately; the real work is done by the **child process (new PID)**. When managing anyproxy with an external program, note: under `-daemon` the parent PID vanishes instantly — use the actually-running child PID as the source of truth.
- **Graceful restart (Linux)**: `kill -HUP <pid>` forks a new process to take over the listening fd, the old process drains then exits.
- **TUN cleanup**: in TUN mode, receiving `SIGINT/SIGTERM` first cancels the context, closes the virtual NIC and reclaims the `0.0.0.0/1`, `128.0.0.0/1` routes, then exits. **A hard kill (`kill -9` / `taskkill /F`) does not trigger cleanup** and leaves routes/NIC behind.
- **Windows**: `ensureEagerRSS()` is a no-op (no re-exec); `mode: tun` uses **WinDivert** (not a virtual NIC), requires admin privileges and `WinDivert.dll`/`.sys`. Process-stop notes see [deployment.md](deployment.md), [windows-winDivert.md](windows-winDivert.md).
