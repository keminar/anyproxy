# Configuration examples (router.yaml)

Ready-to-use `conf/router.yaml` snippets by scenario. Field meanings in [configuration.md](configuration.md); routing rules in [routing.md](routing.md).

> Convention: in the examples, replace placeholders like `<upstream proxy IP>`, `<VPN server IP>`, `en0`/`eth0`, etc. with values for your environment. TUN-related config is written in per-OS blocks (`tun.linux` / `tun.darwin` / `tun.windows`); the program picks the block for the current OS.

---

## 1. Minimal: local global proxy forwarding to upstream proxy

All local TCP traffic is captured by the TUN and forwarded to one upstream socks5 (or tunnel/http). Cross-platform skeleton:

```yaml
listen: :3000
log:
  dir: ./logs/

# global default egress: go to upstream proxy
default:
  target: remote
  tcpTarget: remote
  proxy: socks5://127.0.0.1:10000      # upstream proxy, can also be passed via -p

# TUN global proxy on
mode: tun
tun:
  linux:
    addr: 10.9.0.1/24
    autoRoute: true
    bypassIPs: [<upstream-proxy-ip>]           # upstream proxy must be direct, otherwise loop causes network loss
  darwin:
    addr: 10.9.0.1/24
    autoRoute: true
    bypassIPs: [<upstream-proxy-ip>]
  windows:
    bypassIPs: [<upstream-proxy-ip>]           # on Windows bypassIPs = exclude from capture (direct)
```

> An upstream proxy specified by **IP** (`-p`/`default.proxy`/`hosts[].proxy`) is **automatically merged into `bypassIPs`**; writing `bypassIPs: [<upstream proxy IP>]` manually in the example is just for clarity and can be omitted. If the upstream proxy is a **domain name**, the program can't determine its IP here, so you still must manually fill the IP into `bypassIPs` (or use an IP to specify the proxy).

---

## 2. Route by domain

Most direct, a few domains via proxy, a few denied. Without TUN, point the system proxy/browser to `:3000`; also effective with TUN on.

```yaml
listen: :3000
default:
  target: auto          # default: local if reachable, else remote
  tcpTarget: remote
  dns: local

hosts:
  # suffix wildcard: *.google.com all go to upstream tunnel proxy, remote DNS
  - name: "*google.com"
    target: remote
    dns: remote
    proxy: tunnel://<upstream-ip>:3001

  # route to local 8888 (e.g. Charles); local-direct if unreachable
  - name: "*github.com"
    target: remote
    proxy: http://127.0.0.1:8888 local

  # deny directly
  - name: "*doubleclick.net"
    target: deny

  # change IP + change port, allow only certain clients
  - name: dev.example.com
    ip: 127.0.0.1
    port:
      - from: 80
        to: 8080
    allowIP:
      - 172.17.0.12
```

`name` wildcard: `*x` suffix, `x*` prefix, `*x*` contains, no-asterisk exact; see [routing.md](routing.md).

---

## 3. Windows: running OpenVPN on the same host (prevent loop)

Windows uses WinDivert; if same-host OpenVPN uses TCP transport it gets captured → loop. Just exclude the OpenVPN process:

```yaml
mode: tun
tun:
  windows:
    excludeProcs:
      - openvpn.exe          # preferred: escape by process, independent of server IP
    bypassIPs:
      - <vpn-server-ip>        # optional extra: exclude capture by IP
    blockQUIC: true
```

Principle and troubleshooting in [tun-dns-vpn-coexist.md](tun-dns-vpn-coexist.md).

### 3.1 Windows: accessing VMs / intranet hosts

On Windows `tun.windows.bypassPrivate` **defaults to `true` if unset**: private/LAN/link-local (including VirtualBox/VMware/Hyper-V/WSL2 subnets) are always direct and don't enter the engine, so accessing VMs/intranet hosts is **direct by default**, usually needing no extra config.

Only two cases require touching it:

```yaml
mode: tun
tun:
  windows:
    # to route a particular private target by router rules instead, turn off blanket direct:
    bypassPrivate: false
    # then use bypassIPs to precisely allow the subnets that should stay direct (rest of private net enters engine per rules):
    bypassIPs:
      - 192.168.56.0/24      # e.g.: VirtualBox host-only subnet direct
```

- Default (`bypassPrivate: true`): whole private subnet direct, most worry-free;
- To **proxy a particular private target**: `bypassPrivate: false` (private 80/443 enters engine per rules);
- To **precisely allow only certain subnets** while the rest of the private net still follows rules: `bypassPrivate: false` + `bypassIPs` listing the subnets to keep direct.

Judgment details in "Two connections and direct judgment" of [windows-windivert-redirect.md](windows-windivert-redirect.md).

---

## 4. macOS: this Mac must accept external SSH login

macOS has no source-policy routing; use pf to allow reply packets of inbound service ports (needs root):

```yaml
mode: tun
tun:
  darwin:
    addr: 10.9.0.1/24
    autoRoute: true
    inboundPorts:
      - 22                   # external SSH
      - 443                  # if this Mac also serves https externally
    bypassIPs: [<upstream-proxy-ip>]
```

> On Linux, inbound reply packets are **automatically** allowed by the built-in `ip rule` source-policy routing, no config needed. Windows (WinDivert) neither.

---

## 5. Linux server: iptables transparent global proxy (no TUN)

Use iptables to redirect local traffic to anyproxy; more suitable for servers than TUN:

```yaml
listen: :3000
default:
  target: auto
  tcpTarget: remote
  proxy: tunnel://<upstream-ip>:3001
# no mode set; rely on iptables to steer traffic
```

Companion iptables (see [deployment.md](deployment.md)):

```bash
sudo useradd -M -s /sbin/nologin anyproxy
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner anyproxy -j RETURN
sudo -u anyproxy ./anyproxy -daemon
sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dport 80,443 -j REDIRECT --to-port 3000
```

---

## 6. tunneld server

Deployed on the egress server to receive anyproxy's requests. Start with `-mode tunnel`.

```yaml
listen: :3001
token: anyproxyproxyany       # any length, identical on both ends (internally normalized into a 16-byte AES key)
allowIP:                      # optional: restrict source
  - 203.0.113.0/24
default:
  target: auto
  tcpTarget: remote
```

Start: `./anyproxy -mode tunnel -c conf/tunneld.yaml`. Clients point to it with `proxy: tunnel://<local IP>:3001`.

---

## 7. tcpcopy: port forwarding (e.g. connecting to in-container mysql)

After enabling, hosts rules are disabled, but `allowIP` still works.

```yaml
watcher: true
listen: 192.168.1.2:3306
allowIP:
  - 192.168.1.2
mode: tcpcopy
tcpcopy:
  ip: 10.0.0.2                # target (in container)
  port: 3306
```

Start: `./anyproxy -c conf/tcpcopy.yaml`. (Old form `tcpcopy.enable: true` is still compatible)

---

## 8. websocket intranet penetration

The server (public side) listens; the subscriber (intranet side) **actively connects back**. Can run in the same process as the proxy. There are two forward paths; principle and field details in [websocket.md](websocket.md).

> The server's `users[].user`/`pass` must **match** the subscriber's `client.user`/`pass` (`pass` participates in token verification; a missing subscriber config fails auth); `email` is for identifying/locating subscribers and doesn't participate in the token itself.

### 8.1 HTTP-header subscribe forwarding (send public requests into intranet by request header)

Public-side HTTP requests carrying the `Anyproxy-Action: websocket` header and matching some subscriber's `subscribe` in their headers are forwarded to that subscriber; the subscriber then uses the **local proxy** to initiate into the intranet.

```yaml
# server (public)
websocket:
  server:
    listen: :3002
    users:
      - user: someuser
        pass: SomePass1234567890
```

```yaml
# subscriber (another intranet machine / process)
websocket:
  client:
    connect: <server-ip>:3002
    host: ws.example.com
    user: someuser
    pass: SomePass1234567890              # same as server (for token, required; at least 18 chars, must contain both English letters and digits)
    email: user@example.com     # locate subscriber
    subscribe:
      - key: X-Env              # public request header must match key=val to forward to this endpoint
        val: test
```

### 8.2 Raw TCP port forwarding (intranet penetration / exposing intranet TCP services)

The server starts a raw TCP listening port, bridges by `email` to the subscriber, who dials a hardcoded intranet target.

```yaml
# server (public)
listen: off                   # pure penetration doesn't need local proxy listener, can disable (default :3000 if omitted)
websocket:
  server:
    listen: :3002
    users:
      - user: someuser
        pass: SomePass1234567890
    forward:
      - listen: :2222         # public entry port (raw TCP listen)
        email: home@example.com # forward to the subscriber with this email
        tag: ssh               # pairs with the subscriber's forward[].tag; changing listen doesn't require changing this
```

```yaml
# subscriber (intranet; email matches server's forward.email)
listen: off                   # subscriber doing pure raw-TCP forward also doesn't need local proxy listener
websocket:
  client:
    connect: <server-ip>:3002
    host: ws.example.com
    user: someuser
    pass: SomePass1234567890
    email: home@example.com
    forward:
      - tag: ssh              # must match the server's forward[].tag exactly (string), not a port number
        target: 127.0.0.1:22  # when a connection arrives with this tag, dial the real intranet target (local sshd)
    # pure raw-TCP forward needs no subscribe: email matching a forward rule permits an empty subscription
```

Usage: `ssh -p 2222 youruser@<server IP>` → hits port 22 on the intranet machine. The subscriber only dials the `target` whose `tag` is listed in its own `forward`; unlisted tags are rejected (a natural whitelist). For multiple targets add multiple `forward` entries, distinguishing different intranet machines by different `email`/`tag`.

> `listen: off` (or `-l off`) disables the local proxy listener and only runs the websocket backend, suitable for pure penetration. **Note**: only "raw TCP forwarding" can be used this way; websocket's "HTTP-header subscribe" path (8.1) depends on the local proxy port and won't work after disabling it.

### 8.3 Subscriber connecting to multiple servers at once

A single subscriber process can connect back to multiple servers at once, each with its own independent account/forward table, using the plural `clients` array (each item is a complete `websocket.client` block from 8.1/8.2):

```yaml
# subscriber: penetrate two different servers at once; tag may repeat (independent forward tables, no conflict)
listen: off
websocket:
  clients:
    - connect: <server-a-ip>:3002
      host: ws-a.example.com   # optional, used when behind a TLS gateway
      user: someuser
      pass: SomePass1234567890
      email: home@example.com
      forward:
        - tag: ssh
          target: 127.0.0.1:22
    - connect: <server-b-ip>:3002
      user: anotheruser
      pass: AnotherPass123456789
      email: office@example.com
      subscribe:                # optional; configure this one if it also needs the HTTP-header subscribe path (8.1); pure raw-TCP forward (this example) doesn't need it
        - key: X-Env
          val: office
      forward:
        - tag: rdp
          target: 192.168.1.10:3389
```

Each `clients` item is a complete independent `websocket.client` block; fields like `host`/`subscribe`/`forward` work exactly like the single-block form (8.1/8.2) — configure per each subscriber's needs, not every item must be complete. Without `clients` behavior is unchanged (still reads the single `client` block); fields/common pitfalls in [websocket.md](websocket.md#subscribing-to-multiple-servers-simultaneously).

### 8.4 Server multi-user auth + disabling an account

`websocket.server.users` is itself an array; one server can accept multiple subscribers, each with its own account; adding `disable: true` to an entry temporarily disables a subscriber without deleting the config or changing the password:

```yaml
# server (public): accepts two subscribers, distinct accounts; office temporarily disabled
websocket:
  server:
    listen: :3002
    users:
      - user: home
        pass: HomePass1234567890
      - user: office
        pass: OfficePass1234567890
        disable: true          # temporarily disabled; this account's subscriber can't connect, server log prints "user office is disabled"
    forward:
      - listen: :2222
        email: home@example.com
      - listen: :2223
        email: office@example.com
```

Together with the 8.3 form, the two subscribers each fill the corresponding account in their own `websocket.client.user`/`pass` (8.1/8.2 form) or `clients[].user`/`pass` (8.3 form); this doesn't affect `email` (`email` remains an independent field used by the server's `forward.email` to locate subscribers and doesn't participate in auth). `disable` takes effect on hot reload; fields in [websocket.md](websocket.md#multi-user-authentication).

### 8.5 QUIC direct (hole punching, data doesn't go through server)

In the previous examples data is forwarded by the server. This path moves the entry to the subscriber's own machine; two subscribers directly punch a QUIC connection, and the server only relays signaling:

```yaml
# server (public, only relays signaling, not data)
websocket:
  server:
    listen: :3002
    users:
      - user: office
        pass: OfficePass1234567890
      - user: home
        pass: HomePass1234567890
```

```yaml
# C (the side being connected to, the machine with intranet RDP)
listen: off
websocket:
  client:
    connect: <server-ip>:3002
    user: home
    pass: HomePass1234567890
    email: home@example.com
    direct:
      accept: true              # allow others to connect directly to self; listener starts on demand and frees when idle, no port occupied normally
    forward:
      - tag: rdp                # reuse the same whitelist: unmapped tags are all rejected
        target: 192.168.1.10:3389
```

```yaml
# A (the initiating side, entry on own machine)
listen: off
websocket:
  client:
    connect: <server-ip>:3002
    user: office
    pass: OfficePass1234567890
    email: office@example.com
    direct:
      rules:
        - listen: "both://:13389" # local entry, mstsc connects here; protocol prefix tcp://(default, optional)/udp://both://, RDP 8+ uses both://
          forward:
            email: home@example.com # directly connect to the subscriber with this email
            tag: rdp                # which rule in the peer's forward[] to pick (whitelist index), not the intranet target port; rejected if peer didn't configure this tag
```

Usage: `mstsc` connects to `127.0.0.1:13389`, but the actual bytes go over the A↔C QUIC direct connection, not through the server. Hole punching failure fails directly (connection closed, log states where each candidate got stuck), **no relay fallback** — to go via relay configure `server.forward` as in 8.2; the two paths don't fall back to each other. Fields and punching mechanism in [websocket.md](websocket.md#configuration-fields).

**When the carrier drops punching packets by plaintext signature**: add `direct.encrypt: true` to machine A (a one-time switch per client, not per rule; both ends must have it on or off; independent of `uuid`/`receive.allow`), see [websocket.md](websocket.md#punch-control-packet-encryption-directencrypt):

```yaml
    direct:
      encrypt: true
      rules:
        - listen: "both://:13389"
          forward:
            email: home@example.com
            tag: rdp
```

**When the two machines are actually on the same LAN**, you can manually add this machine's intranet IP as a candidate via `websocket.client.direct.lanAddrs` (no automatic NIC scan), so direct connection prefers the LAN over routing through the public network; see [websocket.md](websocket.md#multiple-paths-raced-simultaneously-winner-is-whoever-connects).

### 8.6 Direct file send/receive (no need for peer to run sshd/rsync)

Reuse the 8.5 direct channel to send/receive files. The peer only needs a directory; works cross-Windows without installing any service:

```yaml
# C (the side holding files, add this to C's 8.5 config)
websocket:
  client:
    direct:
      accept: true
    receive:
      dir: D:/incoming          # received files land here; also the root dir allowed to be fetched; without dir both send and receive are rejected
      allow:                    # one entry per {email, uuid}; empty = accept from no one
        - email: office@example.com
          uuid: 3fa85f64-5717-4562-b3fc-2c963f66afa6   # copy from A's startup log, see below
```

`email` is just a note/lookup aid; the real credential is `uuid` — the identity of this config, which can't be manually set in A's config file: A auto-generates it on first start and prints it in the log (also persisted to a hidden file with the same name in the config file's directory, e.g. `office.yaml` corresponds to `.office.uuid`, unchanged across restarts). Copy that value here (`receive.allow[].uuid` is a manually configurable field). Note it's "per config file" not "per machine": on the same machine, using `-c` to point at different config files generates independent uuids each, not shared.

**`allow` is bidirectional**: whoever is listed here can both send files to `dir` and fetch things under `dir`. So `dir` should point to a directory dedicated to file exchange; don't casually point it at an important location.

Neither direction needs a resident process; a single command runs and exits:

```bash
# push to peer (operator on A, sends A's files to C)
anyproxy -c conf/office.yaml -send D:/photos -to home@example.com

# fetch from peer (operator also on A, no one needed on C; path relative to C's receive.dir)
anyproxy -c conf/office.yaml -recv home@example.com:photos -to D:/pulled
anyproxy -c conf/office.yaml -recv home@example.com:photos/2024.zip -to D:/pulled
```

On punching failure it errors out and transfers not a single byte (non-zero exit code), so `anyproxy -send ... && echo ok` works directly in scripts. Design details (chunked checksums, resume placeholders, no overwrite on name collision, etc.) in [websocket.md](websocket.md#configuration-fields).

**When punching can't get through** (both sides behind strict NAT/CGNAT, e.g. the same carrier's big intranet where they can't see each other), no config change needed — C doesn't need `direct.accept`, and `receive` is reused as-is — just add one parameter to the command, recognized by both directions:

```bash
anyproxy -c conf/office.yaml -send D:/photos -to home@example.com -via relay
anyproxy -c conf/office.yaml -recv home@example.com:photos -to D:/pulled -via relay
```

Data is forwarded through B, but still end-to-end encrypted: the `uuid` configured in `receive.allow` is directly used as the derivation source for this transfer's encryption key; B forwards ciphertext and can't see file contents; in exchange it no longer depends on punching — as long as both A and C connect to the same B it works, at the cost of throughput limited by B's bandwidth. See [websocket.md](websocket.md#configuration-fields).

Note `-recv -via relay` (fetch via relay) requires server B to also be upgraded to this version, otherwise it errors out clearly; `-recv -via direct` is unaffected and B needs no change.

---

## 9. Same-host dual instance: A with TUN + B as egress (prevent loop, Linux)

A acts as global proxy and forwards to same-host B, which egresses in normal mode. **B must use `mode=bypass` to escape A's TUN**, otherwise a loop.
bypass mode is Linux only (macOS/Windows removed).

```yaml
# A: conf/a.yaml — global proxy, forwards to same-host B
mode: tun
tun:
  linux: { addr: 10.9.0.1/24, autoRoute: true, bypassIPs: [127.0.0.1] }
default:
  target: remote
  proxy: socks5://127.0.0.1:11000    # B's listener
```

```yaml
# B: conf/b.yaml — egress, binds physical NIC to escape A's TUN (Linux only)
listen: :11000
mode: bypass
tun:
  linux:
    device: eth0                      # empty = auto-detect default route NIC
loopGuard:
  minActive: 1000                     # fallback circuit breaker, on by default
  ratio: 80
```

See [multi-instance-loop.md](multi-instance-loop.md).

---

## Appendix: command-line overrides

`listen`/`proxy`/`mode` etc. can override config via command line (command line wins), convenient for running different instances from one config:

```bash
./anyproxy -c conf/router.yaml -l :3001 -p 'socks5://127.0.0.1:10000'
./anyproxy -c conf/router.yaml -mode tun
```

Full parameters in [cli.md](cli.md).
