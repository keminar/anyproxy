# websocket intranet penetration

anyproxy ships a websocket long-connection based intranet penetration: the **intranet side actively dials back to the public side**, after which the public side sends traffic to the intranet over websocket. It fits scenarios where the intranet sits behind NAT with no public IP (remotely accessing a home/office machine, exposing intranet services).

The code lives in the [nat/](../nat/) package; configuration is under the `websocket` section of `router.yaml` ([utils/conf/router.go](../utils/conf/router.go)).

## Two roles

| Role | How to determine | Responsibility |
|------|------------------|----------------|
| **Server** (public side) | configured `websocket.server.listen` (or `-ws-listen`) | starts a websocket listener on `/ws`, waits for subscribers to connect; receives traffic from outside and forwards it over ws |
| **Subscriber** (intranet side) | configured `websocket.client.connect` / `websocket.clients[]` (no command-line equivalent, config file only) | actively dials back to the server, authenticates, subscribes; after receiving a connection from the server, dials the intranet target; can dial back to multiple servers simultaneously, see "Subscribing to multiple servers" below |

One process can simultaneously be a normal proxy + server/subscriber (the listening port is shared within the same process). The direction is always **subscriber → server** for the long connection.

> **Pure penetration without starting a proxy listener**: set `listen` to `off` (or `-l off`), and the process only runs the websocket background, without binding a local proxy port. This fits scenarios that only do **bare TCP forwarding**; the **HTTP-header subscription path depends on the local proxy port, and stops working once it is disabled**. See "Configuration fields" at the end.

## Exposing only one port: subscriber reaches B's own websocket.server via B's proxy

Normally the server (B) must separately expose the `websocket.server.listen` port. But B has already exposed its core proxy port (`listen`/`-l`, default `:3000`) — and that proxy itself can CONNECT/SOCKS5 to any target, including B's own loopback address. So the subscriber can instead "first connect to B's already-exposed proxy port, then have that proxy make one more hop to B's locally-bound, non-exposed `websocket.server`", and B only needs to keep one public port open:

```
subscriber ──HTTP CONNECT / SOCKS5──▶ B's proxy port (exposed, e.g. :3000)
                                      │ CONNECT/SOCKS5 to 127.0.0.1:8080
                                      ▼
                           B's local websocket.server (bound to 127.0.0.1 only, not exposed)
```

```yaml
# B
websocket:
  server:
    listen: "127.0.0.1:8080"   # bound to loopback only, not exposed to the outside

# subscriber
websocket:
  client:
    connect: "127.0.0.1:8080"        # that loopback address of B above (only reachable through the proxy)
    proxy: "http://<B's public IP>:3000"  # B's already-exposed proxy port; socks5:// also works
```

`connect` still holds the target address to connect to (here B's loopback address); `proxy` only tells the local machine "who to go through when connecting to it". A loopback target itself is not subject to B's `allowIP` limit (see the `allowIP` row in "Configuration fields" below), so no separate configuration is needed for this path.

## Two forwarding paths

The server tags each forward with a type (`ConnHTTP` / `ConnTCP` in `nat/message.go`); the two paths number their connection IDs independently from 1, never interfering with each other.

### Path A: HTTP header subscription forwarding (`ConnHTTP`, legacy path)

Routes a request from the public side into a specific subscriber based on **HTTP request headers**, after which the subscriber's **local proxy** initiates into the intranet.

```
public client ──HTTP request (with Anyproxy-Action: websocket + headers matching a subscription)──▶ server :3000 proxy entry
                                                                           │ match subscriber by header
                                                                           ▼ (websocket long connection)
                                            subscriber ──dial local proxy 127.0.0.1:ListenPort──▶ intranet target
```

- Trigger: the request comes in through the server's **proxy listening port**, carrying the header `Anyproxy-Action: websocket` (the `response()` in `proto/http.go`). `CONNECT` requests are not supported on this path.
- Selecting the subscriber: the server uses the request headers to match each subscriber's `subscribe` (`GetClient` in `nat/client_hub.go`, a hit on `header.Get(key) == val` selects it). If nothing matches, it falls back to ordinary forwarding.
- Landing: on receiving it, the subscriber dials **its own local proxy** (`127.0.0.1:ListenPort`, `dialProxy` in `nat/handler.go`), replays the original HTTP request verbatim, and the subscriber's router rules then decide what follows (direct / re-proxy).
- Fits: directing "public requests carrying a specific marker" into an intranet environment to go through its proxy.

### Path B: port forwarding (`ConnTCP`, new path)

The server opens a **bare entry port**, and the whole TCP connection is bridged to the subscriber over ws; the subscriber dials a **hard-coded intranet target**. This is a reverse tunnel, i.e. intranet penetration. The same port can additionally open a parallel UDP channel, see below.

```
any client ──TCP──▶ server :2222 (bare TCP listener)
                     │ select subscriber by email
                     ▼ (websocket long connection)
     subscriber ──dial hard-coded target 127.0.0.1:22──▶ intranet sshd
```

- Server: each `websocket.server.forward[].listen` starts a bare TCP listener (when `listen` carries a `udp://`/`both://` prefix, a UDP relay on the same port is also started) (`StartForward`/`listenForward` in `nat/forward.go`); each incoming connection is bridged to a subscriber by that rule's `email` (`GetClientByEmail`).
- Subscriber: `websocket.client.forward[].port → target` builds a mapping (`buildForward` in `nat/forward.go`, one copy per server connection). When a connection arrives on the entry port `Port`, it dials the corresponding `target`; **if `Port` is not in the local mapping it is rejected** (`dialForCreate` in `nat/forward.go`) — an inherent whitelist. The rejection reason is returned to the server via `METHOD_CLOSE` (`Bridge.CloseReason`), folded into the server's own `nat forward closed ... reason=peer close: ...` summary line — no need to cross machines to dig through the subscriber's local logs.
- Fits: exposing any internal TCP service such as a web server or database (e.g. remote SSH, intranet web).

#### The second channel of Path B: UDP relay (`listen: "udp://..."` or `"both://..."`)

The channel above only carries TCP. Adding the `both://` prefix to `listen` makes the server start a UDP listener on the **same host:port**; UDP follows its own path, independent of the TCP one:

```
mstsc ──TCP 3389──▶ B:2222 ──websocket(TCP)──▶ C ──▶ 127.0.0.1:3389
mstsc ──UDP 3389──▶ B:2222 ═══════UDP════════▶ C ──▶ 127.0.0.1:3389
```

```yaml
websocket:
  server:
    forward:
      - listen: "both://:3389"   # protocol prefix: tcp://(default, optional)/ udp:// / both://
        email: c@example.com
```

The subscriber needs no change: the landing target still consults the same `client.forward[port] → target` whitelist, and unmapped ports are rejected the same way.

**Why a separate channel instead of stuffing UDP into the websocket**: websocket runs over TCP; stuffing datagrams into it means re-wrapping every packet with retransmission and ordering — drop one packet and every already-arrived frame behind it must queue waiting for it. That is precisely what the RDP UDP channel deliberately avoids, and doing it would only be laggier than pure TCP. Here all three segments are UDP end to end, so a dropped packet is just a dropped packet, not amplified into a stall.

**Why no hole punching**: both ends initiate actively from inside their NAT, and B is public. `mstsc → B` is initiated by A; the `C → B` upstream is initiated by C, which opens a mapping on C's own NAT on the way out, and B simply replies along it. Mappings age out, so C sends a keepalive packet every 20 seconds.

**The upstream is request-driven** (same idea as Path C): C normally occupies no UDP port and sends no keepalive. Only when B receives the first client datagram does it send `u_open` over websocket to have C build the upstream, buffering up to 16 datagrams while waiting; once C registers it backfills. The cost is that the first packet waits one round trip — RDP's UDP channel is negotiated after the TCP main channel, so it already has slack, and it retries on its own. After all sessions idle for 30 minutes, C tears down its upstream socket and B forgets the endpoint.

**The B↔C segment carries an 8-byte header** (`magic | kind | session(4) | port(2)`, see `nat/relay_udp.go`). The session number tells C which client to send the return packet back to — so each client the intranet target sees is a **separately independent source port**, never merged into one. The port number is carried on every packet, not just the first: UDP reorders, and binding it to the first packet would make the target unresolvable once reordered. The packet sent to the client is a **bare** datagram; the header exists only between B and C.

**Spoofing the upstream**: when C registers it must present the one-time token that B pushed down over websocket; after registration, only packets from that exact endpoint are treated as upstream. Looking at the header magic alone is not enough — otherwise anyone sending a packet starting with `0xA5` could inject data toward the client.

**Two known limitations**:

- **Each packet on the B↔C segment costs an extra 8 bytes**. RDP-UDP itself probes the path MTU to B, unaware of one more hop that adds a header. The actual payload sits around 1200, far from 1500, so it is basically never hit; applications that genuinely fill the MTU should take note.
- **The relay itself is not encrypted**. The `mstsc → B` segment is the client sending bare datagrams directly, which can't be wrapped in a layer to begin with, so encrypting only B↔C does not make the whole path private. RDP's UDP channel has its own DTLS and is unaffected; but for another cleartext UDP protocol you must consider it yourself. For true end-to-end confidentiality, use Path C's direct (that one is QUIC, encrypted throughout).

### Path C: QUIC direct (`direct`, data does not pass through the server)

The first two paths forward all data through the server, which must ingest the entire traffic. This path moves the **entry onto the subscriber's own machine**, and the two subscribers connect directly over QUIC; the server only exchanges candidate addresses and touches no data bytes.

```
any client ──TCP──▶ A (subscriber) :13389 (local entry listener)
                        │ ① ask server over ws for C's endpoint, and have C punch toward me
                      server B (signaling only)
                        │ ②
                        ▼
     A ══QUIC direct (v4/v6/port mapping, best of)══▶ C (subscriber) ──dial client.forward[port]──▶ intranet RDP
```

The code is in [nat/direct.go](../nat/direct.go), [direct_entry.go](../nat/direct_entry.go) (A side), [direct_accept.go](../nat/direct_accept.go) (C side), [direct_broker.go](../nat/direct_broker.go) (server signaling), [direct_reflect.go](../nat/direct_reflect.go) (UDP reflector).

**Why a UDP reflector is required**: websocket is TCP, so the address the server sees on this connection is the subscriber's **TCP socket** address; whereas QUIC uses another UDP socket. A machine often holds multiple addresses simultaneously (IPv6 stable address + the rotating privacy temporary address RFC 4941, or multiple NICs), and the kernel selects source **per destination** per RFC 6724, so the two are not guaranteed to match; the external port is likewise decided by the NAT along the way. So the endpoint must be asked for by the subscriber **using the QUIC socket itself** from the reflector. The reflector automatically binds to the same port number as `websocket.server.listen` (TCP/UDP do not conflict, and binding dual-stack answers both families), derived by the subscriber from the `connect` address, requiring no extra configuration.

**Why hole punching is still needed**: the IPv4 side is NAT, and the IPv6 side, while lacking NAT, has home routers defaulting to stateful firewall that blocks unsolicited inbound — both cases require sending from inside first to open a return channel. So before A initiates, the server first has C spray a few UDP packets toward **each of A's candidates**, opening on C's side the state that allows A's return packets, so A's QUIC Initial can get in.

**A punch packet is not a connection**: PUNCH/PONG are custom cleartext (or, see encryption below) UDP packets that quic-go cannot recognize, so they are handed to `drainNonQUIC` for separate handling and are unrelated to the QUIC protocol; they only open holes in the local NAT/firewall and, incidentally, measure RTT with a single round trip. The real connection is the subsequent independent QUIC/TLS 1.3 handshake (`dialQUIC`) with certificate fingerprint verification. **This handshake is always initiated by A (`tr.Dial`) and accepted passively by C (`ln.Accept`)** — it does not reverse regardless of who punched first or whether `-send` or `-recv` is used — C punching toward A (`punchOnly`) only pre-opens the hole on its own side for the QUIC Initial that A is about to send; C itself never actively dials out; when all punching fails, A falls back to concurrently racing real QUIC dials against all candidates (see below), but the initiator is still A.

Configuration:

```yaml
# C (the connected-to party, the machine holding the intranet target)
websocket:
  client:
    connect: "[2001:db8::1]:3002"   # reflector on the same port's UDP; when the server has addresses in both families both are probed
    user: someuser
    pass: somepass
    email: home
    direct:
      accept: true                   # allow others to connect to me directly (listener starts on demand, no port occupied normally)
    forward:                         # reuse the same whitelist: unmapped ports are rejected
      - port: 3389
        target: 192.168.1.10:3389

# A (the initiator, the entry is on its own machine)
websocket:
  client:
    connect: "[2001:db8::1]:3002"
    user: anotheruser
    pass: anotherpass
    email: office
    direct:
      rules:
        - listen: "both://:13389"    # local entry, mstsc connects here; protocol prefix tcp://(default, optional)/udp:///both://
          email: home                # connect directly to the subscriber with this email
          forwardPort: 3389          # which rule in the other side's forward[] (whitelist index), not the intranet target port; rejected if the other side didn't configure this index
```

### Multiple paths raced simultaneously, winner is whoever connects

The A↔C hop no longer only uses IPv6. Four classes of candidates are probed and punched **simultaneously**, and whichever connects first is observed first:

| Candidate source | How it is obtained |
|---|---|
| Reflector IPv4 endpoint | asking the server's UDP reflector with the QUIC socket (the IPv4 family) |
| Reflector IPv6 endpoint | same as above, the IPv6 family |
| Port mapping | actively requesting an external port from the home router (PCP / NAT-PMP / UPnP, tried in parallel); **not tried by default**, see below |
| `direct.lanAddrs` | the local LAN IPs the user manually fills in `websocket.client.direct.lanAddrs`, spliced with the current QUIC port directly as a candidate, without going through the reflector/port mapping |

Failure to probe any one path just means one fewer candidate and does not affect the others — that is exactly the point of multiple candidates. Previously only IPv6 was probed, and a failed probe meant the whole direct connection was dead.

**Local interface addresses (IPs on NICs) are not auto-collected by default**. Such candidates only help "two machines on the same subnet", while the scenarios here are mostly cross-network — the two machines sit in different networks, separated by CGNAT or true public Internet. The reason for not auto-scanning is that a machine often has multiple NICs (physical NIC, container bridge, VPN virtual NIC, etc.), and most enumerated addresses are meaningless to the peer, only consuming slots in the server's candidate cap (see below) and interfering with troubleshooting. If the user explicitly knows which LAN segment the two machines actually share, they can use `websocket.client.direct.lanAddrs` to manually add that segment's local IP as a candidate, participating in punching/QUIC dial racing — only fill the IP, not the port (the port changes over the connection's lifetime and would be void if filled); an unreachable address times out and silently loses like other candidates, with no side effects.

**Priorities only matter once multiple paths connect**, by measured RTT plus an address-type bias (effectively subtracting a bit of RTT, making it easier to win):

| Address type | Bias | Meaning |
|---|---|---|
| Loopback | −50ms | highest priority, same machine |
| Link-local | −30ms | next, same L2 |
| Private address / CGNAT | −20ms | same-subnet direct beats going through the public Internet |
| Public address | 0 | baseline |

**Public IPv4 and public IPv6 compete equally**, both with a 0 bias, pure measured-RTT comparison. Whichever connects first and is faster wins — there is no a-priori "prefer IPv6".

The bias makes closer addresses "more likely" to win, not unconditionally: a private address 15ms slower than public still wins, 30ms slower should lose.

Which one was chosen and why is visible in the logs, with each candidate's RTT, bias, and final score:

```
path selection for home: 192.0.2.10:41203(v4) rtt=38ms bias=0s score=38ms,
  [2001:db8::53]:41203(v6) rtt=22ms bias=0s score=22ms <-
```

Questions like "why didn't it use IPv6" are only answered by this line.

**Punching and speed measurement are the same action**: send a punch packet, the peer auto-replies with a pong. The send opens the return channel on this machine's firewall/NAT (IPv6 has no NAT, but home routers block unsolicited inbound by default, needing it too), and the return is the RTT of this path. Only the winning path gets one QUIC dial — not a QUIC dial per candidate, which would be N full handshakes, whereas a punch packet's round trip is enough to judge connectability and speed.

**Fallback when all candidates fail punching: QUIC dial racing**. A stateful firewall/operator device may block the custom PUNCH protocol by its cleartext signature, but the real QUIC Initial on the same socket is a standard TLS 1.3 handshake, hard to block specifically. So total punch failure is not declared dead immediately; instead, real QUIC dials are raced in parallel against **all** candidates, and whoever completes the handshake first wins; if more than one candidate succeeds (e.g. two networks are both up at the time), the first to answer is selected and the later-arriving connections are closed in the background without leaking. This is only the last step of Path C's internal retries, and **still has no relay fallback** — only when all candidates (including dial racing) fail is it truly failed; to go through a relay, configure `-via relay` or `server.forward` as below.

**What port mapping can and cannot save**: it handles **symmetric NAT** — the kind that assigns a different external port per destination, where the reflector's probed port is useless to a third party, and you can only ask the router directly for a hole. It **cannot save CGNAT**: the router mapping succeeds but you only get the ISP's internal address, still unreachable from outside unless the ISP itself supports PCP (essentially nonexistent domestically). Failure of all three protocols is normal, just one fewer candidate.

**Port mapping is not tried by default; it is only attempted when `client.direct.portmap: true`**: the hit rate of all three protocols on home routers is very low (most are disabled by default or unsupported entirely), and probing must wait for each protocol's timeout — in practice it can consume one or two seconds of `gatherCandidates`. For most users, turning it on only adds three more failure-reason lines to the log and makes the direct connection wait a bit longer, never actually providing a candidate; only enable it when you confirm your router supports it and suspect you are behind symmetric NAT.

**Address families of the three segments**:

| Segment | Address family | Note |
|---|---|---|
| Initiator → A entry | unlimited | `listen: ":13389"` binds `[::]` dual-stack, IPv4 clients still connect fine |
| A ↔ C | unlimited | QUIC socket binds dual-stack, both families' candidates compete on the same source port |
| C → intranet target | unlimited | a target with an IPv4 intranet address in `forward` is the most common usage |

Note the entry address form: `:13389` is dual-stack; `127.0.0.1:13389` listens on IPv4 only (enough for local access), and `[::1]:13389` listens on IPv6 only.

**Why the QUIC socket must be one dual-stack socket**, rather than one each for v4/v6: the hole opened on the peer's firewall is recorded by "local ip:port ↔ peer ip:port". Two sockets mean two source ports, and the state opened there won't match what this side actually dials with.

**Punch order also decides success or failure**: when crossing "operator CGNAT home broadband ↔ public cloud host", the residential/CGNAT side must send the first packet, otherwise its NAT mapping gets poisoned and both directions die — this is documented separately, see [direct-punch-order.md](direct-punch-order.md).

### Punch control packet encryption (`direct.encrypt`)

The PUNCH/PONG/WHOAMI/SEEN punch control packets are a cleartext ASCII protocol, running on a separately multiplexed side-channel over the QUIC socket, not protected by QUIC's own TLS — some operator devices identify and drop them by the cleartext signature, a root cause confirmed when troubleshooting telecom/Unicom punch failures.

`client.direct.encrypt: true` adds a layer of AES-256-GCM to the punch control packets sent by the local machine as the punch initiator (A): the **key is derived from this session's one-time `token`** (generated by A, sent to the peer via server B's signaling, so both sides have it), deriving bidirectional keys per role, each packet using an independent random nonce (no incrementing counter, to fit the unordered concurrent UDP punch scenario).

**Why token rather than uuid, and therefore no identity configuration needed**: the **sole purpose of this encryption is anti-DPI** (erasing the cleartext signature), **not authentication** (authentication is elsewhere). The key only needs to be "held by both sides, and invisible to the operator DPI middlebox" — `token` fits exactly (it is only transmitted inside the TLS-protected signaling, which DPI cannot see on the punch path). So `direct.encrypt` is a **pure toggle**: on and usable, **no `uuid` / `receive.allow` needed**. (B can see the token and theoretically decrypt punch packets, but punch packets only carry `verb+nonce`, no secret — it guards against the operator, not B.)

**Per-client one-time toggle, not per `direct.rules[]` rule**: applies simultaneously to `direct.rules[]` port forwarding and `-send`/`-recv` file transfer.

**Pure opt-in**: off (default) is exactly the same protocol as before, zero behavior change. **Note both ends must have it on (or both off) to match** — one end encrypted and the other unrecognizing will drop the punch packets.

```yaml
websocket:
  client:
    direct:
      encrypt: true   # pure toggle, no uuid/receive.allow needed; applies to rules[] and -send/-recv simultaneously; both ends must match
      rules:
        - listen: "both://:13389"
          email: home
          forwardPort: 3389
```

### Blind forwarding relay via VPS (`via` / `direct.relay`)

When both A and C are behind restricted CGNAT and simply cannot connect directly to each other, but each can reach a public VPS, let the VPS act as a **blind forwarding relay**: add `via: <VPS's email>` to A's direct entry rule, and the VPS machine sets `direct.relay: true`.

The key is that this VPS **needs no per A-C configuration** (no `forward`/`direct.rules`/`receive.allow`), just one master switch. On receiving a relay request it opens a dedicated UDP socket for that pair, probes its own public endpoint E, has both A and C punch toward E, then **blindly forwards opaque UDP packets between the two source addresses** — it does not terminate TLS, does not parse QUIC, and sees no cleartext throughout.

```
   A ─────(QUIC-TLS end-to-end, VPS cannot see cleartext)───── C
   └───────────▶  VPS dedicated relay socket  ◀──────────┘    data does not pass through B; B only exchanges addresses/fingerprints
```

- **Signaling almost fully reuses the direct set**: `d_request` adds `via`, `d_punch` adds a relay-leg marker, `d_offer`/`d_ready`/`d_punching` are used as-is, only a new `d_relay_open` is added (B→VPS to open a socket and probe E).
- **Both legs are "resident→cloud" punching**: A and C both punch first, the VPS waits for their respective nudges before punching back (reusing the `direct.punchFirst` ordering mechanism). If either leg fails to punch, the whole relay fails, with no further fallback.
- **Authentication is end-to-end between A↔C, bypassing the untrusted VPS**: A uses C's certificate fingerprint to fix-verify the peer is the real C; C does a one-time **uuid challenge-response** on the first stream of the e2e QUIC (sends a random nonce, A replies `HMAC(uuid, nonce ‖ C's certificate fingerprint)`), verified against A's uuid in its own `receive.allow` — **the uuid never goes on the network**, bound to C's fingerprint to prevent VPS-layer replay. So C must configure A's uuid in `receive.allow` (reusing the same list as file transfer).
- **`direct.encrypt` is unrelated to the relay**: the relay's security does not depend on it; it only anti-DPIs the two legs' punch packets.
- **Session reuse includes the full entry/route identity**: A keys reusable QUIC sessions by `listen + target email + forwardPort + via`; different local entries, direct versus relayed paths, and different relay VPSes cannot accidentally reuse one another's session. Isolating `listen` also prevents two UDP rules for the same target port from overwriting each other's return entry.

**Requirement on the VPS: a stable, inbound-reachable public endpoint.** The VPS normally derives E from the reflector probing its own egress mapping, which is fine under **1:1 public IP or endpoint-independent (EIM/cone) NAT** (a normal cloud host 10.x→fixed 49.x is this case). But if the VPS sits behind a **NAT gateway with per-flow random egress IP/port (symmetric)**, the reflector-probed egress ≠ the inbound mapping corresponding to A/C's packets, and the relay fails (same reason as symmetric NAT being unpunchable). In that case, configure a **fixed DNAT inbound rule** on this VPS (public `IP:port` → the VPS's same UDP port), and explicitly fill that public endpoint with `direct.relayPublic`: it skips the reflector and binds the relay socket to that port, with inbound always open regardless of egress randomness. One port can only carry one concurrent relay pair; for more concurrency, configure more ports (each with its DNAT/security group). Of course, the easiest is still giving the relay VPS a real 1:1 public IP.

For a VPS with multiple directly assigned public IPs where routing selects a different source IP for different destination networks, put bare IP addresses (without ports) in `direct.relayPublic`. Every relay binding keeps its own random port and advertises that port on every configured public IP, so A/C can punch all paths. For fixed DNAT, make every entry an `IP:port` endpoint instead. The two forms cannot be mixed.

#### Diagnosing multi-egress routing with `ip route get`

Automatic reflection discovers only the public address selected when the VPS reaches the reflector. If policy routing selects another source IP toward A or C, the advertised endpoint and the VPS's actual reply source differ. A common symptom is that one leg consistently succeeds while the other logs `nudged, punching toward ...` without ever logging `first packet from leg ...`.

Take the reflector, A-candidate, and C-candidate IPs from the logs and query each route on the VPS. The addresses below are RFC 5737 documentation-only examples:

```bash
ip route get 203.0.113.53       # example reflector
ip route get 192.0.2.20         # example A candidate
ip route get 198.51.100.20      # example C candidate
```

Compare the `src` field:

```text
203.0.113.53 via ... dev eth0 src 192.0.2.10
192.0.2.20 via ... dev eth0 src 192.0.2.10
198.51.100.20 via ... dev eth0 src 198.51.100.10
```

Here the reflector and A use `192.0.2.10`, while C uses `198.51.100.10`. Default reflection advertises only the former; if C punches only that endpoint, its address-dependent NAT/firewall may reject replies sourced from the latter. Advertise both directly assigned public IPs in bare-IP form so every random relay port becomes a candidate on both addresses:

```yaml
direct:
  relay: true
  relayPublic:
    - "192.0.2.10"
    - "198.51.100.10"
```

When active, logs skip `probing reflector(s)` and show multiple IPs with the same random port in one binding. If every `ip route get` command shows the same `src` but the path still fails, remember that this command shows only the host's route choice; an upstream SNAT may still rewrite the external IP or port, so verify the observed source with packet capture at A/C or outside the VPS.

```yaml
# A (resident, CGNAT): add via to the entry rule
websocket:
  client:
    direct:
      punchFirst: true
      rules:
        - listen: "both://:13389"     # mstsc connects here
          email: home                 # final target C
          forwardPort: 3389
          via: relay-vps              # relay through this VPS

# VPS (public): one switch, no per-pair config needed
websocket:
  client:
    direct:
      relay: true
      # relayAllow: [office]          # optional: only allow specified source emails

# C (resident, CGNAT): same as usual direct.accept + forward, plus recognize A's uuid in receive.allow
websocket:
  client:
    direct:
      punchFirst: true
      accept: true
    forward:
      - {port: 3389, target: 192.168.1.10:3389}
    receive:
      allow:
        - {email: office, uuid: <A's uuid>}
```

For the full design (signaling flow, failure semantics, authentication derivation, code locations) see [direct-relay-design.md](direct-relay-design.md).

### File transfer (`-send` / `-recv` / `receive`)

The tunnel itself can run scp/rsync, but that requires sshd on the peer — which often doesn't hold across Windows (the OpenSSH server is an optional feature, off by default). So a built-in file transfer is provided, **requiring no extra service on the peer machine**; anyproxy reads and writes files itself.

Two directions, each a one-shot process that runs a single command and exits:

| | What it does | Who operates |
|---|---|---|
| `-send PATH -to EMAIL` | push the local file to the peer | the sending machine |
| `-recv EMAIL:PATH -to DIR` | fetch the peer's file back locally | **the machine fetching**, the peer needs no one around |

Only one configuration block is shared by both directions (the direct path also requires `direct.accept` on):

```yaml
websocket:
  client:
    direct.accept: true
    receive:
      dir: D:/incoming            # received files land here, also the root directory allowed to be fetched; if not set both send and recv are rejected
      readonly: false             # when true, dir can only be fetched from, not written to by anyone
      allow:                      # one {email, uuid} per entry; empty = accept from no one
        - email: office@example.com
          uuid: 3fa85f64-5717-4562-b3fc-2c963f66afa6
```

**`allow` is bidirectional**: someone listed here can both send files into `dir` and fetch anything under `dir`. This is intentional — receive and fetch are symmetric actions aimed at the same set of people (often your own other machines), not worth maintaining two nearly identical lists. Be clear about the cost: **adding a person = handing them both read and write of that directory**, so `dir` should be a directory specifically for exchanging files, not arbitrarily pointing at something important. When fetching, the peer only gets what is inside `dir` (paths are checked segment by segment, `..`, absolute paths, and symlinks pointing outside the directory are all rejected).

To give read but not write, use `readonly: true` — `dir` becomes out-only, others' `-send` get an explicit rejection, `-recv` works as usual. This is for "exposing a set of files for several machines to come fetch on their own" (install packages, backups, release artifacts): that scenario doesn't need the peer to write anyway, while `allow` grants read and write together once filled. Rejection happens at the protocol layer, not dependent on filesystem permissions — whether the directory is read-only at the OS level is none of anyproxy's business or assumption.

The `email` in `allow` is only a note/lookup aid — marking whose machine this `uuid` belongs to; the server (B) never verifies it, and anyone with a valid account password can fill someone else's address in their own `client.email` (`email` is "for locating users, not for authentication" by design, see "Configuration fields"). The real credential is `uuid`: the peer must carry a `websocket.client.uuid` identical to the one configured here to pass verification (exact comparison on the direct path, decryption capability on the relay path, see below).

The sender's `websocket.client.uuid` cannot be configured manually (there is no such field in the config file): a random value is auto-generated at startup, persisted to a **hidden file** with the same directory and name as the config file (`router.yaml` → `.router.uuid`, `office.yaml` → `.office.uuid`; on Windows it also gets the hidden attribute. After generation it is printed in the startup log for easy copying), and does not change on restart. It is state maintained by the program itself rather than configuration, so it is not placed prominently alongside `router.yaml` — when copying the config, don't take it along by hand, because two machines sharing one uuid means one identity. An old-version `router.uuid` (without the dot) is auto-renamed to `.router.uuid` on next startup, with the uuid value unchanged, so the peer's `receive.allow` needs no change. Copy this value once from the sender's startup log and fill it into the receiver's `allow[].uuid` here.

Identity is divided by **config file**, not by physical machine: multiple `client` blocks under the same config file (`websocket.clients[]`) share one uuid; but pointing `-c` at different config files (even in the same directory) generates independent uuids that are not shared — this is consistent with the premise that "one config file is itself one independent setting that can be copied elsewhere on its own", without guessing whether two configs describe the same physical machine.

This is the key difference from the old version: the old `allow` was a pure email list, but email was never authenticated at B, so `allow` was effectively useless. Now it is email (for lookup) + uuid (the real credential): uuid is a randomly generated high-entropy value, not public information the peer already knows like email, so merely knowing the peer's email address is insufficient to impersonate.

The sender (one command, exits after transfer):

```bash
anyproxy -send bigfile.zip -to home@example.com
```

```bash
anyproxy -send D:/photos -to home@example.com    # recursive directory, receiver keeps the same structure
```

Multiple paths directly follow: `anyproxy -send a.zip -to home@example.com b.zip D:/dir`.

**If punching fails, it reports failure and transfers not a single byte** — this path has no fallback through the server relay, consistent with the direct entry convention. On failure the exit code is non-zero and the reason prints to the terminal, so `anyproxy -send ... && echo ok` works directly in a script.

#### Reverse: `-recv` actively fetches from the peer (no one needs to operate on the peer)

`-send` requires someone to run a command on the machine holding the file. But the common case is the opposite: you are on A, want a file on C, and no one is at C — a server in a data center, a NAS at home with no one watching. `-recv` is this direction, written like scp:

```bash
anyproxy -recv home@example.com:backup/db.sql -to /data/in   # fetch one file
anyproxy -recv home@example.com:backup       -to /data/in    # fetch a whole directory, structure rebuilt verbatim
```

The path after the colon is **relative to the peer's `receive.dir`** (not the peer's filesystem root), and must be written — not giving a path does not default to "the whole directory", because accidentally pulling the peer's entire shared directory with a typo shouldn't be possible. `-to` is the local storage directory, defaulting to the current directory if not given.

When running: A first requests a manifest (one line per file, recursing for directories), prints the total count and total size, then fetches one by one, one line of progress per file. Any failure midway stops and exits non-zero, without leaving a "looks successful" half directory.

The prerequisite is fully symmetric with `-send`: A's `websocket.client.uuid` must be listed in C's `receive.allow` — that same list that lets C receive files A sends (see "allow is bidirectional" above).

In implementation, no reversal of connection direction is needed: A is still the punch/dial initiator, only it first says "give me this" on the stream, after which the two sides swap roles — C runs the sender logic, A runs the receiver logic, and landing, `.part` placeholders, SHA-256 verification, and no-overwrite of duplicates are the same code as `-send`.

#### Two paths, must be explicitly declared: `-via direct` (default) or `-via relay` (there is a third value, see below)

Both `-send` and `-recv` accept this parameter.

```bash
anyproxy -send bigfile.zip -to home@example.com -via relay
```

| | `-via direct` (default) | `-via relay` |
|---|---|---|
| How data travels | A↔C punch direct (Path C), does not pass through B | forwarded through B, via A and C's respective already-authenticated websocket connections |
| Encryption | QUIC encrypted throughout, B cannot see content | end-to-end encrypted with the key derived from the uuid in `receive.allow` (see below), B forwards ciphertext and likewise cannot see content |
| Prerequisites | receiver must enable `direct.accept`; punching may fail (both behind strict NAT/CGNAT) | receiver does **not** need `direct.accept`; transfer works as long as both A and C connect to the same B, no punching needed |
| Fail = reject | yes — not a single byte transferred | yes — also no silent fallback, the two paths do not fall back for each other |

`receive.allow` is valid on both paths, but verified differently:

- **`direct`**: the sender self-reports `(email, uuid)` in the QUIC stream header (already end-to-end encrypted, invisible to B), and the receiver looks up the expected uuid by email and compares character by character.
- **`relay`**: the uuid is directly used as the derivation source for this transfer's encryption key — the receiver looks up the uuid by the sender's self-reported email and uses it to encrypt/decrypt the entire payload; the ability to decrypt + pass verification is itself proof of identity, requiring no separate declaration. This brings an extra benefit: **the relay path is now also end-to-end encrypted**, and B only forwards ciphertext throughout, so even the values of fields like email/uuid need not be secret.

Which to choose: both paths are now end-to-end encrypted; the main factor is whether punching works — if it works, use `direct` (lower latency, no bandwidth on B); if punching fails, or both networks are known to be unpunchable (e.g. two machines in the same operator's large intranet can't see each other), use `relay`, at the cost of throughput limited by B's bandwidth.

**When punching fails but both can reach a public VPS, `-via` accepts a third value: an email of a VPS** (that VPS must have `direct.relay` on, see "Blind forwarding relay via VPS"):

```bash
anyproxy -send bigfile.zip -to home@example.com -via relay@example.com
```

`-via` has only two reserved keywords `direct`/`relay`; any other value is treated as a VPS's email — normal emails all carry `@`, so they won't literally collide with those two words. The punch target switches from the peer to the VPS's relay endpoint, QUIC/TLS remains end-to-end between the two subscribers, and the VPS only blindly forwards opaque packets (no content visible) — **not** the `-via relay` path that forwards through B, only "who to punch toward" is switched to the VPS. `receive.allow` needs one more verification: the receiver does a uuid challenge-response against the sender on the e2e QUIC stream header (nonce bound to the certificate fingerprint to prevent relay-layer replay), still against the same `receive.allow`, no extra config. Fits scenarios where both are behind restricted CGNAT and can't punch directly to each other, but each can reach that VPS.

**Version requirement**: `-recv -via relay` (fetch via relay) requires **server B to also be upgraded to this version** — when B forwards a relay request it reassembles a message, and old B doesn't recognize the new "this is a fetch not a send" marker, drops it, and C then treats it as receiving a file, finally returning an obscure error. The symptom is a clear failure (it won't silently transfer the wrong thing), but you need to know this part to understand it. `-recv -via direct` (fetch via punching) is unaffected: the data plane never passes through B, B only forwards addresses, not a single line needs changing.

Some design choices:

- **One file per QUIC stream**. Each file's result (what name it was saved as, whether verified, where it failed) is independent; an error in the middle doesn't scramble the whole batch's state; opening a stream on QUIC is almost free.
- **SHA-256 verification, with the digest placed after the data** (not in the header). Placing it after lets the sender compute while reading — putting it in the header would require reading the whole file first to compute the digest, a wasteful re-read for large files. If the receiver's digest doesn't match, it deletes the file and reports an error: keeping a file with wrong content but a correct name is worse than not receiving it.
- **Write `.part` first, then rename**. An interruption leaves something obviously incomplete, rather than a file that looks normal but is half content.
- **The `.part` name carries a random token, not a simple `target.part`**. The pitfall hit: when the sender exits abnormally (e.g. Ctrl+C mid-transfer), the goroutine handling that stream on the receiver keeps occupying the `.part` for a while before noticing the connection truly died — the data phase deliberately sets no read timeout (a large file on a slow link legitimately takes long), relying on QUIC's own idle timeout as the fallback, meaning cleanup of the old connection and a new retransmission may overlap in time. If both old and new used `target.part`, the new one's rename after finishing would collide with the file still held by the old goroutine, reporting "being used by another process" on Windows, and more subtly on POSIX — no error, but both sides writing the same inode may silently corrupt content. Each transfer using its own token to exclusively occupy one `.part` filename fundamentally prevents this collision.
- **Do not overwrite same-name files**, auto-rename with a numbered name: `x 1.zip`, `x 2.zip` (a space and the number appended to the file name body, extension unchanged). Overwriting silently destroys the receiver's existing data, a cost far greater than an extra numbered name; the actual saved name is reported back to the sender. The rename step is "atomically claim the name with `O_CREATE|O_EXCL`" rather than "first probe existence, then a separate Rename" — split into two steps across two independent processes it is not atomic: when two terminals send same-name files concurrently, both may see "nonexistent" at the probe moment and both pick the same name to Rename. `os.Rename` overwrites an existing target directly (Go on Windows uses `MOVEFILE_REPLACE_EXISTING` to deliberately smooth over the POSIX `rename()` difference, same behavior on both sides), and the later one silently eats the one the earlier just landed and already replied "Saved" — this is not Windows-specific, it happens on Linux/macOS too.
- **Same-name files and resuming can be negotiated by comparing contents first, then the user chooses (`-conflict`)**. Two independent situations:
  - **The target name already holds a complete file**: SHA-256 is compared. **Identical** → rename and resend / overwrite / skip; **different** → rename and resend / skip. "Rename" means the incoming file is saved under a new name and the existing file is left untouched; overwrite only happens when the user explicitly chooses it (senders in `receive.allow` can already write this directory, so there is no separate switch). **The target name never accepts a resume**: a transfer always writes a `.part` first and only renames it to the target after it is complete and verified, so whatever sits on the target name is a complete file.
  - **A previous interrupted transfer left a `.part` temp file** (`x.zip.<16 hex>.part`): if it is exactly the start of the new file (verified by hash) the transfer continues from that point, then the finished file is renamed to the target (if the target name is taken it is renamed as usual, never overwritten). **When a transfer is interrupted, what already arrived is kept in the `.part`** (only deleted if zero bytes arrived); the `.part` of a chunked `-parallel` transfer carries a `.chunks` marker, may have holes, and is never resumed. `.part` files are not cleaned up automatically; delete them by hand when no longer needed.
  - At a prompt, Enter = skip; an uppercase letter (`R`/`O`/`C`/`S`) applies the choice to all later conflicts. `-conflict` values: `ask` (default on a terminal, prompts per file), `rename` (auto-rename; the default when stdin is not a terminal, i.e. the old behavior: no probing, no resuming), `overwrite`, `skip`, `resume` (continue a `.part` if there is one; skip if the target holds an identical complete file; rename if it holds different content).
  - Works for both `-send` and `-recv`: for `-send` the check is on the **peer** (one extra probe round trip; the receiver reports the target name and any resumable `.part`, and only hashes when the file is not larger than the incoming one), for `-recv` it is **local** (the pull `hash` op asks the peer for the hash of the first N bytes).
  - Overwrite receives into a `.part` first and only replaces the existing file after the checksum passes; on error the existing file is untouched. Before taking over a `.part`, the receiver checks that the name is really that target's own `.part`, that no other transfer is writing it, and that its size matches what was negotiated; a bad tail checksum truncates it back. Resuming sends only the tail and is not split by `-parallel`.
  - The probe is a new frame that old receivers do not understand: with no answer within 10s the sender falls back to "receiver auto-renames" and says so once.
- **The fetch direction adds one more symlink check**. Receiving creates new files, so symlinks don't arise; fetching is different — a symlink inside the shared directory pointing at `/etc/shadow` cannot be stopped by the string checks above (the spliced path is indeed inside the directory), so after resolving the symlink, confirm again that it is still inside the directory. A shared directory reached via a symlink (macOS `/tmp` → `/private/tmp`) is a normal config; both sides resolve then compare, no false positives.
- **Both `-send` / `-recv` are independent processes**, not requiring a running anyproxy locally. Sending/receiving files is an action with clear start and end, and an independent process's exit code expresses success or failure. It temporarily opens one more websocket, not affecting the resident one — the direct signaling is returned on "the connection that initiated the request", not looked up by email.
- **If the resident config exists only to give `-send`/`-recv` credentials, no extra config is needed**: when the anyproxy resident process starts, it judges for each `websocket.client(s)` whether it's worth initiating a resident connection — if `subscribe`/`forward`/`direct.rules`/`direct.accept`/`receive.dir` are all empty, it auto-skips (this config remains intact, the resident process just won't connect to it; running `-send`/`-recv` still uses this config's credentials normally). This is because the server uses the same judgment: an empty `subscribe` that is neither a forward target / direct party / receiver gets continuously rejected and disconnected by `serveWs` (log spams `ignore, subscribe is empty`), and the resident process connecting to it is just keeping it company. To force skipping (even if some of these are configured), explicitly add `sendRecvOnly: true`.

**Throughput on a gigabit link (direct only; relay is limited by B's bandwidth, not affected by this)**: the QUIC receive window has been tuned for gigabit (32MB per stream / 64MB per connection). quic-go's default (6MB per stream) is set for web traffic, with a throughput ceiling roughly `window / RTT` — 6MB at 50ms RTT leaves only about 960Mbps, and at 100ms drops to about 480Mbps, exactly hitting cross-province large-file transfers. On Linux you must also ensure the UDP receive buffer is large enough (`anyproxy -check` checks `net.core.rmem_max`), otherwise quic-go prints "failed to sufficiently increase receive buffer size" and can't fill the link.

**Abnormally high packet loss, congestion window won't climb, switch machine/network and it's fine: try `-direct-plain-udp`**. A real case hit: on the same link, with no parameters added, 1.7% packet loss, congestion window stuck near the initial value (tens of KB, hundreds of KB/s); after adding this parameter, 0 packet loss, window normally climbs to hundreds of KB～MB level (more than tenfold speedup).

Principle: quic-go has an internal fast path for a real `*net.UDPConn` (batch send/receive, reading ECN marks, etc.), at the cost of needing to assert the passed-in `net.PacketConn` back to `*net.UDPConn`. This assertion is "successful but toxic" on some machines — the NIC driver, virtual NIC (VPN, etc.) have compatibility issues with the syscalls this path depends on, dropping or scrambling packets, and quic-go treats this as real network congestion, so the congestion window never climbs. `-direct-plain-udp` wraps the socket handed to quic-go in a do-nothing, forward-only dumb shim, making that type assertion fail, so quic-go falls back to the plainest per-packet send/receive — counterintuitively faster and cleaner.

Troubleshooting: with `-debug 2`, quic-go prints `connection doesn't allow setting of receive buffer size. Not a *net.UDPConn?` (`-debug 2` itself, for logging needs, also triggers the same assertion failure, with the side effect of incidentally bypassing this fast path). If adding `-debug 2` drops the packet loss rate sharply and the congestion window climbs normally, that's this issue — just keep `-direct-plain-udp` on long-term; it doesn't log per-packet, so it lacks the `-debug 2` overhead.

`-direct-plain-udp` is a global default; when the resident process configures multiple `websocket.client` (`clients` array) going through different NICs/network paths, the problem usually only appears on one path's NIC driver, and shouldn't sacrifice the other paths' normally-working fast path to work around it — in that case, configure `direct.plainUdp: true` (or `false`) in that corresponding `client` block to override the global default; if not configured it follows the command-line value.

#### Single large file chunked parallel transfer: `-parallel N`

By default each file occupies only one connection (one QUIC stream on `direct`, one relay session on `relay`), which is enough when a single connection's throughput already fills the link, but insufficient when limited by the single-stream congestion window climb or the relay flow-control window — the "single connection" ceiling. `-parallel N` (default 1) splits a **single** large file into at most `N` chunks by byte range, each opening an independent connection for parallel transfer. Both paths (`-via direct`/`-via relay`) and both directions (`-send`/`-recv`) are supported:

```bash
anyproxy -send bigfile.zip -to home@example.com -parallel 4
anyproxy -recv home@example.com:backup/bigfile.zip -to /data/in -parallel 4
```

- **Only splits a single file, no multi-file concurrency**. Batch `-send`/`-recv` of multiple files still transfers one after another — the purpose of chunked parallelism is to let a single large file use the bandwidth faster, not to let multiple files compete for the same bandwidth (that would actually lengthen each file's time).
- **Files too small are not split**: files below 8MiB always take the single-connection path, the `-parallel` value is ignored, since the chunking handshake/header overhead isn't worth it on small files.
- **Failure semantics identical to no-chunk**: if any chunk fails (network error, verification failure) the whole file errors out and the `.part` file is cleaned up, leaving no half-done file with only some chunks right, and no auto-retry.
- **On `-via relay`, each chunk negotiates its own encryption session** (independent random salt, independently derived AES-256-GCM key); the protocol has long supported "open a new encryption session anytime", so no handshake change is needed for chunking.

##### `-parallel` does not always speed up: understand the bottleneck first

**Chunking uses the same underlying connection** — on `direct`, the N chunks are N streams on the same QUIC connection; on `relay`, they are N relay sessions on the same websocket (same TCP connection). QUIC/TCP congestion control is computed per **connection**, not per stream/session, meaning these N concurrent paths share the same congestion window and look like **the same five-tuple** (same pair of source/dest IP+port) to network devices. If the bottleneck is operator per-flow rate limiting, or the link itself is congested with packet loss, `-parallel` in this same-connection-multiplexed implementation most likely won't help — the operator still sees "one flow", and won't allocate more bandwidth just because the app opened a few more streams.

The scenarios where `-parallel` truly helps are when a single stream/relay session's own flow-control window (not congestion window) fills before the network bandwidth — e.g. a single stream's window is too small on a high-latency long-distance link, or the bottleneck is actually CPU (hashing, encryption/decryption) rather than network. These two cases benefit from multiple concurrent paths; if the bottleneck is poor operator cross-network interconnection quality or per-flow/per-account rate limiting, opening more won't help.

**Use `iperf3` to diagnose before relying on feeling** (assuming A transfers slowly, C is the receiving machine, and the two can reach each other):

```bash
# 1. start the server on C (default port 5201, allow it through the firewall)
iperf3 -s

# 2. on A, first measure the single-stream baseline, convert to KB/s and compare with your observed speed
iperf3 -c <C's IP> -t 20

# 3. then measure multi-stream concurrency (TCP), 4 independent connections, look at the [SUM] line total throughput
iperf3 -c <C's IP> -P 4 -t 20

# 4. UDP mode (QUIC runs over UDP, this group is closer to reality; -b specifies target rate, since
#    UDP has no congestion control, iperf3 hard-sends at your rate, look at Lost/Total Datagrams packet loss)
iperf3 -u -b 500M -c <C's IP> -t 20
iperf3 -u -b 500M -c <C's IP> -P 4 -t 20

# 5. optional: add -R to test the reverse direction, to rule out one-way congestion (e.g. telecom->unicom and unicom->telecom
#    bottleneck links are often not the same)
iperf3 -c <C's IP> -P 4 -t 20 -R
```

Reading the results:

| Phenomenon | Conclusion |
|---|---|
| Single stream slow, multi-stream (`-P 4`) `[SUM]` much higher than single | per-flow rate limiting / single-stream window can't fill, `-parallel` is worth using |
| Single stream slow, multi-stream `[SUM]` about the same, high packet loss | link itself congested (common with poor operator cross-network interconnection quality), `-parallel` has limited benefit |
| TCP results ok, UDP noticeably worse | operator may have separately limited UDP; even reshaping into multiple independent QUIC connections may not help, consider switching to `-via relay` (TCP websocket) to bypass |

### TCP and UDP: two protocols carried differently on QUIC

The `listen` protocol prefix (`tcp://`/`udp://`/`both://`) decides which inner protocol the entry and landing must restore; the two take different mechanisms on QUIC for the semantics to line up:

| Inner protocol | QUIC carrier | Note |
|---|---|---|
| TCP | **stream** (reliable, ordered) | one stream per entry TCP connection |
| UDP | **datagram** (unreliable, unordered, RFC 9221) | one session ID per source address |

**Cannot use stream for UDP** — that would force retransmission and ordering onto UDP, bringing back the head-of-line blocking we deliberately avoid.

The `both://` prefix is especially useful for RDP: the mstsc main channel goes over TCP 3389, while RDP 8+'s Enhanced RDP uses **UDP 3389** for the graphics channel specifically to fight lag — forwarding only TCP would kill it.

Two UDP limitations: QUIC datagrams must fit in a single QUIC packet (constrained by MTU, about 1200 bytes), oversized UDP packets are dropped and logged; UDP is connectionless, and sessions are reclaimed by idle timeout (30 minutes, consistent with the websocket forwarding path's `forwardIdleTimeout`). If used to forward many short-lived UDP flows (e.g. DNS), this value should be lowered.

### Connection multiplexing: one QUIC connection, multiple streams

**A maintains only one QUIC connection to the same email**, opening an independent stream on it for each entry TCP connection (SSH/RDP opening multiple sessions simultaneously is normal). This is the core advantage over "single TCP tunnel multiplexing": **streams don't head-of-line-block each other**, one packet loss won't stall other sessions.

Concurrency cap is 256 (`directMaxStreams`). Exceeding it makes `OpenStreamSync` **block and wait** rather than error, the symptom being a new session frozen — when hitting the cap it's hard to think of from logs alone, so this value is explicitly written in code rather than quic-go's default 100.

### Endpoint lifetime: request-driven, no advance advertisement

**C normally occupies no port**. The whole flow is request-driven:

```
A →B  request (my candidate list, token, want to connect to email X)
B →C  someone wants to connect to you: start listening → collect your own candidates on the spot → punch toward each of his candidates
C →B  my candidate list + certificate fingerprint (or failure reason)
B →A  offer (C's candidate list + fingerprint)
A     punch toward each of C's candidates in parallel, measure RTT → pick one by RTT+bias
A ⇒C  QUIC dial the winning one
```

This design is because **the endpoint the peer can use is entirely outside the local machine's control**:

- addresses change — IPv6 privacy temporary addresses typically rotate every few hours to a day, and ISP prefixes may change too;
- ports also change — when there's NAT on the path (inevitable for IPv4, IPv6 also has NAT66/NPTv6, CPE rewriting), the external port and local port are not the same; after mapping aging and rebuild it changes again.

So the protocol **never transmits the local port**, only the full endpoint probed on the spot. Since probing happens every time anyway, advance advertisement is meaningless — a cached endpoint may already be invalid, and the server has no way to know.

**The candidate list is capped at 8 entries on the server**. The server forwards this list to the peer, which sends a punch packet to **every** entry — without a cap, a malicious subscriber reporting hundreds of addresses could use another machine to spray at arbitrary targets, turning the server into an amplifier. The list only accepts IP literals, not domain names, to avoid making the peer do DNS to reach arbitrary hosts.

Being request-driven also incidentally solves a few things: C has zero background traffic when idle, occupies no UDP port; nor is there the "network wasn't ready at boot, so direct is permanently disabled" problem — just retry next time someone connects.

### Identity verification: certificate fingerprint only flows from C to A

When C starts listening it generates a self-signed certificate and computes its SHA-256 fingerprint, handing it to the server via the **authenticated websocket**, which forwards it to A; A puts it into `VerifyPeerCertificate` when dialing, and compares it against the certificate C presents at handshake time.

So **the A→C data carries no fingerprint** — it is the credential A uses to confirm "the one I connected to really is that C", not something A presents to C. A proves its identity to C with something else: a one-time credential (see above).

A self-signed certificate can't pass CA verification, and the fingerprint is permanently the only identity credential on this link, so **a connection lacking a fingerprint is never established**: the server verifies the fingerprint is non-empty when it receives C's reply, and A verifies again when it receives the offer; a fingerprint mismatch fails at the TLS handshake stage.

Note C regenerates the certificate every time it starts listening, and after idle release and restart the fingerprint is new — this doesn't matter, because the fingerprint and endpoint are handed to A together in the same request, always paired.

### Idle auto-release

Two-level reclamation, both premised on "no active session":

- **A-side connection**: after all sessions on a QUIC connection end and it idles beyond 90 seconds, it closes (`reapSessions`).
- **C-side listener**: with no active inbound connection and idle beyond 90 seconds, it closes the listener and **releases the socket** (`reapAccept`). Next time a request comes it starts a new one; the port changed, no problem — endpoints are always probed on the spot anyway.

The criterion for "active" differs by protocol, and this is key:

| | Criterion | Why |
|---|---|---|
| TCP | reference count of the entry connection | connection open = in use, even with no data for a long time (RDP silent, SSH hung idle) |
| UDP | that entry still has a session within its own 30-minute window | UDP has no "connection" to count, judging by "last send/receive" would kill it wrongly |

The UDP one especially matters: **mstsc's UDP graphics channel may go long without packets when the user isn't doing anything**, but the session isn't over. Judged idle by "last send/receive", the connection would be closed, and the user would have to re-punch and reconnect on any mouse move. So as long as the entry still has a user session within the window, it's not idle.

(With the `both://` prefix there's an extra safety net: the mstsc main channel goes over TCP and stays up throughout, and the reference count anchors the whole QUIC connection. But a pure `udp://` config can only rely on the criterion above.)

During active periods QUIC keeps a 20-second keep-alive to keep the NAT mapping and stateful firewall hole warm (RDP often has long stretches with no data). But keep-alive keeps pushing back QUIC's own idle timeout, so the connection won't die naturally, which is why the two-level reclamation above is necessary — otherwise when multiple A's connect to the same C, C would permanently accumulate connections and keepalive packets.

The socket also supports failure-rebuild: on NIC down, address revoked, etc., the broken socket is discarded and a new one built on next use.

## Configuration fields

The `websocket` section ([router.go](../utils/conf/router.go)'s `Websocket`) splits into `server` / `client` blocks by role:

`websocket.server` (server side, `WsServer`):

| Field | Description |
|------|-------------|
| `listen` | websocket listening address, e.g. `:3002` (subscribers connect to its `/ws`). Equivalent to `-ws-listen` |
| `users` | array of authentication accounts, each `{user, pass, disable}` or `{user, key, disable}` (password/key, choose one); different subscribers use their own accounts, and a single one can be disabled separately, see "Multi-user authentication" / "Key-pair authentication" below. `pass` must be at least 18 chars with both English letters and digits; non-compliant accounts (including those with neither `pass` nor `key` configured) are auto-set to `disable` at load, with the reason logged |
| `allowIP` | whitelist of client IPs that may connect (CIDR/single IP, **both IPv4 and IPv6 supported**); empty means unrestricted. Judged by **real TCP source** (`r.RemoteAddr`), not trusting spoofable headers like `X-Real-IP`; loopback is always allowed. On hit, rejected immediately, without even doing upgrade. Scope: websocket access, bare TCP forward entry (`forward.listen`), and the UDP reflector for direct |
| `forward` | array of bare TCP forward entry rules (Path B), each `{listen, email}`, see below |

### Multi-user authentication

The server has only one form: the `websocket.server.users` array, each item `{user, pass}` or `{user, key}` (no single-user shorthand). Even with only one subscriber it must be written as an array of length 1:

```yaml
websocket:
  server:
    listen: :3002
    users:
      - user: dmit
        pass: Tr0ub4dor-and-Battery1
      - user: office
        pass: correcthorsebattery9
        disable: true   # temporarily disable this account: auth rejects directly, no need to delete config/change password
```

Each account is **password or key, choose one** (if both are configured, key is used), see next section. Subscribers fill in the corresponding account in their own `websocket.client.user`/`pass` (or `clients[].user`/`pass`); at auth the server looks up the account info by the `user` the subscriber sent, computing the token (`serveWs` in `nat/conn.go` calls `WsServer.LookupUser` in `utils/conf/router.go`).

**Password strength**: `pass` must be at least 18 chars with both English letters and digits. Non-compliant accounts (including those with neither `pass` nor `key`) are auto-set to `disable` at config load, so a weak/empty password account isn't silently allowed — the server log prints a line explaining which account and why it was disabled. This check is only done on the server, not on the subscriber (`websocket.client(s).pass` being weak doesn't stop the subscriber from using it to connect), so a new-version subscriber can still connect to an un-upgraded old server (or an account whose password hasn't been made compliant yet), and won't fail to dial just because the local check rejected it first — the server-side check is sufficient. Accounts using `key` for challenge-response are not subject to this limit.

**Disabling an account**: add `disable: true` to the corresponding entry, no need to delete the whole config or change the password — `user` can still be looked up, but auth rejects directly (the server log prints `user %s is disabled`, and the error returned to the subscriber is the same `user err` as "not found", not additionally revealing whether the account exists). This field takes effect on hot reload (the next time the subscriber reconnects it gets rejected), no server restart needed; the subscriber itself still retries per its own backoff strategy, just can't connect.

`websocket.client` (subscriber side, `WsClient`):

| Field | Description |
|------|-------------|
| `connect` | the server ws address to dial back to, e.g. `<public IP>:3002`. No command-line equivalent, config file only |
| `host` | the `Host` header/domain for `connect` (needed when going through a TLS gateway; can be the server IP if none) |
| `proxy` | the upstream HTTP/SOCKS5 proxy to go through, format `scheme://host:port` (`socks5://` or `http://`). Used when `connect` is an intranet/loopback address not directly reachable, see "Exposing only one port". If not set, connects directly to `connect` as before |
| `user` | authentication user, **must match the server** |
| `pass` | authentication password, **must match the server**; participates in token computation, missing it causes auth failure. Choose one with `key`. The server requires it to be at least 18 chars with both English letters and digits, but this strength check is only done on the server — the local machine doesn't judge, and a weak password is still used to initiate connection, so a new-version subscriber can still connect to an un-upgraded old server |
| `key` | authentication private key (generated by `anyproxy -genkey`), choose one with `pass`, uses key if both configured; the corresponding public key is configured in the server's `users[].key` |
| `email` | this subscriber's identity, used for server/peer location (HTTP path assistance, TCP path matches `server.forward.email` by it, file transfer `-to`/`receive.allow` look up by it). Non-empty, itself not part of authentication nor a security boundary |
| `uuid` | the identity credential of this config, only used between the two sides of file transfer (`-send`), completely invisible to B. **Cannot be configured in the config file**: auto-generated at startup and persisted to a hidden file with the same directory and name as the config file (`router.yaml` → `.router.uuid`), unchanged on restart; `-c` pointing at different config files gives independent ones, not shared. Printed in the startup log after generation, copy to the peer and fill into its `receive.allow[].uuid`. See "File transfer" |
| `subscribe` | array of HTTP header subscription rules, each `{key, val}`; used by Path A |
| `forward` | array of bare TCP forward target rules (Path B), each `{port, target}`, see below |
| `direct.accept` | when `true`, starts a QUIC listener and advertises the endpoint to the server, allowing other subscribers to connect to itself directly (Path C, see below); listener starts on demand, releases on idle, occupies no port normally |
| `direct.rules` | array of local QUIC direct entry rules (Path C), each `{listen, email, forwardPort, via}`, `listen` may carry protocol prefix `tcp://`(default, optional)/`udp://`/`both://`, see below |
| `direct.encrypt` | when `true`, the punch control packets (PUNCH/PONG) sent by this machine as punch initiator get extra encryption, guarding against operator devices dropping packets by cleartext signature; default `false`, pure opt-in. Per-client one-time toggle, applies to `direct.rules[]` and `-send`/`-recv` simultaneously, see "Punch control packet encryption" |
| `direct.portmap` | when `true`, direct candidate collection will attempt UPnP/PCP/NAT-PMP port mapping; default `false` not tried — low hit rate and waits for three protocol timeouts, see "Multiple paths raced simultaneously, winner is whoever connects" above |
| `direct.punchFirst` | when `true`, declares this machine is behind restricted operator CGNAT and must send the first packet when actively initiating direct (let the peer receiver delay punching); default `false`. Set it when a home-broadband machine can't connect to a public/cloud host, see [direct-punch-order.md](direct-punch-order.md) |
| `direct.relay` | when `true`, this machine (a public VPS) allows being a blind forwarding relay between A↔C; default `false`. **No per A-C config needed**, target C is specified by the initiator via `direct.rules[].via`, see "Blind forwarding relay via VPS" |
| `direct.relayAllow` | optional, tightens `direct.relay`: only allow these source emails (initiator A) to use this machine as relay; empty = unrestricted. Email allowlist only, no uuid involved |
| `direct.relayPublic` | optional public relay address array. With bare IPs, each binding uses a random port advertised on every IP; with `IP:port` endpoints, fixed-port mode is used (for fixed DNAT, one pair per port). The two forms cannot be mixed; see "Blind forwarding relay via VPS" |
| `direct.plainUdp` | overrides the command-line `-direct-plain-udp` default for this connection, tri-state: unset follows global value, explicit `true`/`false` only affects this one |
| `direct.lanAddrs` | manually configure this machine's LAN/intranet IP array (no port), extra candidates participating in punching/QUIC dial racing, see "Multiple paths raced simultaneously, winner is whoever connects" above; no NIC auto-scan |
| `receive` | config for receiving file transfer (direct or relay) `{dir, allow}`, each `allow` `{email, uuid}`; no `dir` means reject all, empty `allow` means accept from no one, see "File transfer" |
| `sendRecvOnly` | when `true`, force this config to only be used to give `-send`/`-recv` command-line credentials (including generating/persisting `uuid`); the resident process won't initiate a connection for it, even if `subscribe`/`forward`/`direct`/`receive` are configured, it still skips. **Usually no need to set it**: when all these are empty the resident process auto-judges there's nothing to connect to and skips, see the note below |
| `direct` | nested block for all QUIC direct/relay config, see the `direct.*` rows above; corresponds to struct `DirectSettings` |

### Key-pair authentication (no clock sync needed)

The password scheme computes a timestamp into the token to prevent replay, at the cost that a clock skew over 300s between the two ends means no connection, which is common on machines without NTP. The key scheme switches to **challenge-response**: the server sends a one-time random each time, the subscriber signs with the private key, and the server verifies with the public key — the random is used only once, naturally anti-replay, **with no regard to time at all**. Another benefit is that the server config only holds the public key, which can't be used to log in if leaked.

Ed25519 is used rather than the X25519 in xray: what needs proving here is "I hold the private key", which is signature's job; X25519 is a key-exchange primitive, and using it for auth would require both sides to each have a key pair and then derive a shared key — more steps, and the extra mutual auth isn't needed here.

Generate a pair (can be generated on any machine, the two strings are a matched set):

```bash
anyproxy -genkey
```

```text
Private key (client, websocket.client.key): b9sbLhlE...（private key, for the subscriber）
Public key  (server, websocket.server.users[].key): dU0T51WQ...（public key, for the server）
```

The server fills the public key into the corresponding account, **leave `pass` empty**:

```yaml
websocket:
  server:
    users:
      - user: dmit
        key: <generated-public-key>
```

The subscriber fills the private key, also leaving `pass` empty:

```yaml
websocket:
  client:
    connect: 192.0.2.10:3002
    user: dmit
    key: <generated-private-key>
    email: me@example.com
```

**Per-account selection**: which scheme is used is decided by that account's config on the server — if `key` is configured it only accepts key, if not it only accepts password. So some subscribers can use keys while others keep using passwords, independently, without a one-time full switch.

**Misconfigured schemes on both ends are detectable**, not just "can't connect": server configured key but subscriber sends password → subscriber receives `auth err: server expects key auth for this user, please set websocket.client.key`; the reverse → `auth err: server has no key for this user, please use websocket.client.pass`. If the private key itself is malformed, the subscriber reports `websocket.client.key is invalid: ...` before sending it.

### Subscribing to multiple servers simultaneously

One subscriber process can dial back to multiple servers simultaneously, with each server's account/subscription rules/port-forward table completely independent. Use `websocket.clients` (plural, array) instead of a single `websocket.client`; each array element is a complete `WsClient` block (fields as in the table above):

```yaml
websocket:
  clients:
    - connect: 192.0.2.10:3002
      host: ws1.example.com   # optional, for TLS gateway
      user: someuser
      pass: somepass
      email: home
      subscribe:               # optional, HTTP header subscription path (Path A); bare TCP forward doesn't need it
        - key: X-Env
          val: home
      forward:
        - port: 2222
          target: 127.0.0.1:22
    - connect: 198.51.100.10:3002
      user: anotheruser
      pass: anotherpass
      email: office
      forward:
        - port: 2222          # entry port number may repeat with the previous one, no conflict (each connection has its own forward table)
          target: 192.168.1.10:3389
```

Each element is a complete independent `WsClient` (same struct as a single `websocket.client`), and fields like `host`/`subscribe`/`forward` are written the same as in a single `client` block — the second example above just omitted them (omitted fields are empty/disabled, not unsupported).

`nat.ConnectServer` maintains an independent websocket connection, request ID counter, bridge table (`Bridge`), and port-forward mapping for each server ([nat/handler.go](../nat/handler.go)'s `wsClientConn`), never interfering; each log line carries a `[connect address]` prefix for distinguishing which connection.

**Relationship with the old `client` field**: `clients` and the old single `client` are mutually exclusive — if `clients` is configured only `clients` is used (the `client` is ignored); if `clients` is not configured it degrades to the old behavior (the `client` block is wrapped into a single-element list).

`server.forward` each (`ServerForward`) / `client.forward` each (`ClientForward`):

| Field | Role | Description |
|------|------|-------------|
| `listen` | server | entry listening address, e.g. `:2222`; may carry protocol prefix `tcp://`(default, optional)/`udp://`/`both://`, e.g. `both://:2222`. TCP is forwarded over websocket, UDP opens a separate UDP relay, the two going their own ways (see Path B's second channel) |
| `email` | server | forward this entry port's connections to the subscriber with this `email` |
| `port` | subscriber | corresponds to the server's entry port number (e.g. `2222`), TCP and UDP share the same table |
| `target` | subscriber | the real intranet target to dial when a connection/datagram arrives on that port, e.g. `127.0.0.1:22` |

`client.direct.rules` each (`ClientDirect`, Path C's local direct entry, configured on the **initiator** A):

| Field | Description |
|------|-------------|
| `listen` | local entry listening address, e.g. `:13389`; `:13389` binds `[::]` dual-stack, IPv4 clients also connect. May carry protocol prefix `tcp://`(default, optional)/`udp://`/`both://`, e.g. `both://:13389` — the two protocols take different carriers on QUIC (stream / datagram), see "TCP and UDP" below; `both://` is common for RDP |
| `email` | connect directly to the subscriber with this email (i.e. C, must match another subscriber under this `server` connection) |
| `forwardPort` | tells C which rule in its own `client.forward[port]` to use; **not** the intranet target port to dial, nor the `listen` port above. Deliberately designed as a whitelist index: without it, A could make C forward to any intranet target C has configured just by `email`; with it, C only accepts ports listed in its own `forward`, and unmapped ones are rejected |
| `via` | optional. Fill a public VPS's email (that VPS needs `direct.relay` on), then blindly forward to `email` (final target C) through it, rather than direct; empty = direct. Fits A, C both behind restricted CGNAT unable to punch to each other but each able to reach the VPS, see "Blind forwarding relay via VPS" |

`client.receive` (`ClientReceive`, receives files sent via direct, configured on the **receiver** C, requires `direct.accept` too):

| Field | Description |
|------|-------------|
| `dir` | directory where received files land; **if not set, reject all** (the peer gets an explicit rejection reason, see "Direct file transfer") |
| `allow` | optional, email whitelist array; only senders listed can send files, empty means unrestricted (still subject to direct's own authentication — the peer must first obtain a one-time credential through server signaling). The basis is **the initiator identity filled by the server in the punch signaling**, not what the peer claims at the application layer, impossible to forge |

## Authentication and handshake

The subscriber connects to the server's `/ws`, then sends `AuthMessage` (`auth` in `nat/handler.go`). The server first looks up the account (`LookupUser`), then branches by whether that account is configured with `key` or `pass` (`authClient` in `nat/conn.go`):

**Password scheme** (`authByPass`):

- `token = md5(user | pass | xtime)`, where `xtime` is the current second-level timestamp;
- the server verifies `email` is non-empty, `user` is found and not `disable`, `|now - xtime| <= 300` (anti-replay, **both ends need roughly synchronized clocks**), and that `token` matches what is computed with **that user's corresponding `pass`**. When the skew exceeds the limit, the reply carries **the actual number of seconds of difference**, no need to dig through server logs.

**Key scheme** (`authByKey`, see "Key-pair authentication" above):

- `AuthMessage` has `KeyAuth: true`, `Token`/`Xtime` not involved;
- the server replies `AuthChallenge{challenge}` (32-byte one-time random) instead of `ok`, the subscriber signs with the private key and replies `AuthSignature{signature}`, the server verifies the signature with the configured public key. **This path does not check the clock**; this step adds one more round trip, and the server sets a 10s timeout on the signature.

After that the subscriber sends `subscribe` (may be empty). If `subscribe` is empty, the connection is only allowed if that `email` matches some server `forward` rule (`isForwardEmail`) — i.e. **a pure bare TCP forward subscriber doesn't need `subscribe`**.

On failure it disconnects and reconnects with backoff (the subscriber has its own reconnect loop).

## Command-line equivalents

| Parameter | Config item |
|------|-------------|
| `-ws-listen` | `websocket.server.listen` |
| `-genkey` | generate a pair of authentication keys and exit (private key → `websocket.client.key`, public key → `websocket.server.users[].key`) |
| `-send PATH -to EMAIL [-via direct\|relay\|VPS's email] [-parallel N]` | send a file/directory to another subscriber and exit; `-via` defaults to `direct`, `-parallel` defaults to 1; `-via` with a public VPS's email blind-forwards via relay punching (see "File transfer") |

> The subscriber (client) **has no command-line parameters**; `connect`/`user`/`pass`/`key`/`email`/`subscribe`/`forward` can only be written in the config file; subscribing to multiple servers simultaneously also only uses `websocket.clients[]`. So bare TCP forwarding (depends on `forward`) and subscriber-related config can only use the config file.

## Common pitfalls

- **`user`/`pass` mismatch between the two ends** → subscriber token verification fails, can't connect. `pass` must be configured on both ends (old doc examples once omitted the subscriber's `pass`); the subscriber's `user` must be findable in the server's `server.users` and that entry not set to `disable: true`, otherwise it reports `user err`.
- **`email` mismatch** → on bare TCP forward the server log shows `no forward ... no subscriber for email ...`. The server's `server.forward.email` must equal some subscriber's `client.email`.
- **Clock skew > 300s** → auth failure, the subscriber receives `xtime err: your clock differs from the server by Ns ...` (with the actual skew). Keep both ends' time synced, or **switch to key-pair authentication** (above), which doesn't look at the clock.
- **Blocked by the server's `allowIP`** → subscriber log `ws connect err: ... (server replied 403 Forbidden ...)`. Note IPv6 addresses rotate (RFC 4941 temporary addresses), so the whitelist should use prefix ranges rather than single addresses.
- **Subscriber only trusts the whitelist**: it only dials the hard-coded `target` in its own `forward`, and unmapped `port`s are rejected outright — even if someone randomly connects to the server entry port they can't get into the intranet. **`forward[].port` holds the server's `forward.listen` entry port number** (e.g. `:2224` means fill `2224`), not the real intranet service port (e.g. RDP's `3389`) — confusing the two is the most common misconfig. The reason for this rejection is returned to the server via `METHOD_CLOSE`, reflected in the server's `nat forward closed ... reason=peer close: no forward target for entry port N` line, so no need to dig through the subscriber's local logs; old anyproxy versions lacked this return, and the server only saw the symptom (`up=19 down=0 dur=0s reason=...connection reset by peer`, the client sent the handshake packet but received nothing, disconnecting soon after).
- **UDP relay's first packet is one beat slow**: the upstream is built only on receiving the first datagram, so the first packet waits one B→C→B round trip. RDP retries on its own, no need to worry; a self-written UDP app that doesn't retry should take note.
- **UDP relay only starts when `listen` carries `udp://`/`both://` prefix**: without the prefix it defaults to `tcp://`, and just configuring `client.forward` is not enough — the entry rule's `listen` must also carry the protocol prefix.
- **Path A doesn't support `CONNECT`**: the HTTP header subscription path only handles non-`CONNECT` HTTP requests.
- **Direct punch failure has no relay fallback**: A's entry connection is closed directly, log prints `nat direct entry ... failed: no path to <email>: <where each candidate stuck>`. This is by design, not a bug — direct and relay are two independent paths with no fallback for each other; to go through relay configure `server.forward`, don't expect `direct` failure to auto-roll-back.
- **`-send` punch failure is the same: non-zero exit code, not a single byte transferred**: common cause is both behind strict NAT/CGNAT, all candidates (reflector v4/v6, port mapping, manually configured `direct.lanAddrs`) plus the QUIC dial-racing fallback after all punching died all failing — the terminal prints `send: direct connect to <email> failed, nothing was sent: ...`, with each candidate's failure reason.
- **The receiving end didn't configure `receive.dir`**: the sender receives `peer does not accept files (websocket.client.receive.dir is not set)` and exits non-zero; this is not punch failure but an explicit peer rejection, check C's config not the network.
- **`receive.allow` email is right but `uuid` was copied wrong**: direct reports `email %s is not in websocket.client.receive.allow, or its uuid does not match`; relay, since uuid is directly the encryption key, a mismatch fails at the decryption stage (the error won't say "uuid wrong", because at this step the relay path fundamentally can't distinguish "wrong key" from "data tampered", both must be uniformly rejected). Go to the sender's startup log to confirm what `websocket.client.uuid` actually is, and compare character by character with the receiver's `receive.allow[].uuid`.
- **`receive.allow` left empty**: the semantics now is "accept from no one", not the old "unrestricted" — with uuid missing there's no way to do identity comparison, nor derive a relay key, so there's no "unrestricted" option anymore; the peer must be explicitly configured.

## Examples

See [config-examples.md](config-examples.md) section 8 (8.1 HTTP header subscription, 8.2 bare TCP intranet penetration).
