# VPS Blind-Forward Relay (TURN-style direct relay)

> **Status: implemented (phase 1).** The control plane (via/d_relay_open/two-leg hole-punch coordination), data plane (dedicated socket blind forwarding), and authentication (e2e uuid challenge-response bound to fingerprint) are all in place and covered by unit tests / end-to-end tests. Code locations are listed in §11.
> This replaces the earlier idea of "VPS terminates TLS on both legs and bridges in the middle" (see the "Discarded design" at the end of this doc).
>
> One wording discrepancy between the implementation and this doc: C does not rely on A self-reporting its email in the stream. Instead C uses **the initiator email forwarded by B via the hole-punch message (DirectPunch.Email)** — an email already authenticated by B — to look up receive.allow (A cannot forge its identity). The challenge-response only exchanges two frames: nonce and HMAC response.

## 1. Goal

A public VPS acts as a **relay with minimal configuration** between A and C: the VPS **does not configure `forward`/`direct`/`receive.allow` per A-C pair** — it only needs a single "allow relay" master switch; the target C is **specified by A in the request**.

Use case: A and C are both behind restrictive CGNAT and cannot reach each other directly (see [direct-punch-order.md](direct-punch-order.md)), but each can establish a connection to a public VPS. Data is relayed through the VPS and **does not pass through** the signaling server B (whose network is poor).

This covers **TCP + UDP** in one shot (RDP's TCP main channel + UDP graphics channel). File transfer (`-send`/`-recv`) is **out of scope for this design** — that path already has `-via relay` (via B) available.

## 2. Core model: VPS only does blind forwarding; QUIC is end-to-end between A↔C

Key choice: **the QUIC/TLS connection is end-to-end A↔C** (A is the client, C is the server presenting C's self-signed certificate, and A pins it by fingerprint); **the VPS only forwards opaque UDP packets at the transport layer**, terminating no TLS and decoding no QUIC.

```
   A ─────(end-to-end QUIC-TLS, VPS cannot see plaintext)───── C
   │                                             │
   │  UDP packet                           UDP packet  │
   └───────────▶  VPS dedicated relay socket  ◀──────────┘
              (blind-forwards between A↔C by source address)
   Data does not pass through B; B only exchanges addresses/fingerprint/token during setup
```

**This model incidentally eliminates the TCP+UDP difficulty**: the VPS forwards the **opaque packets** of the A↔C QUIC connection; TCP rides its stream and UDP rides its datagram, all handled inside that single end-to-end QUIC between A and C — **exactly the same as the current direct connection**. The VPS distinguishes no protocol, does no stream/datagram bridging, and does no sessionID mapping. So "TCP+UDP together" holds naturally.

## 3. Control plane: signaling flow

**A's configuration** (add `via` to `client.direct.rules[]`):

```yaml
# A (resident, CGNAT)
websocket:
  client:
    direct:
      punchFirst: true                # A is behind CGNAT, see direct-punch-order.md
      rules:
        - listen: "both://:13389"     # mstsc connects here
          email: minggui-home@cloudme.io  # final target C
          forwardPort: 2224           # which rule in C's forward[] to use
          via: proxy-test@cloudme.io  # relay through this VPS; empty = direct to C (current behavior)
```

**Signaling reuse principle (important)**: a relay is essentially **two ordinary "resident→cloud" hole-punch legs (A↔VPS, C↔VPS), both punched toward the VPS's same relay endpoint E**, plus B coordinating in the middle. So **the existing direct-connection signaling is reused almost verbatim** — we only change "the target to punch/dial" from "the peer" to "the VPS's relay endpoint E". **Only one new message type `d_relay_open` is needed** (B→VPS).

| Existing signaling | How it's used in relay | Change |
|---|---|---|
| `d_request` (A→B) | A adds `via=VPS`; when B sees `via` non-empty it enters relay mode | `DirectRequest` adds `Via string` |
| `d_relay_open` (B→VPS) | **the only new message**: tells the VPS to open a dedicated socket, ask the reflector for its public endpoint E, and prepare to be hole-punched by A/C | new `DirectRelayOpen` |
| `d_ready` (VPS→B) | VPS uses it to report back the relay endpoint E (filled into `Candidates`) | reused, no change |
| `d_punch` (B→VPS) ×2 | B forwards A's and C's candidates to the VPS **in two separate messages**, so the VPS knows where to "punch back" to open its own side of the hole | reuses its `PeerAddrs` shape |
| `d_offer` (B→A) | fills "the endpoint A should dial" as **E** and gives A **C's certificate fingerprint** | reused, no change |
| `d_punch` (B→C) | makes C punch to **E** (`PeerAddrs` filled with E) instead of toward A | reused, no change |
| `d_punching` (nudge) | both legs' nudges are reused | reused, no change |

> **Why the VPS needs B to forward A/C's candidates**: when the resident punches first, its first packet gets dropped by the VPS's closed security group, so the VPS **cannot observe** the resident's source address; it must rely on B to tell the VPS the resident's candidate via `d_punch`, so the VPS knows where to "punch back" and open its own return channel. This is exactly how §6's "both legs wrapped in `direct.punchFirst`" is realized: the resident punches first (A and C each with `direct.punchFirst: true`), and the VPS punches toward the resident candidate after receiving the nudge.

**Flow** (setup phase, signaling via B; data not via B):

1. `d_request` (A → B, **with `via`**): A wants to relay via `via` (VPS) to C (`email`)'s `forwardPort`, attaching A's own candidates and the current `token`. B sees `via` non-empty → enters relay mode.
2. `d_relay_open` (B → VPS): tells the VPS to **create a new dedicated UDP socket** for this `token`, ask the reflector to discover its public relay endpoint **E**, and prepare to accept hole-punches from A and C. The VPS reports E back to B with `d_ready`.
3. B uses two `d_punch` messages to forward candidates to the VPS separately: one with A's candidate, one with C's candidate (first send a normal `d_punch` to C to obtain C's candidate and fingerprint). The VPS then punches toward both A and C sides (after receiving the nudges).
4. `d_offer` (B → A): fills the endpoint to dial as **E** and attaches **C's certificate fingerprint**. Simultaneously sends `d_punch` to C, with its `PeerAddrs` filled as **E**, making C punch to E (instead of toward A).
5. **A and C each punch to E** (both are "resident→cloud", each with `direct.punchFirst`: resident punches first, VPS punches after receiving nudge; `d_punching` reused for both legs). The VPS **observes** A's and C's public addresses from the two source addresses and binds them as a pair.
   - **Both legs must succeed for the relay to succeed**; if either leg cannot reach the VPS, the entire relay fails (see failure semantics).
6. Once both sides are through, **A initiates the QUIC dial**: destination address filled as E (the relay endpoint), TLS expects C's fingerprint. The VPS forwards the packet to C, C's listener receives it (source is the VPS relay port) and accepts, and the QUIC handshake completes **end-to-end on A↔C**.
7. A sends its own `email` (a label) over this e2e QUIC stream and does one **uuid challenge-response** with C (see authentication; the uuid never goes online); C verifies and then lets it through. After that, the TCP stream / UDP datagrams both run inside this e2e QUIC, and the VPS blindly forwards throughout.

**VPS configuration** (removes per-pair forward/direct):

```yaml
# VPS (public)
websocket:
  client:
    direct:
      accept: true       # still required: so residents can punch-connect up
      relay: true         # new: allow acting as relay; by default open to all authenticated subscribers in B
      # relayAllow:       # optional: restrict which source emails may use this machine's relay (empty = fully open)
```

**C's configuration** (essentially unchanged; the `forward` whitelist is still the gate):

```yaml
# C (resident, CGNAT)
websocket:
  client:
    direct:
      punchFirst: true
      accept: true
    forward:
      - port: 2224
        target: 192.168.1.10:3389
    receive:                         # C keeps a "which A's are allowed" list (see authentication)
      allow:
        - email: office@cloudme.io
          uuid: <A's uuid>
```

## 4. Authentication: the gate is at C; the VPS is blind throughout

- **A confirms the peer is the real C (certificate fingerprint, not uuid)**: the A↔C **e2e QUIC-TLS** uses C's self-signed certificate, and A **pins** it using the fingerprint distributed by B. Even if packets come relayed from the VPS, A can confirm the peer is C by the certificate — **independent of address** — and the VPS, lacking C's private key, cannot impersonate C. Data is also encrypted by this TLS; the VPS has no key and sees only ciphertext.
- **C confirms the peer is the real A (uuid challenge-response, one-way, uuid never goes online)**: within the entire relay the uuid is used **only for the single direction "C verifies A"** ("A verifies C" is already handled by the certificate fingerprint above). A and C both have A's uuid locally (A has its own; C's `receive.allow` has A's — **reusing the existing `receive.allow`, no new list opened**), so there is no need to send the uuid over; just prove "I know the uuid" with a challenge-response:
  1. A sends its own `email` over the e2e QUIC stream (**a label, not a secret** — sending it is harmless);
  2. C looks up the expected uuid by email in `receive.allow` and sends a random `nonce`;
  3. A replies with `HMAC(uuid, nonce || C's certificate fingerprint)`, and C verifies it with the looked-up uuid. A fresh nonce each time prevents replay; **binding C's certificate fingerprint into the HMAC is to prevent relay-layer replay** — the VPS is an untrusted middleman; without the fingerprint binding, a recorded challenge-response could theoretically be replayed by the VPS onto "another connection where it impersonates". Once C's fingerprint is bound, the response is valid only for "the peer that truly holds that certificate's private key" on this e2e TLS; if the VPS switches connections it won't match.
  - This is consistent with the existing `-via relay` approach (uuid treated as keying material, identity proven by "using it correctly", **never sent in the clear**).
  - Comparison: the existing **direct** file transfer puts the uuid verbatim into the e2e stream for byte-by-byte comparison (sent in the clear inside TLS) — acceptable for direct (the peer is C), but in a relay the VPS is an untrusted middleman, so the challenge-response is preferable and the uuid is kept out of even the TLS: even if C's certificate private key leaks, the uuid does not leak with it.
- **No separate broker token needed**: C's relay listening port is only reachable when "the binding is built via B + A's packet comes relayed through the VPS" (a random scan cannot reach it), plus C's `forward` whitelist gates the ports, which already blocks unauthorized connections; the uuid challenge-response alone carries identity authentication. Keeping a token as a cheap "reject illegal connections earlier" door is also fine — but note **a token is a one-time capability value, designed to be transmitted** (B distributes it); sending it leaks no long-term secret, unlike the uuid.
- **Injection prevention**: the VPS's dedicated socket **only relays between "A's address ↔ C's address"**; packets from any other source address are dropped; the binding assignment must go through B (B has authenticated the initiator).

**Only non-long-term secrets are transmitted across the network**: `email` (label), `nonce` (random), C's one-time certificate fingerprint (via B). **The long-term secret uuid never goes online**; data is encrypted by e2e QUIC-TLS.

**Key conclusion: security does NOT depend on `direct.encrypt`.** Authentication (uuid challenge-response) and data are both inside/on top of the A↔C e2e QUIC-TLS, unrelated to hole-punch packet encryption. `direct.encrypt` **degenerates to purely optional**: it only encrypts the "resident↔VPS" two legs' hole-punch packets, masking plaintext features to prevent operator DPI packet drops (a "can it connect" reliability issue, not a "will it leak" issue). With it off, no secret leaks either — the plaintext hole-punch packet only contains `verb+nonce` anyway.

> Difference from the earlier step 2: authentication is **not** placed on "uuid-encrypted hole-punch packets" (that would make authentication depend on direct.encrypt, and amount to using the uuid to directly encrypt/decrypt the hole-punch packets), but instead on the **in-stream challenge-response after the e2e QUIC is built**. In this model the hole-punch packet is only responsible for opening the hole.

## 5. Data plane: dedicated UDP socket blind forwarding

- The VPS uses **one dedicated UDP socket per A↔C pair** (not via quic-go, pure `ReadFrom/WriteTo`).
- Binding: the two source addresses A and C appear on the socket one after another; once recorded, it relays "A→C, C→A"; only these two addresses are recognized.
- **No distinction between TCP/UDP**: what is forwarded is opaque bytes; A↔C's QUIC itself distinguishes stream/datagram.
- **Simple lifecycle**: idle for **30 minutes with no data** closes this socket + its forwarding goroutine (reusing `directUDPIdle`). Because the A↔C QUIC has a 20s keepalive, while the connection is alive the socket sees packets every 20s and is never misjudged idle; only when the QUIC truly dies is it reclaimed after 30 minutes. Living ones stay, dead ones self-clean — no complex reclamation logic needed.
- **Extra benefit of the dedicated socket**: natural isolation — closing one relay pair does not affect other pairs; the address binding also naturally prevents hijacking.

## 6. Reuse of hole-punch ordering

A relay has two legs, both "resident→cloud", each applying [direct-punch-order.md](direct-punch-order.md):

- `A↔VPS`: A (resident) punches first, VPS stops and waits for nudge — A side `direct.punchFirst: true`;
- `C↔VPS`: C (resident) punches first, VPS stops and waits for nudge — C side `direct.punchFirst: true`.

B coordinates both sides' nudges at step 5. Both legs directly reuse the existing `direct.punchFirst` mechanism, needing no extra handling.

## 7. Failure semantics

Both legs (A↔VPS, C↔VPS) must **both** succeed for success; if either leg fails, the entire relay fails and, per the consistent direct-connection convention, **fails outright with no fallback** (the relay itself is the substitute when hole-punching fails, and it has no next level). The failure reason is reported back to A via `METHOD_CLOSE` as much as possible, to help distinguish "which VPS leg cannot connect" from "C's forward/uuid rejection".

## 8. Phasing

Because the VPS is opaque forwarding and makes no TCP/UDP distinction, the data plane is **done in one pass** (dedicated socket blind forwarding). The work is mainly in the **control plane** (new signaling + two-leg punch coordination + QUIC through relay). Recommendation:

- **Phase 1**: the entire control plane + dedicated socket blind forwarding + authentication (uuid challenge-response, e2e). Get A→VPS→C RDP (TCP+UDP together) working, with no per-pair config on the VPS.
- No need to phase for TCP/UDP.

## 9. Decisions already made

- **Authentication direction**: one-way — **C verifies A with uuid challenge-response**; A verifies C with **certificate fingerprint** (not uuid). Both ends are authenticated, and the VPS cannot impersonate either.
- **C-side list**: **reuse the existing `receive.allow`** (email+uuid), do not open a new `relayAllow` (change its comment from "file-transfer only" to "file transfer + relay authentication").
- **`direct.relay` default**: once enabled, open to "all authenticated subscribers within B"; `direct.relayAllow` optionally tightens.
- **Relay target granularity**: one target C per A↔VPS connection.
- **Naming**: A side `via`, VPS side `direct.relay`.
- **No separate broker token needed**: uuid challenge-response alone carries it (see §4); optionally kept as a cheap early-reject door.
- **VPS endpoint vs C address**: A dials the **VPS's relay endpoint (`VPS_ip:dedicated_port`)**; both A and C punch to this same endpoint, and the VPS distinguishes by source address; A **never uses C's real ip:port** (unreachable and unnecessary — "whether the peer is C" is guaranteed by the certificate fingerprint, independent of address).
- **How the VPS relay endpoint's public address is obtained**: the address the VPS's dedicated socket binds locally ≠ the address seen from outside (e.g. Tencent Cloud local `10.x`, public `49.x`), so the VPS cannot directly report its local address. **Reuse the existing reflector discovery** — the VPS lets this socket also ask the reflector once ("what `ip:port` do I look like to you"), and reports the discovered public address to A and C via B (the same `gatherCandidates` used by resident machines, and by the VPS doing ordinary direct connections today to learn its own public endpoint). This way, whether the VPS is pure public, 1:1 NAT (port preserved), or NAT with changing ports, the correct endpoint is obtained.
  - **Exception: a symmetric NAT gateway with per-flow randomized egress.** The public endpoint E_ref the reflector discovers is the mapping of the `VPS->reflector` flow; if the VPS sits behind a symmetric NAT gateway (different external IP:port to the reflector, to A, and to C), the packet A sends to E_ref never reaches the VPS's inbound mapping, and the relay is dead (same reason hole-punching fails against symmetric NAT). In that case the reflector-discovery path itself fails and needs a **static inbound** fallback (see below).
- **Static public endpoint (`direct.relayPublic`)**: when configured it **skips the reflector** and uses the configured endpoint directly as E, and binds the relay socket **to the fixed port in the endpoint**. Used for the symmetric NAT gateway scenario above: configure a fixed DNAT inbound rule (public `IP:port` -> VPS same UDP port), so the inbound is permanently open regardless of whether egress is randomized. Since a fixed port allows only one socket, **configuring N different ports allows at most N concurrent relay pairs** (pick a free port to bind when opening; if all are occupied this attempt fails). DNAT port preservation is assumed; it also applies when there is a direct public IP with no NAT (just allow the port). The simplest is still giving the VPS a real 1:1 public IP, in which case the default reflector discovery suffices.
- **Maximize reuse of existing direct-connection signaling** (see §3 table): a relay = two "resident→cloud" hole-punch legs (both punched toward the VPS relay endpoint E) + B coordinating. Reuse `d_request` (add `Via` field) / `d_ready` / `d_punch` / `d_offer` / `d_punching`, **adding only `d_relay_open` (B→VPS) as one message** to make the VPS open a dedicated socket, discover E, and prepare to be hole-punched. B uses two `d_punch` messages to forward A's and C's candidates to the VPS (the VPS is blocked by the security group and cannot observe the resident's source address, so it must be told by B).
- **uuid challenge-response bound to certificate fingerprint to prevent relay-layer replay**: `HMAC(uuid, nonce || C's certificate fingerprint)`. The VPS is an untrusted middleman; once the fingerprint is bound, the response is valid only for "the peer that truly holds that certificate's private key", and the VPS cannot replay it onto another connection. A fresh nonce each time prevents ordinary replay. The derivation approach in [nat/direct_crypto.go](../nat/direct_crypto.go) can be reused.

## 10. Open (decide at implementation time)

- (Signaling and authentication construction were finalized in §3, §4, §9; there are no open items here for now — supplement with details encountered during implementation if any.)

## 11. Related code (implementation locations)

- Signaling: [nat/direct_msg.go](../nat/direct_msg.go), [nat/direct_broker.go](../nat/direct_broker.go) (B-side new relay coordination), [nat/direct.go](../nat/direct.go) (client-side signaling dispatch).
- A-side initiation: [nat/direct_entry.go](../nat/direct_entry.go) (`via` non-empty → relay setup + e2e dial).
- Command line: `-send`/`-recv`'s `-via`, besides the two reserved keywords `direct`/`relay`, filling in a VPS's email is equivalent to assigning `conf.ClientDirect.Via` for this one-shot transfer (see `resolveVia`), no need to write it into the config file, see [nat/file_send.go](../nat/file_send.go), [nat/file_recv.go](../nat/file_recv.go).
- VPS-side relay: new code (dedicated UDP socket blind forwarding + binding + idle reclamation); `direct.relay` switch.
- C-side accept: [nat/direct_accept.go](../nat/direct_accept.go) (punch to relay endpoint + listen accept + uuid challenge-response verification).
- Hole-punch ordering: reuse [direct-punch-order.md](direct-punch-order.md)'s `direct.punchFirst`.
- Config: [utils/conf/router.go](../utils/conf/router.go) (`ClientDirect.Via`, `DirectSettings.Relay`, optional `DirectSettings.RelayAllow`, `DirectSettings.RelayPublic`, all under `WsClient.Direct`).

## Appendix: Discarded design (VPS two-leg bridge)

Early idea: the VPS terminates the two QUIC-TLS connections `A↔VPS` and `VPS↔C` separately and bridges stream/datagram in the middle. Drawbacks: the VPS can see plaintext, needs sessionID mapping and bidirectional bridging for UDP (complex), and C can only authenticate the VPS, not A. The blind-forwarding model of this design is comprehensively superior (VPS blind, TCP/UDP unified, C authenticates A directly), so the two-leg bridge is discarded.
