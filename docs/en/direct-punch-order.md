# Direct-connection hole-punch ordering: the CGNAT side must send the first packet first

> One-sentence conclusion: when hole-punching across "carrier-grade CGNAT home broadband ↔ public cloud host", **the resident/CGNAT side must send its own first hole-punch packet before receiving any packet from the peer**. Who punches first decides success or failure, unrelated to "how tight the punching is, or whether the two sides bombard continuously". A wrong order not only fails to connect, but even if it barely connects will suffer severe packet loss.

This is the conclusion confirmed while troubleshooting a real "direct connection won't connect" problem — the process took many detours and is worth recording separately, because it is counter-intuitive: both sides' NAT types are normal (both cone/EIM), both sides' packets are sent out, packet capture can see outbound traffic, yet it just won't connect, and the only variable is **who sent the first packet**.

## Phenomenon

Topology: residential broadband A (documentation address `192.0.2.10`), residential broadband C (documentation address `198.51.100.20`), public cloud host VPS (documentation address `203.0.113.30`, 1:1 NAT + stateful security group).

- **VPS actively dials A / C** (run `-send`/`-recv` on the VPS) → **always succeeds**.
- **A / C actively dial the VPS** (run `-send`/`-recv` on A/C) → **always fails**.
- Two residential machines on different carriers behave exactly the same.

Typical log on failure (A actively dials the VPS):

```
nat direct: path selection for ...: punch all failed (no candidate answered: ...: no answer),
  falling back to a quic dial race across all candidates
nat direct: quic dial ...: timeout: no recent network activity
```

Packet capture shows: A's packets leave the physical network interface normally, but the VPS receives none of them; conversely, the VPS's packets toward A, A receives none either. **Neither direction reaches the peer.**

## Pattern and mechanism

**Pattern**: the resident / CGNAT side must send its own first hole-punch packet before receiving any packet from the peer.

**Mechanism**: residential broadband's CGNAT has a characteristic — **if, before it sends its first packet, it first receives the peer's packet, its mapping for this destination gets "poisoned"**: afterwards, when it sends to the peer, the external port it uses is no longer the one it previously advertised (as observed by the reflector). As a result both directions mismatch entirely:

- The packets it sends emerge from a source port the peer does not expect → the peer (especially the cloud host's stateful security group, which only allows returns on the hole it punched earlier) drops them;
- The peer's return packets hit the port it originally advertised, but its CGNAT no longer maps that port to the local machine → also dropped.

**This poisoning persists for the whole round**: once it happens, "keep punching, bombard densely" cannot recover it. The public/cloud-host side has no such problem — even if it receives the peer's packet first, the security group still allows returns on the hole it punched itself.

Strong supporting evidence is the **packet-loss rate**: with a wrong order, even if it barely connects due to some lucky timing, it suffers severe packet loss (measured 37%, because the poisoned mapping sends some packets to the wrong port); with the correct order, the same link has **0% packet loss**.

### More precisely: what's broken is the "association", not the "port"

It's easy to misunderstand as "this port is destroyed because the peer punched it first". The more accurate statement is:

- **The port itself is not broken**: this socket / external port works fine for B, for the reflector, and for any other destination.
  The only thing affected is **this one flow to "this specific peer destination"**.
- **The trigger unit is the pair `(this local socket ↔ this peer destination)`, and the trigger condition is "receive before send"**: A's CGNAT is port-independent (EIM) when "A actively sends first" — so it uses the same port for B and for the reflector, and A advertises it; but if A **receives the peer's packet before it has ever sent a packet to the peer**, the CGNAT switches to a different (port-dependent) mapping for "this peer destination", using an external port that is no longer the advertised one.
- **It does not "run out" the more you try**: opening a new connection (new socket, new port) is a brand-new chance — as long as this time A sends first, it works. One failure does not pollute the next new socket; there is no "port used up, fewer and fewer".

**An honest boundary**: the above "A→peer used a different external port" is the **most reasonable model inferred from behavior** (wrong order → both directions dead + high loss, correct order → 0 loss), but **the different external port was not directly captured** — A's local machine only sees the internal port, and the peer, when the order is wrong, never received a packet and cannot read it. So treat it as a "best explanatory model", not a "packet-capture-proven iron law". Also precisely because it triggers only on "receive before send", the `nat-punch` dual-reflector EIM test **cannot detect it**: in that test A always actively sends to both reflectors first, never "receive then send", so it naturally shows EIM — the real trap only surfaces when "receiving the peer's packet first".

## Empirical evidence

**Bare tool `examples/nat-punch`** (excludes anyproxy entirely, purely testing whether two machines can send UDP to each other):

- **A presses enter first (punches first) → connects**; **VPS presses enter first (punches first) → does not connect**.
- This directly rules out the "tight or not, continuous bombardment" factor — `nat-punch` does continuous bombardment in both orders, the only difference being who pressed enter first (who sent the first packet first).

**anyproxy verification** (see "how to use" below): make the acceptor delay its punch and the resident side punch first, A actively dialing the VPS **connects immediately** (`punch 2.7s`), transfers 19.8MB, **0% packet loss**. The hypothesis is confirmed — this is the origin of the `direct.punchFirst` config below.

## Why anyproxy's current behavior hits this

The current direct-connection signaling timing (see [nat/direct_msg.go](../nat/direct_msg.go)):

```
A --d_request--> B --d_punch--> C   ← C punches only on receiving d_punch, punches first
C --d_ready-->   B --d_offer--> A   ← A only now gets C's address, starts punching
```

**The acceptor (C) always punches first** — it does `punchOnly` on receiving `d_punch`, which is **earlier** than the initiator (A) getting `d_offer` and starting to punch. So whoever is the acceptor punches first:

| Direction | Who is the acceptor (punches first) | Resident side sends first or receives first | Result |
|---|---|---|---|
| VPS → resident | resident | resident sends first → mapping clean | **connects** |
| resident → VPS | VPS | VPS sends first, resident receives first → resident poisoned | **dead** |

This fully explains "VPS as dialer always succeeds, as dialee always fails", and also why changing both sides to "keep punching" (acceptor `punchOnly` continuously, initiator `keepPunching` during dial) **still cannot save it** — the problem is in the **order**, not in persistence.

## How to use: `direct.punchFirst`

Principle: **make the resident / CGNAT side punch first.** Landed as a **per-machine** config switch
`websocket.client.direct.punchFirst`:

```yaml
# The home-broadband / CGNAT machine (A, C) — when it actively initiates a direct connection it must punch first
websocket:
  client:
    direct:
      punchFirst: true
# The public / cloud-host machine (VPS) — keep default (unset); when it is the acceptor it reads the initiator's declaration and delays its own punch
```

- **The side set to `true`**: when this machine acts as initiator connecting to the peer, it carries `punchFirst` in `d_request`;
  the peer (acceptor) receives `d_punch` and **does not punch first, stops the punching**, waiting for the
  `d_punching` nudge forwarded via B after this machine starts punching, then punches. `d_ready` still replies immediately as usual, so this machine (resident side) sends the first packet first.
- **Set per machine, not per `direct.rules[]` rule**: because "whether this machine is behind CGNAT" is a property of the machine;
  it takes effect **simultaneously** for the `direct.rules[]` port forwarding and the `-send`/`-recv` file transfer.
- **Only needed when the CGNAT side is the initiator**: set on home-broadband machines, do not set on public/cloud hosts. Running the previously failing
  direction (home broadband → cloud host) with it should connect immediately (measured `punch 2.7s`, 0% loss).

**Why per machine, and why it auto-adapts to the link**: in the same `resident A → VPS → resident C` chain, the two hops need exactly opposite orders —

| Hop | Initiator | Acceptor | Who should punch first | Achieved by |
|---|---|---|---|---|
| A → VPS | A (resident, set `direct.punchFirst`) | VPS (cloud) | A first | A's `punchFirst` makes VPS stop and wait for nudge |
| VPS → C | VPS (cloud, unset) | C (resident) | C first | default is "acceptor punches first", C happens to punch first |

So as long as **every home-broadband machine is set `direct.punchFirst: true`, and public machines are not**, both hops are correct individually,
without caring about each hop's direction.

**Limitation**: a direct connection where both ends are CGNAT (e.g. A directly to C, not via VPS) is not covered by this switch — then no matter who punches first, the other side will "receive before send" and get poisoned. Fortunately such both-CGNAT direct connections are inherently very hard to establish; in practice go through a relay (via VPS or relay).

### How the order is guaranteed: `d_punching` nudge (signaling control) + fixed-delay fallback

The difficulty: the acceptor wants to punch on receiving `d_punch`, but at that time the initiator has not yet gotten the offer and not started punching — the acceptor must not punch first. So:

1. On receiving `d_punch` with `punchFirst`, the acceptor **does not punch first**, parks this punch in `pendingPunch` by `token`,
   and `d_ready` still replies immediately as usual;
2. The initiator, once it **starts punching**, sends a `d_punching` nudge (`A -> B -> C`, B routes by email,
   C matches it to the parked punch by `token`);
3. Only on receiving the nudge does the acceptor punch `punchOnly`. Because the nudge travels a short path via B while the initiator immediately starts punching right after,
   the **initiator necessarily sends the first packet first**, and the mapping is not poisoned.

This is **deterministic**, not relying on guessing B's latency. `directPunchFirstDelay` (a constant in `nat/direct.go`, 5s,
**not a config item**) is demoted to a **fallback**: in case the nudge is lost (B jitters, initiator didn't send), the acceptor punches when the timer fires, falling back to
the old "fixed delay" behavior — it won't get stuck permanently. Normally when going through the nudge it almost never triggers; in an environment where B is extremely laggy and nudges are often lost, increase it — you can only change this constant and recompile (intentionally not made a config item: it is a very rarely triggered safety net, not worth another knob).

> The temporary environment variable `ANYPROXY_DIRECT_PUNCH_DELAY` (unconditional fixed delay on the acceptor) used in early verification has been replaced and removed by the above "config + nudge + fallback" scheme.

### Don't confuse two time quantities: how long to punch vs when to start punching

When troubleshooting it's easy to confuse these two quantities; in fact one is "duration" and the other is "timing":

- **How long to punch (duration) = `directPunchCount × directPunchGap`**: the acceptor's `punchOnly` sends `directPunchCount` (default 6) packets per candidate consecutively,
  spaced `directPunchGap` (default 150ms), i.e. a **~900ms short pulse** then stops. **No longer needed** — the hole punched on the peer's NAT/security group is a
  **stateful mapping** that, once established, survives tens of seconds or longer; this 900ms is only responsible for **opening** the hole, after which the initiator's QUIC Initial arrives and the handshake begins, and QUIC
  packets themselves keep refreshing this flow, no need for continuous re-punching.
- **When to start punching (timing) = decided by `direct.punchFirst` + nudge**: the acceptor starts that 900ms pulse only **on receiving the nudge** (or
  `directPunchFirstDelay` fallback firing), not on receiving `d_punch`.
  This guarantees the initiator (restricted CGNAT side) sends the first packet first.

A common misunderstanding: when early verification with `ANYPROXY_DIRECT_PUNCH_DELAY=2s` succeeded and showed `punch 2.739s`, that
"2s plus" is "signaling round-trip + acceptor **delayed 2s before starting to punch**" piled up — it is **timing**, not pulse **duration**. At the time,
once the acceptor's first punch arrived, the connection was almost immediately established; the 900ms pulse duration was never the bottleneck. After switching to nudge,
the acceptor starts punching **earlier** than that 2s fixed delay (punches as soon as the nudge arrives), so it is usually faster now.

## Troubleshooting checklist (when "direct connection won't connect")

1. **First confirm it's not proxy hijacking**: if the resident machine has a global/per-app proxy, UDP sent to the peer may be hijacked away from the virtual
   network interface and never goes through the physical network interface. Capture the physical NIC with `host <peer IP>` to confirm the packet truly went out.
2. **Confirm NAT type**: use `nat-punch -mode=punch -reflect=<r1>,<r2>` (two reflectors with different IPs)
   to see if it's cone/EIM. All cone yet won't connect → think in terms of "order".
3. **Capture on both sides aligned**: one side sends, both capture, see if the packet reached the peer. Both sides "sent but peer didn't receive" = typical
   order poisoning (not path blocking).
4. **Swap order to verify**: make the other side send the first packet first (`nat-punch` manually controls enter order, or anyproxy sets `direct.punchFirst: true` on the
   CGNAT side). It connects the moment you swap = hard evidence of an order problem.
5. **Watch the packet-loss rate**: connected but high loss is often also a symptom of misaligned mapping, likewise pointing to order.

## Related code

- [nat/direct_msg.go](../nat/direct_msg.go): direct-connection signaling timing and structures — `d_request`/`d_punch`/
  `d_ready`/`d_offer`, and the newly added `d_punching` (nudge, `DirectPunching`),
  `DirectRequest.PunchFirst`/`DirectPunch.PunchFirst`.
- [nat/direct_entry.go](../nat/direct_entry.go): `ensureSession` (initiator dial; when `direct.punchFirst` set, send `d_punching` nudge before starting punch), `requestPeer` (carries `punchFirst` into
  `d_request`), `raceQUICDial`.
- [nat/direct_broker.go](../nat/direct_broker.go): `onPunching` (B forwards the nudge to C by email).
- [nat/direct_accept.go](../nat/direct_accept.go): `onPunch` (acceptor entry, switches to `parkPunch` when `p.PunchFirst`), `parkPunch` (stop and wait for nudge / fallback timeout), `onPunching` (triggers punch on receiving nudge).
- [nat/direct_reflect.go](../nat/direct_reflect.go): `punchOnly` (acceptor punch, a few packets suffice), reflector.
- [nat/direct.go](../nat/direct.go): `directPunchFirstDelay` (fallback delay when nudge lost),
  `directPeer.pendingPunch` (the parked-punch table waiting for nudge).
- [utils/conf/router.go](../utils/conf/router.go): `DirectSettings.PunchFirst` (under
  `WsClient.Direct`) config field.
- [examples/nat-punch](../examples/nat-punch): standalone bare UDP hole-punch test tool.
- The overall description of path C (QUIC direct connection) is in [websocket.md](websocket.md).
