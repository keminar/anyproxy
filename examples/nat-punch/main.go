// nat-punch is a minimal, dependency-free UDP hole punching tester.
//
// It exists because examples/derp-nat answers only one question — "did
// derphole's whole machinery manage a direct path?" — and that machinery has
// many moving parts (DERP signaling, 4 parallel UDP lanes, a fixed 1.2s punch
// window, a 2-of-4 lane quorum, then a QUIC handshake). When it fails you
// cannot tell which layer failed. This tool strips all of that away and tests
// the one thing underneath: can two hosts behind their respective NATs get a
// single UDP packet to each other?
//
// It also replaces the tcpdump/nc recipe for classifying a NAT, and works the
// same on Windows and Linux.
//
// Two modes:
//
//	# On a public VPS — reflects each packet's observed source address back.
//	# Run it on TWO different VPSes to enable cone/symmetric classification.
//	go run . -mode=reflect -listen=:3478
//	go run . -mode=reflect -network=udp6 -listen=:3478
//
//	# On each machine being tested:
//	go run . -mode=punch -reflect=<vps1-ip>:3478,<vps2-ip>:3478
//	go run . -mode=punch -network=udp6 -reflect=[<vps1-ipv6>]:3478
//	# It prints your public address, then waits for you to paste the peer's.
//	# Start it on BOTH machines, then paste each side's address into the other
//	# within a few seconds of one another — punching only works if both sides
//	# are sending at roughly the same time.
//
// Everything runs on ONE socket for the whole session, which is what makes the
// result meaningful: the address the reflector observes is the same mapping the
// punch packets will use. Restarting the process gets a new mapping.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	whoamiMagic  = "WHOAMI?"
	statusPrefix = "STATUS "
	// How recently the reflector must have received a STATUS heartbeat from an
	// address to call it active. Punching sends one every few seconds, so a peer
	// that is really in its punch loop will always fall inside this window.
	peerActiveWindow = 15 * time.Second
)

type peerActivity struct {
	seen        map[string]time.Time
	lastCleanup time.Time
}

func newPeerActivity(now time.Time) *peerActivity {
	return &peerActivity{seen: make(map[string]time.Time), lastCleanup: now}
}

func (a *peerActivity) mark(addr string, now time.Time) {
	a.seen[addr] = now
	// Bound reflector memory without scanning the map on every packet. An idle
	// reflector needs no cleanup because the map cannot grow while it is idle.
	if now.Sub(a.lastCleanup) >= peerActiveWindow {
		for peer, last := range a.seen {
			if now.Sub(last) >= peerActiveWindow {
				delete(a.seen, peer)
			}
		}
		a.lastCleanup = now
	}
}

func (a *peerActivity) active(addr string, now time.Time) bool {
	last, ok := a.seen[addr]
	return ok && now.Sub(last) < peerActiveWindow
}

func reflectorResponse(activity *peerActivity, from, payload string, now time.Time) (reply string, statusQuery bool) {
	if target, ok := strings.CutPrefix(payload, statusPrefix); ok {
		// STATUS is emitted only after a client enters its punch loop. WHOAMI
		// and keepalives deliberately do not count as peer activity: otherwise
		// a client waiting at the paste prompt could make a failed test look
		// like both peers were punching concurrently.
		activity.mark(from, now)
		if activity.active(strings.TrimSpace(target), now) {
			return "ACTIVE", true
		}
		return "IDLE", true
	}
	return from, false
}

func main() {
	mode := flag.String("mode", "punch", "punch/reflect (UDP, see -reflect/-listen) or tcp-punch/tcp-reflect (TCP, see -tcp-reflect/-tcp-listen)")
	network := flag.String("network", "udp4", "UDP address family: udp4 or udp6")
	listen := flag.String("listen", ":3478", "reflect mode: UDP address to listen on")
	reflect := flag.String("reflect", "", "punch mode: comma-separated reflector addresses; give TWO on different IPs to classify the NAT")
	local := flag.Int("local", 0, "punch mode: local UDP port to bind (0 = let the OS pick)")
	duration := flag.Duration("duration", 0, "punch mode: give up after this long (0 = keep punching until a packet arrives; recommended, since it removes the need to start both sides within seconds of each other)")
	interval := flag.Duration("interval", 200*time.Millisecond, "punch mode: gap between outgoing punch packets")
	flag.Parse()
	if err := validateNetwork(*network); err != nil {
		log.Fatal(err)
	}
	if *mode == "punch" {
		if err := validatePunchArgs(*local, *duration, *interval); err != nil {
			log.Fatal(err)
		}
	}

	if dispatchTCPMode(*mode) {
		return
	}
	switch *mode {
	case "reflect":
		runReflect(*network, *listen)
	case "punch":
		runPunch(*network, *reflect, *local, *duration, *interval)
	default:
		log.Fatal("-mode must be one of: punch, reflect, tcp-punch, tcp-reflect")
	}
}

func validateNetwork(network string) error {
	if network != "udp4" && network != "udp6" {
		return fmt.Errorf("-network must be udp4 or udp6")
	}
	return nil
}

func validatePunchArgs(localPort int, duration, interval time.Duration) error {
	if localPort < 0 || localPort > 65535 {
		return fmt.Errorf("-local must be between 0 and 65535")
	}
	if duration < 0 {
		return fmt.Errorf("-duration must not be negative")
	}
	if interval <= 0 {
		return fmt.Errorf("-interval must be greater than zero")
	}
	return nil
}

// runReflect answers "WHOAMI?" with the source address it observed, and
// "STATUS <addr>" with whether that address has sent a STATUS heartbeat
// recently. The status answer makes a failed punch interpretable: WHOAMI and
// keepalive traffic are deliberately excluded, so ACTIVE means the peer really
// entered its punch loop during the same window.
func runReflect(network, listen string) {
	addr, err := net.ResolveUDPAddr(network, listen)
	if err != nil {
		log.Fatalf("resolve %s: %v", listen, err)
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	defer conn.Close()
	log.Printf("reflector listening on %s (%s)", conn.LocalAddr(), network)

	activity := newPeerActivity(time.Now())

	buf := make([]byte, 1024)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		payload := string(buf[:n])
		reply, statusQuery := reflectorResponse(activity, from.String(), payload, time.Now())
		if statusQuery {
			log.Printf("status query from %s: %q -> %s", from, payload, reply)
		} else {
			log.Printf("saw %s (%d bytes)", from, n)
		}
		if _, err := conn.WriteToUDP([]byte(reply), from); err != nil {
			log.Printf("reply to %s: %v", from, err)
		}
	}
}

func runPunch(network, reflectors string, localPort int, duration, interval time.Duration) {
	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: localPort})
	if err != nil {
		log.Fatalf("bind local port %d: %v", localPort, err)
	}
	defer conn.Close()
	log.Printf("local socket: %s (%s)", conn.LocalAddr(), network)

	if reflectors == "" {
		log.Fatal("-reflect is required in punch mode (run -mode=reflect on a public VPS first)")
	}
	list := nonEmpty(strings.Split(reflectors, ","))
	if len(list) == 0 {
		log.Fatal("-reflect must contain at least one reflector address")
	}
	announced, primaryReflector := classifyNAT(conn, network, list)
	if announced == "" {
		log.Printf("ABORTED — no reflector returned a usable public address; cannot exchange endpoints or run a meaningful punch test")
		return
	}

	// A NAT drops an idle UDP mapping after as little as 30s. The pause while
	// you copy the address to the other machine is easily longer than that, and
	// if the mapping expires the address you handed the peer points at nothing:
	// both sides then punch forever at dead ports. Keep it warm.
	stopKeepalive := startKeepalive(conn, network, list)

	fmt.Fprintln(os.Stderr, "\nPaste the peer's public address (ip:port) and press Enter:")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("read peer address: %v", err)
	}
	peer, err := net.ResolveUDPAddr(network, strings.TrimSpace(line))
	if err != nil {
		log.Fatalf("parse peer address: %v", err)
	}
	stopKeepalive()
	if !verifyMappingUnchanged(conn, primaryReflector, announced) {
		fmt.Printf(`
=== punch result ===
verdict:    INCONCLUSIVE — the public mapping changed before punching; exchange the newly printed address and retry
`)
		return
	}
	punch(conn, network, peer, primaryReflector, duration, interval)
}

func nonEmpty(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

// startKeepalive re-probes a reflector every 10s so the NAT mapping announced
// to the peer stays alive while you copy addresses between machines. Replies
// pile up unread in the socket buffer; that is fine, the punch loop filters by
// source address and drainSocket clears them before the mapping re-check.
func startKeepalive(conn *net.UDPConn, network string, reflectors []string) func() {
	stop := make(chan struct{})
	stopped := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				for _, r := range reflectors {
					addr, err := net.ResolveUDPAddr(network, strings.TrimSpace(r))
					if err != nil {
						continue
					}
					_, _ = conn.WriteToUDP([]byte(whoamiMagic), addr)
				}
			}
		}
	}()
	return func() {
		once.Do(func() {
			close(stop)
			<-stopped
		})
	}
}

// verifyMappingUnchanged re-asks a reflector what it sees now, and warns if the
// mapping drifted from what was announced — in that case the address the peer
// is punching is stale and the exchange has to be redone.
func verifyMappingUnchanged(conn *net.UDPConn, reflector *net.UDPAddr, announced string) bool {
	if announced == "" || reflector == nil {
		return false
	}
	drainSocket(conn)
	if _, err := conn.WriteToUDP([]byte(whoamiMagic), reflector); err != nil {
		log.Printf("could not re-check mapping: send to reflector: %v", err)
		return false
	}
	now, ok := readReflectorReply(conn, reflector, 3*time.Second)
	if !ok {
		log.Printf("could not re-check mapping (reflector did not answer); aborting because the address may be stale")
		return false
	}
	if now == announced {
		log.Printf("mapping still %s — the address your peer has is current", now)
		return true
	}
	log.Printf("WARNING: mapping changed %s -> %s. The address your peer is punching is DEAD; "+
		"re-exchange addresses (use the new one) or this test cannot succeed.", announced, now)
	fmt.Printf("\nYour NEW public address: %s\n", now)
	return false
}

// drainSocket discards packets for one short, strictly bounded window so a
// following read does not consume a stale keepalive answer. Its deadline must
// be absolute: the peer may already be punching every 200ms, and resetting the
// deadline after every packet would otherwise drain forever and prevent this
// side from ever entering its own punch loop.
func drainSocket(conn *net.UDPConn) {
	buf := make([]byte, 1024)
	deadline := time.Now().Add(150 * time.Millisecond)
	for {
		_ = conn.SetReadDeadline(deadline)
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			_ = conn.SetReadDeadline(time.Time{})
			return
		}
	}
}

// classifyNAT sends a probe to each reflector from the SAME socket. For IPv4,
// a NAT that hands out one external port regardless of destination
// (endpoint-independent mapping, i.e. a "cone" NAT) is punchable; one that
// picks a fresh port per destination (symmetric) is not. For IPv6 the same
// comparison detects whether the advertised public endpoint is stable across
// paths, without assuming that NAT is involved.
// It returns the address announced to the peer (the first reflector's view),
// so the caller can later check whether the mapping drifted.
func classifyNAT(conn *net.UDPConn, network string, reflectors []string) (string, *net.UDPAddr) {
	var observed []string
	var primary *net.UDPAddr
	for _, r := range reflectors {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr(network, r)
		if err != nil {
			log.Printf("reflector %s: resolve: %v", r, err)
			continue
		}
		if _, err := conn.WriteToUDP([]byte(whoamiMagic), addr); err != nil {
			log.Printf("reflector %s: write: %v", r, err)
			continue
		}
		// Only the reflector's own reply may be read as our public address.
		// The peer may already be punching at us while we are still probing,
		// and treating one of its packets as the reply would silently corrupt
		// the one value this whole test depends on.
		seen, ok := readReflectorReply(conn, addr, 3*time.Second)
		if !ok {
			log.Printf("reflector %s: no reply — is it running, and is UDP open on that port?", r)
			continue
		}
		log.Printf("reflector %s sees me as %s", r, seen)
		if primary == nil {
			primary = addr
		}
		observed = append(observed, seen)
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch {
	case len(observed) == 0:
		log.Printf("endpoint mapping: UNKNOWN — no reflector answered")
		return "", nil
	case len(observed) == 1:
		fmt.Printf("\nYour public address: %s\n", observed[0])
		if network == "udp6" {
			log.Printf("IPv6 endpoint stability: UNKNOWN — need a second reflector on a DIFFERENT IPv6 address to compare paths")
		} else {
			log.Printf("NAT type: UNKNOWN — need a second reflector on a DIFFERENT public IP to tell cone from symmetric")
		}
	default:
		fmt.Printf("\nYour public address: %s\n", observed[0])
		same := true
		for _, o := range observed[1:] {
			if o != observed[0] {
				same = false
				break
			}
		}
		if network == "udp6" && same {
			log.Printf("IPv6 endpoint: STABLE — every reflector sees the same address and port")
		} else if network == "udp6" {
			log.Printf("IPv6 endpoint: CHANGED across destinations (%s) — do not use the announced endpoint for a reliable direct test", strings.Join(observed, " vs "))
		} else if same {
			log.Printf("NAT type: CONE (endpoint-independent mapping) — same mapping toward every reflector, punchable")
		} else {
			log.Printf("NAT type: SYMMETRIC — mapping changes per destination (%s), hole punching will not work here", strings.Join(observed, " vs "))
		}
	}
	return observed[0], primary
}

// readReflectorReply waits for a packet from exactly this reflector, skipping
// anything else that lands on the socket meanwhile.
func readReflectorReply(conn *net.UDPConn, reflector *net.UDPAddr, wait time.Duration) (string, bool) {
	buf := make([]byte, 1024)
	giveUp := time.Now().Add(wait)
	for time.Now().Before(giveUp) {
		_ = conn.SetReadDeadline(giveUp)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return "", false
		}
		if from.IP.Equal(reflector.IP) && from.Port == reflector.Port {
			return string(buf[:n]), true
		}
		log.Printf("ignoring packet from %s while probing reflector %s", from, reflector)
	}
	return "", false
}

// punch blasts packets at the peer while listening for theirs. Both sides have
// to be sending during the same window — each side's outgoing packets are what
// open its own NAT's return path for the other side — so this keeps going until
// a packet arrives rather than stopping after a fixed time. Coordinating two
// terminals to the second is the single most common reason a punch that would
// have worked reports FAILED.
// statusVia, when non-nil, is a reflector asked every few seconds whether the
// peer is punching right now, so a FAILED result can be told apart from "the
// other side simply was not running".
func punch(conn *net.UDPConn, network string, peer *net.UDPAddr, statusVia *net.UDPAddr, duration, interval time.Duration) {
	if duration > 0 {
		log.Printf("punching to %s, giving up after %s if nothing arrives", peer, duration)
	} else {
		log.Printf("punching to %s until a packet arrives (Ctrl-C to stop)", peer)
	}
	var received atomic.Int64
	var peerSeenActive atomic.Bool
	var staleReflector atomic.Bool
	done := make(chan struct{})
	readerDone := make(chan struct{})
	success := make(chan struct{})
	var receiveErrors int

	go func() {
		defer close(readerDone)
		buf := make([]byte, 1024)
		var lastReadError time.Time
		var suppressedReadErrors int
		for {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				receiveErrors++
				// Linux may surface an ICMP Port Unreachable here as ECONNREFUSED
				// even though this is an unconnected UDP socket. Report it, but keep
				// punching because the peer may not have opened its path yet.
				now := time.Now()
				if lastReadError.IsZero() || now.Sub(lastReadError) >= time.Second {
					if suppressedReadErrors > 0 {
						log.Printf("UDP receive error: %v (%d similar errors suppressed)", err, suppressedReadErrors)
					} else {
						log.Printf("UDP receive error: %v", err)
					}
					lastReadError = now
					suppressedReadErrors = 0
				} else {
					suppressedReadErrors++
					time.Sleep(10 * time.Millisecond)
				}
				continue
			}
			// Only packets from the address we are punching count. Anything
			// else (a reflector reply still in flight, unrelated traffic)
			// would otherwise be reported as a successful punch. A packet
			// from the peer's IP but a different port is worth calling out:
			// that is what a symmetric NAT on their side looks like.
			switch {
			case from.IP.Equal(peer.IP) && from.Port == peer.Port:
				if received.Add(1) == 1 {
					log.Printf("FIRST PACKET IN from %s: %q", from, string(buf[:n]))
					close(success)
				}
			// Checked before the peer-IP-only case below: when the reflector
			// and the peer share an IP (loopback testing), an exact match on
			// the reflector is the more specific answer, and misreading its
			// status reply as a remapped peer port would be actively
			// misleading.
			case statusVia != nil && from.IP.Equal(statusVia.IP) && from.Port == statusVia.Port:
				switch string(buf[:n]) {
				case "ACTIVE":
					if !peerSeenActive.Swap(true) {
						log.Printf("reflector confirms the peer is punching right now — both sides are live, so a failure here is a real network failure")
					}
				case "IDLE":
					if received.Load() == 0 {
						log.Printf("reflector has NOT heard from %s recently — the peer is probably not running; this round proves nothing", peer)
					}
				default:
					// An older reflector build answers every packet with the
					// source address, so it echoes the query instead. Say so
					// rather than letting it look like an absent peer.
					if !staleReflector.Swap(true) {
						log.Printf("this reflector does not understand STATUS (older build) — redeploy it on the VPS to get peer-liveness confirmation")
					}
				}
			case from.IP.Equal(peer.IP):
				if network == "udp6" {
					log.Printf("packet from peer IPv6 address but port %d, not the expected %d — the advertised endpoint changed or was incorrect", from.Port, peer.Port)
				} else {
					log.Printf("packet from peer IP but port %d, not the expected %d — their NAT remapped the port (symmetric behavior)", from.Port, peer.Port)
				}
			default:
				log.Printf("ignoring packet from unrelated source %s", from)
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	progress := time.NewTicker(5 * time.Second)
	defer progress.Stop()
	statusTick := time.NewTicker(3 * time.Second)
	defer statusTick.Stop()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	deadline := time.Now().Add(duration)
	started := time.Now()
	var sent int
	var sendFailed int
	var drainDeadline time.Time
	sendStatus := func() {
		if statusVia == nil {
			return
		}
		if _, err := conn.WriteToUDP([]byte(statusPrefix+peer.String()), statusVia); err != nil {
			log.Printf("status heartbeat to reflector failed: %v", err)
		}
	}
	sendPunch := func() {
		msg := make([]byte, 16)
		binary.BigEndian.PutUint64(msg, uint64(sent))
		copy(msg[8:], "PUNCH")
		if _, err := conn.WriteToUDP(msg, peer); err != nil {
			sendFailed++
			log.Printf("UDP send to %s failed: %v", peer, err)
		}
		sent++
	}
	// Do not wait for the first ticker edge. Immediate heartbeats make short
	// tests observable by the reflector, and the first peer packet opens the
	// NAT path without adding one full interval of avoidable delay.
	sendStatus()
	sendPunch()
loop:
	for {
		select {
		case <-interrupt:
			log.Printf("interrupt received; stopping and printing the result collected so far")
			break loop
		case <-statusTick.C:
			sendStatus()
		case <-success:
			// Keep sending for a moment rather than stopping dead: the peer may
			// have started later and still needs packets from us to confirm its
			// own receive direction. Nil the channel so this case stops firing
			// (a closed channel would spin here).
			drainDeadline = time.Now().Add(2 * time.Second)
			success = nil
		case <-progress.C:
			log.Printf("still punching: sent=%d received=%d elapsed=%s", sent, received.Load(), time.Since(started).Truncate(time.Second))
		case <-ticker.C:
			if !drainDeadline.IsZero() && time.Now().After(drainDeadline) {
				break loop
			}
			if duration > 0 && time.Now().After(deadline) {
				break loop
			}
			sendPunch()
		}
	}
	close(done)
	_ = conn.SetReadDeadline(time.Now())
	<-readerDone

	got := received.Load()
	fmt.Printf(`
=== punch result ===
attempted:  %d
send ok:    %d
send failed: %d
recv errors: %d
received:   %d
peer live:  %s
verdict:    %s
`, sent, sent-sendFailed, sendFailed, receiveErrors, got, peerLive(got, peerSeenActive.Load(), staleReflector.Load(), statusVia), verdict(got, peerSeenActive.Load(), network))
}

func peerLive(received int64, seenActive, staleReflector bool, statusVia *net.UDPAddr) string {
	switch {
	// Its packets arriving is the strongest possible proof of liveness, and
	// beats any reflector opinion — a fast success can finish before the first
	// status query even goes out.
	case received > 0:
		return "yes — its packets arrived here"
	case statusVia == nil:
		return "unknown (no reflector to ask)"
	case seenActive:
		return "yes — reflector saw the peer punching during this run"
	case staleReflector:
		return "unknown — the reflector is an older build with no STATUS support; redeploy it"
	default:
		return "NO — reflector never saw the peer; it likely was not running"
	}
}

func verdict(received int64, peerSeenActive bool, network string) string {
	switch {
	case received > 0:
		return "SUCCESS — a direct UDP path exists between these two hosts"
	case peerSeenActive:
		if network == "udp6" {
			return "FAILED — the peer was confirmed live and still nothing arrived. " +
				"Direct IPv6 UDP is blocked (host/router/cloud firewall or path filtering)"
		}
		return "FAILED — the peer was confirmed live and still nothing arrived. " +
			"Direct UDP between these two networks is genuinely blocked (ISP/CGNAT filtering, " +
			"or a NAT that does not behave as the type test suggests)"
	default:
		return "INCONCLUSIVE — no packet arrived, but the peer was never seen to be running. " +
			"Start both sides so they overlap, then judge the result"
	}
}
