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
//
//	# On each machine being tested:
//	go run . -mode=punch -reflect=<vps1-ip>:3478,<vps2-ip>:3478
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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const whoamiMagic = "WHOAMI?"

func main() {
	mode := flag.String("mode", "punch", "punch (machine under test) or reflect (public VPS helper)")
	listen := flag.String("listen", ":3478", "reflect mode: UDP address to listen on")
	reflect := flag.String("reflect", "", "punch mode: comma-separated reflector addresses; give TWO on different IPs to classify the NAT")
	local := flag.Int("local", 0, "punch mode: local UDP port to bind (0 = let the OS pick)")
	duration := flag.Duration("duration", 0, "punch mode: give up after this long (0 = keep punching until a packet arrives; recommended, since it removes the need to start both sides within seconds of each other)")
	interval := flag.Duration("interval", 200*time.Millisecond, "punch mode: gap between outgoing punch packets")
	flag.Parse()

	switch *mode {
	case "reflect":
		runReflect(*listen)
	case "punch":
		runPunch(*reflect, *local, *duration, *interval)
	default:
		log.Fatal("-mode must be punch or reflect")
	}
}

// runReflect answers every packet with the source address it was seen coming
// from. That observed address is the peer's NAT mapping for this socket.
func runReflect(listen string) {
	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		log.Fatalf("resolve %s: %v", listen, err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	defer conn.Close()
	log.Printf("reflector listening on %s", conn.LocalAddr())
	buf := make([]byte, 1024)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		log.Printf("saw %s (%d bytes)", from, n)
		if _, err := conn.WriteToUDP([]byte(from.String()), from); err != nil {
			log.Printf("reply to %s: %v", from, err)
		}
	}
}

func runPunch(reflectors string, localPort int, duration, interval time.Duration) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		log.Fatalf("bind local port %d: %v", localPort, err)
	}
	defer conn.Close()
	log.Printf("local socket: %s", conn.LocalAddr())

	if reflectors == "" {
		log.Fatal("-reflect is required in punch mode (run -mode=reflect on a public VPS first)")
	}
	list := strings.Split(reflectors, ",")
	announced := classifyNAT(conn, list)

	// A NAT drops an idle UDP mapping after as little as 30s. The pause while
	// you copy the address to the other machine is easily longer than that, and
	// if the mapping expires the address you handed the peer points at nothing:
	// both sides then punch forever at dead ports. Keep it warm.
	stopKeepalive := startKeepalive(conn, list)

	fmt.Fprintln(os.Stderr, "\nPaste the peer's public address (ip:port) and press Enter:")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("read peer address: %v", err)
	}
	peer, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(line))
	if err != nil {
		log.Fatalf("parse peer address: %v", err)
	}
	stopKeepalive()
	verifyMappingUnchanged(conn, list, announced)
	punch(conn, peer, duration, interval)
}

// startKeepalive re-probes a reflector every 10s so the NAT mapping announced
// to the peer stays alive while you copy addresses between machines. Replies
// pile up unread in the socket buffer; that is fine, the punch loop filters by
// source address and drainSocket clears them before the mapping re-check.
func startKeepalive(conn *net.UDPConn, reflectors []string) func() {
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				for _, r := range reflectors {
					addr, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(r))
					if err != nil {
						continue
					}
					_, _ = conn.WriteToUDP([]byte(whoamiMagic), addr)
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }) }
}

// verifyMappingUnchanged re-asks a reflector what it sees now, and warns if the
// mapping drifted from what was announced — in that case the address the peer
// is punching is stale and the exchange has to be redone.
func verifyMappingUnchanged(conn *net.UDPConn, reflectors []string, announced string) {
	if announced == "" || len(reflectors) == 0 {
		return
	}
	addr, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(reflectors[0]))
	if err != nil {
		return
	}
	drainSocket(conn)
	if _, err := conn.WriteToUDP([]byte(whoamiMagic), addr); err != nil {
		return
	}
	now, ok := readReflectorReply(conn, addr, 3*time.Second)
	if !ok {
		log.Printf("could not re-check mapping (reflector did not answer); continuing anyway")
		return
	}
	if now == announced {
		log.Printf("mapping still %s — the address your peer has is current", now)
		return
	}
	log.Printf("WARNING: mapping changed %s -> %s. The address your peer is punching is DEAD; "+
		"re-exchange addresses (use the new one) or this test cannot succeed.", announced, now)
}

// drainSocket discards anything already buffered so a following read gets a
// fresh reply rather than a stale keepalive answer.
func drainSocket(conn *net.UDPConn) {
	buf := make([]byte, 1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			_ = conn.SetReadDeadline(time.Time{})
			return
		}
	}
}

// classifyNAT sends a probe to each reflector from the SAME socket. A NAT that
// hands out one external port regardless of destination (endpoint-independent
// mapping, i.e. a "cone" NAT) is punchable; one that picks a fresh port per
// destination (symmetric) is not, because the port the peer was told about is
// not the port it will actually see.
// It returns the address announced to the peer (the first reflector's view),
// so the caller can later check whether the mapping drifted.
func classifyNAT(conn *net.UDPConn, reflectors []string) string {
	var observed []string
	for _, r := range reflectors {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp4", r)
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
		observed = append(observed, seen)
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch {
	case len(observed) == 0:
		log.Printf("NAT type: UNKNOWN — no reflector answered")
		return ""
	case len(observed) == 1:
		fmt.Printf("\nYour public address: %s\n", observed[0])
		log.Printf("NAT type: UNKNOWN — need a second reflector on a DIFFERENT public IP to tell cone from symmetric")
	default:
		fmt.Printf("\nYour public address: %s\n", observed[0])
		same := true
		for _, o := range observed[1:] {
			if o != observed[0] {
				same = false
				break
			}
		}
		if same {
			log.Printf("NAT type: CONE (endpoint-independent mapping) — same mapping toward every reflector, punchable")
		} else {
			log.Printf("NAT type: SYMMETRIC — mapping changes per destination (%s), hole punching will not work here", strings.Join(observed, " vs "))
		}
	}
	return observed[0]
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
func punch(conn *net.UDPConn, peer *net.UDPAddr, duration, interval time.Duration) {
	if duration > 0 {
		log.Printf("punching to %s, giving up after %s if nothing arrives", peer, duration)
	} else {
		log.Printf("punching to %s until a packet arrives (Ctrl-C to stop)", peer)
	}
	var received atomic.Int64
	done := make(chan struct{})
	success := make(chan struct{})

	go func() {
		buf := make([]byte, 1024)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue // read deadline, keep polling
				}
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
			case from.IP.Equal(peer.IP):
				log.Printf("packet from peer IP but port %d, not the expected %d — their NAT remapped the port (symmetric behavior)", from.Port, peer.Port)
			default:
				log.Printf("ignoring packet from unrelated source %s", from)
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	progress := time.NewTicker(5 * time.Second)
	defer progress.Stop()
	deadline := time.Now().Add(duration)
	started := time.Now()
	var sent int
	var drainDeadline time.Time
loop:
	for {
		select {
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
			msg := make([]byte, 16)
			binary.BigEndian.PutUint64(msg, uint64(sent))
			copy(msg[8:], "PUNCH")
			if _, err := conn.WriteToUDP(msg, peer); err != nil {
				log.Printf("send: %v", err)
			}
			sent++
		}
	}
	close(done)
	time.Sleep(100 * time.Millisecond)

	got := received.Load()
	fmt.Printf(`
=== punch result ===
sent:     %d
received: %d
verdict:  %s
`, sent, got, verdict(got))
}

func verdict(received int64) string {
	if received > 0 {
		return "SUCCESS — a direct UDP path exists between these two hosts"
	}
	return "FAILED — no packet arrived. Either the peer was not punching at the same time, " +
		"a NAT/firewall dropped it, or one side is symmetric (check the NAT type line above on BOTH sides)"
}
