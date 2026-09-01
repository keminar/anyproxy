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
	"sync/atomic"
	"time"
)

const whoamiMagic = "WHOAMI?"

func main() {
	mode := flag.String("mode", "punch", "punch (machine under test) or reflect (public VPS helper)")
	listen := flag.String("listen", ":3478", "reflect mode: UDP address to listen on")
	reflect := flag.String("reflect", "", "punch mode: comma-separated reflector addresses; give TWO on different IPs to classify the NAT")
	local := flag.Int("local", 0, "punch mode: local UDP port to bind (0 = let the OS pick)")
	duration := flag.Duration("duration", 30*time.Second, "punch mode: how long to keep sending/listening")
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
	classifyNAT(conn, strings.Split(reflectors, ","))

	fmt.Fprintln(os.Stderr, "\nPaste the peer's public address (ip:port) and press Enter:")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("read peer address: %v", err)
	}
	peer, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(line))
	if err != nil {
		log.Fatalf("parse peer address: %v", err)
	}
	punch(conn, peer, duration, interval)
}

// classifyNAT sends a probe to each reflector from the SAME socket. A NAT that
// hands out one external port regardless of destination (endpoint-independent
// mapping, i.e. a "cone" NAT) is punchable; one that picks a fresh port per
// destination (symmetric) is not, because the port the peer was told about is
// not the port it will actually see.
func classifyNAT(conn *net.UDPConn, reflectors []string) {
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
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1024)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("reflector %s: no reply (%v) — is it running, and is UDP open on that port?", r, err)
			continue
		}
		seen := string(buf[:n])
		log.Printf("reflector %s (replied from %s) sees me as %s", r, from, seen)
		observed = append(observed, seen)
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch {
	case len(observed) == 0:
		log.Printf("NAT type: UNKNOWN — no reflector answered")
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
}

// punch blasts packets at the peer while listening for theirs. Both sides must
// be doing this at the same time: the outgoing packets are what open each
// NAT's return path for the other side.
func punch(conn *net.UDPConn, peer *net.UDPAddr, duration, interval time.Duration) {
	log.Printf("punching to %s for %s (peer must be doing the same, now)", peer, duration)
	var received atomic.Int64
	done := make(chan struct{})

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
			if received.Add(1) == 1 {
				log.Printf("FIRST PACKET IN from %s: %q", from, string(buf[:n]))
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := time.Now().Add(duration)
	var sent int
	for range ticker.C {
		if time.Now().After(deadline) {
			break
		}
		msg := make([]byte, 16)
		binary.BigEndian.PutUint64(msg, uint64(sent))
		copy(msg[8:], "PUNCH")
		if _, err := conn.WriteToUDP(msg, peer); err != nil {
			log.Printf("send: %v", err)
		}
		sent++
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
