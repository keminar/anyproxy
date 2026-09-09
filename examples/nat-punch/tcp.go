// TCP hole punching support for nat-punch.
//
// This is a genuinely different technique from the UDP punch in main.go, not
// a protocol swap of the same idea. UDP punching works because sending a
// packet out opens the NAT's return path. TCP has no such rule; instead this
// relies on "TCP simultaneous open" — both sides send SYN toward each other
// at roughly the same time, from the SAME local port they reflected off, and
// if the SYNs cross in flight the TCP state machine on both ends completes a
// connection without either side acting as a server. That requires binding
// the same local port for both listening and repeated outbound connects,
// which needs SO_REUSEADDR (see reuseAddrControl below).
//
// Given the derp-nat and UDP nat-punch results already showed both NAT types
// are cone, both mappings are stable, and both sides confirmed live while UDP
// packets still vanished, this is a low-probability, cheap-to-run test: worth
// trying because a different outcome (TCP succeeds where UDP failed) would
// mean the block is UDP-specific — some networks do exactly that — but do not
// expect it to succeed if the underlying block is protocol-agnostic path
// filtering, which is the more common case.
package main

import (
	"bufio"
	"context"
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

func init() {
	registerTCPFlags()
}

var (
	tcpReflectListen *string
	tcpReflector     *string
	tcpLocalPort     *int
	tcpDuration      *time.Duration
)

func registerTCPFlags() {
	tcpReflectListen = flag.String("tcp-listen", ":3479", "tcp-reflect mode: TCP address to listen on")
	tcpReflector = flag.String("tcp-reflect", "", "tcp-punch mode: TCP reflector address (host:port); needs its own reflector, a UDP one will not answer")
	tcpLocalPort = flag.Int("tcp-local", 0, "tcp-punch mode: local TCP port to bind (0 = pick one automatically; unlike UDP this MUST stay fixed for the whole run, so the tool picks one for you if you don't)")
	tcpDuration = flag.Duration("tcp-duration", 60*time.Second, "tcp-punch mode: how long to keep trying before giving up")
}

func dispatchTCPMode(mode string) bool {
	switch mode {
	case "tcp-reflect":
		runTCPReflect(*tcpReflectListen)
		return true
	case "tcp-punch":
		runTCPPunch(*tcpReflector, *tcpLocalPort, *tcpDuration)
		return true
	default:
		return false
	}
}

// runTCPReflect answers every connection with the address it was seen coming
// from, as text, then closes. Deliberately separate from the UDP reflector: a
// NAT commonly uses an independent port pool per protocol, so the mapping a
// UDP reflector reports does not tell you what TCP will get.
func runTCPReflect(listen string) {
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	defer ln.Close()
	log.Printf("TCP reflector listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		remote := conn.RemoteAddr().String()
		log.Printf("saw %s", remote)
		_, _ = conn.Write([]byte(remote))
		conn.Close()
	}
}

// reuseAddrControl (platform-specific implementation in reuseaddr_*.go) lets a
// socket bind a local port that is already occupied by another socket in a
// compatible state (our own prior probe connection just closing into
// TIME_WAIT, or — the whole point here — a listener and repeated outbound
// connects sharing one port at the same time). Without this, TCP simultaneous
// open cannot work: the port is fixed and reused, and a plain bind() would
// fail once anything else holds it.

func runTCPPunch(reflector string, localPort int, duration time.Duration) {
	if reflector == "" {
		log.Fatal("-tcp-reflect is required (run -mode=tcp-reflect on a public VPS first; it is a different listener from the UDP one)")
	}
	if localPort == 0 {
		localPort = pickLocalTCPPort()
		log.Printf("no -tcp-local given, using port %d for this run", localPort)
	}

	announced, err := probeTCPReflector(reflector, localPort)
	if err != nil {
		log.Fatalf("probe reflector %s: %v", reflector, err)
	}
	fmt.Printf("\nYour public TCP address: %s\n", announced)

	fmt.Fprintln(os.Stderr, "\nPaste the peer's public TCP address (ip:port) and press Enter:")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("read peer address: %v", err)
	}
	peerAddr := strings.TrimSpace(line)
	if _, _, err := net.SplitHostPort(peerAddr); err != nil {
		log.Fatalf("parse peer address: %v", err)
	}

	log.Printf("attempting TCP simultaneous open with %s from local port %d for up to %s", peerAddr, localPort, duration)
	log.Printf("(both sides must be at this point at roughly the same time — TCP punching has no keep-alive-until-ready phase like the UDP mode does)")

	result := make(chan net.Conn, 2)
	stop := make(chan struct{})
	closeOnce := sync.OnceFunc(func() { close(stop) })

	stats := &tcpPunchStats{}
	go acceptLoop(localPort, peerAddr, result, stop, stats)
	go dialLoop(localPort, peerAddr, result, stop, stats)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)

	var conn net.Conn
	select {
	case conn = <-result:
	case <-time.After(duration):
	case <-interrupt:
		log.Printf("interrupt received")
	}
	closeOnce()

	if conn == nil {
		fmt.Printf(`
=== tcp punch result ===
dial attempts:  %d
  bind failed:  %d
  timed out:    %d
  refused:      %d
  other errors: %d
listener:       %s
verdict:        FAILED — no TCP connection formed within %s
%s
`, stats.dialAttempts.Load(), stats.bindErrors.Load(), stats.timeoutErrors.Load(),
			stats.refusedErrors.Load(), stats.otherErrors.Load(),
			stats.listenerState(), duration, tcpFailureHint(stats))
		return
	}
	defer conn.Close()
	log.Printf("CONNECTED via %s <-> %s", conn.LocalAddr(), conn.RemoteAddr())
	fmt.Printf(`
=== tcp punch result ===
dial attempts:  %d
listener:       %s
verdict:        SUCCESS — a direct TCP path exists between these two hosts (%s <-> %s)
%s
`, stats.dialAttempts.Load(), stats.listenerState(), conn.LocalAddr(), conn.RemoteAddr(),
		tcpSuccessNote(conn, peerAddr, stats))
}

// tcpPunchStats separates "this side never managed to send anything" from
// "packets went out and got no answer". Without it a systematic local failure
// (a bind that never succeeds, say) looks identical to the network dropping
// the traffic, and the whole run silently tests only one direction.
type tcpPunchStats struct {
	dialAttempts  atomic.Int64
	bindErrors    atomic.Int64
	timeoutErrors atomic.Int64
	refusedErrors atomic.Int64
	otherErrors   atomic.Int64
	listenerUp    atomic.Bool
	listenerErr   atomic.Value // string
	wonByAccept   atomic.Bool
}

func (s *tcpPunchStats) listenerState() string {
	if s.listenerUp.Load() {
		return "up (inbound punch possible)"
	}
	if err, ok := s.listenerErr.Load().(string); ok && err != "" {
		return "DOWN: " + err + " (inbound punch impossible, only outbound was tested)"
	}
	return "unknown"
}

func (s *tcpPunchStats) recordDialError(err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "address already in use"):
		s.bindErrors.Add(1)
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "timeout"):
		s.timeoutErrors.Add(1)
	case strings.Contains(msg, "refused"):
		s.refusedErrors.Add(1)
	default:
		s.otherErrors.Add(1)
	}
}

func tcpFailureHint(s *tcpPunchStats) string {
	switch {
	case s.bindErrors.Load() > 0 && s.bindErrors.Load() == s.dialAttempts.Load():
		return "hint:           EVERY dial failed to bind the local port, so this side never sent a\n" +
			"                single SYN — the result says nothing about the network. The listener\n" +
			"                and the dialer could not share the port (SO_REUSEPORT rejected?)."
	case !s.listenerUp.Load():
		return "hint:           the listener never came up, so only the outbound direction was\n" +
			"                tested; a punch usually needs both."
	case s.timeoutErrors.Load() > 0 && s.refusedErrors.Load() == 0:
		return "hint:           SYNs went out and nothing came back at all (no RST either), which is\n" +
			"                what a silently dropping path looks like — same signature as the UDP result."
	case s.refusedErrors.Load() > 0:
		return "hint:           connections were actively refused (RST), so packets DO reach the peer's\n" +
			"                network — the peer side just was not listening on that port."
	default:
		return "hint:           check whether the peer was running at the same time."
	}
}

func tcpSuccessNote(conn net.Conn, peerAddr string, s *tcpPunchStats) string {
	note := "note:           won by outbound dial"
	if s.wonByAccept.Load() {
		note = "note:           won by inbound accept"
	}
	// A remote port other than the one that was pasted means the peer's NAT gave
	// this connection a different mapping than the one its reflector reported —
	// worth surfacing, since it is the reason TCP punching is less reliable than
	// UDP, and it also means the "success" may just be an ordinary connection to
	// a reachable listener rather than a punched-through path.
	if _, wantPort, err := net.SplitHostPort(peerAddr); err == nil {
		if _, gotPort, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil && gotPort != wantPort {
			note += fmt.Sprintf("\n                peer port is %s, not the announced %s — its NAT remapped this\n"+
				"                connection, so the announced address was not what actually connected", gotPort, wantPort)
		}
	}
	return note
}

func pickLocalTCPPort() int {
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		log.Fatalf("pick local port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// probeTCPReflector learns our own public TCP mapping by connecting out from
// the exact local port the rest of this run will reuse.
func probeTCPReflector(reflector string, localPort int) (string, error) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		LocalAddr: &net.TCPAddr{Port: localPort},
		Control:   reuseAddrControl,
	}
	conn, err := dialer.Dial("tcp4", reflector)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// acceptLoop listens on localPort — sharing it with dialLoop's repeated
// outbound attempts via SO_REUSEADDR — and reports a connection if it arrives
// from the peer's address.
func acceptLoop(localPort int, peerAddr string, result chan<- net.Conn, stop <-chan struct{}, stats *tcpPunchStats) {
	lc := net.ListenConfig{Control: reuseAddrControl}
	ln, err := lc.Listen(context.Background(), "tcp4", fmt.Sprintf(":%d", localPort))
	if err != nil {
		stats.listenerErr.Store(err.Error())
		log.Printf("listen on %d for inbound punch: %v (accept side disabled, relying on outbound connect only)", localPort, err)
		return
	}
	stats.listenerUp.Store(true)
	go func() {
		<-stop
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed, either by stop or a winning result
		}
		peerHost, _, _ := net.SplitHostPort(peerAddr)
		remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if remoteHost != peerHost {
			log.Printf("rejecting inbound connection from unexpected %s (expected peer at %s)", conn.RemoteAddr(), peerAddr)
			conn.Close()
			continue
		}
		stats.wonByAccept.Store(true)
		select {
		case result <- conn:
		default:
			conn.Close()
		}
		return
	}
}

// dialLoop repeatedly attempts an outbound connect from localPort to the
// peer, retrying on failure since the peer's NAT path is not open until it
// has sent its own outbound SYN.
func dialLoop(localPort int, peerAddr string, result chan<- net.Conn, stop <-chan struct{}, stats *tcpPunchStats) {
	attempt := 0
	for {
		select {
		case <-stop:
			return
		default:
		}
		attempt++
		stats.dialAttempts.Add(1)
		dialer := &net.Dialer{
			Timeout:   700 * time.Millisecond,
			LocalAddr: &net.TCPAddr{Port: localPort},
			Control:   reuseAddrControl,
		}
		conn, err := dialer.Dial("tcp4", peerAddr)
		if err == nil {
			select {
			case result <- conn:
			default:
				conn.Close()
			}
			return
		}
		stats.recordDialError(err)
		if attempt%5 == 0 {
			log.Printf("still trying to connect to %s (%d attempts, last error: %v)", peerAddr, attempt, err)
		}
		select {
		case <-stop:
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
}
