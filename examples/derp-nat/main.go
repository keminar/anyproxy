// derp-nat is a standalone feasibility test for using croc's DERP-based UDP
// hole punching (via github.com/shayne/derphole, forked as
// github.com/schollz/derphole for croc) as an alternative data path for
// anyproxy's websocket subscription tunnel (see docs/websocket.md).
//
// Today the subscriber (NAT side) and the server (public side) always relay
// bytes through the websocket control connection. This program checks
// whether two processes on two different real-world networks can instead
// negotiate a direct UDP/QUIC path via the public Tailscale DERP mesh, using
// only public infrastructure, and falling back to DERP relay if punching
// fails.
//
// Run on two machines that are NOT on the same LAN (otherwise NAT punching
// is trivial and proves nothing):
//
//	# machine A (plays the anyproxy subscriber, i.e. the NAT'd side)
//	go run . -mode=listen
//	# prints a token; copy it to machine B
//
//	# machine B (plays the anyproxy server, i.e. the public side)
//	go run . -mode=dial -token=<pasted token>
//
// Both sides print session.AttachGroupStats when the exchange finishes,
// including Path (direct vs relay), RawPathCount, and timing breakdowns.
// Path == direct means the punch succeeded and no server-side bandwidth is
// spent relaying the actual proxied traffic; Path == relay means it fell
// back to the DERP relay, same cost profile as today's websocket relay.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transport"
)

func main() {
	mode := flag.String("mode", "", "listen (NAT/subscriber side) or dial (public/server side)")
	token := flag.String("token", "", "token printed by -mode=listen; required for -mode=dial")
	streams := flag.Int("streams", session.DefaultAttachGroupStreams, "stream count for the attach group")
	forceRelay := flag.Int("force-relay", 0, "1 to force relay-only (baseline comparison, skips punching)")
	timeout := flag.Duration("timeout", 10*time.Minute, "how long to wait for the peer (keep this generous: it starts counting at process launch, not when you paste the token, so a slow copy-paste between two machines can burn most of a short budget before the peer even dials in)")
	flag.Parse()

	emitter := telemetry.WithStatusHook(nil, func(status string) {
		log.Printf("[derp status] %s", status)
	})

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	switch *mode {
	case "listen":
		runListen(ctx, emitter, *streams, *forceRelay == 1)
	case "dial":
		if *token == "" {
			log.Fatal("-token is required for -mode=dial")
		}
		runDial(ctx, emitter, *token, *streams, *forceRelay == 1)
	default:
		log.Fatal("must pass -mode=listen or -mode=dial")
	}
}

func runListen(ctx context.Context, emitter *telemetry.Emitter, streams int, forceRelay bool) {
	listener, err := session.ListenAttachGroup(ctx, session.AttachGroupListenConfig{
		Emitter:       emitter,
		ForceRelay:    forceRelay,
		UsePublicDERP: true,
		MaxStreams:    streams,
	})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	fmt.Println("TOKEN:", listener.Token)
	fmt.Fprintln(os.Stderr, "waiting for peer to dial with the token above...")

	group, err := listener.Accept(ctx)
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	defer group.Close()

	conns := group.Connections()
	if len(conns) == 0 {
		log.Fatal("attach group has no connections")
	}
	log.Printf("peer attached: %d stream(s)", len(conns))
	logConnAddrs("listener", conns, group.Stats().Mode)

	// Echo whatever the dial side sends, once, to prove the data plane works.
	reader := bufio.NewReader(conns[0])
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	log.Printf("received: %q", line)
	if _, err := conns[0].Write([]byte("echo: " + line)); err != nil {
		log.Fatalf("write: %v", err)
	}
	// Give the write time to actually reach the peer before the deferred
	// Close() tears the group down — over a relayed (non-direct) path the
	// close frame can otherwise race the data and the dial side sees
	// "attach group complete" instead of the echoed reply.
	time.Sleep(2 * time.Second)

	printStats("listener", group.Stats())
}

func runDial(ctx context.Context, emitter *telemetry.Emitter, token string, streams int, forceRelay bool) {
	group, err := session.DialAttachGroup(ctx, session.AttachGroupDialConfig{
		Token:         token,
		Emitter:       emitter,
		ForceRelay:    forceRelay,
		UsePublicDERP: true,
		StreamCount:   streams,
	})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer group.Close()

	conns := group.Connections()
	if len(conns) == 0 {
		log.Fatal("attach group has no connections")
	}
	log.Printf("attached: %d stream(s)", len(conns))
	logConnAddrs("dialer", conns, group.Stats().Mode)

	if _, err := conns[0].Write([]byte("hello from dial side\n")); err != nil {
		log.Fatalf("write: %v", err)
	}
	reader := bufio.NewReader(conns[0])
	reply, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("read reply: %v", err)
	}
	log.Printf("reply: %q", reply)

	printStats("dialer", group.Stats())
}

// logConnAddrs prints the local/remote endpoint each stream's underlying
// socket is actually talking to. This is only trustworthy in
// AttachGroupModeRawDirect: that mode's conns wrap the real QUIC/UDP socket,
// so remote is the peer's actual punched-through public IP:port. In
// AttachGroupModeManager, transport.Manager.remotePeerAddr() (derphole
// pkg/transport/peer.go) returns the hardcoded relay sentinel
// 127.0.0.1:1 (pkg/session/external.go relayTransportAddr) whenever relay
// fallback capability is configured — which is always, unless
// -force-relay=1 — regardless of whether that manager session actually
// ended up direct. So a manager-mode remote of 127.0.0.1:1 tells you
// nothing about the real peer address; don't read it as "went via
// loopback" or as evidence either way.
func logConnAddrs(who string, conns []net.Conn, mode session.AttachGroupMode) {
	if mode != session.AttachGroupModeRawDirect {
		log.Printf("%s: mode=%s, not raw-direct — remote addrs below are unreliable placeholders, skipping", who, mode)
		return
	}
	seen := make(map[string]bool)
	for i, c := range conns {
		key := fmt.Sprintf("%s->%s", c.LocalAddr(), c.RemoteAddr())
		if seen[key] {
			continue
		}
		seen[key] = true
		log.Printf("%s stream[%d] local=%s remote=%s", who, i, c.LocalAddr(), c.RemoteAddr())
	}
}

func printStats(who string, stats session.AttachGroupStats) {
	fmt.Printf(`
=== %s stats ===
mode:              %s
path:              %s   (direct = real UDP P2P, relay = fell back to DERP relay)
stream count:      %d
raw path count:    %d
setup duration:    %s
raw setup dur:     %s
fallback duration: %s
fallback reason:   %q
--- phases ---
candidate gather:   %s
candidate exchange: %s
punch:              %s
selection:          %s
handshake:          %s
readiness:          %s
`,
		who,
		stats.Mode,
		pathName(stats.Path),
		stats.StreamCount,
		stats.RawPathCount,
		stats.SetupDuration,
		stats.RawSetupDuration,
		stats.FallbackDuration,
		stats.FallbackReason,
		stats.Phases.CandidateGatherDuration,
		stats.Phases.CandidateExchangeDuration,
		stats.Phases.PunchDuration,
		stats.Phases.SelectionDuration,
		stats.Phases.HandshakeDuration,
		stats.Phases.ReadinessDuration,
	)
}

func pathName(p transport.Path) string {
	switch p {
	case transport.PathDirect:
		return "direct"
	case transport.PathRelay:
		return "relay"
	default:
		return "unknown"
	}
}
