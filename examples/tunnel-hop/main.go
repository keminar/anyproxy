// tunnel-hop compares two "middle hop" transports for anyproxy's websocket
// tunnel data plane: today's plain TCP relay vs a QUIC relay, under real
// network conditions. It does not run a real RDP session — it pushes a
// synthetic, RDP-like traffic pattern (small fixed-size packets on a fixed
// cadence, roughly matching a 30-60fps screen-update rate) through whichever
// hop transport is selected, and measures the thing that actually drives
// perceived smoothness: gaps between consecutive packet arrivals. A single
// lost packet on a plain TCP hop stalls everything behind it until it's
// retransmitted (in-order delivery); QUIC's per-stream loss recovery doesn't
// have that same all-or-nothing stall.
//
// Run the "source" (simulates the RDP target pushing screen updates) on one
// machine and the "sink" (simulates the RDP client) on another, across a
// real network path — ideally the same lossy/high-latency link your actual
// subscriber would use. Run once with -hop=tcp, then again with -hop=quic,
// and compare the stall stats each side of the sink report prints.
//
//	# sink (near/client side) — listens for the hop connection
//	go run . -side=sink -hop=tcp -listen=:9100
//	# source (far/target side) — dials out to the sink
//	go run . -side=source -hop=tcp -connect=<sink-ip>:9100
//
//	# then repeat with -hop=quic on a different port to compare
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sort"
	"time"

	quic "github.com/quic-go/quic-go"
)

// finSeq marks the last packet of a run so the sink can print its report
// without needing its own separate timer/duration flag.
const finSeq = ^uint64(0)

const alpn = "anyproxy-tunnel-hop"

func main() {
	side := flag.String("side", "", "source (pushes synthetic traffic) or sink (receives + reports stats)")
	hop := flag.String("hop", "tcp", "tcp or quic: which middle-hop transport to test")
	listen := flag.String("listen", "", "address to listen on for the hop connection (set this OR -connect)")
	connect := flag.String("connect", "", "address to dial for the hop connection (set this OR -listen)")
	rate := flag.Duration("rate", 20*time.Millisecond, "interval between synthetic packets (source side; ~20ms mimics a 50fps screen-update cadence)")
	payload := flag.Int("payload", 512, "bytes per synthetic packet, including the 8-byte sequence header")
	duration := flag.Duration("duration", 60*time.Second, "how long the source pushes traffic")
	stallThreshold := flag.Duration("stall", 150*time.Millisecond, "an inter-arrival gap above this counts as a stall (sink side; ~150ms is the rough threshold where interactive lag becomes noticeable)")
	flag.Parse()

	if *payload < 8 {
		log.Fatal("-payload must be at least 8 bytes (needs room for the sequence header)")
	}
	if (*listen == "") == (*connect == "") {
		log.Fatal("set exactly one of -listen or -connect")
	}
	if *side != "source" && *side != "sink" {
		log.Fatal("must pass -side=source or -side=sink")
	}

	ctx := context.Background()
	stream, closeFn, err := openHop(ctx, *hop, *listen, *connect)
	if err != nil {
		log.Fatalf("hop setup: %v", err)
	}
	defer closeFn()

	if *side == "source" {
		runSource(stream, *rate, *payload, *duration)
	} else {
		runSink(stream, *payload, *stallThreshold)
	}
}

type hopStream interface {
	io.Reader
	io.Writer
}

func openHop(ctx context.Context, hop, listen, connect string) (hopStream, func(), error) {
	switch hop {
	case "tcp":
		return openTCPHop(listen, connect)
	case "quic":
		return openQUICHop(ctx, listen, connect)
	default:
		return nil, nil, fmt.Errorf("unknown -hop %q (want tcp or quic)", hop)
	}
}

func openTCPHop(listen, connect string) (hopStream, func(), error) {
	if listen != "" {
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			return nil, nil, err
		}
		log.Printf("tcp hop: listening on %s, waiting for peer...", listen)
		conn, err := ln.Accept()
		ln.Close()
		if err != nil {
			return nil, nil, err
		}
		log.Printf("tcp hop: peer connected from %s", conn.RemoteAddr())
		return conn, func() { conn.Close() }, nil
	}
	conn, err := net.Dial("tcp", connect)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("tcp hop: connected to %s", connect)
	return conn, func() { conn.Close() }, nil
}

func openQUICHop(ctx context.Context, listen, connect string) (hopStream, func(), error) {
	if listen != "" {
		tlsConf, err := generateTLSConfig()
		if err != nil {
			return nil, nil, err
		}
		ln, err := quic.ListenAddr(listen, tlsConf, nil)
		if err != nil {
			return nil, nil, err
		}
		log.Printf("quic hop: listening on %s, waiting for peer...", listen)
		conn, err := ln.Accept(ctx)
		if err != nil {
			ln.Close()
			return nil, nil, err
		}
		log.Printf("quic hop: peer connected from %s", conn.RemoteAddr())
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return nil, nil, err
		}
		return stream, func() { stream.Close(); conn.CloseWithError(0, ""); ln.Close() }, nil
	}
	// Self-signed cert, so we skip verification here on purpose: this
	// harness only measures transport behavior, it's not a security
	// example. A real integration would pin/verify a real certificate.
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}}
	conn, err := quic.DialAddr(ctx, connect, tlsConf, nil)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("quic hop: connected to %s", connect)
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, err
	}
	return stream, func() { stream.Close(); conn.CloseWithError(0, "") }, nil
}

func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{alpn}}, nil
}

func runSource(w io.Writer, rate time.Duration, payloadSize int, duration time.Duration) {
	buf := make([]byte, payloadSize)
	ticker := time.NewTicker(rate)
	defer ticker.Stop()
	deadline := time.Now().Add(duration)
	var seq uint64
	log.Printf("source: pushing %d-byte packets every %s for %s", payloadSize, rate, duration)
	for now := range ticker.C {
		if now.After(deadline) {
			break
		}
		binary.BigEndian.PutUint64(buf, seq)
		if _, err := w.Write(buf); err != nil {
			log.Fatalf("source: write: %v", err)
		}
		seq++
	}
	binary.BigEndian.PutUint64(buf, finSeq)
	if _, err := w.Write(buf); err != nil {
		log.Printf("source: write fin marker: %v", err)
	}
	// Give the fin marker time to actually cross the network before the
	// caller's deferred close tears the hop down — over a real WAN link
	// (as opposed to loopback) the close can otherwise race the write,
	// especially on the QUIC hop where Close() doesn't linger like a TCP
	// socket's does.
	time.Sleep(2 * time.Second)
	log.Printf("source: done, sent %d packets", seq)
}

func runSink(r io.Reader, payloadSize int, stallThreshold time.Duration) {
	br := bufio.NewReaderSize(r, payloadSize*4)
	buf := make([]byte, payloadSize)
	var (
		count       int
		lastArrival time.Time
		gaps        []time.Duration
		lastSeq     uint64
		haveLast    bool
	)
	log.Printf("sink: waiting for packets...")
	for {
		if _, err := io.ReadFull(br, buf); err != nil {
			log.Printf("sink: stream ended without a fin marker: %v", err)
			break
		}
		seq := binary.BigEndian.Uint64(buf)
		now := time.Now()
		if seq == finSeq {
			log.Printf("sink: received fin marker")
			break
		}
		if haveLast && seq != lastSeq+1 {
			log.Printf("sink: sequence gap: expected %d, got %d (hop reordered or dropped data)", lastSeq+1, seq)
		}
		lastSeq = seq
		haveLast = true
		if count > 0 {
			gaps = append(gaps, now.Sub(lastArrival))
		}
		lastArrival = now
		count++
	}
	printReport(count, gaps, stallThreshold)
}

func printReport(count int, gaps []time.Duration, stallThreshold time.Duration) {
	if len(gaps) == 0 {
		fmt.Println("no data collected (0 or 1 packets received)")
		return
	}
	sorted := append([]time.Duration(nil), gaps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pct := func(p float64) time.Duration {
		idx := int(p * float64(len(sorted)-1))
		return sorted[idx]
	}
	var stallCount int
	var stallTotal, max time.Duration
	for _, g := range gaps {
		if g > max {
			max = g
		}
		if g > stallThreshold {
			stallCount++
			stallTotal += g
		}
	}
	fmt.Printf(`
=== sink report ===
packets received:      %d
inter-arrival samples:  %d
p50 gap:                %s
p95 gap:                %s
p99 gap:                %s
max gap:                %s
stalls (> %s):       %d   (total stalled time: %s)
`,
		count, len(sorted), pct(0.50), pct(0.95), pct(0.99), max,
		stallThreshold, stallCount, stallTotal)
}
