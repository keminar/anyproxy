//go:build windows

package wdengine

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/proto"
)

// proxyServer accepts the connections WinDivert has redirected here, recovers
// each one's original destination from the NAT table, and hands it to anyproxy's
// own ForwardTCP engine (which applies router.yaml rules, SNI/Host sniffing and
// direct/upstream forwarding).
type proxyServer struct {
	cfg *Config
	nat *natTable
	ln  net.Listener
	rl  *rateLimiter // per-destination new-connection cap (nil = unlimited)
}


// startProxy binds the local listener. If cfg.ProxyPort is 0 an ephemeral port
// is chosen and written back into cfg so the WinDivert filter can reference it.
// It binds ":port" (dual-stack) because redirected packets are addressed to this
// host's NIC IP — IPv4 or IPv6 — rather than to 127.0.0.1/::1; binding a single
// loopback address would miss them. To keep the port from being an externally
// reachable open endpoint, handle() rejects any accepted connection whose remote
// IP is not this host's own (redirected connections always have remote IP ==
// local IP; see the check there).
func startProxy(cfg *Config, nat *natTable) (*proxyServer, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.ProxyPort))
	if err != nil {
		return nil, err
	}
	cfg.ProxyPort = uint16(ln.Addr().(*net.TCPAddr).Port)

	s := &proxyServer{
		cfg: cfg,
		nat: nat,
		ln:  ln,
		rl:  newRateLimiter(cfg.MaxConnPerDomainPerSec),
	}
	go s.serve()
	log.Printf("local redirect proxy listening on :%d", cfg.ProxyPort)
	return s, nil
}

func (s *proxyServer) Close() error { return s.ln.Close() }

func (s *proxyServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(c)
	}
}

// handle recovers the original destination from the NAT table (keyed by the
// accepted connection's remote port, which is the natPort WinDivert rewrote the
// source to) and forwards through anyproxy's ForwardTCP. ForwardTCP does its own
// first-packet SNI/Host sniff and applies routing, so the raw connection is
// handed over untouched — no pre-read here.
func (s *proxyServer) handle(c net.Conn) {
	defer c.Close()

	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	// 安全: 监听虽绑在 :port(必须能收到发往本机 NIC IP 的环回重定向包), 但只应服务
	// 本机重定向来的连接。重定向包由 rewriteForward 把目的 IP 改成「包自身的源 IP」
	// (本机 NIC IP), 源 IP 不变, 故被重定向连接的「远端 IP 恒等于本地 IP」。外部主机
	// 直连本端口时远端 IP 不等, 一律拒绝——避免该端口被当作开放端口扫描/滥用。
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok {
		if !ra.IP.Equal(la.IP) && !ra.IP.IsLoopback() {
			if s.cfg.Verbose {
				log.Printf("reject non-local connection from %s to :%d", ra.IP, s.cfg.ProxyPort)
			}
			return
		}
	}
	ent, ok := s.nat.lookupNat(uint16(ra.Port))
	if !ok {
		if s.cfg.Verbose {
			log.Printf("no NAT entry for :%d (stale connection)", ra.Port)
		}
		return
	}
	// This goroutine owns the connection's whole lifetime; when it ends the
	// mapping is dead. Flag it for prompt grace-based reclaim so cleanly-closed
	// (FIN) connections don't hold their natPort until the idle timeout.
	defer s.nat.markClosed(ent.natPort)

	// Per-destination rate limit: shed a single site's connection storm cheaply.
	if !s.rl.allow(ent.dstIP.String()) {
		if s.cfg.Verbose {
			log.Printf("rate limited %s:%d (> %d conn/s), dropping", ent.dstIP, ent.dstPort, s.cfg.MaxConnPerDomainPerSec)
		}
		return
	}

	id := grace.NextTraceID()
	ctx := context.WithValue(context.Background(), grace.TraceIDContextKey, id)
	srcIP := "127.0.0.1"
	if ent.srcIP.IsValid() {
		srcIP = ent.srcIP.String()
	}
	// ForwardTCP owns the connection from here: sniff, route, dial, splice.
	_ = proto.ForwardTCP(ctx, id, c, srcIP, ent.dstIP.String(), ent.dstPort)
}
