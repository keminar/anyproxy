package nat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/keminar/anyproxy/utils/trace"
	quic "github.com/quic-go/quic-go"
)

// C 侧: 起 IPv6 QUIC 监听、把端点通告给服务端、按服务端转来的请求朝对端打洞,
// 并把每条进来的 stream 接到 client.forward 指定的内网目标上。

// ensureAccept 按需起 QUIC 监听, 已经起着就直接复用。
//
// 按需而非开机就起: C 平时不必占着 UDP 端口和监听, 空闲时零后台流量; 端口空出来
// 之后再有人要连, 重新起一个新的即可 —— 对端拿到的端点是当场探测的, 换端口毫无影响。
// 本地端口也因此不需要配置写死。
func (d *directPeer) ensureAccept() error {
	d.acceptMu.Lock()
	defer d.acceptMu.Unlock()
	if d.acceptListener() != nil {
		return nil
	}
	tr, err := d.ensureTransport()
	if err != nil {
		return err
	}
	tlsConf, fingerprint, err := directServerTLS()
	if err != nil {
		return fmt.Errorf("build tls config: %w", err)
	}
	ln, err := tr.Listen(tlsConf, directQUICConfig())
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}
	d.listener.Store(ln)
	d.fingerprint = fingerprint
	d.logf("quic listening on port %d (fingerprint %s)", d.localUDPPort(), shortFP(fingerprint))
	go d.acceptLoop(ln)
	return nil
}

// stopAccept 关掉监听并释放 socket。只在没有活跃连接时调用(见 reapAccept)。
func (d *directPeer) stopAccept() {
	d.acceptMu.Lock()
	defer d.acceptMu.Unlock()
	ln := d.acceptListener()
	if ln == nil {
		return
	}
	d.listener.Store(nil)
	_ = ln.Close()
	// 连 socket 一起释放: 下次要用时重新建一个, 端口变了也无所谓 —— 端点每次都是
	// 当场探测后经服务端转交的, 不存在别人手里攥着旧端口的问题。
	d.closeTransport()
	d.logf("quic listener idle, released the socket")
}

// reapAccept 没有活跃连接后, 空闲一段就把监听和 socket 放掉。
func (d *directPeer) reapAccept() {
	t := time.NewTicker(directReapEvery)
	defer t.Stop()
	for range t.C {
		if d.acceptListener() == nil {
			continue
		}
		if d.acceptConns.Load() > 0 {
			d.touchAccept()
			continue
		}
		if time.Since(d.lastAcceptUse()) > directSessionIdle {
			d.stopAccept()
		}
	}
}

// onPunch 服务端转来的连接请求。这是 C 侧整条流程的入口: 起监听 -> 探测自己的端点
// -> 朝对端打洞 -> 把端点报回服务端。全程在这一条消息里完成, 所以 C 平时不必占端口。
//
// 打洞那几个包是最关键的一步: IPv6 没有 NAT, 但家用路由器默认对 IPv6 开有状态防火墙、
// 丢弃主动入站。本机先朝对端发包, 才会在自己这侧留下允许对端回包的状态, 对方的
// QUIC Initial 才进得来。包体内容无意义, 对端会当作无法解析的报文丢弃。
func (d *directPeer) onPunch(msg *Message) {
	reply := func(r DirectReady) {
		if err := d.send(METHOD_DIRECT_READY, msg.ID, r); err != nil {
			d.logf("reply ready failed: %v", err)
		}
	}
	var p DirectPunch
	if err := decodeDirect(msg.Body, &p); err != nil {
		d.logf("bad punch: %v", err)
		reply(DirectReady{Err: "bad punch payload"})
		return
	}
	if p.Token == "" || p.PeerAddr == "" {
		reply(DirectReady{Err: "incomplete punch"})
		return
	}
	if !d.cfg.DirectAccept {
		reply(DirectReady{Err: "directAccept is not enabled on this peer"})
		return
	}
	addr, err := net.ResolveUDPAddr("udp6", p.PeerAddr)
	if err != nil {
		reply(DirectReady{Err: fmt.Sprintf("peer endpoint %s is not usable as udp6: %v", p.PeerAddr, err)})
		return
	}
	// 按需起监听: 没起过就现起, 起着就复用。
	if err := d.ensureAccept(); err != nil {
		reply(DirectReady{Err: fmt.Sprintf("cannot start quic listener: %v", err)})
		return
	}
	tr, err := d.ensureTransport()
	if err != nil {
		reply(DirectReady{Err: fmt.Sprintf("cannot get local socket: %v", err)})
		return
	}
	// 当场探测自己的端点: 外网地址与端口都可能已经变了, 不能用缓存。
	endpoint, err := d.probeEndpoint()
	if err != nil {
		reply(DirectReady{Err: fmt.Sprintf("cannot determine my own endpoint: %v", err)})
		return
	}
	d.setObservedEndpoint(endpoint)
	d.touchAccept()

	d.tokens.put(p.Token, p.Port)
	go func() {
		for i := 0; i < directPunchCount; i++ {
			// 经 Transport 发: 这个 socket 已经交给 quic-go 了, 直接 WriteToUDP 是它
			// 明确禁止的用法。带 magic 前缀, 对端才能从 ReadNonQUICPacket 收到。
			if _, err := tr.WriteTo(directPacket(directPunchPayload), addr); err != nil {
				d.logf("punch to %s failed: %v", p.PeerAddr, err)
				return
			}
			time.Sleep(directPunchGap)
		}
	}()
	d.logf("listening at %s, punching toward %s for port %d", endpoint, p.PeerAddr, p.Port)
	reply(DirectReady{Endpoint: endpoint, Fingerprint: d.fingerprint})
}

// acceptLoop 监听参数取自起监听时那一个: stopAccept 会把字段置空, 用字段会误退出。
func (d *directPeer) acceptLoop(ln *quic.Listener) {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			d.logf("quic accept stopped: %v", err)
			return
		}
		go d.serveConn(conn)
	}
}

func (d *directPeer) serveConn(conn *quic.Conn) {
	// 计入活跃连接数: 空闲回收要靠它区分"没人连"和"连着但暂时没数据"。
	d.acceptConns.Add(1)
	d.touchAccept()
	defer func() {
		d.acceptConns.Add(-1)
		d.touchAccept()
	}()
	remote := conn.RemoteAddr()
	d.logf("quic connection from %s", remote)
	// 鉴权按**连接**做一次, 不是每条 stream 一次: 连接本身已由 TLS + 指纹固定绑定,
	// 首条 stream 出示有效凭证后, 这条连接上的后续 stream 与 datagram 都放行。
	// datagram 没法逐包做握手, 逐 stream 鉴权也会给每条入口连接多加一趟信令往返。
	// 凭证只回答"这个对端准不准进来", 具体能到达哪个目标仍由 forward 白名单逐条把关。
	dc := &directConn{peer: d, conn: conn}
	defer dc.closeUDPSessions()
	go dc.receiveDatagrams()
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			d.logf("quic connection %s closed: %v", remote, err)
			return
		}
		go dc.serveStream(stream)
	}
}

// serveStream 一条 stream 对应对端的一条入口 TCP 连接。
func (dc *directConn) serveStream(stream *quic.Stream) {
	d := dc.peer
	defer stream.Close()
	remote := dc.conn.RemoteAddr()

	// 首部要有超时: 连上来却不发首部的对端会一直占着一条 stream。
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	head, err := readStreamHead(stream)
	if err != nil {
		d.logf("stream from %s: bad head: %v", remote, err)
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	if !dc.authorize(head.Token, head.Port) {
		d.logf("stream from %s: rejected (token invalid/expired, or connection not authenticated)", remote)
		return
	}
	if head.Kind == directStreamAuth {
		// 纯鉴权流: 只认证连接, 不落地。回一个字节让对端确认认证已完成 —— 对端要等到
		// 这个确认才敢发 datagram, 否则会被当作未认证丢掉。
		if _, err := stream.Write([]byte{1}); err != nil {
			d.logf("auth ack to %s failed: %v", remote, err)
		}
		return
	}
	// 复用 websocket 转发那套白名单: 未在 client.forward 里映射的端口一律拒绝,
	// 对端只能到达本机明确开放的目标。
	target, ok := d.forward[head.Port]
	if !ok {
		d.logf("stream from %s: no forward target for port %d, rejected", remote, head.Port)
		return
	}

	id := uint(forwardInc.ID())
	start := time.Now()
	targetConn, err := bypassDial("tcp", target, 5*time.Second)
	if err != nil {
		d.logf("stream from %s: dial %s failed: %v", remote, target, err)
		return
	}
	defer targetConn.Close()
	log.Println(trace.ID(id), fmt.Sprintf("nat direct accept %s -> %s (port %d)", remote, target, head.Port))

	up, down := directCopy(stream, targetConn)
	log.Println(trace.ID(id), fmt.Sprintf("nat direct accept closed %s up=%d down=%d dur=%s",
		remote, up, down, time.Since(start).Round(time.Second)))
}

// directQUICConfig 两侧共用的 QUIC 参数。
func directQUICConfig() *quic.Config {
	return &quic.Config{
		// 直连是给 RDP 这类长时间挂着、可能长时间无数据的会话用的, 空闲超时给足;
		// 同时开 keep-alive, 让中途的有状态防火墙不会把这条流的状态老化掉。
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 20 * time.Second,
		// UDP 通路要用 datagram(RFC 9221)承载, 两侧都必须开, 否则 SendDatagram 报错。
		EnableDatagrams: true,
		// 到同一个对端只维持一条 QUIC 连接, 每条入口连接占一条 stream(像 SSH 那样同时
		// 开很多会话是正常用法), 所以这个上限就是"同一对端的并发会话数上限"。
		// 显式写出来: quic-go 不设时默认 100, 超过后 OpenStreamSync 会阻塞等待而不是
		// 报错, 现象是新会话卡住不动, 光看日志很难想到是撞了上限。
		MaxIncomingStreams: directMaxStreams,
	}
}

// directServerTLS 生成一张自签证书, 并返回其 SHA-256 指纹。QUIC 强制要求 TLS, 但这里
// 两端都不在任何 CA 体系里, 所以用自签 + 指纹固定: 指纹经已鉴权的 websocket 通道交给
// 对端, 对端只认这一张证书。
func directServerTLS() (*tls.Config, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "anyproxy-direct"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{directALPN},
		MinVersion:   tls.VersionTLS13,
	}
	return conf, hex.EncodeToString(sum[:]), nil
}

// directClientTLS 拨号侧: 不走 CA 校验, 只认服务端经 websocket 通告的那张证书的指纹。
func directClientTLS(fingerprint string) *tls.Config {
	return &tls.Config{
		NextProtos: []string{directALPN},
		MinVersion: tls.VersionTLS13,
		// 自签证书必然过不了标准校验, 这里改用指纹固定, 安全性来自"指纹是经过鉴权的
		// websocket 通道下发的", 而不是证书链。
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer sent no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != fingerprint {
				return fmt.Errorf("certificate fingerprint mismatch: got %s want %s", shortFP(got), shortFP(fingerprint))
			}
			return nil
		},
	}
}

func shortFP(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "..."
}
