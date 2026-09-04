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

// startAccept 起 QUIC 监听。端口随机(每次启动重新分配), 具体端口经 websocket 通告,
// 所以不需要配置写死。监听绑在 udp6 通配地址上。
func (d *directPeer) startAccept() error {
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
	d.listener = ln
	d.fingerprint = fingerprint
	d.logf("quic listening on port %d (fingerprint %s)", d.localUDPPort(), shortFP(fingerprint))
	go d.acceptLoop()
	return nil
}

// announce 把 QUIC 端口与证书指纹报给服务端。只报端口: 地址由服务端按 websocket 连接的
// 真实来源填(本机自报不可靠, 见 DirectAnnounce 注释)。每次 websocket 重连后都要重报,
// 因为服务端是按连接记录的。
func (d *directPeer) announce() {
	if d.listener == nil {
		return
	}
	// 每次重连都重新探测: 服务端是按 websocket 连接记端点的, 旧连接一断记录即失效;
	// 而且本机的全局 IPv6 地址可能在这期间轮换过(隐私临时地址), 不能沿用上次的结果。
	endpoint, err := d.probeEndpoint()
	if err != nil {
		d.logf("cannot determine my quic endpoint, direct accept unavailable: %v", err)
		return
	}
	d.setObservedEndpoint(endpoint)
	if err := d.send(METHOD_DIRECT_ANNOUNCE, 0, DirectAnnounce{Endpoint: endpoint, Fingerprint: d.fingerprint}); err != nil {
		d.logf("announce failed: %v", err)
		return
	}
	d.logf("announced quic endpoint %s", endpoint)
}

// onPunch 服务端转来的连接请求: 记下期望的凭证, 并朝对端连发几个 UDP 包。
//
// 这几个包是整套流程里最关键的一步: IPv6 没有 NAT, 但家用路由器默认对 IPv6 开有状态
// 防火墙、丢弃主动入站。本机先朝对端发包, 才会在自己这侧留下允许对端回包的状态,
// 对方的 QUIC Initial 才进得来。包体内容无意义, 对端会当作无法解析的报文丢弃。
func (d *directPeer) onPunch(msg *Message) {
	var p DirectPunch
	if err := decodeDirect(msg.Body, &p); err != nil {
		d.logf("bad punch: %v", err)
		return
	}
	if p.Token == "" || p.PeerAddr == "" {
		d.logf("incomplete punch")
		return
	}
	tr, err := d.ensureTransport()
	if err != nil {
		d.logf("cannot punch: %v", err)
		return
	}
	addr, err := net.ResolveUDPAddr("udp6", p.PeerAddr)
	if err != nil {
		d.logf("punch target %s unresolvable as udp6: %v", p.PeerAddr, err)
		return
	}
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
	d.logf("punching toward %s for port %d", p.PeerAddr, p.Port)
}

func (d *directPeer) acceptLoop() {
	for {
		conn, err := d.listener.Accept(context.Background())
		if err != nil {
			d.logf("quic accept stopped: %v", err)
			return
		}
		go d.serveConn(conn)
	}
}

func (d *directPeer) serveConn(conn *quic.Conn) {
	remote := conn.RemoteAddr()
	d.logf("quic connection from %s", remote)
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			d.logf("quic connection %s closed: %v", remote, err)
			return
		}
		go d.serveStream(conn, stream)
	}
}

// serveStream 一条 stream 对应对端的一条入口 TCP 连接。
func (d *directPeer) serveStream(conn *quic.Conn, stream *quic.Stream) {
	defer stream.Close()
	remote := conn.RemoteAddr()

	// 首部要有超时: 连上来却不发首部的对端会一直占着一条 stream。
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	head, err := readStreamHead(stream)
	if err != nil {
		d.logf("stream from %s: bad head: %v", remote, err)
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	// 凭证必须是服务端提前经 punch 交给过我们的, 且一次性。QUIC 端口被扫到也没用。
	wantPort, ok := d.tokens.take(head.Token)
	if !ok {
		d.logf("stream from %s: unknown or expired token, rejected", remote)
		return
	}
	if wantPort != head.Port {
		d.logf("stream from %s: port %d does not match the requested %d, rejected", remote, head.Port, wantPort)
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
