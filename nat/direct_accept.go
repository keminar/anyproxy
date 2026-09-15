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
	"sync"
	"time"

	"github.com/keminar/anyproxy/utils/trace"
	quic "github.com/quic-go/quic-go"
)

// C 侧: 起 QUIC 监听、把端点通告给服务端、按服务端转来的请求朝对端打洞,
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
	peerCands := mergeCandidates(p.PeerAddrs, p.PeerAddr)
	if p.Token == "" || len(peerCands) == 0 {
		reply(DirectReady{Err: "incomplete punch"})
		return
	}
	// VPS 中继腿: 本机已为该 token 开好中继绑定(onRelayOpen), 这条 d_punch 是 B 转来的
	// 某条腿(A 或 C, 由 p.Email 标明)的候选, 让 VPS 朝它打洞。VPS 不接受 QUIC 监听、不回
	// d_ready(B 已从 relay-open 拿到 E), 只登记这条腿。见 direct_relay.go。
	if p.Relay && d.cfg.Direct.Relay && d.hasRelay(p.Token) {
		d.registerRelayLeg(p.Token, p.Email, peerCands)
		return
	}
	if !d.cfg.Direct.Accept {
		reply(DirectReady{Err: "direct.accept is not enabled on this peer"})
		return
	}
	// 打洞包加密准备: 密钥从 token 派生(见 deriveDirectSessionKeys), 不依赖 uuid/receive.allow。
	if errMsg := d.prepareDirectCrypto(p.Token, p.Encrypt, false); errMsg != "" {
		d.logf("punch from email %s: %s", p.Email, errMsg)
		reply(DirectReady{Err: errMsg})
		return
	}
	// 按需起监听: 没起过就现起, 起着就复用。
	if err := d.ensureAccept(); err != nil {
		reply(DirectReady{Err: fmt.Sprintf("cannot start quic listener: %v", err)})
		return
	}
	// 当场收集自己的候选: 外网地址与端口都可能已经变了, 不能用缓存。
	myCands, err := d.gatherCandidates()
	if err != nil {
		reply(DirectReady{Err: fmt.Sprintf("cannot determine my own endpoints: %v", err)})
		return
	}
	d.setMyCandidates(myCands)
	d.touchAccept()

	// 中继连接经不可信 VPS 盲转发, 光有 token 不够: 登记时标为 relay 并记下 B 认证过的发起方
	// email, 进数据面前还要在 e2e QUIC 流里做一次 uuid 挑战-应答(见 direct_relay_auth.go)。
	if p.Relay {
		d.tokens.putRelay(p.Token, p.Port, p.Email)
	} else {
		d.tokens.put(p.Token, p.Port)
	}
	// 朝对端的**所有**候选各连发几个打洞包, 不等回执: C 这侧不需要知道哪条更快(择优是
	// A 做的), 只需要把每条路上的返回通道开出来。等回执会白白拖住 ready, 让 A 多等近一秒。
	//
	// p.PunchFirst: 发起方 A 声明它在受限 CGNAT 后、必须先发第一个包(它配了 directPunchFirst)。
	// 此时本侧**先不打**, 把打洞停下(parkPunch), 等 A 开打后经 B 转来的 d_punching nudge
	// 再打——这样 A 必先发出第一个包, 否则本侧的包先到 A 的 CGNAT, A 的映射会被毒化、双向
	// 全灭(见 docs/direct-punch-order.md)。nudge 丢了则 directPunchFirstDelay 到点兜底。
	// 不管哪种, d_ready 都照常立即回(下面 reply), 不拖慢 A 拿 offer。
	switch {
	case p.Relay:
		// C 中继腿: peerCands 是 VPS 的中继端点 E。本侧是居民、必须先打, 所以立即朝 E 打洞
		// (不 park), 再发一个 nudge 让 VPS 知道可以朝本侧打回来了(见 sendRelayNudge、
		// direct_relay.go)。之后照常 accept 经 VPS 盲转发过来的 e2e QUIC。
		d.punchOnly(p.Token, peerCands)
		d.sendRelayNudge(p.Token)
	case p.PunchFirst:
		d.parkPunch(p.Token, peerCands)
	default:
		d.punchOnly(p.Token, peerCands)
	}
	d.logf("my candidates %v, punching toward %v for port %d, encrypt=%v, peerPunchFirst=%v, relay=%v", myCands, peerCands, p.Port, p.Encrypt, p.PunchFirst, p.Relay)
	reply(DirectReady{Candidates: myCands, Endpoint: firstAddr(myCands), Fingerprint: d.fingerprint})
}

// parkedPunch order Y 下一次"停着等信号"的打洞: fire 被关闭(收到 nudge)或兜底超时后打。
type parkedPunch struct {
	fire chan struct{}
	once sync.Once
}

// parkPunch 对端要求"它先打"时, 本侧先不打, 把打洞按 token 停在这里, 等 A 的 d_punching
// nudge(onPunching 触发)再打; nudge 丢了则 directPunchFirstDelay 到点兜底打。无论哪条,
// punchOnly 只会被调一次。
func (d *directPeer) parkPunch(token string, cands []directCandidate) {
	pp := &parkedPunch{fire: make(chan struct{})}
	d.punchMu.Lock()
	if d.pendingPunch == nil {
		d.pendingPunch = map[string]*parkedPunch{}
	}
	d.pendingPunch[token] = pp
	d.punchMu.Unlock()

	d.logf("peer wants to punch first; holding our punch until its nudge (or %s fallback)", directPunchFirstDelay)
	go func() {
		select {
		case <-pp.fire:
			d.logf("got punch-first nudge, punching now")
		case <-time.After(directPunchFirstDelay):
			d.logf("punch-first nudge not received in %s, punching anyway (fallback)", directPunchFirstDelay)
		}
		d.punchMu.Lock()
		if d.pendingPunch[token] == pp {
			delete(d.pendingPunch, token)
		}
		d.punchMu.Unlock()
		d.punchOnly(token, cands)
	}()
}

// onPunching 收到经 B 转来的 d_punching nudge。两种角色:
//   - VPS 中继: 本机已为该 token 开好中继绑定, nudge 里的 Email 是"哪条腿"(B 保留的
//     发出方 email), 触发 VPS 朝那条腿打洞(fireRelayLeg)。
//   - 普通 C: A 已开打, 触发本侧停着的那次打洞(order Y)。
func (d *directPeer) onPunching(msg *Message) {
	var p DirectPunching
	if err := decodeDirect(msg.Body, &p); err != nil {
		d.logf("bad punching nudge: %v", err)
		return
	}
	if d.cfg.Direct.Relay && d.hasRelay(p.Token) {
		d.fireRelayLeg(p.Token, p.Email)
		return
	}
	d.punchMu.Lock()
	pp, ok := d.pendingPunch[p.Token]
	d.punchMu.Unlock()
	if !ok {
		return // 没有对应的停着的打洞(已打/已超时清掉, 或 token 不对), 静默忽略
	}
	pp.once.Do(func() { close(pp.fire) })
}

// sendRelayNudge C 中继腿朝 E 打洞后发的 nudge: 经 B 转给 VPS(B 认出这是中继会话, 保留
// 本机 email 当"腿"标签), 让 VPS 知道本侧已先打、可以朝本侧打回来了。Email 填本机自己的
// (B 会用它认证过的 c.Email 覆盖/核对, 不可伪造成别的腿)。
func (d *directPeer) sendRelayNudge(token string) {
	if err := d.send(METHOD_DIRECT_PUNCHING, 0, DirectPunching{Email: d.cfg.Email, Token: token}); err != nil {
		d.logf("relay: send nudge for token %s failed: %v", shortToken(token), err)
	}
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
	go dc.logUDPTraffic(conn.Context())
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
	// stream.Close() 只关自己这侧的发送方向, 不关接收方向(quic-go 的语义)。如果这个
	// 函数是提前返回的 —— 比如收文件收到一半本地写盘出错(见 recvFileOver/writeIncoming
	// 的错误路径)—— 对端还在往这条 stream 写身后剩下的字节, 而这里已经没人再读了:
	// 数据会一直攒在对端的发送缓冲/flow control window 里, 对端的 Write() 永远堵住,
	// 我们这边看着像什么都没发生(连接本身靠 keepalive 一直活着, 不会触发空闲超时)。
	// 用 CancelRead 把接收方向也主动断掉, 会给对端发 STOP_SENDING, 让它卡住的 Write
	// 立刻报错退出, 而不是无限期卡死。stream 已经被正常读完(EOF)时这是个无操作
	// (quic-go: errorRead 为真则 CancelRead 直接返回), 不影响正常收发完成的路径。
	defer stream.CancelRead(0)
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

	if err := dc.authorize(stream, head); err != nil {
		d.logf("stream from %s: rejected (%v)", remote, err)
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
	if head.Kind == directStreamFile {
		// 文件流不落到任何 TCP 目标, 由 anyproxy 自己写盘(见 nat/file.go)。收不收、
		// 写到哪, 由 client.receive 决定, 与 forward 白名单无关。
		dc.recvFile(stream, remote.String())
		return
	}
	if head.Kind == directStreamPull {
		// 取件流: 方向反过来, 由本机把 receive.dir 下的文件推给对端(见 nat/file_pull.go)。
		// 准不准取同样只看 client.receive, 与 forward 白名单无关。
		dc.servePullStream(stream, remote.String())
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
	dur := time.Since(start)
	log.Println(trace.ID(id), fmt.Sprintf("nat direct accept closed %s up=%d(%s) down=%d(%s) dur=%s",
		remote, up, rate(up, dur), down, rate(down, dur), dur.Round(time.Second)))
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

		// 接收窗口。吞吐上限约等于 窗口/RTT, 所以窗口要盖住带宽时延积(BDP)。
		//
		// quic-go 的默认值(单流 6MB / 连接 15MB)是按普通网页流量定的, 对千兆家宽偏小:
		// 千兆 = 125MB/s, 6MB 窗口在 50ms RTT 下就只剩 ~960Mbps, 100ms 下掉到 ~480Mbps
		// —— 跨省传大文件正好撞上。这里放到单流 32MB, 够千兆跑到 250ms RTT。
		//
		// 代价是内存: 这些是**上限**, quic-go 会按实测 BDP 自动调节, 只有真的在满速传
		// 时才涨到这么大, RDP 那种空闲连接一直贴着初始值。连接级上限同时封住了单条
		// 连接的总占用(256 条流也不会各占 32MB)。
		//
		// 初始值也一并调大: 默认 512KB 要好几个 RTT 才爬到位, 传一个几百 MB 的文件时
		// 这段爬坡很显眼。
		InitialStreamReceiveWindow:     2 << 20,  // 2MB
		MaxStreamReceiveWindow:         32 << 20, // 32MB
		InitialConnectionReceiveWindow: 4 << 20,  // 4MB
		MaxConnectionReceiveWindow:     64 << 20, // 64MB
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
