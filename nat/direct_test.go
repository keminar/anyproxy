package nat

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// 这些用例覆盖直连的数据路径与准入判断, 但绕开 websocket 信令: 信令只负责把
// "端点/指纹/凭证"送到对面, 用例里直接把这几个值交给对应方法即可。
//
// 全部走 IPv6 回环(::1)。回环上没有防火墙也没有 NAT, 所以这里验证不了打洞本身,
// 只验证"拿到端点之后能不能真的把字节送到内网目标"。

// echoTarget 起一个把收到内容原样回写的 TCP 服务, 模拟 C 的内网目标。
func echoTarget(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// newAcceptPeer 起一个开了 directAccept 的 C 侧 directPeer。
func newAcceptPeer(t *testing.T, forward map[uint16]string) *directPeer {
	t.Helper()
	d := newDirectPeer("test-c", conf.WsClient{}, forward)
	if err := d.ensureAccept(); err != nil {
		// 环境没有可用 IPv6 时直接跳过, 而不是判失败: 这套机制本来就以 IPv6 为前提。
		t.Skipf("cannot start ipv6 quic listener (no usable IPv6 here?): %v", err)
	}
	t.Cleanup(func() {
		if ln := d.acceptListener(); ln != nil {
			ln.Close()
		}
	})
	return d
}

func newDialPeer(t *testing.T) *directPeer {
	t.Helper()
	d := newDirectPeer("test-a", conf.WsClient{}, nil)
	if _, err := d.ensureTransport(); err != nil {
		t.Skipf("cannot create ipv6 udp socket: %v", err)
	}
	return d
}

// peerEndpoint 拼出 C 在回环上的 QUIC 端点。真实部署里这个地址由服务端观测后下发,
// 用例里直接用 ::1。
func peerEndpoint(d *directPeer) string {
	return fmt.Sprintf("[::1]:%d", d.localUDPPort())
}

// TestDirectEndToEnd 完整跑一遍: A 拨号 -> 出示凭证 -> C 查 forward 表 -> dial 内网目标 -> 双向搬字节。
func TestDirectEndToEnd(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	const port = uint16(2222)
	c := newAcceptPeer(t, map[uint16]string{port: target})
	a := newDialPeer(t)

	// 模拟服务端把请求转交给 C: C 记下这个一次性凭证(回环上不需要真打洞)。
	const token = "test-token-1"
	c.tokens.put(token, port, "a@example.com")

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("ensure transport: %v", err)
	}
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect peer: %v", err)
	}
	stream, err := a.openHeadedStream(sess, directStreamData, token, port)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	want := "hello over direct quic"
	if _, err := stream.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != want {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

// TestDirectRejectsUnknownToken 没有经服务端转交过的凭证必须被拒: 否则 QUIC 端口
// 一旦被扫到, 任何人都能穿到内网目标。
func TestDirectRejectsUnknownToken(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	const port = uint16(2222)
	c := newAcceptPeer(t, map[uint16]string{port: target})
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("ensure transport: %v", err)
	}
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect peer: %v", err)
	}
	stream, err := a.openHeadedStream(sess, directStreamData, "never-issued", port)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	// C 认不出凭证时会直接关掉这条流, 读侧应拿到 EOF/错误而不是目标的回声。
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	if n, err := stream.Read(buf); err == nil && n > 0 {
		t.Fatalf("stream with an unknown token should not carry data, got %q", buf[:n])
	}
}

// TestDirectRejectsUnmappedPort 端口没在 client.forward 里映射就必须拒绝, 与
// websocket 转发路径共用同一张白名单。
func TestDirectRejectsUnmappedPort(t *testing.T) {
	c := newAcceptPeer(t, map[uint16]string{2222: "127.0.0.1:1"})
	a := newDialPeer(t)

	const unmapped = uint16(3389)
	const token = "test-token-2"
	c.tokens.put(token, unmapped, "a@example.com") // 凭证有效, 但端口没映射

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("ensure transport: %v", err)
	}
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect peer: %v", err)
	}
	stream, err := a.openHeadedStream(sess, directStreamData, token, unmapped)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	if n, err := stream.Read(buf); err == nil && n > 0 {
		t.Fatalf("unmapped port should be rejected, got %q", buf[:n])
	}
}

// TestDirectRejectsWrongFingerprint 指纹对不上必须拨号失败: 指纹固定是这条链路唯一的
// 身份校验(自签证书过不了 CA 校验, 我们靠经鉴权的 websocket 下发指纹)。
func TestDirectRejectsWrongFingerprint(t *testing.T) {
	c := newAcceptPeer(t, map[uint16]string{2222: "127.0.0.1:1"})
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("ensure transport: %v", err)
	}
	wrong := strings.Repeat("00", 32)
	_, err = a.connectPeer(tr, "c@example.com", peerEndpoint(c), wrong)
	if err == nil {
		t.Fatal("dial with a wrong fingerprint should fail")
	}
	if !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected a fingerprint mismatch error, got: %v", err)
	}
}

// TestDirectParallelStreams 同一对端只用一条 QUIC 连接, 多个并发会话各占一条 stream
// (SSH/RDP 同时开多个是常态)。同时验证 stream 之间是独立的: 一条上的数据不会串到另一条。
func TestDirectParallelStreams(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	const port = uint16(2222)
	c := newAcceptPeer(t, map[uint16]string{port: target})
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("ensure transport: %v", err)
	}
	// 一条连接, 认证一次。
	const token = "test-token-parallel"
	c.tokens.put(token, port, "a@example.com")
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect peer: %v", err)
	}
	if err := a.authenticateSession(sess, token, port); err != nil {
		t.Fatalf("authenticate session: %v", err)
	}

	// 之后的会话都不带凭证, 复用这条已认证的连接。
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stream, err := a.openHeadedStream(sess, directStreamData, "", port)
			if err != nil {
				errs <- fmt.Errorf("stream %d: open: %w", i, err)
				return
			}
			defer stream.Close()
			// 每条流写不同内容, 回声必须原样对上, 串流就能发现。
			want := fmt.Sprintf("session-%d-payload", i)
			if _, err := stream.Write([]byte(want)); err != nil {
				errs <- fmt.Errorf("stream %d: write: %w", i, err)
				return
			}
			got := make([]byte, len(want))
			stream.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(stream, got); err != nil {
				errs <- fmt.Errorf("stream %d: read: %w", i, err)
				return
			}
			if string(got) != want {
				errs <- fmt.Errorf("stream %d: got %q want %q", i, got, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// 全程只应有一条 QUIC 连接。
	if got := a.session("c@example.com"); got != sess {
		t.Fatalf("expected all sessions to reuse one quic connection")
	}
}

// TestDirectUDPRoundTrip UDP 通路: 用户 UDP -> A 入口 -> QUIC datagram -> C -> 内网目标,
// 回程原路返回。RDP 8+ 的图形通道走 UDP, 这条路通不通直接决定能不能用上它。
func TestDirectUDPRoundTrip(t *testing.T) {
	// 内网 UDP 目标: 原样回显。
	tconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp target: %v", err)
	}
	defer tconn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := tconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			tconn.WriteToUDP(buf[:n], from)
		}
	}()

	const port = uint16(3389)
	c := newAcceptPeer(t, map[uint16]string{port: tconn.LocalAddr().String()})
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("ensure transport: %v", err)
	}
	const token = "test-token-udp"
	c.tokens.put(token, port, "a@example.com")
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect peer: %v", err)
	}
	// datagram 在连接认证之前会被丢弃, 所以必须先认证。
	if err := a.authenticateSession(sess, token, port); err != nil {
		t.Fatalf("authenticate session: %v", err)
	}
	go a.receiveDatagrams(sess)

	// 起 A 侧 UDP 入口, 并把回程分发绑上去。
	entry := &directUDPEntry{
		peer:     a,
		rule:     conf.ClientDirect{Listen: "127.0.0.1:0", Email: "c@example.com", Port: port},
		byAddr:   make(map[string]uint32),
		byID:     make(map[uint32]*net.UDPAddr),
		lastSeen: make(map[uint32]time.Time),
	}
	econn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp entry: %v", err)
	}
	defer econn.Close()
	entry.conn = econn
	sess.bindUDPEntry(port, entry)
	go entry.pump(func() (*directSession, error) { return sess, nil })

	// 扮演用户: 往入口发 UDP, 应收到内网目标的回声。
	user, err := net.DialUDP("udp", nil, econn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial entry: %v", err)
	}
	defer user.Close()

	want := "udp payload over quic datagram"
	if _, err := user.Write([]byte(want)); err != nil {
		t.Fatalf("send: %v", err)
	}
	user.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	n, err := user.Read(buf)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf[:n]) != want {
		t.Fatalf("udp echo mismatch: got %q want %q", buf[:n], want)
	}
}

// TestDirectUDPStats UDP 两个方向的字节都要被计入。
//
// UDP 没有"连接关闭"事件, 不主动统计就完全看不出数据有没有在走 —— 排查"mstsc 到底
// 用上 UDP 图形通道没有"时这是唯一依据, 统计恒为 0 会让人误判成没通。
func TestDirectUDPStats(t *testing.T) {
	tconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp target: %v", err)
	}
	defer tconn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := tconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			tconn.WriteToUDP(buf[:n], from)
		}
	}()

	const port = uint16(3389)
	c := newAcceptPeer(t, map[uint16]string{port: tconn.LocalAddr().String()})
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("ensure transport: %v", err)
	}
	const token = "test-token-udp-stats"
	c.tokens.put(token, port, "a@example.com")
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect peer: %v", err)
	}
	if err := a.authenticateSession(sess, token, port); err != nil {
		t.Fatalf("authenticate session: %v", err)
	}
	go a.receiveDatagrams(sess)

	entry := &directUDPEntry{
		peer:     a,
		rule:     conf.ClientDirect{Listen: "127.0.0.1:0", Email: "c@example.com", Port: port},
		byAddr:   make(map[string]uint32),
		byID:     make(map[uint32]*net.UDPAddr),
		lastSeen: make(map[uint32]time.Time),
	}
	econn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp entry: %v", err)
	}
	defer econn.Close()
	entry.conn = econn
	sess.bindUDPEntry(port, entry)
	go entry.pump(func() (*directSession, error) { return sess, nil })

	user, err := net.DialUDP("udp", nil, econn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial entry: %v", err)
	}
	defer user.Close()

	payload := "counted bytes"
	if _, err := user.Write([]byte(payload)); err != nil {
		t.Fatalf("send: %v", err)
	}
	user.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	if _, err := user.Read(buf); err != nil {
		t.Fatalf("read back: %v", err)
	}

	// 计数是在 socket 写完之后加的, 所以 user.Read 返回时回程那两笔可能还没记上 ——
	// 等一下而不是立刻断言, 否则这是个偶发失败。
	waitFor(t, 3*time.Second, func() bool {
		_, _, down, downPkts := entry.stats()
		return down == int64(len(payload)) && downPkts == 1
	}, "downstream bytes were never counted")

	up, upPkts, down, downPkts := entry.stats()
	if up != int64(len(payload)) || upPkts != 1 {
		t.Errorf("up stats = %dB/%dpkt, want %dB/1pkt", up, upPkts, len(payload))
	}
	if down != int64(len(payload)) || downPkts != 1 {
		t.Errorf("down stats = %dB/%dpkt, want %dB/1pkt", down, downPkts, len(payload))
	}
	if n := entry.sessionCount(); n != 1 {
		t.Errorf("session count = %d, want 1", n)
	}
}

// TestReflectorAddrsLiteralFamilyMismatch 覆盖一个真实撞过的坑: connect 填字面量
// IPv6(而不是同时有 A/AAAA 记录的域名)时, IPv4 反射器地址天然解不出来——这不是网络
// 问题, 纯语法层面就注定了。关键是: 这个失败必须报出来, 不能因为 IPv6 那族成功了就
// 被吞掉, 否则"为什么没有 IPv4 候选"这种问题永远查不到。
func TestReflectorAddrsLiteralFamilyMismatch(t *testing.T) {
	v4, v6, v4Err, v6Err := reflectorAddrs("[2001:db8::1]:3002")
	if v4 != nil {
		t.Fatalf("an IPv6 literal should not resolve as udp4, got %v", v4)
	}
	if v4Err == nil {
		t.Fatal("want a per-family error for the failed udp4 resolution, got nil")
	}
	if v6 == nil || v6Err != nil {
		t.Fatalf("the udp6 family should still succeed: v6=%v err=%v", v6, v6Err)
	}

	// 反过来同理: connect 填 IPv4 字面量时 IPv6 那族解不出来, 也要单独报错。
	v4, v6, v4Err, v6Err = reflectorAddrs("1.2.3.4:3002")
	if v6 != nil {
		t.Fatalf("an IPv4 literal should not resolve as udp6, got %v", v6)
	}
	if v6Err == nil {
		t.Fatal("want a per-family error for the failed udp6 resolution, got nil")
	}
	if v4 == nil || v4Err != nil {
		t.Fatalf("the udp4 family should still succeed: v4=%v err=%v", v4, v4Err)
	}
}

// TestDirectProbeEndpoint 反射器必须把**QUIC 那个 socket**的真实源端口回给订阅方。
// 这是整套地址交换的地基: websocket 是 TCP、是另一个 socket, 它的地址不能拿来当 QUIC 的
// 端点用(内核按 RFC 6724 按目的地分别选源, 隐私临时地址还会轮换)。
func TestDirectProbeEndpoint(t *testing.T) {
	// 起一个只回显来源地址的反射器, 等价于服务端上的那个。nonce 要原样带回 —— 现在
	// 多条探测并行在飞, 回包靠 nonce 关联。
	rconn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 on loopback: %v", err)
	}
	defer rconn.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := rconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			payload, ok := directPayload(buf[:n])
			if !ok {
				continue
			}
			verb, nonce, _ := splitPacket(payload)
			if verb != verbWhoami {
				continue
			}
			rconn.WriteToUDP(directPacket(fmt.Sprintf("%s %s %s", verbSeen, nonce, from)), from)
		}
	}()

	// cfg.Connect 指向反射器: 订阅方就是按 websocket 的连接地址推出反射器地址的。
	d := newDirectPeer("test-probe", conf.WsClient{Connect: rconn.LocalAddr().String()}, nil)
	if _, err := d.ensureTransport(); err != nil {
		t.Skipf("cannot create udp socket: %v", err)
	}

	endpoint, err := d.probeReflector(rconn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("probe endpoint: %v", err)
	}
	_, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatalf("probed endpoint %q is not host:port: %v", endpoint, err)
	}
	// 关键断言: 探测结果必须反映 QUIC socket 自己的端口, 而不是别的 socket 的。
	//
	// 只有在回环上"观测端口 == 本地端口"才成立(没有 NAT / 端口映射)。真实路径上两者
	// 可能不同, 而且映射老化重建后还会变 —— 所以协议里传的一律是探测结果, 从不传
	// 本地端口。这条断言验的是"探测确实问的是这个 socket", 不是"两者恒等"。
	if portStr != fmt.Sprint(d.localUDPPort()) {
		t.Fatalf("probed port %s does not match the quic socket port %d (loopback has no NAT, so they must match here)", portStr, d.localUDPPort())
	}
}

// TestCheckDirectEndpoint 端点格式校验。注意这里**不再**排斥 IPv4 / 私有 / 回环 ——
// 多候选之后它们都是合法候选(同机同网段时反而是最优的那条), 通不通交给打洞去回答。
// 这里只挡格式上就没有意义的。
func TestCheckDirectEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		ok       bool
	}{
		{"[2001:db8::1]:4242", true},
		{"1.2.3.4:4242", true},   // IPv4 现在与 IPv6 平等竞争
		{"[fe80::1]:4242", true}, // 链路本地: 同二层时是最优路径之一
		{"[::1]:4242", true},     // 回环: 同机
		{"192.168.1.5:4242", true},
		{"not-an-endpoint", false},  // 格式不对
		{"[2001:db8::1]", false},    // 缺端口
		{"example.com:4242", false}, // 只收 IP 字面量, 不让对端顺带做 DNS 去够任意主机
		{"[2001:db8::1]:0", false},  // 端口 0
		{"[::]:4242", false},        // 未指定地址
		{"224.0.0.1:4242", false},   // 多播不是端点
	}
	for _, c := range cases {
		err := checkDirectEndpoint(c.endpoint)
		if c.ok && err != nil {
			t.Errorf("%s should be accepted, got %v", c.endpoint, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s should be rejected", c.endpoint)
		}
	}
}

// 候选列表必须有上限。服务端会把这份列表转给对端, 对端朝**每一条**发打洞包 —— 不封顶
// 的话, 一个恶意订阅方报几百个地址就能借另一台机器朝任意目标扫射。
func TestCheckDirectCandidatesCaps(t *testing.T) {
	var many []directCandidate
	for i := 0; i < 50; i++ {
		many = append(many, directCandidate{Addr: fmt.Sprintf("10.0.0.%d:4242", i+1), Source: candSrcLocal})
	}
	got, err := checkDirectCandidates(many)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(got) != directMaxCandidates {
		t.Fatalf("want the list capped at %d, got %d", directMaxCandidates, len(got))
	}
}

// 单条格式不对不该拖垮整次直连 —— 多候选的意义就是"有一条能用就行"。
func TestCheckDirectCandidatesKeepsGoodOnes(t *testing.T) {
	got, err := checkDirectCandidates([]directCandidate{
		{Addr: "garbage", Source: candSrcLocal},
		{Addr: "[2001:db8::1]:4242", Source: candSrcReflectV6},
	})
	if err != nil {
		t.Fatalf("one bad candidate should not fail the whole list: %v", err)
	}
	if len(got) != 1 || got[0].Addr != "[2001:db8::1]:4242" {
		t.Fatalf("unexpected result %v", got)
	}
	// 全部不可用时才报错, 且要带上每条的原因。
	_, err = checkDirectCandidates([]directCandidate{{Addr: "garbage"}, {Addr: "also-garbage"}})
	if err == nil {
		t.Fatal("want an error when every candidate is unusable")
	}
	for _, want := range []string{"garbage", "also-garbage"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestDirectAcceptLifecycle C 侧监听是按需起、空闲放的: 放掉之后再起一个新的照样能用,
// 而且端口通常会变 —— 这正是"端点必须每次当场探测、不能缓存"的原因。
func TestDirectAcceptLifecycle(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	const port = uint16(2222)
	c := newDirectPeer("test-c", conf.WsClient{DirectAccept: true}, map[uint16]string{port: target})

	// 一开始不该占任何端口。
	if c.acceptListener() != nil {
		t.Fatal("listener should not be running before anything asks for it")
	}

	if err := c.ensureAccept(); err != nil {
		t.Skipf("cannot start ipv6 quic listener: %v", err)
	}
	first := c.localUDPPort()
	if first == 0 {
		t.Fatal("expected a bound port after ensureAccept")
	}
	// 重复调用必须复用同一个监听, 不能重复绑定。
	if err := c.ensureAccept(); err != nil {
		t.Fatalf("second ensureAccept: %v", err)
	}
	if got := c.localUDPPort(); got != first {
		t.Fatalf("ensureAccept should reuse the listener, port changed %d -> %d", first, got)
	}

	// 释放: 监听与 socket 都该放掉。
	c.stopAccept()
	if c.acceptListener() != nil {
		t.Fatal("listener should be nil after stopAccept")
	}
	if c.localUDPPort() != 0 {
		t.Fatal("socket should be released after stopAccept")
	}

	// 再起一个: 必须能正常工作(端口大概率不同, 但这不影响, 因为端点是当场探的)。
	if err := c.ensureAccept(); err != nil {
		t.Fatalf("restart after release: %v", err)
	}
	defer c.stopAccept()

	a := newDialPeer(t)
	const token = "test-token-lifecycle"
	c.tokens.put(token, port, "a@example.com")
	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("ensure transport: %v", err)
	}
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect to the restarted listener: %v", err)
	}
	stream, err := a.openHeadedStream(sess, directStreamData, token, port)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	want := "works after a restart"
	if _, err := stream.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != want {
		t.Fatalf("echo mismatch after restart: got %q want %q", got, want)
	}
}

// TestDirectIdleKeepsQuietUDPAlive 长时间没数据的 UDP 会话不能被当成空闲回收。
//
// 现实场景: mstsc 走 UDP 图形通道时, 用户不操作就可能很久没有包。UDP 没有"连接"
// 可计数, 若只看"最近一次收发", 会话还活着却会被判定空闲、把 QUIC 连接关掉,
// 用户一动鼠标就得重新打洞建连。
func TestDirectIdleKeepsQuietUDPAlive(t *testing.T) {
	sess := &directSession{}
	// 模拟"很久没有数据流过": 最近一次使用时间推到远早于空闲阈值。
	sess.lastUse.Store(time.Now().Add(-10 * directSessionIdle).UnixNano())

	// 没有任何在用的东西时, 应当判定为空闲。
	if got := sess.idleFor(); got <= directSessionIdle {
		t.Fatalf("a session with nothing in use should look idle, got %s", got)
	}

	// 绑一个 UDP 入口, 且它有一个仍在空闲窗口内的用户会话。
	entry := &directUDPEntry{
		byAddr:   make(map[string]uint32),
		byID:     make(map[uint32]*net.UDPAddr),
		lastSeen: map[uint32]time.Time{1: time.Now().Add(-directUDPIdle / 2)},
	}
	sess.bindUDPEntry(3389, entry)

	if got := sess.idleFor(); got != 0 {
		t.Fatalf("a session with a live UDP session must not look idle, got %s", got)
	}

	// 该 UDP 会话也过了自己的空闲窗口后, 才允许回收。
	entry.mu.Lock()
	entry.lastSeen[1] = time.Now().Add(-2 * directUDPIdle)
	entry.mu.Unlock()
	if got := sess.idleFor(); got <= directSessionIdle {
		t.Fatalf("once every UDP session expired the connection should look idle, got %s", got)
	}
}

// TestDirectTokenIsOneShot 凭证取走即失效, 重放无效。
func TestDirectTokenIsOneShot(t *testing.T) {
	s := newDirectTokenStore()
	s.put("tok", 2222, "a@example.com")

	e, ok := s.take("tok")
	if !ok || e.port != 2222 {
		t.Fatalf("first take should succeed with the stored port, got %d %v", e.port, ok)
	}
	// 发起方身份也要一起带出来: 收文件时按它匹配 receive.allow, C 自己看不到对端是谁。
	if e.email != "a@example.com" {
		t.Fatalf("token should carry the requester email, got %q", e.email)
	}
	if _, ok := s.take("tok"); ok {
		t.Fatal("token should not be reusable")
	}
}

// TestDirectStreamHeadRoundTrip 首部编解码。
func TestDirectStreamHeadRoundTrip(t *testing.T) {
	var buf strings.Builder
	in := directStreamHead{Token: "abc", Port: 3389}
	if err := writeStreamHead(&buf, in); err != nil {
		t.Fatalf("write head: %v", err)
	}
	out, err := readStreamHead(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: got %+v want %+v", out, in)
	}
}

// 多条路并行打洞: 通的那条要被观测到, 不通的那条不能拖垮整次直连。
//
// 这条用例走的是真实的 UDP 收发(回环), 覆盖 punch -> 对端 drainNonQUIC 自动回 pong ->
// 本端按 nonce 关联并计 RTT 这一整条链路。
func TestDirectPunchAllPicksTheReachableOne(t *testing.T) {
	c := newAcceptPeer(t, nil)
	a := newDialPeer(t)

	live := directCandidate{Addr: peerEndpoint(c), Source: candSrcReflectV6}
	// 一个没人监听的端口。UDP 打过去要么静默丢弃、要么回 ICMP 不可达, 两种都该算失败。
	dead := directCandidate{Addr: "[::1]:1", Source: candSrcReflectV6}
	// 一个格式就不对的, 不该让整批探测崩掉。
	junk := directCandidate{Addr: "garbage", Source: candSrcLocal}

	results := a.punchAll([]directCandidate{dead, junk, live})
	if len(results) != 3 {
		t.Fatalf("want a result per candidate, got %d", len(results))
	}
	byAddr := map[string]candidateResult{}
	for _, r := range results {
		byAddr[r.Cand.Addr] = r
	}
	if r := byAddr[live.Addr]; r.Err != nil {
		t.Fatalf("the reachable candidate should have answered: %v", r.Err)
	}
	if r := byAddr[dead.Addr]; r.Err == nil {
		t.Errorf("a port with nothing listening should not report success")
	}
	if r := byAddr[junk.Addr]; r.Err == nil {
		t.Errorf("a malformed candidate should not report success")
	}

	// 择优只在通了的里面挑, 所以必须选中活着的那条。
	winner, err := selectCandidate(results)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if winner.Addr != live.Addr {
		t.Fatalf("selected %s, want the reachable %s", winner.Addr, live.Addr)
	}
}

// 打洞包必须换来一个 pong: 这是"这条路通了"的唯一凭据, 也是 RTT 的来源。
func TestDirectPunchGetsPong(t *testing.T) {
	c := newAcceptPeer(t, nil)
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	addr, err := net.ResolveUDPAddr("udp", peerEndpoint(c))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	rtt, err := a.punchOne(tr, addr)
	if err != nil {
		t.Fatalf("punch got no pong: %v", err)
	}
	// 只断言 RTT 在合理范围内, 不钉具体数值。回环上一个来回可能短到时钟粒度以下
	// (Windows 上就会量出 0), 所以下界是 0 而不是"必须大于 0"。
	if rtt < 0 || rtt > directPunchGap*directPunchCount {
		t.Fatalf("implausible rtt %s", rtt)
	}
}
