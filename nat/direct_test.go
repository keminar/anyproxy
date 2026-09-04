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
	if err := d.startAccept(); err != nil {
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
	c.tokens.put(token, port)

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
	c.tokens.put(token, unmapped) // 凭证有效, 但端口没映射

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
	c.tokens.put(token, port)
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
	c.tokens.put(token, port)
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

// TestDirectProbeEndpoint 反射器必须把**QUIC 那个 socket**的真实源端口回给订阅方。
// 这是整套地址交换的地基: websocket 是 TCP、是另一个 socket, 它的地址不能拿来当 QUIC 的
// 端点用(内核按 RFC 6724 按目的地分别选源, 隐私临时地址还会轮换)。
func TestDirectProbeEndpoint(t *testing.T) {
	// 起一个只回显来源地址的反射器, 等价于服务端上的那个。
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
			if !ok || payload != directWhoami {
				continue
			}
			rconn.WriteToUDP(directPacket(from.String()), from)
		}
	}()

	// cfg.Connect 指向反射器: 订阅方就是按 websocket 的连接地址推出反射器地址的。
	d := newDirectPeer("test-probe", conf.WsClient{Connect: rconn.LocalAddr().String()}, nil)
	if _, err := d.ensureTransport(); err != nil {
		t.Skipf("cannot create ipv6 udp socket: %v", err)
	}

	endpoint, err := d.probeEndpoint()
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

// TestCheckDirectEndpoint IPv4 端点必须在服务端就被拒掉并说明原因, 而不是等对端拨号
// 时才失败得不明不白。
func TestCheckDirectEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		ok       bool
	}{
		{"[2001:db8::1]:4242", true},
		{"1.2.3.4:4242", false},    // IPv4 不能用于直连
		{"[fe80::1]:4242", false},  // 链路本地不是全局地址
		{"[::1]:4242", false},      // 回环
		{"not-an-endpoint", false}, // 格式不对
		{"[2001:db8::1]", false},   // 缺端口
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

// TestDirectTokenIsOneShot 凭证取走即失效, 重放无效。
func TestDirectTokenIsOneShot(t *testing.T) {
	s := newDirectTokenStore()
	s.put("tok", 2222)

	if port, ok := s.take("tok"); !ok || port != 2222 {
		t.Fatalf("first take should succeed with the stored port, got %d %v", port, ok)
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
