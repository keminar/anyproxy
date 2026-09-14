package nat

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// startTestReflector 起一个最小 whoami->seen 反射器(回环), 返回它的地址。中继要靠它探到
// 自己的公网端点 E。
func startTestReflector(t *testing.T) (addr string, stop func()) {
	t.Helper()
	rconn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 reflector: %v", err)
	}
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
	return rconn.LocalAddr().String(), func() { rconn.Close() }
}

// TestRelayBlindForward VPS 盲转发的核心: 开中继绑定探到 E, 登记 A、C 两腿后, 从 A 发到 E
// 的包被原样转给 C, 从 C 发到 E 的包被原样转给 A —— VPS 不看内容, 只按来源地址对转。
func TestRelayBlindForward(t *testing.T) {
	refAddr, stopRef := startTestReflector(t)
	defer stopRef()

	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true}, Connect: refAddr}, nil)
	const token = "relay-token-blindforward"
	rb, err := vps.openRelay(token)
	if err != nil {
		t.Skipf("cannot open relay (no usable udp6 here?): %v", err)
	}
	defer vps.closeRelay(token)
	if len(rb.endpoints) == 0 {
		t.Fatal("relay reported no endpoint")
	}
	eAddr, err := net.ResolveUDPAddr("udp", rb.endpoints[0])
	if err != nil {
		t.Fatalf("relay endpoint %q not resolvable: %v", rb.endpoints[0], err)
	}

	// 两个居民: 各一个回环 UDP socket。它们的实际地址就是登记给 VPS 的候选(回环无 NAT)。
	aConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 for A: %v", err)
	}
	defer aConn.Close()
	cConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 for C: %v", err)
	}
	defer cConn.Close()

	aCand := directCandidate{Addr: aConn.LocalAddr().String(), Source: candSrcReflectV6}
	cCand := directCandidate{Addr: cConn.LocalAddr().String(), Source: candSrcReflectV6}
	vps.registerRelayLeg(token, "a@example.com", []directCandidate{aCand})
	vps.registerRelayLeg(token, "c@example.com", []directCandidate{cCand})

	// A -> E 应被转给 C。
	wantAC := []byte("hello-from-A-through-relay")
	if _, err := aConn.WriteToUDP(wantAC, eAddr); err != nil {
		t.Fatalf("A send to relay: %v", err)
	}
	cConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, from, err := cConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("C did not receive the relayed packet: %v", err)
	}
	if string(buf[:n]) != string(wantAC) {
		t.Fatalf("C got %q, want %q", buf[:n], wantAC)
	}
	// 来源应是中继端点(C 看到的是 VPS 的中继口, 不是 A 的真实地址)——盲转发的意义所在。
	if from.Port != eAddr.Port {
		t.Fatalf("relayed packet came from port %d, want relay endpoint port %d", from.Port, eAddr.Port)
	}

	// C -> E 应被转回给 A。
	wantCA := []byte("reply-from-C-through-relay")
	if _, err := cConn.WriteToUDP(wantCA, eAddr); err != nil {
		t.Fatalf("C send to relay: %v", err)
	}
	aConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = aConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("A did not receive the relayed reply: %v", err)
	}
	if string(buf[:n]) != string(wantCA) {
		t.Fatalf("A got %q, want %q", buf[:n], wantCA)
	}
}

// TestRelayDropsUnknownSource 注入防护: 来源不属于任何一腿的包一律丢弃, 不转发。
func TestRelayDropsUnknownSource(t *testing.T) {
	refAddr, stopRef := startTestReflector(t)
	defer stopRef()

	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true}, Connect: refAddr}, nil)
	const token = "relay-token-injection"
	rb, err := vps.openRelay(token)
	if err != nil {
		t.Skipf("cannot open relay: %v", err)
	}
	defer vps.closeRelay(token)
	eAddr, err := net.ResolveUDPAddr("udp", rb.endpoints[0])
	if err != nil {
		t.Fatalf("relay endpoint not resolvable: %v", err)
	}

	cConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 for C: %v", err)
	}
	defer cConn.Close()
	// 只登记一条合法腿 C, 另一条腿用一个"从未发过包、也不是候选"的地址占位。
	cCand := directCandidate{Addr: cConn.LocalAddr().String(), Source: candSrcReflectV6}
	vps.registerRelayLeg(token, "c@example.com", []directCandidate{cCand})
	vps.registerRelayLeg(token, "a@example.com", []directCandidate{{Addr: "[::1]:1", Source: candSrcReflectV6}})

	// 一个不在任何候选里的来源朝 E 发包: 不应被转给 C。
	evil, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 for evil: %v", err)
	}
	defer evil.Close()
	if _, err := evil.WriteToUDP([]byte("injected"), eAddr); err != nil {
		t.Fatalf("evil send: %v", err)
	}
	cConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	if n, _, err := cConn.ReadFromUDP(buf); err == nil {
		t.Fatalf("C should not have received an injected packet, got %q", buf[:n])
	}
}

// TestRelayStaticEndpoint 配了 directRelayPublic 时: 跳过反射器、把 socket 绑到配置端口, 直接
// 用配置端点当 E; 盲转发照常。覆盖"VPS 挂在随机出口 NAT 后、改用固定 DNAT 入站"的场景。
func TestRelayStaticEndpoint(t *testing.T) {
	// 先抢一个空闲端口当"公网/本地"端口(回环上二者相同, 无 NAT)。
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot pick a free udp6 port: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	pub := fmt.Sprintf("[::1]:%d", port)

	// 注意: 不配 Connect —— 静态端点必须完全不依赖反射器。
	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true, RelayPublic: []string{pub}}}, nil)
	const token = "relay-static-token"
	rb, err := vps.openRelay(token)
	if err != nil {
		t.Skipf("cannot open static relay (port %d taken?): %v", port, err)
	}
	defer vps.closeRelay(token)
	if len(rb.endpoints) != 1 || rb.endpoints[0] != pub {
		t.Fatalf("static relay endpoints = %v, want [%s]", rb.endpoints, pub)
	}
	if got := rb.conn.LocalAddr().(*net.UDPAddr).Port; got != port {
		t.Fatalf("static relay bound to port %d, want the configured %d", got, port)
	}

	// 盲转发仍然工作(用固定端口的 socket)。
	aConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 for A: %v", err)
	}
	defer aConn.Close()
	cConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 for C: %v", err)
	}
	defer cConn.Close()
	eAddr, _ := net.ResolveUDPAddr("udp", pub)
	vps.registerRelayLeg(token, "a@example.com", []directCandidate{{Addr: aConn.LocalAddr().String(), Source: candSrcReflectV6}})
	vps.registerRelayLeg(token, "c@example.com", []directCandidate{{Addr: cConn.LocalAddr().String(), Source: candSrcReflectV6}})

	want := []byte("static-endpoint relay works")
	if _, err := aConn.WriteToUDP(want, eAddr); err != nil {
		t.Fatalf("A send: %v", err)
	}
	cConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("C did not receive relayed packet: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("C got %q, want %q", buf[:n], want)
	}
}

// TestRelayStaticEndpointCapacity 端口即插槽: 只配一个端口时, 第二对并发中继因端口被占而开不起来。
func TestRelayStaticEndpointCapacity(t *testing.T) {
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot pick a free udp6 port: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	pub := fmt.Sprintf("[::1]:%d", port)

	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true, RelayPublic: []string{pub}}}, nil)
	rb1, err := vps.openRelay("token-1")
	if err != nil {
		t.Skipf("cannot open first static relay: %v", err)
	}
	defer vps.closeRelay("token-1")
	_ = rb1
	if _, err := vps.openRelay("token-2"); err == nil {
		vps.closeRelay("token-2")
		t.Fatal("second concurrent relay should fail: the only configured port is already in use")
	}
}

// TestRelayEndToEnd 全链路: A 经 VPS 盲转发连到 C, e2e QUIC 在 A<->C(TLS 指纹固定), 首条流
// 上做 uuid 挑战-应答, 再在数据流上打通到 C 的内网目标。全程回环, 验的是"拿到中继端点后
// 字节能真的经 VPS 转到 C 并落到目标", 打洞本身回环无从验证(无 NAT/防火墙)。
func TestRelayEndToEnd(t *testing.T) {
	refAddr, stopRef := startTestReflector(t)
	defer stopRef()
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	const (
		port   = uint16(2223)
		aEmail = "a@example.com"
		cEmail = "c@example.com"
		token  = "relay-e2e-token"
	)

	// C: 开 directAccept, receive.allow 里认 A 的 uuid(中继鉴权复用它)。
	c := newDirectPeer("test-c", conf.WsClient{
		Direct:  conf.DirectSettings{Accept: true},
		Receive: conf.ClientReceive{Allow: []conf.AllowedSender{{Email: aEmail, UUID: testUUIDA}}},
	}, map[uint16]string{port: target})
	if err := c.ensureAccept(); err != nil {
		t.Skipf("cannot start ipv6 quic listener: %v", err)
	}
	t.Cleanup(func() {
		if ln := c.acceptListener(); ln != nil {
			ln.Close()
		}
	})

	// VPS: 开中继绑定。
	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true}, Connect: refAddr}, nil)
	rb, err := vps.openRelay(token)
	if err != nil {
		t.Skipf("cannot open relay: %v", err)
	}
	defer vps.closeRelay(token)
	eAddr := rb.endpoints[0]

	// A: 有 uuid/email, 用来应答 C 的挑战。
	a := newDirectPeer("test-a", conf.WsClient{Email: aEmail, UUID: testUUIDA}, nil)
	tr, err := a.ensureTransport()
	if err != nil {
		t.Skipf("cannot create udp socket: %v", err)
	}

	// 在 VPS 登记两腿(用两端 QUIC socket 的真实回环地址当候选; 回环无 NAT, 实际来源与之一致)。
	vps.registerRelayLeg(token, aEmail, []directCandidate{{Addr: peerEndpoint(a), Source: candSrcReflectV6}})
	vps.registerRelayLeg(token, cEmail, []directCandidate{{Addr: peerEndpoint(c), Source: candSrcReflectV6}})

	// C 登记中继凭证(模拟 B 经 relay d_punch 交给它的: 标 relay + 发起方 email)。
	c.tokens.putRelay(token, port, aEmail)

	// A 拨号到中继端点 E, TLS 期望 C 的指纹; QUIC 经 VPS 盲转发在 A<->C 端到端完成。
	sess, err := a.connectPeer(tr, cEmail, eAddr, c.fingerprint)
	if err != nil {
		t.Fatalf("A dial relay endpoint %s: %v", eAddr, err)
	}
	// 首条流: 出示 token + 应答 uuid 挑战(relay=true)。
	if err := a.authenticateSession(sess, token, port, true, c.fingerprint); err != nil {
		t.Fatalf("relay authenticate: %v", err)
	}
	// 数据流: 连接已认证, 不再带 token。打到 C 的 forward[port] 目标。
	stream, err := a.openHeadedStream(sess, directStreamData, "", port)
	if err != nil {
		t.Fatalf("open data stream: %v", err)
	}
	defer stream.Close()

	want := "hello over the blind relay"
	if _, err := stream.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read back through relay: %v", err)
	}
	if string(got) != want {
		t.Fatalf("echo mismatch through relay: got %q want %q", got, want)
	}
}

// TestRelayAuthRejectsWrongUUID 中继鉴权: A 的 uuid 与 C 的 receive.allow 对不上时, 首条流
// 上的挑战-应答必须失败, 连接进不了数据面。
func TestRelayAuthRejectsWrongUUID(t *testing.T) {
	refAddr, stopRef := startTestReflector(t)
	defer stopRef()
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	const (
		port   = uint16(2224)
		aEmail = "a@example.com"
		cEmail = "c@example.com"
		token  = "relay-badauth-token"
	)
	// C 认的是 testUUIDA, 但 A 手里是另一个 uuid。
	c := newDirectPeer("test-c", conf.WsClient{
		Direct:  conf.DirectSettings{Accept: true},
		Receive: conf.ClientReceive{Allow: []conf.AllowedSender{{Email: aEmail, UUID: testUUIDA}}},
	}, map[uint16]string{port: target})
	if err := c.ensureAccept(); err != nil {
		t.Skipf("cannot start ipv6 quic listener: %v", err)
	}
	t.Cleanup(func() {
		if ln := c.acceptListener(); ln != nil {
			ln.Close()
		}
	})
	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true}, Connect: refAddr}, nil)
	rb, err := vps.openRelay(token)
	if err != nil {
		t.Skipf("cannot open relay: %v", err)
	}
	defer vps.closeRelay(token)

	a := newDirectPeer("test-a", conf.WsClient{Email: aEmail, UUID: testUUIDStranger}, nil)
	tr, err := a.ensureTransport()
	if err != nil {
		t.Skipf("cannot create udp socket: %v", err)
	}
	vps.registerRelayLeg(token, aEmail, []directCandidate{{Addr: peerEndpoint(a), Source: candSrcReflectV6}})
	vps.registerRelayLeg(token, cEmail, []directCandidate{{Addr: peerEndpoint(c), Source: candSrcReflectV6}})
	c.tokens.putRelay(token, port, aEmail)

	sess, err := a.connectPeer(tr, cEmail, rb.endpoints[0], c.fingerprint)
	if err != nil {
		t.Fatalf("A dial relay endpoint: %v", err)
	}
	if err := a.authenticateSession(sess, token, port, true, c.fingerprint); err == nil {
		t.Fatal("relay auth must fail when A's uuid is not in C's receive.allow")
	}
}
