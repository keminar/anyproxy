package nat

import (
	"fmt"
	"io"
	"net"
	"strconv"
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

// readMatching 从 conn 循环读, 跳过不匹配 want 的包, 直到读到匹配的那个或超时。
//
// 需要这个而不是直接读一次: primeLeg 在"第一次听到某条腿"时会反过来朝它连发几个探路包
// (见 direct_relay.go), 这些包会先于真正要断言的那个转发包到达测试用的裸 UDP 连接, 单次
// ReadFromUDP 可能先读到探路包而不是期望的内容, 必须循环跳过。
func readMatching(t *testing.T, conn *net.UDPConn, want []byte, timeout time.Duration) *net.UDPAddr {
	t.Helper()
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timed out waiting for %q", want)
		}
		conn.SetReadDeadline(time.Now().Add(remaining))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("did not receive %q: %v", want, err)
		}
		if string(buf[:n]) == string(want) {
			return from
		}
	}
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

	// forwardLoop 只往"已经亲耳听到过"的地址转发, 谁都还没发过声时两条腿都是"未学到"。
	// C 先朝 E 发一个包探路: 这一下不会被转发(A 还没学到), 但会让 VPS 学到 C 的真实地址,
	// 之后 A 的包才有地方可转。
	if _, err := cConn.WriteToUDP([]byte("c-priming-packet"), eAddr); err != nil {
		t.Fatalf("C priming send: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// A -> E 应被转给 C。
	wantAC := []byte("hello-from-A-through-relay")
	if _, err := aConn.WriteToUDP(wantAC, eAddr); err != nil {
		t.Fatalf("A send to relay: %v", err)
	}
	from := readMatching(t, cConn, wantAC, 3*time.Second)
	// 来源应是中继端点(C 看到的是 VPS 的中继口, 不是 A 的真实地址)——盲转发的意义所在。
	if from.Port != eAddr.Port {
		t.Fatalf("relayed packet came from port %d, want relay endpoint port %d", from.Port, eAddr.Port)
	}

	// C -> E 应被转回给 A。
	wantCA := []byte("reply-from-C-through-relay")
	if _, err := cConn.WriteToUDP(wantCA, eAddr); err != nil {
		t.Fatalf("C send to relay: %v", err)
	}
	readMatching(t, aConn, wantCA, 3*time.Second)
}

// TestRelayPunchesLegAfterNudge 中继能不能通, 全靠 VPS 自己"主动朝外发一次": VPS 这台机器
// 前面通常有一层有状态防火墙/安全组, 只放行"本机先朝某个具体地址发过包"之后的回程——
// 它不主动发这一下, 居民先打的洞在 VPS 眼里等于不存在, 居民的包一个都进不来。
//
// 所以 nudge(居民已朝 E 打过第一发的信号)到达后, VPS 必须朝那条腿的候选发包, **哪怕这条腿
// 的包一个都还没到过 VPS**(本测试里 A 就一个包都没发过)。反过来, 没被 nudge 的腿不该收到
// 任何东西 —— VPS 绝不抢在某条腿说话之前发。
func TestRelayPunchesLegAfterNudge(t *testing.T) {
	refAddr, stopRef := startTestReflector(t)
	defer stopRef()

	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true}, Connect: refAddr}, nil)
	const token = "relay-token-nudge-punch"
	rb, err := vps.openRelay(token)
	if err != nil {
		t.Skipf("cannot open relay (no usable udp6 here?): %v", err)
	}
	defer vps.closeRelay(token)
	eAddr, err := net.ResolveUDPAddr("udp", rb.endpoints[0])
	if err != nil {
		t.Fatalf("relay endpoint %q not resolvable: %v", rb.endpoints[0], err)
	}

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
	const aEmail, cEmail = "a@example.com", "c@example.com"
	vps.registerRelayLeg(token, aEmail, []directCandidate{{Addr: aConn.LocalAddr().String(), Source: candSrcReflectV6}})
	vps.registerRelayLeg(token, cEmail, []directCandidate{{Addr: cConn.LocalAddr().String(), Source: candSrcReflectV6}})

	// A 一个包都还没朝 E 发过(生产里就是被 VPS 自己的防火墙挡掉的情形), 只有它的 nudge 到了。
	vps.fireRelayLeg(token, aEmail)

	// A 应收到来自中继端点 E 的打洞包。
	aConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, from, err := aConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("A did not get the relay's punch after its nudge: %v", err)
	}
	if from.Port != eAddr.Port {
		t.Fatalf("punch came from port %d, want relay endpoint port %d", from.Port, eAddr.Port)
	}
	payload, ok := directPayload(buf[:n])
	if !ok {
		t.Fatalf("got %q, want a direct punch packet", buf[:n])
	}
	if verb, _, _ := splitPacket(payload); verb != verbPunch {
		t.Fatalf("got verb %q, want %q", verb, verbPunch)
	}

	// C 没被 nudge, 不该收到任何东西: VPS 绝不抢在一条腿说话之前朝它发。
	cConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, _, err := cConn.ReadFromUDP(buf); err == nil {
		t.Fatalf("C must not be punched before its own nudge, got %q", buf[:n])
	}
}

// TestRelayStopsPunchingOnceLegAnswers VPS 朝一条腿发包的**唯一**目的是打开自己这侧的回程
// 通道; 一旦亲耳听到这条腿(addr 学到), 这个目的就达成了, 剩下的几发是白送的噪声——它们换
// 回来的 pong 还会被盲转给对侧、再被对侧查不到 nonce 丢掉, 全都挤在 QUIC 握手的头一秒里。
// 所以必须在收到回应后停下, 而不是照发满 directPunchCount。
//
// 对照组是 TestRelayNudgeIsIdempotent: 那边居民只读不回(VPS 听不到它), 于是必须发满一轮。
func TestRelayStopsPunchingOnceLegAnswers(t *testing.T) {
	refAddr, stopRef := startTestReflector(t)
	defer stopRef()

	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true}, Connect: refAddr}, nil)
	const token = "relay-token-stop-after-answer"
	if _, err := vps.openRelay(token); err != nil {
		t.Skipf("cannot open relay (no usable udp6 here?): %v", err)
	}
	defer vps.closeRelay(token)

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
	const aEmail, cEmail = "a@example.com", "c@example.com"
	vps.registerRelayLeg(token, aEmail, []directCandidate{{Addr: aConn.LocalAddr().String(), Source: candSrcReflectV6}})
	vps.registerRelayLeg(token, cEmail, []directCandidate{{Addr: cConn.LocalAddr().String(), Source: candSrcReflectV6}})

	vps.fireRelayLeg(token, aEmail)

	// A 每收到一发就立刻回一个包——这就是生产里"VPS 的防火墙放行之后, 居民的包终于进来了"
	// 的那一刻。窗口给足(覆盖发满一轮的 directPunchCount*directPunchGap), 之后不再有包。
	buf := make([]byte, 1500)
	got := 0
	aConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, from, err := aConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		got++
		if _, werr := aConn.WriteToUDP(directPacket(verbPong+" answered"), from); werr != nil {
			t.Fatalf("A could not answer the relay: %v", werr)
		}
		_ = n
	}
	if got == 0 {
		t.Fatal("A got no punch at all after its nudge")
	}
	if got >= directPunchCount {
		t.Fatalf("relay sent %d punches although the leg already answered, want fewer than %d",
			got, directPunchCount)
	}
}

// TestRelayNudgeIsIdempotent 居民的 nudge 会重发 3 次(见 directRelayNudgeGaps), 重复到达
// 必须被吃掉: 否则每来一个 nudge 就朝这条腿再打一轮, 既浪费 VPS 出口, 又会在对侧看到一串
// 莫名其妙的探测包。VPS 侧按腿 once, 一轮 directPunchCount 个, 多一个都不该有。
// 这里居民只读不回, VPS 听不到它, 所以一轮必须打满(见 TestRelayStopsPunchingOnceLegAnswers)。
func TestRelayNudgeIsIdempotent(t *testing.T) {
	refAddr, stopRef := startTestReflector(t)
	defer stopRef()

	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true}, Connect: refAddr}, nil)
	const token = "relay-token-nudge-twice"
	if _, err := vps.openRelay(token); err != nil {
		t.Skipf("cannot open relay (no usable udp6 here?): %v", err)
	}
	defer vps.closeRelay(token)

	aConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 for A: %v", err)
	}
	defer aConn.Close()
	const aEmail = "a@example.com"
	vps.registerRelayLeg(token, aEmail, []directCandidate{{Addr: aConn.LocalAddr().String(), Source: candSrcReflectV6}})

	vps.fireRelayLeg(token, aEmail)
	vps.fireRelayLeg(token, aEmail)
	vps.fireRelayLeg(token, aEmail)

	// 数完一轮(6 包 ×150ms ≈ 900ms)再等一会儿, 确认后面没有第二批。
	aConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	got := 0
	for {
		n, _, err := aConn.ReadFromUDP(buf)
		if err != nil {
			break // 读超时 = 这一轮发完了
		}
		if _, ok := directPayload(buf[:n]); ok {
			got++
		}
	}
	if got != directPunchCount {
		t.Fatalf("leg got %d punch packets after 3 nudges, want exactly %d (one round)", got, directPunchCount)
	}
}

// TestRelayNudgeBeforeRegister C 那条腿的 nudge 常常比 B 转来的"登记"先到(C 一打完就发 nudge,
// 而 B 要等 C 的 d_ready 才去 VPS 登记这条腿)。先到的 nudge 不能被丢掉, 登记时必须补触发。
func TestRelayNudgeBeforeRegister(t *testing.T) {
	refAddr, stopRef := startTestReflector(t)
	defer stopRef()

	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{Relay: true}, Connect: refAddr}, nil)
	const token = "relay-token-early-nudge"
	rb, err := vps.openRelay(token)
	if err != nil {
		t.Skipf("cannot open relay (no usable udp6 here?): %v", err)
	}
	defer vps.closeRelay(token)
	eAddr, err := net.ResolveUDPAddr("udp", rb.endpoints[0])
	if err != nil {
		t.Fatalf("relay endpoint %q not resolvable: %v", rb.endpoints[0], err)
	}

	cConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen udp6 for C: %v", err)
	}
	defer cConn.Close()

	// nudge 先到(此时这条腿还没登记)。
	vps.fireRelayLeg(token, "c@example.com")
	// 登记随后到: 应立刻补上那次主动发包。
	vps.registerRelayLeg(token, "c@example.com", []directCandidate{{Addr: cConn.LocalAddr().String(), Source: candSrcReflectV6}})

	cConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	_, from, err := cConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("C did not get the relay's punch (early nudge lost): %v", err)
	}
	if from.Port != eAddr.Port {
		t.Fatalf("punch came from port %d, want relay endpoint port %d", from.Port, eAddr.Port)
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

	// forwardLoop 只往已学到的地址转发: C 先探一下路, VPS 才知道 C 的真实地址。
	if _, err := cConn.WriteToUDP([]byte("c-priming-packet"), eAddr); err != nil {
		t.Fatalf("C priming send: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	want := []byte("static-endpoint relay works")
	if _, err := aConn.WriteToUDP(want, eAddr); err != nil {
		t.Fatalf("A send: %v", err)
	}
	readMatching(t, cConn, want, 3*time.Second)
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

// TestRelayDynamicPublicIPs 多公网 IP 模式仍为每个 binding 分配独立随机端口，并把同一个
// 端口与全部 IP 组合上报；旧 binding 活着时，新会话也不应因固定端口被占而失败。
func TestRelayDynamicPublicIPs(t *testing.T) {
	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{
		Relay:       true,
		RelayPublic: []string{"127.0.0.1", "::1", "127.0.0.1"},
	}}, nil)
	rb1, err := vps.openRelay("dynamic-token-1")
	if err != nil {
		t.Fatalf("open first dynamic relay: %v", err)
	}
	defer vps.closeRelay("dynamic-token-1")
	rb2, err := vps.openRelay("dynamic-token-2")
	if err != nil {
		t.Fatalf("open second dynamic relay while first is alive: %v", err)
	}
	defer vps.closeRelay("dynamic-token-2")

	for i, rb := range []*relayBinding{rb1, rb2} {
		port := rb.conn.LocalAddr().(*net.UDPAddr).Port
		want := map[string]bool{
			net.JoinHostPort("127.0.0.1", strconv.Itoa(port)): true,
			net.JoinHostPort("::1", strconv.Itoa(port)):       true,
		}
		if len(rb.endpoints) != len(want) {
			t.Fatalf("binding %d endpoints = %v, want both public IPs on port %d", i+1, rb.endpoints, port)
		}
		for _, ep := range rb.endpoints {
			if !want[ep] {
				t.Fatalf("binding %d unexpected endpoint %q, want %v", i+1, ep, want)
			}
		}
	}
	if rb1.conn.LocalAddr().(*net.UDPAddr).Port == rb2.conn.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("concurrent dynamic bindings unexpectedly reused port %d", rb1.conn.LocalAddr().(*net.UDPAddr).Port)
	}
}

func TestRelayPublicRejectsMixedRandomAndFixedForms(t *testing.T) {
	vps := newDirectPeer("test-vps", conf.WsClient{Direct: conf.DirectSettings{
		Relay:       true,
		RelayPublic: []string{"127.0.0.1", "127.0.0.1:40000"},
	}}, nil)
	if _, err := vps.openRelay("mixed-public-token"); err == nil {
		vps.closeRelay("mixed-public-token")
		t.Fatal("mixed bare-IP and IP:port relayPublic forms should be rejected")
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

	// forwardLoop 只往已学到的地址转发: 复现生产环境里 C 收到 relay d_punch 后会做的
	// punchOnly, 让 VPS 先学到 C 的真实地址, A 的 QUIC Initial 到达时才有地方可转。
	c.punchOnly(token, []directCandidate{{Addr: eAddr, Source: candSrcReflectV6}})
	time.Sleep(200 * time.Millisecond)

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
	if !sess.streamReady.Load() {
		t.Fatal("new peer did not advertise data stream ready ACK support")
	}
	stream, err := a.openDataStream(sess, port)
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

	// forwardLoop 只往已学到的地址转发, 先让 C 探一下路(见 TestRelayEndToEnd 的同一处注释)。
	c.punchOnly(token, []directCandidate{{Addr: rb.endpoints[0], Source: candSrcReflectV6}})
	time.Sleep(200 * time.Millisecond)

	sess, err := a.connectPeer(tr, cEmail, rb.endpoints[0], c.fingerprint)
	if err != nil {
		t.Fatalf("A dial relay endpoint: %v", err)
	}
	if err := a.authenticateSession(sess, token, port, true, c.fingerprint); err == nil {
		t.Fatal("relay auth must fail when A's uuid is not in C's receive.allow")
	}
}
