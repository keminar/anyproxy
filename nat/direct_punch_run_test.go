package nat

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// 这组用例盯的是"选路什么时候收手":
//
//	以前 = 等所有候选都出结论 -> 只要有一条不回包, 第一条路通了也要等满 directPunchWait
//	现在 = 第一条回包 + directPunchSettle 收敛窗 -> 剩下的按 still probing 跳过, 探测继续跑
//
// 以及两段式 offer 的判定: 半截(只有中继端点 E)时必须继续等指纹, 不能拿去拨号。

// TestPunchRunStopsAtFirstAnswer 一条候选立刻回包、另一条从头不回包时, 必须在"第一条回包 +
// 收敛窗"附近就返回。实测里那 3s 的等齐正是整次连接 5.3s 里最长的一段。
func TestPunchRunStopsAtFirstAnswer(t *testing.T) {
	c := newAcceptPeer(t, nil)
	a := newDialPeer(t)

	live := directCandidate{Addr: peerEndpoint(c), Source: candSrcReflectV6}
	// 没人监听的端口: 不会有人回 pong。
	dead := directCandidate{Addr: "[::1]:1", Source: candSrcReflectV6}

	start := time.Now()
	run := a.startPunchAll("", []directCandidate{dead, live}, nil)
	winner, err := a.pickPeerAddr("c@example.com", run)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if winner.Addr != live.Addr {
		t.Fatalf("selected %s, want the reachable %s", winner.Addr, live.Addr)
	}
	// 死的那条要跑满 directPunchWait 才有结论, 按时返回就意味着没有等它。
	if elapsed >= directPunchWait/2 {
		t.Fatalf("took %s: must return right after the first answer + the %s settle window, not wait for the silent candidate (%s)",
			elapsed, directPunchSettle, directPunchWait)
	}
	// 但也不能早于收敛窗: 那等于"谁先回就用谁", 稍慢但更优的路(同网段/回环)就没机会了。
	if elapsed < directPunchSettle {
		t.Errorf("returned after %s, before the %s settle window: a slower-but-better candidate never gets a chance",
			elapsed, directPunchSettle)
	}
	t.Logf("returned after %s, while a silent candidate would have needed %s",
		elapsed.Round(time.Millisecond), directPunchWait)

	// 还没出结论的那条要标成"还在探", 不能报成失败 —— 否则会被误读成对方不可达。
	if line := describeResults(run.snapshot(), winner); !strings.Contains(line, "still probing") {
		t.Fatalf("a candidate with no conclusion yet should read as still probing, got %q", line)
	}
}

// TestPunchKeepsSendingUntilTheRelayIsReady 中继腿的发包窗口必须给满 directPunchWait。
//
// 场景: 中间层(VPS)在头 1.2s 里"还没同时听到两条腿", 于是把这一侧打过去的包全丢了 ——
// 这正是 direct_relay.go 的 forwardLoop 在对侧腿地址还没学到时的行为(直接 continue)。
// 直连那 900ms 的窗口会在中间层就绪之前就把包发完, 之后只剩干等, 最终只能退到 raceQUICDial
// 兜底; 中继窗口会一直发到就绪之后, 于是正常拿到 pong、正常选路拨号。
func TestPunchKeepsSendingUntilTheRelayIsReady(t *testing.T) {
	a := newDialPeer(t)

	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("cannot listen on ipv6 loopback: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// 一个"就绪得很慢"的假 VPS: 到点之前把收到的打洞包全丢掉, 之后才回 pong。
	readyAt := time.Now().Add(1 * time.Second)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if time.Now().Before(readyAt) {
				continue
			}
			payload, ok := directPayload(buf[:n])
			if !ok {
				continue
			}
			if verb, nonce, _ := splitPacket(payload); verb == verbPunch {
				_, _ = conn.WriteToUDP(directPacket(verbPong+" "+nonce), src)
			}
		}
	}()

	cand := []directCandidate{{Addr: conn.LocalAddr().String(), Source: candSrcReflectV6}}

	// 两条**同时**开跑才可比: 直连窗口的那条会在就绪(1s)之前就把 6 个包发完, 中继窗口的那条
	// 会一直发到就绪之后。
	directRun := a.startPunchAllFor("", cand, nil, punchSendSpan(false))
	relayRun := a.startPunchAllFor("", cand, nil, punchSendSpan(true))

	if !relayRun.waitFirst(3 * time.Second) {
		t.Fatal("the relay send window should still be sending when the relay becomes ready, so a pong must arrive")
	}
	if directRun.waitFirst(1500 * time.Millisecond) {
		t.Fatal("the direct send window was exhausted before the relay was ready, so no pong should have arrived")
	}
}

// TestPunchRunPendingIsNotAWinner 收敛窗到点时还在探的候选 RTT 是零值, 绝不能因此赢过真正
// 回了包的那条。
func TestPunchRunPendingIsNotAWinner(t *testing.T) {
	real := directCandidate{Addr: "198.51.100.7:2222", Source: candSrcReflectV6}
	pending := directCandidate{Addr: "198.51.100.8:2222", Source: candSrcReflectV6}
	run := newPunchRun([]directCandidate{pending, real})

	if _, err := selectCandidate(run.snapshot()); err == nil {
		t.Fatal("nothing has answered yet, so there must be no winner at all")
	}
	run.finish(1, 3*time.Millisecond, nil)

	got, err := selectCandidate(run.snapshot())
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if got.Addr != real.Addr {
		t.Fatalf("selected %s: a still-probing candidate must not beat one that really answered", got.Addr)
	}
	if line := describeResults(run.snapshot(), got); !strings.Contains(line, "still probing") {
		t.Fatalf("pending candidate should read as still probing, got %q", line)
	}
}

// TestPunchRunDeadCandidatesFailFast 候选全都在还没发包时就已判失败(比如地址解析不了)时,
// 要立刻收手: 没有候选还在飞了, 再等满预算也不会有人回包。
func TestPunchRunDeadCandidatesFailFast(t *testing.T) {
	a := newDialPeer(t)
	run := a.startPunchAll("", []directCandidate{{Addr: "garbage", Source: candSrcLocal}}, nil)

	start := time.Now()
	if run.waitFirst(directPunchWait) {
		t.Fatal("a candidate that could not even be parsed must not report success")
	}
	if elapsed := time.Since(start); elapsed > directPunchWait/4 {
		t.Fatalf("waited %s although every candidate had already settled: nothing was left to wait for", elapsed)
	}
}

// TestHandshakeFromOfferTwoPhase 覆盖两段式 offer 的判定与等待: 半截(只有 E)时先交出端点、
// 继续等指纹, 完整的一段立刻可用; 缺端点/缺指纹/第二段带错误都必须明确失败。
func TestHandshakeFromOfferTwoPhase(t *testing.T) {
	e := []directCandidate{{Addr: "203.0.113.7:21359", Source: candSrcReflectV4}}
	fp := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	ch := make(chan DirectOffer, 2)

	// 第一段: 只有中继端点 E —— 端点立刻可用(调用方据此开始打洞), 指纹还得等。
	hs, err := handshakeFromOffer(DirectOffer{PeerAddrs: e, EndpointOnly: true}, ch, nil)
	if err != nil {
		t.Fatalf("stage one: %v", err)
	}
	if len(hs.addrs) != 1 || hs.done != nil {
		t.Fatalf("stage one should hand out the endpoint right away and stay open, got %+v", hs)
	}
	if _, err := hs.waitFinal(20 * time.Millisecond); err == nil {
		t.Fatal("without the peer certificate the handshake must not be considered ready")
	}
	ch <- DirectOffer{PeerAddrs: e, Fingerprint: fp}
	final, err := hs.waitFinal(time.Second)
	if err != nil {
		t.Fatalf("stage two: %v", err)
	}
	if final.Fingerprint != fp {
		t.Fatalf("fingerprint = %q, want %q", final.Fingerprint, fp)
	}

	// 一段式的完整 offer: 立刻可用, 不等第二段。
	hs, err = handshakeFromOffer(DirectOffer{PeerAddrs: e, Fingerprint: fp}, ch, nil)
	if err != nil {
		t.Fatalf("one stage: %v", err)
	}
	if hs.done == nil {
		t.Fatal("a complete offer must be usable immediately")
	}
	if got, err := hs.waitFinal(time.Second); err != nil || got.Fingerprint != fp {
		t.Fatalf("waitFinal on a complete offer = %+v, %v", got, err)
	}

	// 第二段带来失败原因。
	hs, err = handshakeFromOffer(DirectOffer{PeerAddrs: e, EndpointOnly: true}, ch, nil)
	if err != nil {
		t.Fatalf("stage one: %v", err)
	}
	ch <- DirectOffer{Err: "peer went offline"}
	if _, err := hs.waitFinal(time.Second); err == nil {
		t.Fatal("an error reported in the second stage must fail the handshake")
	}

	// 残缺的 offer 一律拒绝。
	for _, bad := range []DirectOffer{
		{Err: "no subscriber online"},
		{EndpointOnly: true},
		{PeerAddrs: e},
	} {
		if _, err := handshakeFromOffer(bad, ch, nil); err == nil {
			t.Fatalf("offer %+v should have been rejected", bad)
		}
	}
}

// TestTwoPhaseOfferSurvivesFirstStage 回归: 中继两段式 offer 的第二段(带指纹)在 requestPeer
// 拿到第一段并返回**之后**才到。登记项若在此时就撤掉, onOffer 会报 "unknown request id"
// 把它丢掉, A 只能干等到 "timed out waiting for the peer certificate fingerprint"。
func TestTwoPhaseOfferSurvivesFirstStage(t *testing.T) {
	d := newDirectPeer("test-two-phase", conf.WsClient{}, nil)
	e := []directCandidate{{Addr: "203.0.113.7:21359", Source: candSrcReflectV4}}
	fp := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	offerMsg := func(id uint, o DirectOffer) *Message {
		body, err := encodeDirect(o)
		if err != nil {
			t.Fatal(err)
		}
		return &Message{ID: id, Method: METHOD_DIRECT_OFFER, Body: body}
	}

	id, ch, release := d.registerOffer()
	defer release()

	d.onOffer(offerMsg(id, DirectOffer{PeerAddrs: e, EndpointOnly: true}))
	first, err := waitOffer(ch, time.Second, "first stage")
	if err != nil {
		t.Fatal(err)
	}
	hs, err := handshakeFromOffer(first, ch, release)
	if err != nil {
		t.Fatal(err)
	}
	if hs.release == nil {
		t.Fatal("a partial offer must keep the request registered until the fingerprint arrives")
	}

	// requestPeer 已返回, 第二段现在才到。
	d.onOffer(offerMsg(id, DirectOffer{PeerAddrs: e, Fingerprint: fp}))
	final, err := hs.waitFinal(time.Second)
	if err != nil {
		t.Fatalf("second stage was lost: %v", err)
	}
	if final.Fingerprint != fp {
		t.Fatalf("fingerprint = %q, want %q", final.Fingerprint, fp)
	}

	// 握手结束后登记必须撤掉, 不能泄漏。
	hs.close()
	d.mu.Lock()
	_, still := d.offers[id]
	d.mu.Unlock()
	if still {
		t.Fatal("offer registration leaked after the handshake finished")
	}
}
