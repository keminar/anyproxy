package nat

import (
	"testing"
	"time"
)

// 这组用例盯的是中继会话里 B **两段式 offer** 的顺序: 拿到 VPS 报回的中继端点 E 之后, 先把
// "只有 E"的那一段发给 A(让 A 立刻开打), 等 C 回了候选与证书指纹再补一条完整的。
//
// 顺序反了就等于没优化: 实测"等 C 的指纹"这一段是秒级的(见 docs/direct-handshake-flow.md)。
// 用例直接驱动 broker 的 onRelayReady, 不碰 websocket —— 入参就是 B 真正会收到的两条 d_ready。

// newTestBrokerHub 起一个真的 Hub(含 run()), 用例从各 Client 的 send 队列里看 B 发了什么。
func newTestBrokerHub(t *testing.T) *Hub {
	t.Helper()
	h := newHub()
	go h.run()
	return h
}

// newTestBrokerClient 注册一个只带 email 与发送队列的 Client。注册是异步的(broadcast 那条
// 路径会在 hub 里按 email 查表), 所以这里等到查得到再返回。
func newTestBrokerClient(t *testing.T, h *Hub, email string) *Client {
	t.Helper()
	c := &Client{hub: h, send: make(chan *Message, 8), Email: email, tag: email}
	h.register <- c
	deadline := time.Now().Add(2 * time.Second)
	for h.GetClientByEmail(email) == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.GetClientByEmail(email) == nil {
		t.Fatalf("client %s was never registered", email)
	}
	return c
}

// recvDirectMsg 取该 Client 队列里的下一条消息, 并断言就是预期的方法。
func recvDirectMsg(t *testing.T, ch <-chan *Message, method string) *Message {
	t.Helper()
	select {
	case m := <-ch:
		if m.Method != method {
			t.Fatalf("got method %q, want %q", m.Method, method)
		}
		return m
	case <-time.After(2 * time.Second):
		t.Fatalf("no %q message arrived", method)
		return nil
	}
}

func decodeDirectMsg[T any](t *testing.T, m *Message) T {
	t.Helper()
	var v T
	if err := decodeDirect(m.Body, &v); err != nil {
		t.Fatalf("decode %s: %v", m.Method, err)
	}
	return v
}

// newRelayBrokerFixture 建好 broker + A/VPS/C 三个 Client + 一条中继会话。
func newRelayBrokerFixture(t *testing.T, twoPhase bool) (*directBroker, *relaySession, *Client, *Client, *Client, []directCandidate, []directCandidate) {
	t.Helper()
	b := &directBroker{pending: map[uint]*directPending{}, relays: map[string]*relaySession{}}
	h := newTestBrokerHub(t)
	a := newTestBrokerClient(t, h, "a@example.com")
	vps := newTestBrokerClient(t, h, "vps@example.com")
	c := newTestBrokerClient(t, h, "c@example.com")

	rs := &relaySession{
		token: "tok", asker: a, askerID: 7, aEmail: a.Email, cEmail: c.Email,
		vpsEmail: vps.Email, vps: vps,
		aCands: []directCandidate{{Addr: "198.51.100.1:42700", Source: candSrcReflectV4}},
		port:   2222, twoPhase: twoPhase,
		deadline: time.Now().Add(time.Minute),
	}
	b.mu.Lock()
	b.relays[rs.token] = rs
	b.mu.Unlock()
	return b, rs, a, vps, c,
		[]directCandidate{{Addr: "203.0.113.7:21359", Source: candSrcReflectV4}}, // E
		[]directCandidate{{Addr: "198.51.100.2:49925", Source: candSrcReflectV4}} // C 的候选
}

// TestRelayTwoPhasePushesEndpointAheadOfFingerprint 声明了 TwoPhase 的 A, 在 VPS 报回 E 的
// 那一刻就该拿到半截 offer; C 的指纹到齐后再补一条完整的。同时确认 VPS 的 A 腿登记也在那时
// 就发出去了(nudge 必须先看到腿的候选)。
func TestRelayTwoPhasePushesEndpointAheadOfFingerprint(t *testing.T) {
	b, rs, a, vps, c, e, cCands := newRelayBrokerFixture(t, true)

	openID := b.trackRelay(rs, relayRoleOpen)
	b.onRelayReady(vps, b.take(openID), DirectReady{Candidates: e})

	early := decodeDirectMsg[DirectOffer](t, recvDirectMsg(t, a.send, METHOD_DIRECT_OFFER))
	if !early.EndpointOnly {
		t.Fatalf("the first offer must be marked endpointOnly, got %+v", early)
	}
	if early.Fingerprint != "" {
		t.Fatalf("the first offer must not carry a fingerprint yet, got %q", early.Fingerprint)
	}
	if len(early.PeerAddrs) != 1 || early.PeerAddrs[0].Addr != e[0].Addr {
		t.Fatalf("the first offer should carry the relay endpoint E, got %v", early.PeerAddrs)
	}

	legA := decodeDirectMsg[DirectPunch](t, recvDirectMsg(t, vps.send, METHOD_DIRECT_PUNCH))
	if !legA.Relay || legA.Email != a.Email || len(legA.PeerAddrs) != 1 {
		t.Fatalf("the VPS should learn A's leg (with its candidates) right then, got %+v", legA)
	}

	punchC := decodeDirectMsg[DirectPunch](t, recvDirectMsg(t, c.send, METHOD_DIRECT_PUNCH))
	if !punchC.Relay || len(punchC.PeerAddrs) != 1 || punchC.PeerAddrs[0].Addr != e[0].Addr {
		t.Fatalf("C should be asked to punch toward E, got %+v", punchC)
	}

	// C 回候选 + 指纹: 第二段(完整 offer)补发给 A。
	punchCID := b.trackRelay(rs, relayRolePunchC)
	b.onRelayReady(c, b.take(punchCID), DirectReady{Candidates: cCands, Fingerprint: "fp-abc"})

	full := decodeDirectMsg[DirectOffer](t, recvDirectMsg(t, a.send, METHOD_DIRECT_OFFER))
	if full.EndpointOnly {
		t.Fatal("the second offer must be the complete one, not another partial")
	}
	if full.Fingerprint != "fp-abc" {
		t.Fatalf("the second offer must carry C's fingerprint, got %q", full.Fingerprint)
	}
}

// TestRelayOnePhaseOfferStaysSingle 没声明 TwoPhase 的 A(老客户端)只能收到**一段**完整 offer:
// 半截 offer 会让它在"缺指纹"上直接判失败, 那就把老客户端连根打死了。
func TestRelayOnePhaseOfferStaysSingle(t *testing.T) {
	b, rs, a, vps, c, e, cCands := newRelayBrokerFixture(t, false)

	openID := b.trackRelay(rs, relayRoleOpen)
	b.onRelayReady(vps, b.take(openID), DirectReady{Candidates: e})

	select {
	case m := <-a.send:
		t.Fatalf("an old client must not receive a partial offer, got %q", m.Method)
	case <-time.After(200 * time.Millisecond):
	}

	punchCID := b.trackRelay(rs, relayRolePunchC)
	b.onRelayReady(c, b.take(punchCID), DirectReady{Candidates: cCands, Fingerprint: "fp-abc"})

	full := decodeDirectMsg[DirectOffer](t, recvDirectMsg(t, a.send, METHOD_DIRECT_OFFER))
	if full.EndpointOnly || full.Fingerprint != "fp-abc" {
		t.Fatalf("an old client should get exactly one complete offer, got %+v", full)
	}
}
