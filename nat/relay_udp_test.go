package nat

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

func TestRelayUDPCodec(t *testing.T) {
	frame := encodeRelayUDP(relayUDPHead{kind: relayKindData, session: 7, port: 3389}, []byte("hello"))
	if !hasRelayUDPMagic(frame) {
		t.Fatal("encoded frame lost its magic")
	}
	h, payload, err := decodeRelayUDP(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.kind != relayKindData || h.session != 7 || h.port != 3389 {
		t.Fatalf("head round trip lost fields: %+v", h)
	}
	if string(payload) != "hello" {
		t.Fatalf("payload round trip: %q", payload)
	}
	// 裸 RDP-UDP 数据报不该被当成上行包, 否则客户端流量会被解释成控制帧。
	if hasRelayUDPMagic([]byte("plain rdp datagram")) {
		t.Fatal("a plain datagram was taken for an uplink frame")
	}
	if _, _, err := decodeRelayUDP(frame[:relayUDPHeadLen-1]); err == nil {
		t.Fatal("want error for a truncated frame")
	}
}

// echoUDP 起一个回显 UDP 服务, 冒充 C 内网里的目标(如 127.0.0.1:3389)。
func echoUDP(t *testing.T, prefix string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(append([]byte(prefix), buf[:n]...), from)
		}
	}()
	return conn.LocalAddr().String()
}

// relayPair 搭起 B 侧中继 + C 侧上行, 并完成注册。信令(u_open/u_ready)本身走 websocket,
// 这里直接把它的效果手工做出来, 好把数据面单独测干净。
func relayPair(t *testing.T, target string) (*udpRelay, *udpUplink) {
	t.Helper()
	old := conf.RouterConfig
	t.Cleanup(func() { conf.RouterConfig = old })
	conf.RouterConfig = &conf.Router{}

	relay, err := newUDPRelay(conf.ServerForward{Listen: "127.0.0.1:0", Email: "c@example.com", Protocol: conf.ProtoBoth})
	if err != nil {
		t.Fatalf("new relay: %v", err)
	}
	t.Cleanup(func() { relay.conn.Close() })
	go relay.readLoop()

	// C 侧: forward 白名单的键是 B 的入口端口。
	up := newUDPUplink("test", relay.conn.LocalAddr().String(), map[uint16]string{relay.port: target})
	t.Cleanup(up.close)

	relay.mu.Lock()
	relay.upToken = "tok-123"
	relay.mu.Unlock()
	if err := up.ensureConn(RelayUDPOpen{Port: relay.port, Token: "tok-123"}); err != nil {
		t.Fatalf("uplink: %v", err)
	}
	waitFor(t, time.Second, func() bool { return relay.isUplinkSet() }, "uplink never registered")
	return relay, up
}

func (u *udpRelay) isUplinkSet() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.upAddr != nil
}

func waitFor(t *testing.T, d time.Duration, ok func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

// 整条链路: 客户端 -> B(UDP 入口) -> C(上行) -> 内网目标 -> 原路回来。
func TestRelayUDPEndToEnd(t *testing.T) {
	target := echoUDP(t, "echo:")
	relay, _ := relayPair(t, target)

	client, err := net.DialUDP("udp", nil, relay.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("packet-%d", i)
		if _, err := client.Write([]byte(msg)); err != nil {
			t.Fatalf("client write: %v", err)
		}
		buf := make([]byte, 2048)
		client.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("no reply for %s: %v", msg, err)
		}
		// 回到客户端的必须是**裸**数据报: 中继头只存在于 B<->C 那一段, 客户端看不到。
		if want := "echo:" + msg; string(buf[:n]) != want {
			t.Fatalf("got %q, want %q", buf[:n], want)
		}
	}
}

// 两个客户端要各自一条会话, 回包不能串到对方去。
func TestRelayUDPSeparatesClients(t *testing.T) {
	target := echoUDP(t, "echo:")
	relay, _ := relayPair(t, target)
	raddr := relay.conn.LocalAddr().(*net.UDPAddr)

	send := func(msg string) string {
		c, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 2048)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read for %s: %v", msg, err)
		}
		return string(buf[:n])
	}
	if got := send("aaa"); got != "echo:aaa" {
		t.Fatalf("client A got %q", got)
	}
	if got := send("bbb"); got != "echo:bbb" {
		t.Fatalf("client B got %q", got)
	}
	relay.mu.Lock()
	n := len(relay.sessions)
	relay.mu.Unlock()
	if n != 2 {
		t.Fatalf("want 2 sessions on the relay, got %d", n)
	}
}

// 没有正确 token 的注册包必须被拒: 端点是对方现场报的, 不核对凭证的话谁都能把自己
// 注册成上行, 把别人的流量整条接走。
func TestRelayUDPRejectsBadToken(t *testing.T) {
	old := conf.RouterConfig
	t.Cleanup(func() { conf.RouterConfig = old })
	conf.RouterConfig = &conf.Router{}

	relay, err := newUDPRelay(conf.ServerForward{Listen: "127.0.0.1:0", Email: "c@example.com"})
	if err != nil {
		t.Fatalf("new relay: %v", err)
	}
	defer relay.conn.Close()
	go relay.readLoop()

	relay.mu.Lock()
	relay.upToken = "right"
	relay.mu.Unlock()

	imposter, err := net.DialUDP("udp", nil, relay.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer imposter.Close()
	imposter.Write(encodeRelayUDP(relayUDPHead{kind: relayKindRegister}, []byte("wrong")))
	time.Sleep(200 * time.Millisecond)
	if relay.isUplinkSet() {
		t.Fatal("a register with the wrong token was accepted")
	}
}

// 上行还没建好时进来的数据报要先存着, 上行一注册就补发 —— 否则握手的头几个包全丢,
// 客户端只能等自己重试。
func TestRelayUDPFlushesPending(t *testing.T) {
	old := conf.RouterConfig
	t.Cleanup(func() { conf.RouterConfig = old })
	conf.RouterConfig = &conf.Router{}

	relay, err := newUDPRelay(conf.ServerForward{Listen: "127.0.0.1:0", Email: "c@example.com"})
	if err != nil {
		t.Fatalf("new relay: %v", err)
	}
	defer relay.conn.Close()
	go relay.readLoop()

	// 装成"已经发过 u_open, 正在等注册", 免得 openUplink 去够还不存在的 ServerHub。
	relay.mu.Lock()
	relay.opening = true
	relay.upToken = "tok"
	relay.mu.Unlock()

	client, err := net.DialUDP("udp", nil, relay.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	client.Write([]byte("early"))
	waitFor(t, time.Second, func() bool {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		return len(relay.pending) == 1
	}, "the early datagram was not buffered")

	// 现在冒充 C 完成注册, 应当立刻收到补发的那一包。
	peer, err := net.DialUDP("udp", nil, relay.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("peer dial: %v", err)
	}
	defer peer.Close()
	peer.Write(encodeRelayUDP(relayUDPHead{kind: relayKindRegister}, []byte("tok")))

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("pending datagram never arrived: %v", err)
	}
	h, payload, err := decodeRelayUDP(buf[:n])
	if err != nil {
		t.Fatalf("decode flushed frame: %v", err)
	}
	if h.kind != relayKindData || h.port != relay.port || !bytes.Equal(payload, []byte("early")) {
		t.Fatalf("flushed frame is wrong: %+v %q", h, payload)
	}
}

// 空闲会话要能回收, 且回收后上行也不再留着 —— 否则 C 会为一条早没人用的中继一直发保活包。
func TestRelayUDPReapsIdle(t *testing.T) {
	target := echoUDP(t, "echo:")
	relay, _ := relayPair(t, target)

	client, err := net.DialUDP("udp", nil, relay.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	client.Write([]byte("hi"))
	waitFor(t, time.Second, func() bool {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		return len(relay.sessions) == 1
	}, "session was never created")

	// 用一个很小的空闲窗口跑一次回收, 不必真等 30 分钟。
	relay.reapOnce(time.Now().Add(time.Hour), time.Minute)
	relay.mu.Lock()
	nSess, up := len(relay.sessions), relay.upAddr
	relay.mu.Unlock()
	if nSess != 0 {
		t.Fatalf("idle session survived, %d left", nSess)
	}
	if up != nil {
		t.Fatal("uplink kept after every session went away")
	}
}

// 端口不在 client.forward 白名单里时要当场回绝, 而不是默默把包丢掉让对面等超时。
func TestRelayUDPUnmappedPort(t *testing.T) {
	up := newUDPUplink("test", "127.0.0.1:1", map[uint16]string{3389: "127.0.0.1:3389"})
	_, err := up.session(nil, relayUDPHead{session: 1, port: 9999})
	if err == nil {
		t.Fatal("an unmapped entry port was accepted")
	}
}
