package nat

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// TestBuildForward 确认 Port==0 或 Target=="" 的规则被过滤, 不进最终映射;
// 这是从原全局 SetLocalForward 提炼出的纯函数, 每条 server 连接各自调用一份。
func TestBuildForward(t *testing.T) {
	rules := []conf.ClientForward{
		{Port: 2222, Target: "127.0.0.1:22"},
		{Port: 0, Target: "127.0.0.1:80"}, // Port 为 0, 应被过滤
		{Port: 3389, Target: ""},          // Target 为空, 应被过滤
		{Port: 3306, Target: "10.0.0.1:3306"},
	}
	m := buildForward(rules)
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(m), m)
	}
	if m[2222] != "127.0.0.1:22" || m[3306] != "10.0.0.1:3306" {
		t.Fatalf("unexpected map content: %+v", m)
	}
	if _, ok := m[0]; ok {
		t.Fatalf("port 0 should be filtered")
	}
	if _, ok := m[3389]; ok {
		t.Fatalf("empty target should be filtered")
	}
}

// TestDialForCreateNoForwardTarget 锁定"入口端口没有映射"这条错误的准确文案。
//
// 这个字符串现在不只是打在订阅方本地日志里, 还会经 METHOD_CLOSE 的 Body 带回给
// 服务端、折进它自己的关闭汇总日志(见 Bridge.CloseReason / client.go 的拒绝分支)。
// 一旦这里的措辞被顺手改掉, 服务端那边看到的原因就跟着变, 所以专门钉一个测试。
func TestDialForCreateNoForwardTarget(t *testing.T) {
	c := &Client{forward: map[uint16]string{2222: "127.0.0.1:22"}}
	_, err := dialForCreate(c, &Message{Type: ConnTCP, Port: 2224})
	if err == nil {
		t.Fatal("an unmapped entry port should fail, not silently succeed")
	}
	want := "no forward target for entry port 2224"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
	// 映射了的端口不受影响。
	if _, err := dialForCreate(c, &Message{Type: ConnTCP, Port: 2222}); err != nil {
		// 22 端口在测试机上多半没监听, dial 本身失败是预期的; 只要不是
		// "no forward target" 这条就说明查表本身是对的。
		if strings.Contains(err.Error(), "no forward target") {
			t.Fatalf("a mapped port was rejected as unmapped: %v", err)
		}
	}
}

// tcpPipe 起一对真实连上的 TCP 连接, 供需要 *net.TCPConn 的用例使用(Bridge.conn 是
// 具体类型而非接口, WritePump 里直接调 CloseWrite, net.Pipe 那种内存管道不满足)。
func tcpPipe(t *testing.T) (server, client *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c.(*net.TCPConn)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	return s, c.(*net.TCPConn)
}

// TestBridgeCloseReasonPropagation 覆盖这条链路的核心机制: 订阅方经 METHOD_CLOSE 带
// 回的拒绝原因, 服务端这边的 Bridge 要能在 WritePump 返回后读到。
//
// 这正是本次要修的现象: 之前 METHOD_CLOSE 不带 Body, B 只看得到"连接没数据就断了",
// 真正原因(比如查不到 forward 映射)只留在 C 自己的本地日志里, 要跨机器去查。
func TestBridgeCloseReasonPropagation(t *testing.T) {
	hub := newBridgeHub()
	go hub.run()

	srvConn, cliConn := tcpPipe(t)
	defer cliConn.Close()

	b := hub.Register(nil, 1, ConnTCP, srvConn)
	defer b.Unregister()

	const reason = "no forward target for entry port 2224"
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.WritePump() // 收到 METHOD_CLOSE 后 send 通道被关, 这里应正常返回而不是卡住
	}()

	hub.broadcast <- &Message{ID: 1, Type: ConnTCP, Method: METHOD_CLOSE, Body: []byte(reason)}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("WritePump did not return after METHOD_CLOSE")
	}
	if got := b.CloseReason(); got != reason {
		t.Fatalf("CloseReason() = %q, want %q", got, reason)
	}
}

// 对端正常关闭(不带原因)时不能报出一个假原因——空 Body 必须还是空 CloseReason,
// 不能被上一次遗留的值污染, 也不能把"没有原因"误报成某个具体错误。
func TestBridgeCloseReasonEmptyWhenNotGiven(t *testing.T) {
	hub := newBridgeHub()
	go hub.run()

	srvConn, cliConn := tcpPipe(t)
	defer cliConn.Close()

	b := hub.Register(nil, 2, ConnTCP, srvConn)
	defer b.Unregister()

	done := make(chan struct{})
	go func() {
		defer close(done)
		b.WritePump()
	}()

	hub.broadcast <- &Message{ID: 2, Type: ConnTCP, Method: METHOD_CLOSE}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("WritePump did not return after METHOD_CLOSE")
	}
	if got := b.CloseReason(); got != "" {
		t.Fatalf("CloseReason() = %q, want empty for a plain close", got)
	}
}
