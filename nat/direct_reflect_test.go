package nat

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// TestDirectReflectorRetriesOccupiedPort 回归 SIGHUP 平滑重启时的端口交接：新进程
// 启动之初旧进程仍占着 UDP 端口，旧 socket 随后释放；反射器必须自行绑定成功，不能
// 因第一次 EADDRINUSE 就永久消失。
func TestDirectReflectorRetriesOccupiedPort(t *testing.T) {
	oldConfig := conf.RouterConfig()
	conf.SetRouterConfig(&conf.Router{})
	t.Cleanup(func() { conf.SetRouterConfig(oldConfig) })

	// 抓住重试路径里异步绑定出来的 conn 与其读循环的退出信号: 不这样做的话, 反射器
	// 的后台 goroutine 会在本用例返回后继续跑, 与后续用例并发 touch reflectorLog/
	// log.SetOutput 这类全局状态, 引出跨用例的 data race(而不是本用例自身的 bug)。
	var (
		hookMu      sync.Mutex
		reflectConn *net.UDPConn
		stopped     <-chan struct{}
	)
	directReflectorStartedHook = func(c *net.UDPConn, s <-chan struct{}) {
		hookMu.Lock()
		reflectConn, stopped = c, s
		hookMu.Unlock()
	}
	t.Cleanup(func() { directReflectorStartedHook = nil })
	t.Cleanup(func() {
		hookMu.Lock()
		c, s := reflectConn, stopped
		hookMu.Unlock()
		if c != nil {
			c.Close()
		}
		if s != nil {
			<-s
		}
	})

	blocker, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	port := blocker.LocalAddr().(*net.UDPAddr).Port

	// 首次绑定在本调用返回前发生，因 blocker 占用端口必然失败；后续重试在后台进行。
	StartDirectReflector(fmt.Sprintf(":%d", port))
	// 让后台的第一次重试也撞到旧 socket，模拟新旧进程确实重叠一段时间，而不是
	// StartDirectReflector 一返回就恰好抢到已经释放的端口。
	time.Sleep(100 * time.Millisecond)
	if err := blocker.Close(); err != nil {
		t.Fatalf("release old reflector socket: %v", err)
	}

	server := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatalf("listen probe socket: %v", err)
		}
		nonce := newNonce()
		_, writeErr := client.WriteToUDP(directPacket(verbWhoami+" "+nonce), server)
		if writeErr == nil {
			_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			buf := make([]byte, 512)
			n, _, readErr := client.ReadFromUDP(buf)
			if readErr == nil {
				payload, ok := directPayload(buf[:n])
				client.Close()
				if ok && strings.HasPrefix(payload, verbSeen+" "+nonce+" ") {
					return
				}
				t.Fatalf("unexpected reflector reply %q", payload)
			}
		}
		client.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("reflector did not bind and answer after the old UDP socket was released")
}

// TestDirectReflectorLogHasNoRawMagicByte 回归: "answered with" 这行日志之前直接打了
// directPacket 的结果, 首字节是 directPacketMagic(0x00) —— 终端/日志采集里会显示成
// ^@ 之类的控制符, 让这一行看起来半文本半二进制。这里断言日志里只有可读的
// ANYPROXY-DIRECT-SEEN 载荷, 不含 NUL 字节。
func TestDirectReflectorLogHasNoRawMagicByte(t *testing.T) {
	oldConfig := conf.RouterConfig()
	conf.SetRouterConfig(&conf.Router{})
	t.Cleanup(func() { conf.SetRouterConfig(oldConfig) })

	// 清掉限速表: 同一个日志 key("answered|127.0.0.1")在同进程内其它用例(比如
	// TestDirectReflectorRetriesOccupiedPort)可能已经记过, 不清的话这里会被限速吞掉。
	reflectorLog = reflectorLogState{}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen reflector socket: %v", err)
	}
	serveDirectReflector(conn)
	t.Cleanup(func() { conn.Close() })

	// 用带锁的 buffer, 不能直接用 bytes.Buffer: 下面轮询 logBuf.String() 是在测试的
	// 主 goroutine 里做的, 而 serveDirectReflector 的后台读循环会并发调用 log.Printf
	// 写向同一个 buffer —— bytes.Buffer 本身不是并发安全的, 这是两个 goroutine 各自
	// 该干的事, 不是前面那个"上一用例遗留 goroutine"的跨用例竞争, 得单独同步。
	logBuf := &syncBuffer{}
	oldOut := log.Writer()
	log.SetOutput(logBuf)
	t.Cleanup(func() { log.SetOutput(oldOut) })

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen probe socket: %v", err)
	}
	defer client.Close()

	nonce := newNonce()
	if _, err := client.WriteToUDP(directPacket(verbWhoami+" "+nonce), conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send whoami: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read reflector reply: %v", err)
	}
	payload, ok := directPayload(buf[:n])
	if !ok || !strings.HasPrefix(payload, verbSeen+" "+nonce+" ") {
		t.Fatalf("unexpected reflector reply %q", payload)
	}

	// 日志是后台 goroutine 异步写的, 给它一点时间落地。
	deadline := time.Now().Add(2 * time.Second)
	var line string
	for time.Now().Before(deadline) {
		if strings.Contains(logBuf.String(), "answered with") {
			line = logBuf.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if line == "" {
		t.Fatal(`did not see the "answered with" log line in time`)
	}
	if strings.ContainsRune(line, 0x00) {
		t.Fatalf("log line contains a raw NUL byte (renders as ^@), want the readable payload only: %q", line)
	}
	if !strings.Contains(line, verbSeen+" "+nonce+" ") {
		t.Fatalf("log line should still contain the readable %s payload, got: %q", verbSeen, line)
	}
}

// syncBuffer 给 bytes.Buffer 包一层锁。log.SetOutput 的目标会被后台 goroutine(这里是
// serveDirectReflector 的读循环)在调用 log.Printf 时并发写入, 同时测试的主 goroutine
// 又要轮询读它的内容——裸 bytes.Buffer 两头都不安全, 包一层互斥锁即可。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
