package nat

import (
	"fmt"
	"net"
	"strings"
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
