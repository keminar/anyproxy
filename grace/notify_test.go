package grace

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newFakeNotifySocket 起一个临时 unixgram socket 模拟 systemd 的 NOTIFY_SOCKET,
// 返回收到的每条消息。
func newFakeNotifySocket(t *testing.T) (addr string, recv <-chan string) {
	t.Helper()
	addr = filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unixgram: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ch := make(chan string, 8)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			ch <- string(buf[:n])
		}
	}()
	return addr, ch
}

func recvOrTimeout(t *testing.T, recv <-chan string) string {
	t.Helper()
	select {
	case msg := <-recv:
		return msg
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sd_notify message")
		return ""
	}
}

func TestNotifyReady(t *testing.T) {
	addr, recv := newFakeNotifySocket(t)
	t.Setenv("NOTIFY_SOCKET", addr)

	NotifyReady()

	if msg := recvOrTimeout(t, recv); msg != "READY=1" {
		t.Fatalf("got %q, want READY=1", msg)
	}
}

func TestNotifyReloading(t *testing.T) {
	addr, recv := newFakeNotifySocket(t)
	t.Setenv("NOTIFY_SOCKET", addr)

	NotifyReloading()

	if msg := recvOrTimeout(t, recv); msg != "RELOADING=1" {
		t.Fatalf("got %q, want RELOADING=1", msg)
	}
}

func TestNotifyMainPID(t *testing.T) {
	addr, recv := newFakeNotifySocket(t)
	t.Setenv("NOTIFY_SOCKET", addr)

	NotifyMainPID(12345)

	if msg := recvOrTimeout(t, recv); msg != "MAINPID=12345\n" {
		t.Fatalf("got %q, want MAINPID=12345\\n", msg)
	}
}

func TestSdNotifyWithoutSocketIsNoop(t *testing.T) {
	os.Unsetenv("NOTIFY_SOCKET")

	if err := sdNotify("READY=1"); err != nil {
		t.Fatalf("sdNotify with empty NOTIFY_SOCKET should be a no-op, got err: %v", err)
	}
}
