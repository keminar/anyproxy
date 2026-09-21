package nat

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

// TestBuildMagicPacket 覆盖两种常见 MAC 写法, 校验包长与内容: 前 6 字节全 0xFF,
// 之后 16 遍原样重复目标 MAC。
func TestBuildMagicPacket(t *testing.T) {
	want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for _, mac := range []string{"AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff"} {
		packet, err := buildMagicPacket(mac)
		if err != nil {
			t.Fatalf("buildMagicPacket(%q): %v", mac, err)
		}
		if len(packet) != 6+16*6 {
			t.Fatalf("buildMagicPacket(%q): got %d bytes, want %d", mac, len(packet), 6+16*6)
		}
		if !bytes.Equal(packet[:6], bytes.Repeat([]byte{0xff}, 6)) {
			t.Fatalf("buildMagicPacket(%q): header is not 6x0xFF: %x", mac, packet[:6])
		}
		for i := 0; i < 16; i++ {
			got := packet[6+i*6 : 6+i*6+6]
			if !bytes.Equal(got, want) {
				t.Fatalf("buildMagicPacket(%q): repeat #%d = %x, want %x", mac, i, got, want)
			}
		}
	}
}

// TestBuildMagicPacketInvalid: 格式错误的字符串, 以及合法但不是 6 字节以太网 MAC 的
// 写法(net.ParseMAC 也认的 20 字节 InfiniBand 格式), 都应报错。
func TestBuildMagicPacketInvalid(t *testing.T) {
	cases := []string{
		"not-a-mac",
		"AA:BB:CC:DD:EE", // 少一段
		"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00", // 20 字节
	}
	for _, mac := range cases {
		if _, err := buildMagicPacket(mac); err == nil {
			t.Fatalf("buildMagicPacket(%q): expected error, got nil", mac)
		}
	}
}

// TestWolTarget 覆盖空/只带地址/已带端口三种情况。
func TestWolTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "255.255.255.255:9"},
		{"192.168.1.255", "192.168.1.255:9"},
		{"192.168.1.255:7", "192.168.1.255:7"},
	}
	for _, c := range cases {
		if got := wolTarget(c.in); got != c.want {
			t.Fatalf("wolTarget(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestWakeOnLANInvalidMac: 列表里混一个坏 MAC 时整批都不该发送, 直接报错。
func TestWakeOnLANInvalidMac(t *testing.T) {
	err := WakeOnLAN([]string{"AA:BB:CC:DD:EE:FF", "garbage"}, "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected an error for an invalid mac in the list")
	}
}

// TestWakeOnLANSendsPacket 在本机起一个 UDP 监听当唤醒目标, 断言收到的字节与
// buildMagicPacket 算出来的完全一致 —— 不依赖真实广播/硬件, 可在 CI 里稳定跑。
func TestWakeOnLANSendsPacket(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	mac := "AA:BB:CC:DD:EE:FF"
	if err := WakeOnLAN([]string{mac}, ln.LocalAddr().String()); err != nil {
		t.Fatalf("WakeOnLAN: %v", err)
	}

	buf := make([]byte, 256)
	n, err := ln.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want, err := buildMagicPacket(mac)
	if err != nil {
		t.Fatalf("buildMagicPacket: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("received %x, want %x", buf[:n], want)
	}
}

// ---------- 远程唤醒(直连/中继共用的 sendWolOver/serveWolOver) ----------

// TestSendWolOverRoundTrip: net.Pipe 两端天然满足 fileConn(Read/Write/Close/
// SetReadDeadline, 见 nat/file_pull_test.go 同样的用法), c 那头跑 serveWolOver,
// 真正把 wol 广播到本机起的一个 UDP 监听上, a 那头验证收到成功回执。
func TestSendWolOverRoundTrip(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	aSide, cSide := net.Pipe()
	go serveWolOver(cSide, "a@example.com", "test", func(string, ...interface{}) {})

	mac := "AA:BB:CC:DD:EE:FF"
	if err := sendWolOver(aSide, []string{mac}, ln.LocalAddr().String()); err != nil {
		t.Fatalf("sendWolOver: %v", err)
	}

	buf := make([]byte, 256)
	n, err := ln.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want, _ := buildMagicPacket(mac)
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("received %x, want %x", buf[:n], want)
	}
}

// TestSendWolOverPropagatesRemoteError: 对端(serveWolOver)执行 WakeOnLAN 失败时,
// 错误要原样带回给发起方, 而不是让 sendWolOver 误报成功。
func TestSendWolOverPropagatesRemoteError(t *testing.T) {
	aSide, cSide := net.Pipe()
	go serveWolOver(cSide, "a@example.com", "test", func(string, ...interface{}) {})

	err := sendWolOver(aSide, []string{"garbage-mac"}, "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected an error for an invalid mac")
	}
	if !strings.Contains(err.Error(), "garbage-mac") {
		t.Fatalf("error %q does not mention the bad mac", err.Error())
	}
}
