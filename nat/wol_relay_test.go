package nat

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

// TestWolRelayRequiresAllowWol: allow 里有这个 email 但没打开 wol(默认 false)时,
// -wol 必须被拒绝——收发文件在 allow 里就默认放行, 网络唤醒是另一件事(骚扰局域网
// 里别的设备), 需要单独打开开关。
func TestWolRelayRequiresAllowWol(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: t.TempDir(), Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{})

	err := sendWolViaRelay(a.client, "c@example.com", []string{"AA:BB:CC:DD:EE:FF"}, "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected an error: allow[].wol defaults to false")
	}
	if !strings.Contains(err.Error(), "wol") {
		t.Fatalf("error %q should explain the missing wol permission", err.Error())
	}
}

// TestWolRelayAllowedWithWolFlag: allow[].wol=true 时 -wol 应该成功, 并且真的把
// 魔术包广播到了指定地址(用本机一个 UDP 监听当唤醒目标, 不依赖真实硬件)。
func TestWolRelayAllowedWithWolFlag(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: t.TempDir(), Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA, Wol: true}}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{})

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	mac := "AA:BB:CC:DD:EE:FF"
	if err := sendWolViaRelay(a.client, "c@example.com", []string{mac}, ln.LocalAddr().String()); err != nil {
		t.Fatalf("sendWolViaRelay: %v", err)
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

// TestWolRelayRejectsStranger: 不在 allow 名单里的人, 就算他"声称"自己想 wol,
// 也要在能不能 wol 之前先被身份核对挡住(与文件收发同一份 email/uuid 校验)。
func TestWolRelayRejectsStranger(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: t.TempDir(), Allow: []conf.AllowedSender{{Email: "trusted@example.com", UUID: testUUIDTrusted, Wol: true}}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDStranger, conf.ClientReceive{})

	err := sendWolViaRelay(a.client, "c@example.com", []string{"AA:BB:CC:DD:EE:FF"}, "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected an error: a@example.com is not in c's receive.allow")
	}
	if !strings.Contains(err.Error(), "receive.allow") {
		t.Fatalf("stranger should be rejected on identity (receive.allow), got: %q", err.Error())
	}
}

// TestFileRelayPerSenderDirOverride: allow[].dir 非空时, 这个发送者上传的文件应该
// 落到它自己的目录, 而不是共享的 receive.dir——即便共享 Dir 配了别的路径。
func TestFileRelayPerSenderDirOverride(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})
	sharedDir := t.TempDir()
	ownDir := t.TempDir()
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: sharedDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA, Dir: ownDir}}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{})

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "mine.txt")
	if err := os.WriteFile(srcPath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	saved, err := sendFileViaRelay(a.client, "c@example.com", items[0], nil)
	if err != nil {
		t.Fatalf("send via relay: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ownDir, saved)); err != nil {
		t.Fatalf("expected the file under the sender's own dir %s: %v", ownDir, err)
	}
	if entries, _ := os.ReadDir(sharedDir); len(entries) != 0 {
		t.Fatalf("the shared receive.dir should stay empty, found %d entries", len(entries))
	}
}
