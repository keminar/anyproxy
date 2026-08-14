package proto

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// buildClientHello 用真实 tls.Client 生成一个 ClientHello 字节流
func buildClientHello(serverName string) []byte {
	c1, c2 := net.Pipe()
	go func() {
		tlsConn := tls.Client(c1, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		// 握手会写出 ClientHello 后因无服务端而阻塞/失败，忽略结果
		_ = tlsConn.Handshake()
		c1.Close()
	}()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := c2.Read(buf)
	c2.Close()
	return buf[:n]
}

func TestSniffTLSServerName(t *testing.T) {
	hello := buildClientHello("www.example.com")
	if len(hello) == 0 {
		t.Fatal("failed to build ClientHello")
	}
	if got := sniffDomain(hello); got != "www.example.com" {
		t.Fatalf("sniff SNI = %q, want www.example.com", got)
	}
}

func TestSniffHTTPHost(t *testing.T) {
	req := "GET /path HTTP/1.1\r\nHost: api.example.com:8080\r\nUser-Agent: x\r\n\r\n"
	if got := sniffDomain([]byte(req)); got != "api.example.com" {
		t.Fatalf("sniff Host = %q, want api.example.com", got)
	}
}

func TestSniffNonMatch(t *testing.T) {
	// 服务端先说话的协议(如SSH banner)不应解析出域名
	if got := sniffDomain([]byte("SSH-2.0-OpenSSH_8.9\r\n")); got != "" {
		t.Fatalf("sniff ssh banner = %q, want empty", got)
	}
	if got := sniffDomain(nil); got != "" {
		t.Fatalf("sniff nil = %q, want empty", got)
	}
}

// 无 ServerName 的 ClientHello 不带 SNI 扩展，应返回空
func TestSniffTLSNoSNI(t *testing.T) {
	hello := buildClientHello("")
	if len(hello) == 0 {
		t.Fatal("failed to build ClientHello")
	}
	if hello[0] != 0x16 {
		t.Fatalf("not a TLS record: 0x%02x", hello[0])
	}
	if got := sniffDomain(hello); got != "" {
		t.Fatalf("sniff no-SNI = %q, want empty", got)
	}
}

// ClientHello 分片/截断: 任意长度都不能panic;
// 截到SNI之后仍应解析出域名，截到SNI之前应返回空
func TestSniffTLSTruncated(t *testing.T) {
	const name = "secure.example.com"
	hello := buildClientHello(name)
	if len(hello) < 20 {
		t.Fatalf("hello too short: %d", len(hello))
	}
	// 从每个长度截断都不能panic
	for i := 0; i <= len(hello); i++ {
		_ = sniffDomain(hello[:i])
	}
	idx := bytes.Index(hello, []byte(name))
	if idx < 10 {
		t.Fatalf("sni not found in bytes (idx=%d)", idx)
	}
	// 截断到刚好包含完整SNI，应仍能解析
	cut := idx + len(name)
	if got := sniffDomain(hello[:cut]); got != name {
		t.Fatalf("sniff truncated-after-sni = %q, want %s", got, name)
	}
	// 截断到SNI主机名开始之前，应返回空(数据不足)
	if got := sniffDomain(hello[:idx-5]); got != "" {
		t.Fatalf("sniff truncated-before-sni = %q, want empty", got)
	}
}

// 以0x16开头但内容非法/长度声明超过实际数据，均不能panic且返回空
func TestSniffTLSGarbage(t *testing.T) {
	cases := [][]byte{
		{0x16},
		{0x16, 0x03, 0x01},
		{0x16, 0x03, 0x01, 0xff, 0xff}, // record长度声明远超实际
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff}, // handshake长度超实际
		{0x16, 0x03, 0x01, 0x00, 0x02, 0x02, 0x00},             // 非ClientHello(type=0x02)
	}
	for i, c := range cases {
		if got := sniffDomain(c); got != "" {
			t.Fatalf("case %d garbage = %q, want empty", i, got)
		}
	}
	// 一段较长的0x16开头随机字节
	buf := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc}
	for i := 0; i < 512; i++ {
		buf = append(buf, byte(i*31+7))
	}
	_ = sniffDomain(buf) // 只要不panic
}

// CONNECT 请求(级联 http 代理转发时无 Host 头，域名在请求行)应能嗅探到域名。
// 纯 IP 目标不当域名返回。回归防护: 曾因先按 \r\n\r\n 截断导致只含请求行的
// CONNECT 报文取不到域名。
func TestSniffConnect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"无Host头", "CONNECT www.baidu.com:443 HTTP/1.1\r\n\r\n", "www.baidu.com"},
		{"带Host头", "CONNECT www.baidu.com:443 HTTP/1.1\r\nHost: www.baidu.com:443\r\n\r\n", "www.baidu.com"},
		{"纯IP不当域名", "CONNECT 1.2.3.4:443 HTTP/1.1\r\n\r\n", ""},
		{"仅请求行未完(无换行)", "CONNECT www.baidu.com:443 HTTP/1.1", ""},
	}
	for _, c := range cases {
		if got := sniffDomain([]byte(c.in)); got != c.want {
			t.Errorf("%s: sniffDomain = %q, want %q", c.name, got, c.want)
		}
	}
}

// connectTarget 从 CONNECT 行解析真实 host:port(级联场景真实端口在此，
// 而非 TCP 连接的目标端口)。非 CONNECT / 无端口 / 端口非法均返回 ok=false。
func TestConnectTarget(t *testing.T) {
	cases := []struct {
		name string
		in   string
		host string
		port uint16
		ok   bool
	}{
		{"域名带端口", "CONNECT www.baidu.com:443 HTTP/1.1\r\n\r\n", "www.baidu.com", 443, true},
		{"IP带端口", "CONNECT 1.2.3.4:8443 HTTP/1.1\r\n\r\n", "1.2.3.4", 8443, true},
		{"粘连TLS数据", "CONNECT a.com:443 HTTP/1.1\r\n\r\n\x16\x03\x01", "a.com", 443, true},
		{"非CONNECT", "GET / HTTP/1.1\r\nHost: a.com\r\n\r\n", "", 0, false},
		{"无端口", "CONNECT badhostnoport HTTP/1.1\r\n\r\n", "", 0, false},
		{"端口非数字", "CONNECT a.com:https HTTP/1.1\r\n\r\n", "", 0, false},
		{"无换行", "CONNECT a.com:443 HTTP/1.1", "", 0, false},
	}
	for _, c := range cases {
		host, port, ok := connectTarget([]byte(c.in))
		if host != c.host || port != c.port || ok != c.ok {
			t.Errorf("%s: got (%q,%d,%v), want (%q,%d,%v)", c.name, host, port, ok, c.host, c.port, c.ok)
		}
	}
}
