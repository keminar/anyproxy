package nat

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startEchoServer 起一个原样回显收到字节的 TCP 服务, 作为"最终目标"供代理转发。
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// startHTTPConnectProxy 起一个最小的假 HTTP CONNECT 代理: 读一行 CONNECT 请求, 按
// statusLine 回应; 200 时再把连接原样双向转发给 CONNECT 里声明的目标地址。
func startHTTPConnectProxy(t *testing.T, statusLine string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					c.Close()
					return
				}
				// "CONNECT host:port HTTP/1.1"
				parts := strings.Fields(line)
				target := ""
				if len(parts) >= 2 {
					target = parts[1]
				}
				// 消费剩余头部直到空行。
				for {
					h, err := br.ReadString('\n')
					if err != nil || h == "\r\n" || h == "\n" {
						break
					}
				}
				fmt.Fprintf(c, "%s\r\n\r\n", statusLine)
				if !strings.HasPrefix(statusLine, "HTTP/1.1 200") {
					c.Close()
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					c.Close()
					return
				}
				go io.Copy(up, br)
				io.Copy(c, up)
				c.Close()
				up.Close()
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// startSocks5Proxy 起一个最小的假 SOCKS5 代理(no-auth, 只认 IPv4 CONNECT), 握手完成
// 后把连接原样双向转发给客户端请求的目标地址。
func startSocks5Proxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// 问候: VER NMETHODS METHODS...
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				n := int(hdr[1])
				methods := make([]byte, n)
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				// 回应: VER=5 METHOD=0(无认证)
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				// 请求: VER CMD RSV ATYP ...
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if req[3] != 1 { // 只支持 IPv4
					c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				addr := make([]byte, 4)
				port := make([]byte, 2)
				if _, err := io.ReadFull(c, addr); err != nil {
					return
				}
				if _, err := io.ReadFull(c, port); err != nil {
					return
				}
				target := fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3], int(port[0])<<8|int(port[1]))
				up, err := net.Dial("tcp", target)
				if err != nil {
					c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				// 成功应答: VER REP RSV ATYP BND.ADDR BND.PORT
				if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestDialThroughProxyHTTPConnect(t *testing.T) {
	target := startEchoServer(t)
	proxyAddr := startHTTPConnectProxy(t, "HTTP/1.1 200 Connection Established")

	conn, err := dialThroughProxy("http://"+proxyAddr, "tcp", target, 3*time.Second)
	if err != nil {
		t.Fatalf("dialThroughProxy: %v", err)
	}
	defer conn.Close()

	assertEchoRoundtrip(t, conn)
}

func TestDialThroughProxySocks5(t *testing.T) {
	target := startEchoServer(t)
	proxyAddr := startSocks5Proxy(t)

	conn, err := dialThroughProxy("socks5://"+proxyAddr, "tcp", target, 3*time.Second)
	if err != nil {
		t.Fatalf("dialThroughProxy: %v", err)
	}
	defer conn.Close()

	assertEchoRoundtrip(t, conn)
}

func assertEchoRoundtrip(t *testing.T, conn net.Conn) {
	t.Helper()
	msg := []byte("hello through proxy")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

// TestDialThroughProxyUnknownScheme 配错 scheme 时必须报错, 不能静默退化为直连。
func TestDialThroughProxyUnknownScheme(t *testing.T) {
	target := startEchoServer(t)
	_, err := dialThroughProxy("ftp://127.0.0.1:1", "tcp", target, time.Second)
	if err == nil {
		t.Fatal("expected error for unsupported scheme, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported proxy scheme") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDialThroughProxyConnectionRefused 代理地址连不上要报错, 不能悄悄换成直连目标。
func TestDialThroughProxyConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close() // 立刻关掉, 拿一个大概率没人监听的端口号

	target := startEchoServer(t)
	_, err = dialThroughProxy("http://"+deadAddr, "tcp", target, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when proxy is unreachable, got nil")
	}
}

// TestDialThroughProxyHTTPConnectNon200 CONNECT 被代理拒绝(非 200)要报错并关闭连接。
func TestDialThroughProxyHTTPConnectNon200(t *testing.T) {
	target := startEchoServer(t)
	proxyAddr := startHTTPConnectProxy(t, "HTTP/1.1 403 Forbidden")

	_, err := dialThroughProxy("http://"+proxyAddr, "tcp", target, 3*time.Second)
	if err == nil {
		t.Fatal("expected error for non-200 CONNECT response, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("unexpected error: %v", err)
	}
}
