package nat

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// dialThroughProxy 经上游 HTTP/SOCKS5 代理拨号到 addr, 给 websocket.client.proxy 用
// (见 conf.WsClient.Proxy 的注释)。proxySpec 格式 scheme://host:port, scheme 只认
// socks5/http/https, 其它一律报错、不静默退化为直连——配错 scheme 不该悄悄走错路径。
func dialThroughProxy(proxySpec, network, addr string, timeout time.Duration) (net.Conn, error) {
	scheme, proxyAddr, err := parseProxySpec(proxySpec)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "socks5":
		d, err := proxy.SOCKS5(network, proxyAddr, nil, bypassProxyDialer{timeout: timeout})
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy %s: %w", proxyAddr, err)
		}
		return d.Dial(network, addr)
	case "http", "https":
		return httpConnectProxy(proxyAddr, addr, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q in %q (use socks5:// or http://)", scheme, proxySpec)
	}
}

// parseProxySpec 解析 scheme://host:port。不复用 proto 包里的同类函数
// (parseProxyServer): proto 已经 import nat, nat 反向 import proto 会成环。
func parseProxySpec(spec string) (scheme, hostport string, err error) {
	u, err := url.Parse(spec)
	if err != nil {
		return "", "", fmt.Errorf("invalid proxy %q: %w", spec, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("invalid proxy %q, want scheme://host:port", spec)
	}
	return strings.ToLower(u.Scheme), u.Host, nil
}

// bypassProxyDialer 实现 golang.org/x/net/proxy.Dialer, 用 bypassDial 去连"代理"
// 自身的地址(不是最终目标)——连代理这一跳也要走 TUN 旁路逻辑, 不能被 TUN 截回自己。
type bypassProxyDialer struct {
	timeout time.Duration
}

func (d bypassProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return bypassDial(network, addr, d.timeout)
}

// httpConnectProxy 经标准 HTTP CONNECT 建立到 target 的隧道, 返回握手完成、可直接
// 当作到 target 的连接使用的 net.Conn。
func httpConnectProxy(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	conn, err := bypassDial("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response from %s: %w", proxyAddr, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy %s CONNECT %s: %s", proxyAddr, target, resp.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	// br 可能在读响应时把紧跟着的隧道数据也一起读进了缓冲区(响应和后续字节挤在同一个
	// TCP 段很常见), 这里用 br 包一层, 把缓冲区里剩下的字节先吐出来, 否则会被静默丢掉。
	return &bufConn{Conn: conn, r: br}, nil
}

// bufConn 把 bufio.Reader 里滞留的字节接到后续 Read 上, 见 httpConnectProxy 的注释。
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
