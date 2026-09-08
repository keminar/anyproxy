package nat

import (
	"net"
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

// TestIPInCIDR allowIP 的匹配必须对 IPv6 成立, 且不受书写形式影响。
//
// 同一个 IPv6 地址有多种合法写法(大小写、是否压缩零段), 早先单 IP 分支比的是
// ip.String() == cidr, 而 String() 只产出规范形式 —— 配置里写 2001:0DB8::1 就会
// 匹配不上, 现象是白名单"配了却不生效", 且只在 IPv6 下出现(IPv4 写法唯一)。
func TestIPInCIDR(t *testing.T) {
	cases := []struct {
		name  string
		ip    string
		entry string
		want  bool
	}{
		{"ipv4 单地址", "1.2.3.4", "1.2.3.4", true},
		{"ipv4 不匹配", "1.2.3.5", "1.2.3.4", false},
		{"ipv4 网段", "172.17.0.9", "172.17.0.0/16", true},
		{"ipv4 网段外", "172.18.0.9", "172.17.0.0/16", false},

		{"ipv6 单地址", "2001:db8::1", "2001:db8::1", true},
		{"ipv6 单地址-大写", "2001:db8::1", "2001:0DB8::1", true},
		{"ipv6 单地址-未压缩", "2001:db8::1", "2001:db8:0:0:0:0:0:1", true},
		{"ipv6 不匹配", "2001:db8::2", "2001:db8::1", false},
		{"ipv6 网段", "2001:db8::1234", "2001:db8::/32", true},
		{"ipv6 网段外", "2001:dead::1", "2001:db8::/32", false},

		{"非法条目不放行", "1.2.3.4", "not-an-ip", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := net.ParseIP(c.ip)
			if ip == nil {
				t.Fatalf("bad test ip %q", c.ip)
			}
			if got := ipInCIDR(ip, c.entry); got != c.want {
				t.Fatalf("ipInCIDR(%s, %s) = %v, want %v", c.ip, c.entry, got, c.want)
			}
		})
	}
}

// TestEmptySubscribeAllowed 一条没有 subscribe 头部规则的连接, 只在它确实有事可干
// (转发目标/直连/接收文件三者之一)时才该被放行, 三者都没有的纯陪跑连接必须拒绝
// ——不然服务端也没法把它路由给任何请求方, 白占一个 hub 位置。
func TestEmptySubscribeAllowed(t *testing.T) {
	old := conf.RouterConfig
	t.Cleanup(func() { conf.RouterConfig = old })
	conf.RouterConfig = &conf.Router{Websocket: conf.Websocket{Server: conf.WsServer{
		Forward: []conf.ServerForward{{Listen: ":2222", Email: "forward-target@example.com"}},
	}}}

	cases := []struct {
		name       string
		user       AuthMessage
		wantOK     bool
		wantReason string
	}{
		{"forward target", AuthMessage{Email: "forward-target@example.com"}, true, "forward"},
		{"direct", AuthMessage{Email: "someone@example.com", Direct: true}, true, "direct"},
		{"receive", AuthMessage{Email: "someone@example.com", Receive: true}, true, "receive"},
		{"nothing configured", AuthMessage{Email: "someone@example.com"}, false, ""},
		{"forward rule exists but different email", AuthMessage{Email: "not-forward@example.com"}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, ok := emptySubscribeAllowed(c.user)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if ok && reason != c.wantReason {
				t.Fatalf("reason = %q, want %q", reason, c.wantReason)
			}
		})
	}
}
