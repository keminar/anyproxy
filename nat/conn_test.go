package nat

import (
	"net"
	"testing"
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
