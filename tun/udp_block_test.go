//go:build !windows
// +build !windows

package tun

import (
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

// 配了 ip 的域名: 目标 IP == host.ip 时命中(drop UDP443)。
func TestHostBlocksUDP_ByIP(t *testing.T) {
	conf.RouterConfig = &conf.Router{Hosts: []conf.Host{
		{Name: "a.com", IP: "10.0.0.5"},
	}}
	if !hostBlocksUDP("10.0.0.5") {
		t.Fatal("10.0.0.5 should be blocked (matches host.ip)")
	}
	if hostBlocksUDP("10.0.0.6") {
		t.Fatal("10.0.0.6 should NOT be blocked (no rule)")
	}
}

// deny 域名不配 ip 时不参与 UDP 判定(deny 在 DNS 层已 NXDOMAIN, 客户端发不出 QUIC)。
func TestHostBlocksUDP_DenyNoIP(t *testing.T) {
	conf.RouterConfig = &conf.Router{Hosts: []conf.Host{
		{Name: "bad.com", Target: "deny"},
	}}
	if hostBlocksUDP("1.2.3.4") {
		t.Fatal("deny domain without ip should NOT block by arbitrary IP")
	}
}

// 无 hosts 规则的 IP 不 drop。
func TestHostBlocksUDP_NoMatch(t *testing.T) {
	conf.RouterConfig = &conf.Router{Hosts: []conf.Host{
		{Name: "a.com", IP: "10.0.0.5"},
	}}
	if hostBlocksUDP("8.8.8.8") {
		t.Fatal("8.8.8.8 should NOT be blocked")
	}
}

// blockQUICEnabled 三态: 不配置=true, 显式 false=false, 显式 true=true。
func TestBlockQUICEnabled(t *testing.T) {
	f := false
	tr := true
	cases := []struct {
		name string
		val  *bool
		want bool
	}{
		{"nil default true", nil, true},
		{"explicit false", &f, false},
		{"explicit true", &tr, true},
	}
	for _, c := range cases {
		conf.RouterConfig = &conf.Router{Tun: conf.Tun{TunOS: conf.TunOS{BlockQUIC: c.val}}}
		if got := blockQUICEnabled(); got != c.want {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
