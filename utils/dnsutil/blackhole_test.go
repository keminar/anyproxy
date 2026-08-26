package dnsutil

import (
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

// BlackholeIP 默认返回 192.0.0.0; 可自定义; off/none/disable 关闭(空串)。
func TestBlackholeIP(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want string
	}{
		{"nil config -> default", "\x00nil", defaultBlackholeIP}, // 特殊: 置空 RouterConfig
		{"unset -> default", "", defaultBlackholeIP},
		{"custom ip", "10.9.9.9", "10.9.9.9"},
		{"trim spaces", "  192.0.0.0  ", "192.0.0.0"},
		{"off", "off", ""},
		{"none upper", "NONE", ""},
		{"disable", "disable", ""},
	}
	for _, c := range cases {
		if c.cfg == "\x00nil" {
			conf.RouterConfig = nil
		} else {
			conf.RouterConfig = &conf.Router{Default: conf.Default{BlackholeIP: c.cfg}}
		}
		if got := BlackholeIP(); got != c.want {
			t.Fatalf("%s: BlackholeIP()=%q, want %q", c.name, got, c.want)
		}
	}
}

// IsBlackholeIP: 命中当前生效哨兵为 true; 空串/未命中/关闭时为 false。
func TestIsBlackholeIP(t *testing.T) {
	conf.RouterConfig = &conf.Router{} // 默认 192.0.0.0
	if !IsBlackholeIP("192.0.0.0") {
		t.Fatal("192.0.0.0 should be blackhole by default")
	}
	if IsBlackholeIP("192.0.0.1") {
		t.Fatal("192.0.0.1 should not be blackhole")
	}
	if IsBlackholeIP("") {
		t.Fatal("empty ip is never blackhole")
	}

	conf.RouterConfig = &conf.Router{Default: conf.Default{BlackholeIP: "off"}}
	if IsBlackholeIP("192.0.0.0") {
		t.Fatal("disabled: 192.0.0.0 should not be blackhole")
	}

	conf.RouterConfig = &conf.Router{Default: conf.Default{BlackholeIP: "10.9.9.9"}}
	if !IsBlackholeIP("10.9.9.9") {
		t.Fatal("custom blackhole 10.9.9.9 should match")
	}
	if IsBlackholeIP("192.0.0.0") {
		t.Fatal("custom set: 192.0.0.0 no longer blackhole")
	}
}
