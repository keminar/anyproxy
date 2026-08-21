package nat

import (
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

// TestBuildForward 确认 Port==0 或 Target=="" 的规则被过滤, 不进最终映射;
// 这是从原全局 SetLocalForward 提炼出的纯函数, 每条 server 连接各自调用一份。
func TestBuildForward(t *testing.T) {
	rules := []conf.ClientForward{
		{Port: 2222, Target: "127.0.0.1:22"},
		{Port: 0, Target: "127.0.0.1:80"}, // Port 为 0, 应被过滤
		{Port: 3389, Target: ""},          // Target 为空, 应被过滤
		{Port: 3306, Target: "10.0.0.1:3306"},
	}
	m := buildForward(rules)
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(m), m)
	}
	if m[2222] != "127.0.0.1:22" || m[3306] != "10.0.0.1:3306" {
		t.Fatalf("unexpected map content: %+v", m)
	}
	if _, ok := m[0]; ok {
		t.Fatalf("port 0 should be filtered")
	}
	if _, ok := m[3389]; ok {
		t.Fatalf("empty target should be filtered")
	}
}
