package conf

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v2"
)

// TestModeTcpcopyNormalize 确认 mode: tcpcopy 经 LoadRouterConfig 归一为 tcpcopy.enable,
// 且旧的 tcpcopy.enable 仍生效(消费方只看 Enable)。
func TestModeTcpcopyNormalize(t *testing.T) {
	write := func(y string) string {
		p := filepath.Join(t.TempDir(), "router.yaml")
		if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 新写法: mode: tcpcopy → Enable 应被归一为 true
	r, err := LoadRouterConfig(write("mode: tcpcopy\ntcpcopy:\n  ip: 10.0.0.2\n  port: 3306\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.TcpCopy.Enable || r.TcpCopy.IP != "10.0.0.2" || r.TcpCopy.Port != 3306 {
		t.Fatalf("mode:tcpcopy not normalized: %+v", r.TcpCopy)
	}

	// 旧写法: tcpcopy.enable: true 仍然生效
	r2, err := LoadRouterConfig(write("tcpcopy:\n  enable: true\n  ip: 1.2.3.4\n  port: 80\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !r2.TcpCopy.Enable {
		t.Fatalf("legacy tcpcopy.enable lost: %+v", r2.TcpCopy)
	}

	// 非 tcpcopy 模式: Enable 保持 false
	r3, err := LoadRouterConfig(write("mode: proxy\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r3.TcpCopy.Enable {
		t.Fatalf("proxy mode should not enable tcpcopy")
	}
}

// TestTunFlatConfig 确认旧的扁平写法(向后兼容)仍能正确解析到内嵌 TunOS 字段。
// inline 内嵌一旦失效, 存量配置会静默丢失, 故此测试是回归护栏。
func TestTunFlatConfig(t *testing.T) {
	y := `
tun:
  name: anytun0
  addr: 10.9.0.1/24
  mtu: 1500
  bypassIPs:
    - 203.0.113.10
  excludeProcs:
    - openvpn.exe
`
	var r Router
	if err := yaml.Unmarshal([]byte(y), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	r.Tun.applyOS("linux") // 无系统块, 应保持扁平值不变
	if r.Tun.Name != "anytun0" || r.Tun.Addr != "10.9.0.1/24" || r.Tun.MTU != 1500 {
		t.Fatalf("flat inline fields lost: %+v", r.Tun.TunOS)
	}
	if len(r.Tun.BypassIPs) != 1 || r.Tun.BypassIPs[0] != "203.0.113.10" {
		t.Fatalf("flat bypassIPs lost: %v", r.Tun.BypassIPs)
	}
	if len(r.Tun.ExcludeProcs) != 1 || r.Tun.ExcludeProcs[0] != "openvpn.exe" {
		t.Fatalf("flat excludeProcs lost: %v", r.Tun.ExcludeProcs)
	}
}

// TestTunPerOSConfig 确认按系统分块 + applyOS 整块覆盖生效, 且不同系统各取各块。
func TestTunPerOSConfig(t *testing.T) {
	y := `
tun:
  addr: 10.0.0.1/24            # 扁平默认(无对应系统块时才用)
  linux:
    addr: 10.9.0.1/24
    bypassIPs:
      - 1.1.1.1
  windows:
    excludeProcs:
      - openvpn.exe
    bypassIPs:
      - 2.2.2.2
`
	load := func() Router {
		var r Router
		if err := yaml.Unmarshal([]byte(y), &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return r
	}

	// linux: 取 linux 块
	rl := load()
	rl.Tun.applyOS("linux")
	if rl.Tun.Addr != "10.9.0.1/24" {
		t.Fatalf("linux addr not from block: %q", rl.Tun.Addr)
	}
	if len(rl.Tun.BypassIPs) != 1 || rl.Tun.BypassIPs[0] != "1.1.1.1" {
		t.Fatalf("linux bypassIPs: %v", rl.Tun.BypassIPs)
	}

	// windows: 取 windows 块(不含 addr, 整块覆盖后 addr 应为空, 非扁平的 10.0.0.1)
	rw := load()
	rw.Tun.applyOS("windows")
	if rw.Tun.Addr != "" {
		t.Fatalf("windows block should fully replace flat; addr=%q", rw.Tun.Addr)
	}
	if len(rw.Tun.ExcludeProcs) != 1 || rw.Tun.ExcludeProcs[0] != "openvpn.exe" {
		t.Fatalf("windows excludeProcs: %v", rw.Tun.ExcludeProcs)
	}
	if len(rw.Tun.BypassIPs) != 1 || rw.Tun.BypassIPs[0] != "2.2.2.2" {
		t.Fatalf("windows bypassIPs: %v", rw.Tun.BypassIPs)
	}

	// darwin: 无 darwin 块, 回退扁平默认
	rd := load()
	rd.Tun.applyOS("darwin")
	if rd.Tun.Addr != "10.0.0.1/24" {
		t.Fatalf("darwin should fall back to flat; addr=%q", rd.Tun.Addr)
	}
}

// TestBypassConfig 确认 bypass 配置能正确解析(仅 Linux 支持, 写在 tun.linux 下,
// 经 applyOS("linux") 压平进 Tun 扁平字段供消费者读取)。
func TestBypassConfig(t *testing.T) {
	y := `
tun:
  linux:
    excludeNics:
      - anytun0
    device: eth0
`
	var r Router
	if err := yaml.Unmarshal([]byte(y), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	r.Tun.applyOS("linux")
	if len(r.Tun.ExcludeNics) != 1 || r.Tun.ExcludeNics[0] != "anytun0" {
		t.Fatalf("excludeNics lost: %v", r.Tun.ExcludeNics)
	}
	if r.Tun.Device != "eth0" {
		t.Fatalf("device lost: %q", r.Tun.Device)
	}
}
