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

// TestLoadRouterConfigToleratesFieldTypeErrors receive.allow 从旧版的纯 email 字符串
// 列表改成了 {email,uuid} 结构, 存量配置文件升级后这一个字段会解析失败(见
// utils/conf/uuid.go 上下文)——这不该拖累整个服务起不来: 出错的字段留空(=不生效,
// 不是"悄悄按旧值用"), 其余配置照常加载, LoadRouterConfig 只应打警告、不返回错误。
func TestLoadRouterConfigToleratesFieldTypeErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "router.yaml")
	y := "listen: :3000\n" +
		"websocket:\n" +
		"  client:\n" +
		"    connect: 1.2.3.4:3002\n" +
		"    email: a@example.com\n" +
		"    receive:\n" +
		"      dir: /tmp\n" +
		"      allow:\n" +
		"        - old-style-plain-email@example.com\n" // 旧格式, 解不进 AllowedSender
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := LoadRouterConfig(p)
	if err != nil {
		t.Fatalf("a field type error must not fail the whole load, got: %v", err)
	}
	if r.Listen != ":3000" {
		t.Fatalf("unrelated top-level field should still parse, got Listen=%q", r.Listen)
	}
	if r.Websocket.Client.Email != "a@example.com" {
		t.Fatalf("sibling fields in the same block should still parse, got Email=%q", r.Websocket.Client.Email)
	}
	if r.Websocket.Client.Receive.Dir != "/tmp" {
		t.Fatalf("sibling field receive.dir should still parse, got %q", r.Websocket.Client.Receive.Dir)
	}
	if len(r.Websocket.Client.Receive.Allow) != 0 {
		t.Fatalf("the malformed allow list should end up empty, not partially garbage: %+v", r.Websocket.Client.Receive.Allow)
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

// TestWebsocketClientList 确认 Websocket.ClientList() 的合并/回退逻辑:
// 配了 clients 就用 clients(忽略旧 client); 只配旧 client 时回退为单元素列表;
// 都不配(或旧 client.connect 为空)时返回空, 不应凭空多出一条要连接的 server。
func TestWebsocketClientList(t *testing.T) {
	cA := WsClient{Connect: "a:1", Email: "a"}
	cB := WsClient{Connect: "b:2", Email: "b"}
	legacy := WsClient{Connect: "legacy:3", Email: "legacy"}

	// 只配 clients
	w := Websocket{Clients: []WsClient{cA, cB}}
	got := w.ClientList()
	if len(got) != 2 || got[0].Connect != "a:1" || got[1].Connect != "b:2" {
		t.Fatalf("clients-only: %+v", got)
	}

	// 只配旧 client
	w = Websocket{Client: legacy}
	got = w.ClientList()
	if len(got) != 1 || got[0].Connect != "legacy:3" {
		t.Fatalf("legacy-only: %+v", got)
	}

	// 两者都配: 以 clients 为准
	w = Websocket{Client: legacy, Clients: []WsClient{cA}}
	got = w.ClientList()
	if len(got) != 1 || got[0].Connect != "a:1" {
		t.Fatalf("clients should win over legacy client: %+v", got)
	}

	// 都不配
	w = Websocket{}
	got = w.ClientList()
	if len(got) != 0 {
		t.Fatalf("expected empty list, got: %+v", got)
	}
}

// TestWsServerLookupUser 确认 WsServer.LookupUser 的多用户查找与停用逻辑:
// disable=true 的账号能查到(found=true)但调用方应据此拒绝; 都不匹配或 user 为空返回 found=false。
func TestWsServerLookupUser(t *testing.T) {
	s := WsServer{
		Users: []ServerUser{
			{User: "alice", Pass: "alicepass"},
			{User: "bob", Pass: "bobpass", Disable: true},
		},
	}

	if u, ok := s.LookupUser("alice"); !ok || u.Pass != "alicepass" || u.Disable {
		t.Fatalf("alice: %+v ok=%v", u, ok)
	}
	// 停用的账号: 查得到, 但 Disable=true, 由调用方拒绝
	if u, ok := s.LookupUser("bob"); !ok || u.Pass != "bobpass" || !u.Disable {
		t.Fatalf("bob: %+v ok=%v", u, ok)
	}
	// 未配置的 user
	if _, ok := s.LookupUser("nobody"); ok {
		t.Fatalf("nobody should not match")
	}
	// 空 user
	if _, ok := s.LookupUser(""); ok {
		t.Fatalf("empty user should not match")
	}
}

// TestWsClientWantsPersistentConnect 常驻进程该不该为一条 client 配置发起连接:
// subscribe/forward/direct/directAccept/receive.dir 任意一项非空就该连(服务端也会
// 因为同一项放行空订阅, 见 nat/conn.go emptySubscribeAllowed); 全空则不该连——连了
// 也只会被服务端一直拒绝。SendRecvOnly 是显式的强制跳过, 不管其它项配没配都优先生效。
func TestWsClientWantsPersistentConnect(t *testing.T) {
	cases := []struct {
		name string
		c    WsClient
		want bool
	}{
		{"nothing configured", WsClient{}, false},
		{"subscribe", WsClient{Subscribe: []Subscribe{{Key: "k", Val: "v"}}}, true},
		{"forward", WsClient{Forward: []ClientForward{{Port: 22, Target: "127.0.0.1:22"}}}, true},
		{"direct rule", WsClient{Direct: []ClientDirect{{Listen: ":1", Email: "a@example.com", Port: 1}}}, true},
		{"directAccept", WsClient{DirectAccept: true}, true},
		{"receive.dir", WsClient{Receive: ClientReceive{Dir: "/data"}}, true},
		{"sendRecvOnly alone", WsClient{SendRecvOnly: true}, false},
		{"sendRecvOnly overrides forward", WsClient{SendRecvOnly: true, Forward: []ClientForward{{Port: 22, Target: "127.0.0.1:22"}}}, false},
		{"sendRecvOnly overrides receive.dir", WsClient{SendRecvOnly: true, Receive: ClientReceive{Dir: "/data"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.c.WantsPersistentConnect(); got != c.want {
				t.Errorf("WantsPersistentConnect() = %v, want %v", got, c.want)
			}
		})
	}
}
