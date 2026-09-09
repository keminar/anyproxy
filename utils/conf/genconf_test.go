package conf

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 模板是手写的 YAML 文本, 最容易出的错就是缩进/引号写错却没人发现 —— 直到用户在新
// 机器上拿它启动才炸。这里对每个模式都走一遍真实的加载路径, 确保生成的东西能解析,
// 且关键字段解出来的值和模板里写的一致。
func TestGenerateConfigLoadable(t *testing.T) {
	for _, mode := range GenModes {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "router.yaml")
			got, err := WriteConfigTemplate(mode, path)
			if err != nil {
				t.Fatalf("WriteConfigTemplate: %v", err)
			}
			if got != path {
				t.Fatalf("path = %s, want %s", got, path)
			}
			cnf, err := LoadRouterConfig(path)
			if err != nil {
				t.Fatalf("LoadRouterConfig: %v", err)
			}
			if cnf.Mode != mode {
				t.Errorf("mode = %q, want %q", cnf.Mode, mode)
			}
			if !cnf.Watcher {
				t.Error("watcher = false, want true")
			}
			if len(cnf.Token) != 16 {
				t.Errorf("token = %q, len %d, want 16", cnf.Token, len(cnf.Token))
			}
			if cnf.Listen == "" {
				t.Error("listen is empty")
			}
			switch mode {
			case "tcpcopy":
				// mode: tcpcopy 会被归一成 tcpcopy.enable, 且必须给出转发目标, 否则这个模式没意义
				if !cnf.TcpCopy.Enable || cnf.TcpCopy.IP == "" || cnf.TcpCopy.Port == 0 {
					t.Errorf("tcpcopy = %+v, want enabled with ip/port", cnf.TcpCopy)
				}
			case "tun":
				// tun 块按系统分块写, genTunBlock 只生成运行 -genconf 时所在系统(这里就是
				// 跑测试的系统)的那一块, applyOS 后同一系统的字段应已压平出来
				if cnf.Tun.BlockQUIC == nil || !*cnf.Tun.BlockQUIC {
					t.Errorf("tun.blockQUIC = %v, want true after applyOS", cnf.Tun.BlockQUIC)
				}
			}
		})
	}
}

// 模板里注释掉的示例块(hosts/forward/receive 等)必须真的是注释: 一旦缩进写错让它们
// 生效了, 新机器一起来就会带上一堆没人想要的规则。
func TestGenerateConfigExamplesStayCommented(t *testing.T) {
	for _, mode := range GenModes {
		path := filepath.Join(t.TempDir(), "router.yaml")
		if _, err := WriteConfigTemplate(mode, path); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		cnf, err := LoadRouterConfig(path)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if len(cnf.Hosts) != 0 {
			t.Errorf("%s: hosts = %+v, want none active", mode, cnf.Hosts)
		}
		if len(cnf.AllowIP) != 0 {
			t.Errorf("%s: allowIP = %v, want none active", mode, cnf.AllowIP)
		}
		if cnf.Websocket.Server.Listen != "" || len(cnf.Websocket.Server.Users) != 0 {
			t.Errorf("%s: websocket.server should stay empty, got %+v", mode, cnf.Websocket.Server)
		}
		if cnf.Websocket.Client.Connect != "" || len(cnf.Websocket.Client.Forward) != 0 {
			t.Errorf("%s: websocket.client should stay empty, got %+v", mode, cnf.Websocket.Client)
		}
		if len(cnf.GeoIP) != 0 || len(cnf.GeoSite) != 0 {
			t.Errorf("%s: geo files should stay commented, got %v %v", mode, cnf.GeoIP, cnf.GeoSite)
		}
	}
}

// 已存在的文件绝不覆盖 —— 这个命令是"新机器初始化", 手滑冲掉在跑的配置的代价太大。
func TestWriteConfigTemplateNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "router.yaml")
	if err := os.WriteFile(path, []byte("listen: :3000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteConfigTemplate("proxy", path); err == nil {
		t.Fatal("want error when file exists, got nil")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "listen: :3000\n" {
		t.Fatalf("existing file was modified: %q", data)
	}
}

// TestGenerateConfigShowsBothWebsocketRoles websocket.server(服务端角色)和
// websocket.client(订阅端角色)跟 -mode 没有从属关系(任何 mode 都能独立开启任意一个,
// 见 genWebsocket 的注释), 模板必须两个角色都给出示例——不管 -mode 是什么, 用户都
// 该能在生成的文件里看到 websocket.server 长什么样, 哪怕它对应的角色暂时是注释掉的。
func TestGenerateConfigShowsBothWebsocketRoles(t *testing.T) {
	cases := []struct {
		mode         string
		activeRole   string // 该 mode 下生效的角色行, 不带注释
		inactiveRole string // 该 mode 下示例但注释掉的角色行
	}{
		{"proxy", "  client:", "  #server:"},
		{"tun", "  client:", "  #server:"},
		{"tunnel", "  server:", "  #client:"},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			body, err := GenerateConfig(c.mode)
			if err != nil {
				t.Fatalf("GenerateConfig(%s): %v", c.mode, err)
			}
			if !strings.Contains(body, c.activeRole+"\n") {
				t.Errorf("%s: missing active role line %q in:\n%s", c.mode, c.activeRole, body)
			}
			if !strings.Contains(body, c.inactiveRole+"\n") {
				t.Errorf("%s: missing commented-out example for the other role (%q) in:\n%s", c.mode, c.inactiveRole, body)
			}
		})
	}
	// bypass/tcpcopy 不涉及 websocket, 两个角色都不该出现。
	for _, mode := range []string{"bypass", "tcpcopy"} {
		body, err := GenerateConfig(mode)
		if err != nil {
			t.Fatalf("GenerateConfig(%s): %v", mode, err)
		}
		if strings.Contains(body, "websocket:") {
			t.Errorf("%s: should not mention websocket at all, got:\n%s", mode, body)
		}
	}
}

// TestCommentOutBlock 逐行在原有缩进后插入 "#", 空行原样保留、不强行补注释符。
func TestCommentOutBlock(t *testing.T) {
	in := "  server:\n    listen:\n\n    users:\n"
	want := "  #server:\n    #listen:\n\n    #users:\n"
	if got := commentOutBlock(in); got != want {
		t.Errorf("commentOutBlock(%q) = %q, want %q", in, got, want)
	}
}

// TestGenTunBlockOnlyCurrentOS 生成配置的机器和最终运行的机器通常是同一台, 三个
// 系统块里另外两个在这台机器上永远不会生效, 堆进模板只会让人误以为都要填。
// genTunBlock 必须只给出 runtime.GOOS 对应的那一块。
func TestGenTunBlockOnlyCurrentOS(t *testing.T) {
	all := map[string]string{"linux": "  linux:", "darwin": "  darwin:", "windows": "  windows:"}
	want, known := all[runtime.GOOS]
	if !known {
		t.Skipf("unrecognized runtime.GOOS %q, genTunBlock falls back to all three blocks; nothing OS-specific to assert here", runtime.GOOS)
	}
	got := genTunBlock()
	if !strings.Contains(got, want+"\n") {
		t.Errorf("genTunBlock() missing %q for the current OS, got:\n%s", want, got)
	}
	for os, line := range all {
		if os == runtime.GOOS {
			continue
		}
		if strings.Contains(got, line+"\n") {
			t.Errorf("genTunBlock() on %s should not include the %s block, got:\n%s", runtime.GOOS, os, got)
		}
	}
}

// TestGenModeBlockBypassOnlyOnLinux mode=bypass 本身仅 Linux 支持: 在其它系统上
// -genconf 不该生成一段这台机器永远用不上的 tun.linux 示例, 只留一句说明; 只有在
// Linux 上运行 -genconf 时才给出真正的 tun.linux 示例。
func TestGenModeBlockBypassOnlyOnLinux(t *testing.T) {
	got := genModeBlock("bypass")
	if runtime.GOOS == "linux" {
		if !strings.Contains(got, "tun:\n  linux:") {
			t.Errorf("on linux, genModeBlock(bypass) should include a tun.linux example, got:\n%s", got)
		}
		return
	}
	if strings.Contains(got, "tun:") {
		t.Errorf("on %s, genModeBlock(bypass) should not generate a tun block (bypass is Linux-only), got:\n%s", runtime.GOOS, got)
	}
	if !strings.Contains(got, runtime.GOOS) {
		t.Errorf("on %s, genModeBlock(bypass) should explain why there's nothing to generate, got:\n%s", runtime.GOOS, got)
	}
}

func TestGenerateConfigUnknownMode(t *testing.T) {
	if _, err := GenerateConfig("nosuchmode"); err == nil {
		t.Fatal("want error for unknown mode, got nil")
	}
	// 留空按 proxy 处理(与运行时 -mode 留空的默认一致)
	body, err := GenerateConfig("")
	if err != nil {
		t.Fatalf("empty mode: %v", err)
	}
	if !strings.Contains(body, "mode: proxy") {
		t.Error("empty mode should generate a proxy template")
	}
}
