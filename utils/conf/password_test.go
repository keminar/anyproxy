package conf

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsValidPass(t *testing.T) {
	valid := []string{
		"TestPassword1234567", // 19 位, 字母+数字都有
		"abcdefghijklmnopq1",  // 18 位, 刚好达标
		"密码需要英文和数字abc123456",  // 中文字符也算一个字符, 只要总数够且含英文字母/数字
	}
	for _, s := range valid {
		if !IsValidPass(s) {
			t.Errorf("IsValidPass(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"short1A",            // 位数不够
		"abcdefghijklmnopqr", // 18 位但没有数字
		"123456789012345678", // 18 位但没有字母
		"abcdefghijklmnopq",  // 17 位, 差一位
	}
	for _, s := range invalid {
		if IsValidPass(s) {
			t.Errorf("IsValidPass(%q) = true, want false", s)
		}
	}
}

// TestValidateServerUsersDisablesWeakPass 没配 key、密码又不达标(含没配密码)的账号
// 应该被自动停用; 配了 key 的账号、密码本身够强的账号、以及本来就已停用的账号都不
// 该被这一步改动。
func TestValidateServerUsersDisablesWeakPass(t *testing.T) {
	w := &Websocket{
		Server: WsServer{
			Users: []ServerUser{
				{User: "weak", Pass: "tooshort1"},
				{User: "empty"},
				{User: "strong", Pass: "TestPassword1234567"},
				{User: "keyed", Key: "somepubkey", Pass: "tooshort1"},
				{User: "already-disabled", Pass: "tooshort1", Disable: true},
			},
		},
	}
	validateServerUsers("router.yaml", w)

	get := func(user string) ServerUser {
		for _, u := range w.Server.Users {
			if u.User == user {
				return u
			}
		}
		t.Fatalf("user %s not found", user)
		return ServerUser{}
	}

	if !get("weak").Disable {
		t.Error("a user with a too-short/weak pass and no key must be disabled")
	}
	if !get("empty").Disable {
		t.Error("a user with neither key nor pass must be disabled")
	}
	if get("strong").Disable {
		t.Error("a user with a strong pass must not be disabled")
	}
	if get("keyed").Disable {
		t.Error("a user authenticating via key must not be disabled just because pass is weak")
	}
	if !get("already-disabled").Disable {
		t.Error("an already-disabled user must stay disabled")
	}
}

// TestLoadRouterConfigDisablesWeakServerPass 端到端: 从 yaml 加载一个密码太弱的账号,
// 加载完之后这个账号必须是 Disable=true, 不能悄悄放行。
func TestLoadRouterConfigDisablesWeakServerPass(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")
	y := "websocket:\n" +
		"  server:\n" +
		"    users:\n" +
		"      - user: weak\n" +
		"        pass: tooshort1\n" +
		"      - user: strong\n" +
		"        pass: TestPassword1234567\n"
	if err := os.WriteFile(cfgPath, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := LoadRouterConfig(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	weak, ok := r.Websocket.Server.LookupUser("weak")
	if !ok || !weak.Disable {
		t.Fatalf("weak password user must be disabled, got %+v ok=%v", weak, ok)
	}
	strong, ok := r.Websocket.Server.LookupUser("strong")
	if !ok || strong.Disable {
		t.Fatalf("strong password user must stay enabled, got %+v ok=%v", strong, ok)
	}
}

// captureLog 临时把标准 log 输出重定向到一个 buffer, 返回读取内容和还原函数;
// 用于断言某个只打日志、不改配置/不报错的校验确实打了(或没打)那行日志。
func captureLog(t *testing.T) (get func() string, restore func()) {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	return func() string { return buf.String() }, func() { log.SetOutput(orig) }
}

// TestWarnSendRecvOnlyReceive sendRecvOnly 让常驻进程跳过这条连接, 若同时配了
// receive.dir 就永远收不到文件——这个自相矛盾的组合必须被提示出来, 但不能阻断加载
// 或反过来悄悄改动用户的配置(既不清 sendRecvOnly 也不清 receive.dir)。
func TestWarnSendRecvOnlyReceive(t *testing.T) {
	cases := []struct {
		name    string
		w       *Websocket
		wantLog bool
	}{
		{
			name: "single client conflicting",
			w: &Websocket{Client: WsClient{
				Connect: "1.2.3.4:3002", SendRecvOnly: true,
				Receive: ClientReceive{Dir: "/data/incoming"},
			}},
			wantLog: true,
		},
		{
			name: "single client sendRecvOnly without receive, fine",
			w: &Websocket{Client: WsClient{
				Connect: "1.2.3.4:3002", SendRecvOnly: true,
			}},
			wantLog: false,
		},
		{
			name: "single client receive without sendRecvOnly, fine",
			w: &Websocket{Client: WsClient{
				Connect: "1.2.3.4:3002",
				Receive: ClientReceive{Dir: "/data/incoming"},
			}},
			wantLog: false,
		},
		{
			name: "clients[] entry conflicting",
			w: &Websocket{Clients: []WsClient{
				{Connect: "1.2.3.4:3002", SendRecvOnly: true, Receive: ClientReceive{Dir: "/data/incoming"}},
			}},
			wantLog: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			get, restore := captureLog(t)
			defer restore()
			before := *c.w
			warnSendRecvOnlyReceive("router.yaml", c.w)
			got := strings.Contains(get(), "sendRecvOnly")
			if got != c.wantLog {
				t.Errorf("log contains sendRecvOnly warning = %v, want %v (log: %s)", got, c.wantLog, get())
			}
			if c.w.Client.SendRecvOnly != before.Client.SendRecvOnly || c.w.Client.Receive.Dir != before.Client.Receive.Dir {
				t.Error("warnSendRecvOnlyReceive must not mutate the config, only log")
			}
		})
	}
}
