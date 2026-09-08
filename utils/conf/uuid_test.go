package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureClientUUIDGeneratesAndPersists 没配 uuid 时要自动生成一个, 且写到配置
// 文件同目录的状态文件里——不这样的话每次重启身份都不一样, 对端 receive.allow 就
// 没法配(见 conf.WsClient.UUID 的注释)。
func TestEnsureClientUUIDGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")

	w := &Websocket{Client: WsClient{Connect: "1.2.3.4:3002"}}
	if err := ensureClientUUID(cfgPath, w); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if w.Client.UUID == "" {
		t.Fatal("a uuid should have been generated")
	}

	statePath := clientUUIDStateFile(cfgPath)
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("state file not written: %v", err)
	}
	if string(data) != w.Client.UUID+"\n" {
		t.Fatalf("state file content %q does not match generated uuid %q", data, w.Client.UUID)
	}
}

// TestEnsureClientUUIDStableAcrossReloads 重启(或热加载)不能换一个新 uuid——那样
// 对端配置的 receive.allow 就跟着失效了。
func TestEnsureClientUUIDStableAcrossReloads(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")

	w1 := &Websocket{Client: WsClient{Connect: "1.2.3.4:3002"}}
	if err := ensureClientUUID(cfgPath, w1); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	w2 := &Websocket{Client: WsClient{Connect: "1.2.3.4:3002"}}
	if err := ensureClientUUID(cfgPath, w2); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if w1.Client.UUID != w2.Client.UUID {
		t.Fatalf("uuid changed across reloads: %q vs %q", w1.Client.UUID, w2.Client.UUID)
	}
}

// TestEnsureClientUUIDRespectsExplicitConfig 显式配了 uuid 就不能被覆盖, 也不该去
// 碰状态文件。
func TestEnsureClientUUIDRespectsExplicitConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")

	w := &Websocket{Client: WsClient{Connect: "1.2.3.4:3002", UUID: "manually-pinned-uuid"}}
	if err := ensureClientUUID(cfgPath, w); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if w.Client.UUID != "manually-pinned-uuid" {
		t.Fatalf("explicit uuid was overwritten: %q", w.Client.UUID)
	}
	if _, err := os.Stat(clientUUIDStateFile(cfgPath)); !os.IsNotExist(err) {
		t.Fatal("state file should not be created when uuid is already configured")
	}
}

// TestEnsureClientUUIDSharedAcrossClients 同一份配置文件下的多个 client 块(见
// Websocket.Clients)代表的是同一台机器, 该共用同一个生成出来的 uuid。
func TestEnsureClientUUIDSharedAcrossClients(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")

	w := &Websocket{Clients: []WsClient{
		{Connect: "1.2.3.4:3002"},
		{Connect: "5.6.7.8:3002", UUID: "pinned-for-this-one"},
		{Connect: "9.9.9.9:3002"},
	}}
	if err := ensureClientUUID(cfgPath, w); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if w.Clients[0].UUID == "" || w.Clients[2].UUID == "" {
		t.Fatal("empty uuid client blocks should have been filled in")
	}
	if w.Clients[0].UUID != w.Clients[2].UUID {
		t.Fatalf("client blocks without an explicit uuid should share one: %q vs %q", w.Clients[0].UUID, w.Clients[2].UUID)
	}
	if w.Clients[1].UUID != "pinned-for-this-one" {
		t.Fatalf("an explicitly configured uuid must not be touched, got %q", w.Clients[1].UUID)
	}
}

// TestEnsureClientUUIDNoopWithoutClient 没配 websocket.client(s) 时不该生成任何东西
// (纯服务端部署不需要 uuid, 不该无端在磁盘上留一个状态文件)。
func TestEnsureClientUUIDNoopWithoutClient(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")

	w := &Websocket{}
	if err := ensureClientUUID(cfgPath, w); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := os.Stat(clientUUIDStateFile(cfgPath)); !os.IsNotExist(err) {
		t.Fatal("no state file should be created without a configured client")
	}
}

// TestEnsureClientUUIDIndependentAcrossConfigFiles -c 指向不同的配置文件, 哪怕在
// 同一目录下, 也必须各自生成独立的 uuid——身份是按配置文件分的, 不是按目录/机器分
// 的, 不然同一目录下跑两份配置(比如两个 profile)会意外共用同一个身份。
func TestEnsureClientUUIDIndependentAcrossConfigFiles(t *testing.T) {
	dir := t.TempDir()
	officePath := filepath.Join(dir, "office.yaml")
	homePath := filepath.Join(dir, "home.yaml")

	office := &Websocket{Client: WsClient{Connect: "1.2.3.4:3002"}}
	if err := ensureClientUUID(officePath, office); err != nil {
		t.Fatalf("ensure office: %v", err)
	}
	home := &Websocket{Client: WsClient{Connect: "5.6.7.8:3002"}}
	if err := ensureClientUUID(homePath, home); err != nil {
		t.Fatalf("ensure home: %v", err)
	}

	if office.Client.UUID == home.Client.UUID {
		t.Fatalf("different -c config files must not share the same uuid, both got %q", office.Client.UUID)
	}
	if got := clientUUIDStateFile(officePath); got != filepath.Join(dir, ".office.uuid") {
		t.Fatalf("state file for office.yaml = %q, want .office.uuid alongside it", got)
	}
	if got := clientUUIDStateFile(homePath); got != filepath.Join(dir, ".home.uuid") {
		t.Fatalf("state file for home.yaml = %q, want .home.uuid alongside it", got)
	}
}

// TestClientUUIDStateFileIsHidden 状态文件是程序自己维护的东西, 不该混在 conf/ 里
// 看着像一份配置, 名字要带点前缀。
func TestClientUUIDStateFileIsHidden(t *testing.T) {
	dir := t.TempDir()
	got := clientUUIDStateFile(filepath.Join(dir, "router.yaml"))
	if want := filepath.Join(dir, ".router.uuid"); got != want {
		t.Fatalf("state file = %q, want %q", got, want)
	}
}

// TestEnsureClientUUIDMigratesLegacyFile 老机器上已经有一个不带点前缀的 router.uuid,
// 升级后必须沿用里面的值——重新生成一个等于换身份, 对端 receive.allow 里配的全失效。
func TestEnsureClientUUIDMigratesLegacyFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")
	const old = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	legacy := legacyUUIDStateFile(cfgPath)
	if err := os.WriteFile(legacy, []byte(old+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := &Websocket{Client: WsClient{Connect: "1.2.3.4:3002"}}
	if err := ensureClientUUID(cfgPath, w); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if w.Client.UUID != old {
		t.Fatalf("uuid = %q, want the legacy one %q", w.Client.UUID, old)
	}
	// 迁移过去了就不该在原地再留一份: 两个文件并存的话, 以后谁改了哪个都说不清。
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("legacy state file should have been moved away, stat err = %v", err)
	}
	data, err := os.ReadFile(clientUUIDStateFile(cfgPath))
	if err != nil {
		t.Fatalf("hidden state file not present after migration: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != old {
		t.Fatalf("hidden state file content = %q, want %q", got, old)
	}
}

// TestEnsureClientUUIDPrefersHiddenFile 两个文件都在时以新的隐藏文件为准(比如迁移
// 之后有人又手工放回来一个旧文件), 不能被旧值顶掉。
func TestEnsureClientUUIDPrefersHiddenFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")
	const current = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	const stale = "11111111-2222-4333-8444-555555555555"
	if err := os.WriteFile(clientUUIDStateFile(cfgPath), []byte(current+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyUUIDStateFile(cfgPath), []byte(stale+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := &Websocket{Client: WsClient{Connect: "1.2.3.4:3002"}}
	if err := ensureClientUUID(cfgPath, w); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if w.Client.UUID != current {
		t.Fatalf("uuid = %q, want the hidden file's %q", w.Client.UUID, current)
	}
}

// TestLoadRouterConfigIgnoresConfiguredUUID client.uuid 没有 yaml 标签, 配置文件里
// 写了也不能生效——不然改一次配置就能顶替掉持久化的身份, 破坏"重启不变"这个前提。
func TestLoadRouterConfigIgnoresConfiguredUUID(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")
	y := "websocket:\n" +
		"  client:\n" +
		"    connect: 1.2.3.4:3002\n" +
		"    uuid: attacker-supplied-uuid\n"
	if err := os.WriteFile(cfgPath, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := LoadRouterConfig(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if r.Websocket.Client.UUID == "attacker-supplied-uuid" {
		t.Fatal("uuid written in the config file must be ignored, not honored")
	}
	if r.Websocket.Client.UUID == "" {
		t.Fatal("a uuid should still have been auto-generated")
	}
}

// TestIsValidUUID 覆盖文件传输(nat/file.go、nat/file_relay.go)在使用一个 uuid 之前
// 会遇到的几类输入: 合法生成值本身、大小写混排、空值、格式明显不对的字符串。
func TestIsValidUUID(t *testing.T) {
	valid := []string{
		"3fa85f64-5717-4562-b3fc-2c963f66afa6",
		"3FA85F64-5717-4562-B3FC-2C963F66AFA6",
	}
	for _, s := range valid {
		if !IsValidUUID(s) {
			t.Errorf("IsValidUUID(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"not-a-real-uuid",
		"3fa85f64571745 62b3fc2c963f66afa6",     // 少了连字符
		"3fa85f64-5717-4562-b3fc-2c963f66afa6x", // 多一个字符
		"3fa85f64-5717-4562-b3fc-2c963f66afa",   // 少一个字符
		"gggggggg-5717-4562-b3fc-2c963f66afa6",  // 非法十六进制字符
		"3fa85f64_5717_4562_b3fc_2c963f66afa6",  // 分隔符不对
	}
	for _, s := range invalid {
		if IsValidUUID(s) {
			t.Errorf("IsValidUUID(%q) = true, want false", s)
		}
	}

	if id, err := newUUID(); err != nil {
		t.Fatalf("newUUID: %v", err)
	} else if !IsValidUUID(id) {
		t.Errorf("a freshly generated uuid %q must itself be considered valid", id)
	}
}

func TestNewUUIDLooksLikeUUID(t *testing.T) {
	id, err := newUUID()
	if err != nil {
		t.Fatalf("newUUID: %v", err)
	}
	// 8-4-4-4-12 十六进制分段, 用长度粗略校验格式(不追求完整校验版本/变体位)。
	if len(id) != 36 {
		t.Fatalf("unexpected uuid format: %q", id)
	}
	id2, err := newUUID()
	if err != nil {
		t.Fatalf("newUUID: %v", err)
	}
	if id == id2 {
		t.Fatal("two generated uuids must not collide in practice")
	}
}
