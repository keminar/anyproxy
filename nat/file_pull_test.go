package nat

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

// pullTestPair 起一条内存管道: c 那头跑 servePull, 返回 a 那头供测试直接说话。
// net.Pipe 的两端天然满足 fileConn(Read/Write/Close/SetReadDeadline)。
func pullTestPair(t *testing.T, cfg conf.ClientReceive) net.Conn {
	t.Helper()
	aSide, cSide := net.Pipe()
	go func() {
		defer cSide.Close()
		servePull(cSide, cfg, "a@example.com", "test", func(string, ...interface{}) {})
	}()
	t.Cleanup(func() { aSide.Close() })
	return aSide
}

// pullTestDir 造一个共享目录: backup/db.sql 与 backup/sub/x.log。
func pullTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "backup", "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for rel, body := range map[string]string{
		filepath.Join("backup", "db.sql"):       "create table t;",
		filepath.Join("backup", "sub", "x.log"): "hello",
		"loose.txt":                             "top level",
	} {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return dir
}

// 取一个目录: 清单要把子目录递归展开, Name 以被取的目录本身为根(与 -send 发目录的
// 相对名口径一致), Path 则相对共享目录根 —— 两者必须分开, 否则取回来的结构会错位。
func TestServePullListsDirectory(t *testing.T) {
	dir := pullTestDir(t)
	conn := pullTestPair(t, conf.ClientReceive{Dir: dir})

	entries, err := pullList(conn, "backup")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := map[string]string{} // Name -> Path
	for _, e := range entries {
		got[e.Name] = e.Path
		if e.Size <= 0 {
			t.Errorf("entry %s has size %d", e.Name, e.Size)
		}
	}
	want := map[string]string{
		"backup/db.sql":    "backup/db.sql",
		"backup/sub/x.log": "backup/sub/x.log",
	}
	if len(got) != len(want) {
		t.Fatalf("listed %v, want %v", got, want)
	}
	for name, path := range want {
		if got[name] != path {
			t.Errorf("entry %q has path %q, want %q", name, got[name], path)
		}
	}
}

// 取单个文件: Name 只有文件名本身(存到 -to 目录下就叫这个), 不带它在对端的目录前缀。
func TestServePullListsSingleFile(t *testing.T) {
	dir := pullTestDir(t)
	conn := pullTestPair(t, conf.ClientReceive{Dir: dir})

	entries, err := pullList(conn, "backup/db.sql")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("listed %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Name != "db.sql" || entries[0].Path != "backup/db.sql" {
		t.Fatalf("got name=%q path=%q, want name=db.sql path=backup/db.sql", entries[0].Name, entries[0].Path)
	}
}

// 端到端(不含网络): list 出来的每一条都能 get 回来, 内容一致。
func TestServePullGetsFile(t *testing.T) {
	dir := pullTestDir(t)
	local := t.TempDir()

	e := filePullEntry{Path: "backup/sub/x.log", Name: "backup/sub/x.log", Size: 5}
	conn := pullTestPair(t, conf.ClientReceive{Dir: dir})
	saved, err := pullFile(conn, local, e, "c@example.com", "test", func(string, ...interface{}) {}, nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if saved != "backup/sub/x.log" {
		t.Fatalf("saved as %q", saved)
	}
	got, err := os.ReadFile(filepath.Join(local, "backup", "sub", "x.log"))
	if err != nil {
		t.Fatalf("read fetched: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("fetched %q, want %q", got, "hello")
	}
}

// 没配 receive.dir 就一律不给取 —— 与"没配 dir 就一律拒收"是同一条规则的两面。
func TestServePullRefusedWhenNoDir(t *testing.T) {
	conn := pullTestPair(t, conf.ClientReceive{})
	_, err := pullList(conn, "anything")
	if err == nil || !strings.Contains(err.Error(), "receive.dir") {
		t.Fatalf("want a receive.dir complaint, got %v", err)
	}
}

// 路径穿越: 名字是对端说了算的, 拒绝要发生在读文件之前。
func TestServePullRejectsEscapes(t *testing.T) {
	dir := pullTestDir(t)
	secret := filepath.Join(filepath.Dir(dir), "outside.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	t.Cleanup(func() { os.Remove(secret) })

	for _, bad := range []string{"../outside.txt", "backup/../../outside.txt", "/etc/passwd", `back\slash`} {
		conn := pullTestPair(t, conf.ClientReceive{Dir: dir})
		if _, err := pullList(conn, bad); err == nil {
			t.Errorf("path %q was accepted, it must be rejected", bad)
		}
	}
}

// 符号链接是读方向独有的坑: 拼出来的路径确实在共享目录内, 光靠 safeJoin 那套字符串
// 检查拦不住, 一取就把目录外的东西送出去了。写方向没这个问题(写的是新文件), 所以
// 这道防线只在 resolveShared 里, 也只有这条用例盖得住。
func TestServePullRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra privileges on Windows")
	}
	dir := pullTestDir(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	link := filepath.Join(dir, "escape.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	conn := pullTestPair(t, conf.ClientReceive{Dir: dir})
	if _, err := pullList(conn, "escape.txt"); err == nil {
		t.Fatal("a symlink pointing outside the shared directory must not be readable")
	}
}

// 共享目录本身经由符号链接是完全正常的配置(macOS 的 /tmp -> /private/tmp 就是),
// 不能被 EvalSymlinks 那道检查误判成越界。
func TestServePullAllowsSymlinkedShareRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra privileges on Windows")
	}
	real := pullTestDir(t)
	link := filepath.Join(t.TempDir(), "shared")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	conn := pullTestPair(t, conf.ClientReceive{Dir: link})
	entries, err := pullList(conn, "backup/db.sql")
	if err != nil {
		t.Fatalf("a symlinked share root must work: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("listed %d entries, want 1", len(entries))
	}
}

// 目录不能直接 get: 要先 list 再逐个取。混淆了的话对端会收到一个内容是垃圾的"文件"。
func TestServePullGetRejectsDirectory(t *testing.T) {
	dir := pullTestDir(t)
	conn := pullTestPair(t, conf.ClientReceive{Dir: dir})
	e := filePullEntry{Path: "backup", Name: "backup"}
	if _, err := pullFile(conn, t.TempDir(), e, "c@example.com", "test", func(string, ...interface{}) {}, nil); err == nil {
		t.Fatal("getting a directory must fail, it has to be listed first")
	}
}

// 回给对端的错误里不能带本机的绝对路径: 取文件的人没有理由知道那个目录在对面叫
// 什么。系统调用的错误(lstat /srv/data/x: no such file)最容易顺手带出去, 所以这条
// 用例把几种"取不到"的情况都过一遍。
func TestServePullErrorsDoNotLeakLocalPaths(t *testing.T) {
	dir := pullTestDir(t)
	for _, bad := range []string{"nope", "backup/nope", "../outside"} {
		conn := pullTestPair(t, conf.ClientReceive{Dir: dir})
		_, err := pullList(conn, bad)
		if err == nil {
			t.Errorf("path %q should have failed", bad)
			continue
		}
		if strings.Contains(err.Error(), dir) {
			t.Errorf("path %q: error leaks the peer's local directory: %v", bad, err)
		}
	}
	// get 那条分支是另一段代码, 单独走一遍。
	conn := pullTestPair(t, conf.ClientReceive{Dir: dir})
	_, err := pullFile(conn, t.TempDir(), filePullEntry{Path: "gone.txt", Name: "gone.txt"},
		"c@example.com", "test", func(string, ...interface{}) {}, nil)
	if err == nil {
		t.Fatal("getting a missing file should have failed")
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatalf("get error leaks the peer's local directory: %v", err)
	}
}

// 不认识的 op 要明确拒绝, 而不是当成默认动作处理 —— 版本不匹配时那会静默地做错事。
func TestServePullRejectsUnknownOp(t *testing.T) {
	dir := pullTestDir(t)
	conn := pullTestPair(t, conf.ClientReceive{Dir: dir})
	if err := writeFrame(conn, filePullReq{Op: "delete", Path: "backup"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var resp filePullResp
	if err := readPullFrame(conn, &resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(resp.Err, "unknown pull op") {
		t.Fatalf("got %q, want an unknown-op rejection", resp.Err)
	}
}
