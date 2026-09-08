package nat

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// 测试里代替 client.uuid/receive.allow[].uuid 用的占位值: 现在使用前要过
// conf.IsValidUUID 这一关(见 nat/file.go、nat/file_relay.go), 不能再用 "uuid-a" 这种
// 一眼假的字符串, 得是合法的 8-4-4-4-12 格式——名字仍按角色/用途区分, 内容用重复的
// 十六进制字符拼出来, 方便一眼看出"这是哪一个", 同时在 nat 包内(本文件与
// file_relay_test.go)共用。
const (
	testUUIDA        = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testUUIDTrusted  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	testUUIDStranger = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	testUUIDReal     = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	testUUIDForged   = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

// 收文件最危险的一步就是文件名: 它完全由对端说了算。一个 "../../.ssh/authorized_keys"
// 就能写到接收目录外面去, 所以这条用例把各种越界写法都钉住。
func TestSafeJoinRejectsEscapes(t *testing.T) {
	dir := t.TempDir()
	bad := []string{
		"",
		"..",
		"../x",
		"a/../../x",
		"/etc/passwd",
		"/x",
		`..\x`,         // Windows 分隔符, 在 Linux 上是合法文件名字符, 一律不收
		`C:\Windows\x`, // 盘符
		"a/b/../../../x",
		"./../x",
	}
	for _, name := range bad {
		if got, err := safeJoin(dir, name); err == nil {
			t.Errorf("safeJoin(%q) should be rejected, got %q", name, got)
		}
	}

	good := map[string]string{
		"a.txt":     "a.txt",
		"sub/a.txt": filepath.Join("sub", "a.txt"),
		"./a.txt":   "a.txt",
		"a/b/c.txt": filepath.Join("a", "b", "c.txt"),
		"a/./b.txt": filepath.Join("a", "b.txt"),
	}
	for name, want := range good {
		got, err := safeJoin(dir, name)
		if err != nil {
			t.Errorf("safeJoin(%q): %v", name, err)
			continue
		}
		abs, _ := filepath.Abs(filepath.Join(dir, want))
		if got != abs {
			t.Errorf("safeJoin(%q) = %q, want %q", name, got, abs)
		}
	}
}

// 已存在的文件不能被悄悄覆盖 —— 那会毁掉收方已有的数据, 代价远大于多一个带序号的名字。
func TestUniquePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.zip")
	if got := uniquePath(p); got != p {
		t.Fatalf("a free name should be used as is, got %q", got)
	}
	os.WriteFile(p, []byte("old"), 0o644)
	got := uniquePath(p)
	if got != filepath.Join(dir, "x (1).zip") {
		t.Fatalf("got %q, want x (1).zip", got)
	}
	os.WriteFile(got, []byte("old"), 0o644)
	if got := uniquePath(p); got != filepath.Join(dir, "x (2).zip") {
		t.Fatalf("got %q, want x (2).zip", got)
	}
	// 原文件必须原封不动。
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatalf("the existing file was touched: %q", b)
	}
}

func TestCollectFiles(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "data", "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "data", "a.txt"), []byte("aaa"), 0o644)
	os.WriteFile(filepath.Join(dir, "data", "sub", "b.txt"), []byte("bb"), 0o644)
	os.WriteFile(filepath.Join(dir, "loose.bin"), []byte("x"), 0o644)

	// 单个文件: 相对名就是文件名本身。
	items, err := collectFiles([]string{filepath.Join(dir, "loose.bin")})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(items) != 1 || items[0].name != "loose.bin" || items[0].size != 1 {
		t.Fatalf("unexpected %+v", items)
	}

	// 目录: 递归进去, 相对名以该目录本身为根, 收端的结构跟这边一致。
	items, err = collectFiles([]string{filepath.Join(dir, "data")})
	if err != nil {
		t.Fatalf("collect dir: %v", err)
	}
	got := map[string]int64{}
	for _, it := range items {
		got[it.name] = it.size
	}
	want := map[string]int64{"data/a.txt": 3, "data/sub/b.txt": 2}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	if _, err := collectFiles([]string{filepath.Join(dir, "nope")}); err == nil {
		t.Fatal("a missing path should be an error, not a silent skip")
	}
}

// filePipe 把 writeIncoming 需要的那一段(首部之后的原始字节)喂进去。
func TestWriteIncomingChecksAndRenames(t *testing.T) {
	dir := t.TempDir()
	body := []byte("hello direct file transfer")
	dest := filepath.Join(dir, "a.txt")

	saved, sum, err := writeIncoming(dest, bytes.NewReader(body), fileHead{Name: "a.txt", Size: int64(len(body))})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if saved != dest {
		t.Fatalf("saved to %q, want %q", saved, dest)
	}
	want := sha256.Sum256(body)
	if sum != hex.EncodeToString(want[:]) {
		t.Fatalf("checksum mismatch")
	}
	if b, _ := os.ReadFile(saved); !bytes.Equal(b, body) {
		t.Fatalf("content mismatch")
	}
	// .part 不能留下来: 留着会让人以为还有一个没传完的文件。
	if _, err := os.Stat(dest + filePartSuffix); !os.IsNotExist(err) {
		t.Fatal("the .part file was left behind")
	}

	// 声称的长度比实际给的多 -> 必须报错, 且不留下半截文件。
	_, _, err = writeIncoming(filepath.Join(dir, "short.txt"), bytes.NewReader([]byte("ab")),
		fileHead{Name: "short.txt", Size: 100})
	if err == nil {
		t.Fatal("a truncated body should be rejected")
	}
	if _, err := os.Stat(filepath.Join(dir, "short.txt")); !os.IsNotExist(err) {
		t.Fatal("a truncated transfer must not leave a file behind")
	}

	// 对端谎报较小的长度并继续发 -> 只收下声称的那些字节, 不能被它一直写下去。
	long := bytes.Repeat([]byte("x"), 1000)
	saved, _, err = writeIncoming(filepath.Join(dir, "cap.bin"), bytes.NewReader(long),
		fileHead{Name: "cap.bin", Size: 10})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if fi, _ := os.Stat(saved); fi.Size() != 10 {
		t.Fatalf("wrote %d bytes, want exactly the announced 10", fi.Size())
	}
}

// 端到端: A 走真实的 QUIC 直连把文件发给 C, C 落盘并校验。
func TestFileTransferEndToEnd(t *testing.T) {
	recvDir := t.TempDir()
	srcDir := t.TempDir()

	// 一个够大的文件, 保证走满多次读写循环而不是一次 write 就完事。
	body := make([]byte, 3*1024*1024)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, body, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}}
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "a@example.com", testUUIDA

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-file"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	var lastProgress int64
	saved, err := a.sendFile(sess, items[0], func(n int64) { lastProgress = n })
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if saved != "payload.bin" {
		t.Fatalf("peer saved it as %q", saved)
	}
	if lastProgress != int64(len(body)) {
		t.Fatalf("progress ended at %d, want %d", lastProgress, len(body))
	}
	got, err := os.ReadFile(filepath.Join(recvDir, "payload.bin"))
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("received %d bytes, content differs from the %d sent", len(got), len(body))
	}
}

// 端到端: A 走真实的 QUIC 直连从 C 取一整个目录(-recv 的反向传输)。这条用例盖住的
// 是直连那一侧独有的部分 —— 新的 pull 流 Kind、复用的 fileAuth 身份校验, 以及"同一
// 条 QUIC 连接上开多条流"这个复用(清单一条, 每个文件各一条)。
func TestFilePullDirectEndToEnd(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(shareDir, "backup", "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// 一个够大的文件, 保证走满多次读写循环而不是一次 write 就完事。
	big := make([]byte, 3*1024*1024)
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := map[string][]byte{
		filepath.Join("backup", "big.bin"):      big,
		filepath.Join("backup", "sub", "x.log"): []byte("hello from sub"),
	}
	for rel, body := range want {
		if err := os.WriteFile(filepath.Join(shareDir, rel), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: shareDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}}
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "a@example.com", testUUIDA

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-pull"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	listConn, err := a.openPullStream(sess)
	if err != nil {
		t.Fatalf("open pull stream: %v", err)
	}
	entries, err := pullList(listConn, "backup")
	listConn.Close()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != len(want) {
		t.Fatalf("listed %d entries, want %d: %+v", len(entries), len(want), entries)
	}

	localDir := t.TempDir()
	logf := func(string, ...interface{}) {}
	var lastProgress int64
	for _, e := range entries {
		conn, err := a.openPullStream(sess)
		if err != nil {
			t.Fatalf("open pull stream for %s: %v", e.Name, err)
		}
		saved, err := pullFile(conn, localDir, e, "c@example.com", "test", logf,
			func(n int64) { lastProgress = n })
		conn.Close()
		if err != nil {
			t.Fatalf("get %s: %v", e.Name, err)
		}
		if saved != e.Name {
			t.Fatalf("fetched %s but saved it as %q", e.Name, saved)
		}
	}
	// 进度回调至少要跑到最后一个文件的大小; 不看等号是因为首部那几十个字节也被计进去
	// 之后会被 progressConn 截到 size 上。
	if lastProgress == 0 {
		t.Fatal("progress callback never fired")
	}

	for rel, body := range want {
		got, err := os.ReadFile(filepath.Join(localDir, rel))
		if err != nil {
			t.Fatalf("read fetched %s: %v", rel, err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("fetched %s: %d bytes, content differs from the %d shared", rel, len(got), len(body))
		}
	}
}

// readonly: true 的目录只出不进 —— 同一个对端、同一份 allow, 取得走文件, 但发不进来。
// 两件事要一起断言: 只测拒收的话, 一个把整个目录都关掉的实现也能过。
func TestFileReceiveReadOnlyServesButRefusesWrites(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "pkg.tar"), []byte("payload"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: shareDir, ReadOnly: true,
		Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}}
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "a@example.com", testUUIDA

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-readonly"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	// 取: 照常。
	localDir := t.TempDir()
	conn, err := a.openPullStream(sess)
	if err != nil {
		t.Fatalf("open pull stream: %v", err)
	}
	entries, err := pullList(conn, "pkg.tar")
	conn.Close()
	if err != nil {
		t.Fatalf("a read-only directory must still serve files: %v", err)
	}
	conn, err = a.openPullStream(sess)
	if err != nil {
		t.Fatalf("open pull stream: %v", err)
	}
	_, err = pullFile(conn, localDir, entries[0], "c@example.com", "test", func(string, ...interface{}) {}, nil)
	conn.Close()
	if err != nil {
		t.Fatalf("get from a read-only directory: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(localDir, "pkg.tar")); string(got) != "payload" {
		t.Fatalf("fetched %q, want %q", got, "payload")
	}

	// 发: 必须被拒, 且理由要指向配置而不是让人去查磁盘权限。
	src := filepath.Join(t.TempDir(), "unwanted.txt")
	if err := os.WriteFile(src, []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	items, err := collectFiles([]string{src})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	_, err = a.sendFile(sess, items[0], nil)
	if err == nil {
		t.Fatal("a read-only receive directory must refuse incoming files")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("error should say the directory is read-only, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(shareDir, "unwanted.txt")); !os.IsNotExist(statErr) {
		t.Fatal("the refused file must not have been written")
	}
}

// 取文件复用 receive.allow 那份名单, 所以不在名单里的人直连过来取也必须被挡在
// 读任何文件之前 —— 与收文件那侧是同一个 authorizeFileSender。
func TestFilePullDirectRejectsStranger(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: shareDir, Allow: []conf.AllowedSender{{Email: "trusted@example.com", UUID: testUUIDTrusted}}}
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "stranger@example.com", testUUIDStranger

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-pull-stranger"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	conn, err := a.openPullStream(sess)
	if err != nil {
		t.Fatalf("open pull stream: %v", err)
	}
	defer conn.Close()
	_, err = pullList(conn, "secret.txt")
	if err == nil {
		t.Fatal("a peer outside receive.allow must not be able to list anything")
	}
	if !strings.Contains(err.Error(), "receive.allow") {
		t.Fatalf("error should mention receive.allow, got %v", err)
	}
}

// TestDirectQUICStatsCollected 统计要真的采到东西。这条用例的价值在于"接错了会静默
// 失效": tracer 没挂上、schema 判断写错、或者事件类型断言写成了指针, 任何一个错都
// 不会报错, 只会一直采到 0, 而那时候统计恰恰最没用(正是排查慢速问题时要看它)。
func TestDirectQUICStatsCollected(t *testing.T) {
	recvDir := t.TempDir()
	body := make([]byte, 512*1024)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(t.TempDir(), "stats.bin")
	if err := os.WriteFile(srcPath, body, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}}
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "a@example.com", testUUIDA

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-stats"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if _, err := a.sendFile(sess, items[0], nil); err != nil {
		t.Fatalf("send: %v", err)
	}

	if sess.stats == nil {
		t.Fatal("the dial side should have a stats collector attached")
	}
	summary := sess.stats.summary()
	if summary == "" {
		t.Fatal("no packets were counted: the qlog tracer is not wired up (wrong schema, or event type assertions do not match)")
	}
	sess.stats.mu.Lock()
	sent, cwnd := sess.stats.sent, sess.stats.cwnd
	sess.stats.mu.Unlock()
	// 512KB 怎么也不止几个包; 拥塞窗口也该被采到过一次。
	if sent < 10 {
		t.Fatalf("only %d packets counted for a 512KB transfer, tracer looks broken: %s", sent, summary)
	}
	if cwnd == 0 {
		t.Fatalf("congestion window was never recorded, metrics events are not being read: %s", summary)
	}
	t.Logf("quic: %s", summary)
}

// 没配 receive.dir 的对端必须明确回绝, 而不是默默丢掉 —— 发送端要能从退出码看出没传成。
func TestFileRefusedWhenNoReceiveDir(t *testing.T) {
	c := newAcceptPeer(t, nil) // 不设 Receive.Dir
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "a@example.com", testUUIDA // sendFile 现在会先校验自己的 uuid 格式, 不设就走不到 receive.dir 那一步

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-noreceive"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})
	_, err = a.sendFile(sess, items[0], nil)
	if err == nil {
		t.Fatal("a peer without receive.dir must refuse")
	}
	if !strings.Contains(err.Error(), "receive.dir") {
		t.Fatalf("the error should say what to configure, got %v", err)
	}
}

// receive.allow 限定谁能发过来。email 在直连路径下由发送方自己在 fileAuth 里声明
// (见 nat/file.go), 但真正把关的是 uuid——一个不在列表里的 email 直接被拒。
func TestFileReceiveAllowList(t *testing.T) {
	recvDir := t.TempDir()
	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "trusted@example.com", UUID: testUUIDTrusted}}}
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "stranger@example.com", testUUIDStranger

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-allow"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})
	if _, err := a.sendFile(sess, items[0], nil); err == nil {
		t.Fatal("an email outside receive.allow must be refused")
	}
	if entries, _ := os.ReadDir(recvDir); len(entries) != 0 {
		t.Fatalf("nothing should have been written, found %d entries", len(entries))
	}
}

// 光知道对方的 email 还不够——这正是修复"任何合法账号都能自称任意 email"这个漏洞的
// 核心: 就算发送方把 email 报成 receive.allow 里配置的那个, uuid 对不上照样必须拒绝。
func TestFileReceiveAllowRequiresMatchingUUID(t *testing.T) {
	recvDir := t.TempDir()
	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "trusted@example.com", UUID: testUUIDReal}}}
	a := newDialPeer(t)
	// email 对了, 但 uuid 是瞎编的——必须挡住, 否则 email 又变回了唯一的安全边界。
	a.cfg.Email, a.cfg.UUID = "trusted@example.com", testUUIDForged

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-uuid-mismatch"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})
	if _, err := a.sendFile(sess, items[0], nil); err == nil {
		t.Fatal("a forged uuid must be refused even if the email matches")
	}
	if entries, _ := os.ReadDir(recvDir); len(entries) != 0 {
		t.Fatalf("nothing should have been written, found %d entries", len(entries))
	}
}

// TestFileSendRefusesEmptyUUID 发送方自己的 uuid 是空的(比如生成失败, 见
// utils/conf/uuid.go)就不该动手发——本地直接拒绝, 不建立连接、不打开 stream。
func TestFileSendRefusesEmptyUUID(t *testing.T) {
	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: t.TempDir(), Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}}
	a := newDialPeer(t)
	a.cfg.Email = "a@example.com" // 故意不设 UUID, 保持零值

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-empty-uuid"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})
	if _, err := a.sendFile(sess, items[0], nil); err == nil {
		t.Fatal("an empty websocket.client.uuid must refuse to send")
	}
}

// TestFileSendRefusesMalformedOwnUUID sendFile 自己的 uuid 一旦不是合法格式(比如状态
// 文件被手改坏了)就该在本地直接拒绝, 连 stream 都不打开。
func TestFileSendRefusesMalformedOwnUUID(t *testing.T) {
	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: t.TempDir(), Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: "not-a-real-uuid"}}}
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "a@example.com", "not-a-real-uuid"

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-malformed-uuid"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})
	if _, err := a.sendFile(sess, items[0], nil); err == nil {
		t.Fatal("a sender-side malformed uuid must be refused before it ever reaches the network")
	}
}

// TestFileReceiveRefusesMalformedConfiguredUUID 哪怕对方自报的 uuid 跟 receive.allow
// 里配的一字不差, 只要它本身不是合法 uuid 格式(比如配置文件被手改坏了)接收方也必须
// 拒绝——不能让一次"巧合的字符串相等"通过身份校验。这里绕过 sendFile 自己的格式
// 校验、手写一段 fileAuth 帧, 专门盯住接收端(recvFile)这一侧的校验。
func TestFileReceiveRefusesMalformedConfiguredUUID(t *testing.T) {
	recvDir := t.TempDir()
	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: "not-a-real-uuid"}}}
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-malformed-uuid-wire"
	c.tokens.put(token, directFilePort)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFilePort); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	stream, err := a.openHeadedStream(sess, directStreamFile, "", directFilePort)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := writeFrame(stream, fileAuth{Email: "a@example.com", UUID: "not-a-real-uuid"}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	var reply fileReply
	if err := readFrame(stream, &reply, fileFrameMax); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply.Err == "" {
		t.Fatal("a matching-but-malformed uuid must still be refused")
	}
	if entries, _ := os.ReadDir(recvDir); len(entries) != 0 {
		t.Fatalf("nothing should have been written, found %d entries", len(entries))
	}
}

func TestClientReceiveLookup(t *testing.T) {
	// 空列表 = 谁都不接受(不再是旧版"为空=不限制"——没有 uuid 就没法比对, 也没法给
	// 中继派生密钥, 没有"不限制"这个选项)。
	if _, ok := (conf.ClientReceive{}).Lookup("anyone@example.com"); ok {
		t.Error("an empty allow list should accept nobody")
	}
	r := conf.ClientReceive{Allow: []conf.AllowedSender{{Email: "a@x.com", UUID: "ua"}, {Email: "b@x.com", UUID: "ub"}}}
	if uuid, ok := r.Lookup("b@x.com"); !ok || uuid != "ub" {
		t.Errorf("a listed email should resolve to its uuid, got %q ok=%v", uuid, ok)
	}
	if _, ok := r.Lookup("c@x.com"); ok {
		t.Error("an unlisted email should not resolve")
	}
	if _, ok := r.Lookup(""); ok {
		t.Error("an empty email should not match")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0: "0B", 512: "512B", 1024: "1.0KB",
		1536: "1.5KB", 1048576: "1.0MB", 3221225472: "3.0GB",
	}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %s, want %s", n, got, want)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := fileHead{Name: "a/b.txt", Size: 12345, Mode: 0o644}
	if err := writeFrame(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out fileHead
	if err := readFrame(&buf, &out, fileFrameMax); err != nil {
		t.Fatalf("read: %v", err)
	}
	if out != in {
		t.Fatalf("got %+v, want %+v", out, in)
	}

	// 超过上限的帧要被拒, 否则对端报一个巨大的长度就能让我们分配同样大的内存。
	var big bytes.Buffer
	writeFrame(&big, fileHead{Name: strings.Repeat("x", 500)})
	if err := readFrame(&big, &out, 100); err == nil {
		t.Fatal("a frame over the limit should be rejected")
	}
}

// 进度回调必须一路报到最后一个字节, 否则进度条会停在中途, 看着像卡住了。
func TestProgressReader(t *testing.T) {
	var last int64
	pr := &progressReader{r: bytes.NewReader(bytes.Repeat([]byte("x"), 1000)), on: func(n int64) { last = n }}
	buf := make([]byte, 128)
	for {
		if _, err := pr.Read(buf); err != nil {
			break
		}
	}
	if last != 1000 {
		t.Fatalf("progress ended at %d, want 1000", last)
	}
}

func TestFileTransferTimeoutsAreSane(t *testing.T) {
	// 首部有超时(开了流不发首部的对端会占着它), 但数据本身不设总时限 —— 大文件在慢
	// 链路上传很久是正常的, 真正断掉的连接由 QUIC 的空闲超时兜住。
	if directQUICConfig().MaxIdleTimeout < time.Minute {
		t.Fatal("idle timeout too short for large transfers")
	}
	if got := directQUICConfig().MaxStreamReceiveWindow; got < 16<<20 {
		t.Fatalf("stream receive window %d is too small for gigabit links", got)
	}
}

func TestFilePermFallback(t *testing.T) {
	// Windows 上文件模式常常是 0, 不能因此建出一个谁都读不了的文件。
	if got := filePerm(0); got != 0o644 {
		t.Fatalf("filePerm(0) = %v, want 0644", got)
	}
	if got := filePerm(0o600); got != 0o600 {
		t.Fatalf("filePerm(0600) = %v", got)
	}
}

func TestShortSum(t *testing.T) {
	if got := short(fmt.Sprintf("%064d", 0)); len(got) != 12 {
		t.Fatalf("short() should trim to 12 chars, got %d", len(got))
	}
	if got := short("abc"); got != "abc" {
		t.Fatalf("a short string should pass through, got %q", got)
	}
}
