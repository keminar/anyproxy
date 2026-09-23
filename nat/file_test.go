package nat

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
func TestClaimName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.zip")
	got, err := claimName(p)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got != p {
		t.Fatalf("a free name should be used as is, got %q", got)
	}
	// claimName 认领的是一个占位文件, 不是"看一眼就完事"——调用方后续会把真正内容
	// rename 过去覆盖它。这里模拟那个覆盖, 好继续测下一次认领时 p 已经"名花有主"。
	os.WriteFile(got, []byte("old"), 0o644)

	got2, err := claimName(p)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if want := dupName(p, 1); got2 != want {
		t.Fatalf("got %q, want %q", got2, want)
	}
	os.WriteFile(got2, []byte("old"), 0o644)

	got3, err := claimName(p)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if want := dupName(p, 2); got3 != want {
		t.Fatalf("got %q, want %q", got3, want)
	}
	// 原文件必须原封不动。
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatalf("the existing file was touched: %q", b)
	}

	// 非 Windows 下的可执行文件常带版本号(如 v2.1), 末尾的".1"是版本号不是后缀名,
	// 序号要加在整个文件名后面, 不能拆进版本号中间。
	vp := filepath.Join(dir, "anyproxy-amd64-v2.1")
	os.WriteFile(vp, []byte("old"), 0o644)
	if got, err := claimName(vp); err != nil || got != dupName(vp, 1) {
		t.Fatalf("claimName(%q) = %q, %v; want %q, nil", vp, got, err, dupName(vp, 1))
	}
}

func TestDupName(t *testing.T) {
	cases := []struct {
		dest string
		i    int
		want string
	}{
		{"/d/x.zip", 1, "/d/x 1.zip"},
		{"/d/x.zip", 2, "/d/x 2.zip"},
		{"/d/v2.1", 1, "/d/v2.1 1"}, // 数字后缀是版本号, 序号加在末尾
	}
	for _, c := range cases {
		if got := dupName(c.dest, c.i); got != c.want {
			t.Errorf("dupName(%q, %d) = %q, want %q", c.dest, c.i, got, c.want)
		}
	}
}

// TestClaimNameConcurrent 是这次 bug 的回归测试: 两次并发的"同名传输"必须落到两个
// 不同的最终文件名上, 谁都不能覆盖谁——这正是 claimName 要替掉旧版 uniquePath(先
// os.Stat 探测、调用方再另外一步 Rename)的原因: 探测和占用分成两步, 在两个独立的
// goroutine/进程之间就不是原子的, 并发时会都探测到"名字空闲", 都去用同一个名字,
// 后一个的 Rename 把前一个已经落盘、已经回复过"Saved"的文件悄悄覆盖掉。
func TestClaimNameConcurrent(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "same.bin")

	const n = 20
	names := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			names[i], errs[i] = claimName(dest)
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for i, name := range names {
		if errs[i] != nil {
			t.Fatalf("claim %d: %v", i, errs[i])
		}
		if seen[name] {
			t.Fatalf("two concurrent claims both got %q — one would silently overwrite the other's finished file", name)
		}
		seen[name] = true
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
	// .part 不能留下来: 留着会让人以为还有一个没传完的文件。part 名字带随机 token
	// (见 writeIncoming 的注释), 用 glob 而不是拼一个固定路径去检查。
	if matches, _ := filepath.Glob(dest + ".*" + filePartSuffix); len(matches) != 0 {
		t.Fatalf("the .part file was left behind: %v", matches)
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

// TestWriteIncomingConcurrentSameName 是"两个终端同时发同名文件"这个场景的回归
// 测试。两次 writeIncoming 各自的 .part 名字已经带了独立的随机 token, 不会像最早
// 那版那样在写的过程中撞名; 这里要验证的是后半段——两次都完整收完之后, 各自选定
// 最终文件名(uniquePath 曾经的做法)不能有"都探测到同一个名字空闲、都 rename 过去、
// 后一个悄悄覆盖前一个"的窗口。写两份不同内容的文件, 收完后两份内容都必须完整、
// 分别可查, 不能有一份丢失或被覆盖。
func TestWriteIncomingConcurrentSameName(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "race.bin")

	bodyA := bytes.Repeat([]byte("A"), 64*1024)
	bodyB := bytes.Repeat([]byte("B"), 64*1024)

	var wg sync.WaitGroup
	var savedA, savedB string
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		savedA, _, errA = writeIncoming(dest, bytes.NewReader(bodyA), fileHead{Name: "race.bin", Size: int64(len(bodyA))})
	}()
	go func() {
		defer wg.Done()
		savedB, _, errB = writeIncoming(dest, bytes.NewReader(bodyB), fileHead{Name: "race.bin", Size: int64(len(bodyB))})
	}()
	wg.Wait()

	if errA != nil {
		t.Fatalf("write A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("write B: %v", errB)
	}
	if savedA == savedB {
		t.Fatalf("both concurrent transfers were saved as %q — one must have overwritten the other", savedA)
	}

	got := map[string][]byte{}
	for _, p := range []string{savedA, savedB} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %q: %v", p, err)
		}
		got[p] = b
	}
	if !bytes.Equal(got[savedA], bodyA) {
		t.Fatalf("%q: content does not match what A sent", savedA)
	}
	if !bytes.Equal(got[savedB], bodyB) {
		t.Fatalf("%q: content does not match what B sent", savedB)
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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

// 同一种拒绝, 但文件大到超过 QUIC 初始流接收窗口(direct_accept.go 里的 2MB) ——
// 对端(c)在读文件首部之前就已经拒绝、从没读过 a 写的任何一个字节, a 这次
// io.CopyBuffer 必然会写到卡住。这是在回归 serveStream 那个死锁: c 在拒绝之后如果只
// Close() 不 CancelRead(), a 会永远卡在这次 Write 里, 既不报错也不超时(整条 QUIC
// 连接本身靠 keepalive 撑着, 不会触发空闲超时)。真实场景见几百 MB~几 GB 的大文件
// 传输——所以这里用一个刻意超过窗口的文件大小复现, 而不是像上面那个测试用几个字节
// 侥幸落在窗口内、掩盖了这个问题。
func TestFileRefusedWhenNoReceiveDirLargeFile(t *testing.T) {
	c := newAcceptPeer(t, nil) // 不设 Receive.Dir
	a := newDialPeer(t)
	a.cfg.Email, a.cfg.UUID = "a@example.com", testUUIDA

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-noreceive-large"
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	src := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(src, make([]byte, 8<<20), 0o644); err != nil { // 8MB > 2MB 初始窗口
		t.Fatalf("write src: %v", err)
	}
	items, err := collectFiles([]string{src})
	if err != nil {
		t.Fatalf("collectFiles: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := a.sendFile(sess, items[0], nil)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("a peer without receive.dir must refuse")
		}
		if !strings.Contains(err.Error(), "receive.dir") {
			t.Fatalf("the error should say what to configure (not a raw QUIC/stream error), got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sendFile hung: receiver rejected but never freed the sender's blocked Write (missing CancelRead?)")
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
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
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	stream, err := a.openHeadedStream(sess, directStreamFile, "", directFileTag)
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

// TestClientReceiveLookupSender: LookupSender 要把 Wol/Dir 一并带出来(Lookup 只是
// 它的 uuid-only 简化版), 且未配置时保持各自的零值(Wol 默认 false, Dir 默认空
// 即"跟其他人一样落到共享 Dir")。
func TestClientReceiveLookupSender(t *testing.T) {
	r := conf.ClientReceive{Allow: []conf.AllowedSender{
		{Email: "a@x.com", UUID: "ua"},
		{Email: "b@x.com", UUID: "ub", Wol: true, Dir: "/srv/b"},
	}}
	a, ok := r.LookupSender("a@x.com")
	if !ok || a.UUID != "ua" || a.Wol || a.Dir != "" {
		t.Errorf("a@x.com should resolve with zero Wol/Dir, got %+v ok=%v", a, ok)
	}
	b, ok := r.LookupSender("b@x.com")
	if !ok || b.UUID != "ub" || !b.Wol || b.Dir != "/srv/b" {
		t.Errorf("b@x.com should resolve with Wol=true Dir=/srv/b, got %+v ok=%v", b, ok)
	}
	if _, ok := r.LookupSender("c@x.com"); ok {
		t.Error("an unlisted email should not resolve")
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

// ---------- 单文件分块并行传输 ----------

func TestChunkCursorClaim(t *testing.T) {
	size := int64(5*probeChunkSize) + 777
	c := newChunkCursor(size)

	var off int64
	var total int64
	seenIdx := map[int]bool{}
	for {
		offset, length, idx, ok := c.claim(probeChunkSize)
		if !ok {
			break
		}
		if offset != off {
			t.Fatalf("claim starts at %d, want %d", offset, off)
		}
		if seenIdx[idx] {
			t.Fatalf("idx %d handed out twice", idx)
		}
		seenIdx[idx] = true
		off += length
		total += length
	}
	if total != size {
		t.Fatalf("claimed %d bytes total, want %d", total, size)
	}
	// 耗尽之后继续认领应该一直是 ok=false, 不panic、不越界。
	if _, _, _, ok := c.claim(probeChunkSize); ok {
		t.Fatal("claim after exhaustion should return ok=false")
	}

	// 最后一片必须 clamp 到剩余字节数, 不能超发。
	c2 := newChunkCursor(10)
	_, length, _, ok := c2.claim(7)
	if !ok || length != 7 {
		t.Fatalf("first claim(7) on a 10-byte file = length %d ok %v, want 7 true", length, ok)
	}
	_, length, _, ok = c2.claim(7)
	if !ok || length != 3 {
		t.Fatalf("second claim(7) on a 10-byte file should clamp to the remaining 3, got length %d ok %v", length, ok)
	}
	if _, _, _, ok := c2.claim(7); ok {
		t.Fatal("claiming a fully-claimed cursor should return ok=false")
	}

	// size==0 的文件不应该产生任何一次成功的认领。
	if _, _, _, ok := newChunkCursor(0).claim(probeChunkSize); ok {
		t.Fatal("claim on a zero-size file should return ok=false")
	}
}

func TestChunkCursorClaimConcurrent(t *testing.T) {
	const size = 97 * 1024 // 不对齐任何一档分片大小, 顺带盖住"最后一片拿余数"。
	c := newChunkCursor(size)

	type claim struct{ offset, length int64 }
	results := make(chan claim, 64)
	idxCh := make(chan int, 64)

	var wg sync.WaitGroup
	sizes := []int64{997, 1500, 2048, 4096} // 模拟不同 worker 选了不同的分片大小
	for _, want := range sizes {
		wg.Add(1)
		go func(want int64) {
			defer wg.Done()
			for {
				offset, length, idx, ok := c.claim(want)
				if !ok {
					return
				}
				results <- claim{offset, length}
				idxCh <- idx
			}
		}(want)
	}
	wg.Wait()
	close(results)
	close(idxCh)

	var claims []claim
	for r := range results {
		claims = append(claims, r)
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].offset < claims[j].offset })

	var off, total int64
	for i, cl := range claims {
		if cl.offset != off {
			t.Fatalf("claim %d starts at %d, want %d (gap or overlap)", i, cl.offset, off)
		}
		off += cl.length
		total += cl.length
	}
	if total != size {
		t.Fatalf("claimed %d bytes total, want %d", total, size)
	}

	seen := map[int]bool{}
	for idx := range idxCh {
		if seen[idx] {
			t.Fatalf("idx %d handed out to more than one claim", idx)
		}
		seen[idx] = true
	}
}

func TestChunkSizeForRate(t *testing.T) {
	const KB, MB = 1 << 10, 1 << 20
	cases := []struct {
		rate float64
		want int64
	}{
		{0, 2 * MB},
		{50 * KB, 2 * MB},
		{100 * KB, 3 * MB}, // 下边界落进更快那档
		{150 * KB, 3 * MB},
		{200 * KB, 6 * MB},
		{300 * KB, 6 * MB},
		{500 * KB, 15 * MB},
		{800 * KB, 15 * MB},
		{1 * MB, 30 * MB},
		{10 * MB, 30 * MB},
	}
	for _, c := range cases {
		if got := chunkSizeForRate(c.rate); got != c.want {
			t.Errorf("chunkSizeForRate(%v) = %d, want %d", c.rate, got, c.want)
		}
	}
}

func TestWorkerChunkSize(t *testing.T) {
	if got := workerChunkSize(3<<20, 0); got != chunkSizeMax {
		t.Fatalf("elapsed<=0 should fall back to chunkSizeMax, got %d", got)
	}
	if got := workerChunkSize(3<<20, -time.Second); got != chunkSizeMax {
		t.Fatalf("negative elapsed should fall back to chunkSizeMax, got %d", got)
	}
	// 3MiB 用了 1 秒钟, 吞吐 3MiB/s, 应该落进 >=1MB/s 那档(30MiB)。
	if got := workerChunkSize(3<<20, time.Second); got != chunkSizeMax {
		t.Fatalf("workerChunkSize(3MiB, 1s) = %d, want %d", got, chunkSizeMax)
	}
}

func TestWantParallel(t *testing.T) {
	if wantParallel(10*probeChunkSize, 1) {
		t.Fatal("workers<=1 should never want parallel, regardless of size")
	}
	if wantParallel(2*probeChunkSize-1, 4) {
		t.Fatal("a file just under 2*probeChunkSize should not want parallel")
	}
	if !wantParallel(2*probeChunkSize, 4) {
		t.Fatal("a file exactly 2*probeChunkSize should want parallel (boundary is inclusive)")
	}
	if !wantParallel(10*probeChunkSize, 2) {
		t.Fatal("a clearly large file with workers=2 should want parallel")
	}
}

// TestChunkProgressSummaryShowsPieceSize 覆盖 chunkProgress.setPieceSize/summary:
// 每条连接当前正在传的这一片有多大要出现在进度行里, 这样才看得出是不是某条连接
// 因为测速偏低被分到了明显更小的分片(见 setPieceSize 的注释)。
func TestChunkProgressSummaryShowsPieceSize(t *testing.T) {
	p := newProgress("test", 100)
	defer p.done()
	cp := newChunkProgress(2, p)

	cp.setPieceSize(0, 2*1024*1024)
	cp.setPieceSize(1, 6*1024*1024)
	cp.update(0, 1000)
	cp.update(1, 2000)

	line, _ := cp.summary()
	if !strings.Contains(line, "("+humanBytes(2*1024*1024)+")") {
		t.Fatalf("summary %q missing conn1's piece size", line)
	}
	if !strings.Contains(line, "("+humanBytes(6*1024*1024)+")") {
		t.Fatalf("summary %q missing conn2's piece size", line)
	}

	// 换了一片之后展示的应该是新的那个大小, 不是停留在上一片。
	cp.setPieceSize(0, 3*1024*1024)
	line, _ = cp.summary()
	if !strings.Contains(line, "("+humanBytes(3*1024*1024)+")") {
		t.Fatalf("summary %q did not pick up the new piece size", line)
	}
	if strings.Contains(line, "("+humanBytes(2*1024*1024)+")") {
		t.Fatalf("summary %q still shows the stale piece size", line)
	}
}

func TestRunChunkWorkersCoverage(t *testing.T) {
	const size = 10 * probeChunkSize
	const workers = 3

	type claim struct{ offset, length int64 }
	var mu sync.Mutex
	var claims []claim
	firstLength := make([]int64, workers)
	lastLength := make([]int64, workers)
	for i := range firstLength {
		firstLength[i] = -1
	}

	p := newProgress("test", size)
	defer p.done()
	cp := newChunkProgress(workers, p)

	do := func(w int, offset, length int64, idx int, onProgress func(int64)) (string, error) {
		mu.Lock()
		claims = append(claims, claim{offset, length})
		if firstLength[w] == -1 {
			firstLength[w] = length
		}
		lastLength[w] = length
		mu.Unlock()
		onProgress(length)
		return "", nil
	}

	if _, err := runChunkWorkers(size, workers, cp, do); err != nil {
		t.Fatalf("runChunkWorkers: %v", err)
	}

	sort.Slice(claims, func(i, j int) bool { return claims[i].offset < claims[j].offset })
	var off, total int64
	for i, c := range claims {
		if c.offset != off {
			t.Fatalf("claim %d starts at %d, want %d (gap or overlap)", i, c.offset, off)
		}
		off += c.length
		total += c.length
	}
	if total != size {
		t.Fatalf("claimed %d bytes total, want %d", total, size)
	}
	for w, l := range firstLength {
		want := int64(probeChunkSize)
		if l == -1 {
			continue // 这个 worker 没抢到任何活, 可能发生(见 wantParallel/claim 的边界)
		}
		if l > want {
			t.Errorf("worker %d's first claim was %d bytes, want <= probeChunkSize(%d)", w, l, want)
		}
		// runChunkWorkers 应该在每次认领之后把片大小记进 cp(见 setPieceSize), 供
		// 进度行展示——认领完最后一片, cp 里记的该是那一片的大小, 不是别的。
		if got := cp.piece[w]; got != lastLength[w] {
			t.Errorf("worker %d: chunkProgress.piece = %d, want its last claimed length %d", w, got, lastLength[w])
		}
	}
}

func TestRunChunkWorkersErrorStopsOtherWorkers(t *testing.T) {
	const size = 10 * probeChunkSize
	const workers = 3

	p := newProgress("test", size)
	defer p.done()
	cp := newChunkProgress(workers, p)

	var claimed int64
	do := func(w int, offset, length int64, idx int, onProgress func(int64)) (string, error) {
		atomic.AddInt64(&claimed, length)
		if offset == 0 {
			// 认领游标严格按字节顺序发号, 第一个成功认领到的分片永远是 offset==0
			// 这一片(不论被哪个 worker 抢到), 让它立刻失败, 不需要猜是哪个 worker。
			return "", errors.New("simulated failure")
		}
		// do 是假操作, 瞬间就能把整份文件认领完——真实场景里"其它 worker 别再领
		// 新的一片"的信号来得及被看到, 是因为真实的一片传输本身要花时间; 这里用
		// 一点延迟模拟同样的时间窗口, 让失败信号有机会先传播到, 断言才有意义
		// (否则文件可能在出错的那个 goroutine 设好 firstErr 之前就已经被认领光了)。
		time.Sleep(5 * time.Millisecond)
		onProgress(length)
		return "", nil
	}

	_, err := runChunkWorkers(size, workers, cp, do)
	if err == nil {
		t.Fatal("expected an error to propagate from runChunkWorkers")
	}
	// 出错之后不应该把整份文件都认领完——虽然已经在飞的那几片会跑完, 但错误发生后
	// 不会再有新的认领。跑完的总量必须明显小于文件全长(否则说明其它 worker 没有
	// 及时停手)。
	if got := atomic.LoadInt64(&claimed); got >= size {
		t.Fatalf("claimed %d bytes out of %d after a failure, workers did not stop claiming new work", got, size)
	}
}

// 端到端: 一个大文件切 3 块, 各开一条独立的 QUIC stream 并行发, 落盘后内容必须和
// 源文件逐字节一致——并行本身不能引入任何数据错误(乱序落盘、块与块之间接不上等)。
func TestChunkedFileTransferDirect(t *testing.T) {
	recvDir := t.TempDir()
	srcDir := t.TempDir()

	// 凑一个不对齐 probeChunkSize 的大小, 顺带盖住"最后一块拿余数"。
	body := make([]byte, 5*probeChunkSize+777)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(srcDir, "chunked.bin")
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
	const token = "test-token-chunk"
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	it := items[0]
	if !wantParallel(it.size, 3) {
		t.Fatalf("expected the test file (%d bytes) to be big enough for parallel chunking", it.size)
	}

	p := newProgress("test", it.size)
	// 必须停掉它的渲染 goroutine: 漏掉的话它会一直往 stderr 刷进度行到进程结束,
	// 把后面用例的输出和失败信息冲乱(见 progress.done 的说明)。
	defer p.done()
	sendChunk := func(worker int, it fileItem, offset, length int64, tid string, chunkIdx int, onProgress func(int64)) (string, error) {
		return a.sendFileChunk(sess, it, offset, length, tid, chunkIdx, onProgress)
	}
	saved, err := sendParallel(it, 3, sendChunk, nil, p)
	if err != nil {
		t.Fatalf("chunked send: %v", err)
	}
	if saved != "chunked.bin" {
		t.Fatalf("peer saved it as %q", saved)
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "chunked.bin"))
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("received %d bytes, content differs from the %d sent", len(got), len(body))
	}
	if matches, _ := filepath.Glob(filepath.Join(recvDir, "chunked.bin.*"+filePartSuffix)); len(matches) != 0 {
		t.Fatalf("the .part file was left behind: %v", matches)
	}
}

// corruptOnceConn 在正文第一次 Write 时(而不是首部帧那次)翻转一个字节, 模拟"这一块
// 在传输途中出了错"——用来验证分块传输里一块校验失败会让整份传输报错、且不留下半截
// 或内容错误的文件。
type corruptOnceConn struct {
	fileConn
	calls int
}

func (c *corruptOnceConn) Write(b []byte) (int, error) {
	c.calls++
	if c.calls == 2 && len(b) > 0 { // 第 1 次 Write 是 fileHead 帧, 第 2 次才是正文。
		mutated := append([]byte(nil), b...)
		mutated[0] ^= 0xFF
		return c.fileConn.Write(mutated)
	}
	return c.fileConn.Write(b)
}

func TestChunkedFileTransferOneBadChunkFailsWholeFile(t *testing.T) {
	recvDir := t.TempDir()
	srcDir := t.TempDir()

	body := make([]byte, 4*probeChunkSize)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(srcDir, "bad.bin")
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
	const token = "test-token-bad-chunk"
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	it := items[0]
	cursor := newChunkCursor(it.size)
	type chunk struct {
		offset, length int64
		idx            int
	}
	var chunks []chunk
	for {
		offset, length, idx, ok := cursor.claim(it.size / 4)
		if !ok {
			break
		}
		chunks = append(chunks, chunk{offset, length, idx})
	}
	if len(chunks) < 2 {
		t.Fatalf("expected the test file to split into multiple chunks, got %d", len(chunks))
	}

	tid, err := newTransferID()
	if err != nil {
		t.Fatalf("transfer id: %v", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i, ch := range chunks {
		wg.Add(1)
		go func(i int, ch chunk) {
			defer wg.Done()
			stream, err := a.openFileStream(sess)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			var conn fileConn = stream
			if i == 1 { // 只破坏中间那一块, 其余块本身都是完整正确的。
				conn = &corruptOnceConn{fileConn: stream}
			}
			if _, err := sendFileOverRange(conn, it, ch.offset, ch.length, tid, ch.idx, nil); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(i, ch)
	}
	wg.Wait()

	if firstErr == nil {
		t.Fatal("a corrupted chunk should fail the whole transfer, got no error")
	}

	dest := filepath.Join(recvDir, "bad.bin")
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("a failed chunked transfer must not leave the final file behind")
	}
	if matches, _ := filepath.Glob(dest + ".*" + filePartSuffix); len(matches) != 0 {
		t.Fatalf("a failed chunked transfer must not leave the .part file behind: %v", matches)
	}
}

// TestChunkAssemblyByteCompletion 专门证明分块拼接靠"收到的字节数是否等于整份文件
// 大小"判断是否收全, 不依赖任何固定片数——三片大小(7/13/5 字节)互不相等、也不是
// probeChunkSize 的整数倍, 旧的"块数倒计数"模型根本无从谈起, 这正是这次改动要验证
// 的行为(见 nat/file.go 的 chunkAssembly)。用 sendFileOverRange(客户端)配
// recvFileOver(服务端)在内存管道上跑, 不需要真实网络。
func TestChunkAssemblyByteCompletion(t *testing.T) {
	recvDir := t.TempDir()
	srcDir := t.TempDir()

	body := []byte("abcdefghijklmnopqrstuvwxy") // 25 字节, 切成 7+13+5
	srcPath := filepath.Join(srcDir, "small.bin")
	if err := os.WriteFile(srcPath, body, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	it := items[0]

	tid, err := newTransferID()
	if err != nil {
		t.Fatalf("transfer id: %v", err)
	}
	ranges := []struct{ offset, length int64 }{
		{0, 7}, {7, 13}, {20, 5},
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i, r := range ranges {
		wg.Add(1)
		go func(i int, offset, length int64) {
			defer wg.Done()
			aSide, cSide := net.Pipe()
			go func() {
				defer cSide.Close()
				recvFileOver(cSide, recvDir, "a@example.com", "test", func(string, ...interface{}) {}, recvOpts{}, nil)
			}()
			if _, err := sendFileOverRange(aSide, it, offset, length, tid, i, nil); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(i, r.offset, r.length)
	}
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("chunked send: %v", firstErr)
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "small.bin"))
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("received %q, want %q", got, body)
	}
	if matches, _ := filepath.Glob(filepath.Join(recvDir, "small.bin.*"+filePartSuffix)); len(matches) != 0 {
		t.Fatalf("the .part file was left behind: %v", matches)
	}
}

// TestAbortChunkAssemblyOverWire 覆盖 fileHead.Abort(见其注释): 只有一部分分片真的
// 发出去过, 其余那些从未认领/从未打开过连接的分片永远不会来——光靠字节计数
// (chunkAssembly.remaining)永远等不到归零, 没有这条显式通知的话只能靠 5 分钟的
// 空闲回收器兜底(见 reapChunkAssemblies)。发一帧 Abort 应该让接收端立刻收掉
// .chunks 临时文件与内存状态, 不必等那么久——这正是 -send 用 -parallel 时, 某个
// worker 出错后 sendParallel 会做的事(见 file_send.go)。
func TestAbortChunkAssemblyOverWire(t *testing.T) {
	recvDir := t.TempDir()
	srcDir := t.TempDir()

	body := make([]byte, 4*probeChunkSize)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(srcDir, "abort.bin")
	if err := os.WriteFile(srcPath, body, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	it := items[0]

	tid, err := newTransferID()
	if err != nil {
		t.Fatalf("transfer id: %v", err)
	}

	// 只发第一片(总共本该切成 4 片), 模拟"其余分片永远不会来"——不是靠一个显式
	// 出错的分片让 remaining 提前扣到零, 是那些分片压根没被认领、没开过连接。
	aSide, cSide := net.Pipe()
	go func() {
		defer cSide.Close()
		recvFileOver(cSide, recvDir, "a@example.com", "test", func(string, ...interface{}) {}, recvOpts{}, nil)
	}()
	quarter := it.size / 4
	if _, err := sendFileOverRange(aSide, it, 0, quarter, tid, 0, nil); err != nil {
		t.Fatalf("send first chunk: %v", err)
	}

	chunkAssemblies.mu.Lock()
	_, ok := chunkAssemblies.m[tid]
	chunkAssemblies.mu.Unlock()
	if !ok {
		t.Fatal("expected an in-progress assembly after the first chunk")
	}
	if matches, _ := filepath.Glob(filepath.Join(recvDir, "abort.bin.*.chunks"+filePartSuffix)); len(matches) != 1 {
		t.Fatalf("expected one .chunks temp file, got %v", matches)
	}

	// 发送方这时放弃了(比如另一个 worker 出的错), 告诉接收端别再等了。
	aSide2, cSide2 := net.Pipe()
	go func() {
		defer cSide2.Close()
		recvFileOver(cSide2, recvDir, "a@example.com", "test", func(string, ...interface{}) {}, recvOpts{}, nil)
	}()
	if err := writeFrame(aSide2, fileHead{TransferID: tid, Abort: true}); err != nil {
		t.Fatalf("send abort: %v", err)
	}
	var r fileReply
	if err := readFrame(aSide2, &r, fileFrameMax); err != nil {
		t.Fatalf("read abort reply: %v", err)
	}

	chunkAssemblies.mu.Lock()
	_, stillThere := chunkAssemblies.m[tid]
	chunkAssemblies.mu.Unlock()
	if stillThere {
		t.Fatal("abort should remove the assembly immediately, not wait for the idle reaper")
	}
	if matches, _ := filepath.Glob(filepath.Join(recvDir, "abort.bin.*"+filePartSuffix)); len(matches) != 0 {
		t.Fatalf("abort should delete the .chunks temp file immediately, got %v", matches)
	}
}

// TestDirectPeerAbortTransfer 用真实的直连 QUIC 会话覆盖 directPeer.abortTransfer
// 本身(帧怎么开流/怎么写), 而不是像 TestAbortChunkAssemblyOverWire 那样直接摆一个
// 手搭的 Abort 帧——两个测试合起来才覆盖了"sendParallel 失败后怎么通知对端"这条
// 路径从发送方方法到接收端落地的完整链路。
func TestDirectPeerAbortTransfer(t *testing.T) {
	recvDir := t.TempDir()
	srcDir := t.TempDir()

	body := make([]byte, 4*probeChunkSize)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(srcDir, "abort2.bin")
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
	const token = "test-token-abort"
	c.tokens.put(token, directFileTag)
	sess, err := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := a.authenticateSession(sess, token, directFileTag, false, ""); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	it := items[0]

	tid, err := newTransferID()
	if err != nil {
		t.Fatalf("transfer id: %v", err)
	}
	// 只发第一片, 其余当作发送方已经放弃、永远不会再发。
	if _, err := a.sendFileChunk(sess, it, 0, it.size/4, tid, 0, nil); err != nil {
		t.Fatalf("send first chunk: %v", err)
	}
	chunkAssemblies.mu.Lock()
	_, ok := chunkAssemblies.m[tid]
	chunkAssemblies.mu.Unlock()
	if !ok {
		t.Fatal("expected an in-progress assembly after the first chunk")
	}

	a.abortTransfer(sess, tid)

	chunkAssemblies.mu.Lock()
	_, stillThere := chunkAssemblies.m[tid]
	chunkAssemblies.mu.Unlock()
	if stillThere {
		t.Fatal("abortTransfer should remove the assembly immediately")
	}
	if matches, _ := filepath.Glob(filepath.Join(recvDir, "abort2.bin.*"+filePartSuffix)); len(matches) != 0 {
		t.Fatalf("abortTransfer should delete the .chunks temp file immediately, got %v", matches)
	}
}
