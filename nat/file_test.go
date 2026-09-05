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
	c.cfg.Receive = conf.ClientReceive{Dir: recvDir}
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-file"
	c.tokens.put(token, directFilePort, "a@example.com")
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

// 没配 receive.dir 的对端必须明确回绝, 而不是默默丢掉 —— 发送端要能从退出码看出没传成。
func TestFileRefusedWhenNoReceiveDir(t *testing.T) {
	c := newAcceptPeer(t, nil) // 不设 Receive.Dir
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-noreceive"
	c.tokens.put(token, directFilePort, "a@example.com")
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

// receive.allow 限定谁能发过来。身份是服务端在 punch 里给的, 不是对端自报的。
func TestFileReceiveAllowList(t *testing.T) {
	recvDir := t.TempDir()
	c := newAcceptPeer(t, nil)
	c.cfg.Receive = conf.ClientReceive{Dir: recvDir, Allow: []string{"trusted@example.com"}}
	a := newDialPeer(t)

	tr, err := a.ensureTransport()
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	const token = "test-token-allow"
	// 凭证记的是 "stranger@example.com", 不在白名单里。
	c.tokens.put(token, directFilePort, "stranger@example.com")
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

func TestClientReceiveAllowed(t *testing.T) {
	// 空白名单 = 不限制(仍受直连本身的鉴权约束)。
	if !(conf.ClientReceive{}).Allowed("anyone@example.com") {
		t.Error("an empty allow list should not block anyone")
	}
	r := conf.ClientReceive{Allow: []string{"a@x.com", "b@x.com"}}
	if !r.Allowed("b@x.com") {
		t.Error("a listed email should be allowed")
	}
	if r.Allowed("c@x.com") {
		t.Error("an unlisted email should be refused")
	}
	if r.Allowed("") {
		t.Error("an empty email should not match a non-empty list")
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
