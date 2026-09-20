package nat

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// ---------- 决策器(不联网) ----------

func newTestResolver(policy, input string) (*conflictResolver, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &conflictResolver{policy: policy, in: bufio.NewReader(strings.NewReader(input)), out: out}, out
}

func TestParseConflict(t *testing.T) {
	for _, ok := range []string{"", "ask", "rename", "overwrite", "skip", "resume"} {
		if _, err := ParseConflict(ok); err != nil {
			t.Errorf("ParseConflict(%q): %v", ok, err)
		}
	}
	if _, err := ParseConflict("clobber"); err == nil {
		t.Error("an unknown policy must be rejected")
	}
}

func TestDecideFixedPolicies(t *testing.T) {
	same := conflictInfo{name: "a", where: "locally", existing: 5, incoming: 5, same: true}
	prefix := conflictInfo{name: "a", where: "locally", existing: 3, incoming: 5, resumable: true}
	differ := conflictInfo{name: "a", where: "locally", existing: 3, incoming: 5}

	cases := []struct {
		policy string
		ci     conflictInfo
		want   string
		errSub string
	}{
		{ConflictRename, same, ConflictRename, ""},
		{ConflictSkip, differ, ConflictSkip, ""},
		{ConflictOverwrite, differ, ConflictOverwrite, ""},
		{ConflictResume, prefix, ConflictResume, ""},
		{ConflictResume, same, ConflictSkip, ""}, // 已经完整了: 没什么可续的
		{ConflictResume, differ, ConflictRename, ""},
	}
	for _, c := range cases {
		r, _ := newTestResolver(c.policy, "")
		got, err := r.decide(c.ci)
		if c.errSub != "" {
			if err == nil || !strings.Contains(err.Error(), c.errSub) {
				t.Errorf("policy %s: want error containing %q, got %v", c.policy, c.errSub, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("policy %s: got %q, %v; want %q", c.policy, got, err, c.want)
		}
	}
}

// 提示里给出的选项要与用户描述的一致: 内容一致 = 改名/覆盖/跳过; 内容不同 = 续传/改名/跳过。
func TestPromptOptions(t *testing.T) {
	same := conflictInfo{name: "a.zip", where: "on the peer", existing: 5, incoming: 5, same: true, hash: "abcdef0123456789"}
	prefix := conflictInfo{name: "a.zip", where: "on the peer", existing: 3, incoming: 5, resumable: true}
	differ := conflictInfo{name: "a.zip", where: "on the peer", existing: 3, incoming: 5}

	cases := []struct {
		name    string
		ci      conflictInfo
		input   string
		want    string
		sticky  bool
		must    []string
		mustNot []string
	}{
		{"same: rename", same, "r\n", ConflictRename, false, []string{"identical", "[r]ename", "[o]verwrite", "[s]kip"}, []string{"[c]ontinue"}},
		{"same: overwrite", same, "o\n", ConflictOverwrite, false, nil, nil},
		{"same: default is skip", same, "\n", ConflictSkip, false, nil, nil},
		{"same: uppercase is sticky", same, "S\n", ConflictSkip, true, nil, nil},
		{"differ, resumable: continue", prefix, "c\n", ConflictResume, false, []string{"differs", "[c]ontinue from 3B", "[r]ename", "[s]kip"}, []string{"[o]verwrite"}},
		{"differ, not resumable: no continue", differ, "c\nr\n", ConflictRename, false, []string{"cannot continue"}, []string{"[c]ontinue"}},
		{"garbage then answer", differ, "??\nx\ns\n", ConflictSkip, false, []string{"please answer"}, nil},
	}
	for _, c := range cases {
		r, out := newTestResolver(ConflictAsk, c.input)
		got, sticky, err := r.prompt(c.ci)
		if err != nil || got != c.want || sticky != c.sticky {
			t.Errorf("%s: got %q sticky=%v err=%v; want %q sticky=%v", c.name, got, sticky, err, c.want, c.sticky)
		}
		for _, s := range c.must {
			if !strings.Contains(out.String(), s) {
				t.Errorf("%s: prompt should contain %q, got:\n%s", c.name, s, out.String())
			}
		}
		for _, s := range c.mustNot {
			if strings.Contains(out.String(), s) {
				t.Errorf("%s: prompt must not contain %q, got:\n%s", c.name, s, out.String())
			}
		}
	}

	r, _ := newTestResolver(ConflictAsk, "")
	if _, _, err := r.prompt(same); err == nil {
		t.Error("EOF on the prompt must be an error, not a silent default")
	}
}

func TestHashFilePrefix(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("hello world"), 0o644)
	whole, err := hashFilePrefix(p, 11)
	if err != nil {
		t.Fatal(err)
	}
	part, _ := hashFilePrefix(p, 5)
	if whole == part {
		t.Fatal("prefix hash must differ from whole-file hash")
	}
	other := filepath.Join(t.TempDir(), "g")
	os.WriteFile(other, []byte("hello"), 0o644)
	if h, _ := hashFilePrefix(other, 5); h != part {
		t.Fatal("same bytes must hash the same")
	}
	if _, err := hashFilePrefix(p, 12); err == nil {
		t.Fatal("asking for more bytes than the file has must fail")
	}
}

// ---------- 端到端: -send 经中继 ----------

func setConflictInput(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(input)
	w.Close()
	old := conflictIn
	conflictIn = r
	t.Cleanup(func() { conflictIn = old; r.Close() })
}

// conflictRig 一对经中继相连的 A(发送/取件方)与 C(收方/被取方)。
type conflictRig struct {
	connect string
	cfgA    conf.WsClient
	dirC    string // C 的 receive.dir
}

func newConflictRig(t *testing.T) *conflictRig {
	t.Helper()
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})
	dirC := t.TempDir()
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: dirC,
			Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})
	return &conflictRig{
		connect: connect, dirC: dirC,
		cfgA: conf.WsClient{Connect: connect, User: "a", Pass: testPassA, Email: "a@example.com", UUID: testUUIDA},
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFileStr(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func TestConflictSendRelay(t *testing.T) {
	const src = "0123456789" // 来件
	cases := []struct {
		name      string
		existing  string
		policy    string
		input     string // 提示时的输入
		wantDest  string // 收方 x.txt 最后的内容
		wantDup   string // 改名文件的内容, 空表示不应有
		wantErr   string
		wantLeft  bool // 收方目录里不应残留任何 .part
		unchanged bool
	}{
		{name: "identical, skip", existing: src, policy: ConflictSkip, wantDest: src},
		{name: "identical, rename", existing: src, policy: ConflictRename, wantDest: src, wantDup: src},
		{name: "identical, overwrite", existing: src, policy: ConflictOverwrite, wantDest: src},
		{name: "identical, resume means already complete", existing: src, policy: ConflictResume, wantDest: src},
		{name: "prefix, resume", existing: "01234", policy: ConflictResume, wantDest: src},
		{name: "differs, resume -> rename", existing: "abcde", policy: ConflictResume, wantDest: "abcde", wantDup: src},
		{name: "existing larger, resume -> rename", existing: src + "extra", policy: ConflictResume, wantDest: src + "extra", wantDup: src},
		{name: "differs, overwrite", existing: "abcde", policy: ConflictOverwrite, wantDest: src},
		{name: "differs, skip", existing: "abcde", policy: ConflictSkip, wantDest: "abcde"},
		{name: "ask: continue", existing: "01234", policy: ConflictAsk, input: "c\n", wantDest: src},
		{name: "ask: rename", existing: "abcde", policy: ConflictAsk, input: "r\n", wantDest: "abcde", wantDup: src},
		{name: "ask: skip", existing: "abcde", policy: ConflictAsk, input: "s\n", wantDest: "abcde"},
		{name: "ask: identical, overwrite", existing: src, policy: ConflictAsk, input: "o\n", wantDest: src},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rig := newConflictRig(t)
			writeFile(t, filepath.Join(rig.dirC, "x.txt"), c.existing)
			local := filepath.Join(t.TempDir(), "x.txt")
			writeFile(t, local, src)
			if c.input != "" {
				setConflictInput(t, c.input)
			}

			err := SendFiles(rig.cfgA, "c@example.com", []string{local}, ViaRelay, 1, c.policy)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want error containing %q, got %v", c.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("send: %v", err)
			}

			dest := filepath.Join(rig.dirC, "x.txt")
			if got := readFileStr(t, dest); got != c.wantDest {
				t.Fatalf("x.txt = %q, want %q", got, c.wantDest)
			}
			dup := dupName(dest, 1, runtime.GOOS)
			if c.wantDup == "" {
				if exists(dup) {
					t.Fatalf("unexpected renamed copy %s", dup)
				}
			} else if got := readFileStr(t, dup); got != c.wantDup {
				t.Fatalf("renamed copy = %q, want %q", got, c.wantDup)
			}
			if parts, _ := filepath.Glob(filepath.Join(rig.dirC, "*"+filePartSuffix)); len(parts) != 0 {
				t.Fatalf("left-over .part files: %v", parts)
			}
		})
	}
}

// 一个大写回答对之后所有冲突生效, 只问一次。
func TestConflictSendStickyAnswer(t *testing.T) {
	rig := newConflictRig(t)
	srcDir := filepath.Join(t.TempDir(), "d")
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		writeFile(t, filepath.Join(srcDir, n), "new "+n)
		writeFile(t, filepath.Join(rig.dirC, "d", n), "old "+n)
	}
	setConflictInput(t, "S\n") // 只有一行: 第二、三个冲突不能再去读输入
	if err := SendFiles(rig.cfgA, "c@example.com", []string{srcDir}, ViaRelay, 1, ConflictAsk); err != nil {
		t.Fatalf("send: %v", err)
	}
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		if got := readFileStr(t, filepath.Join(rig.dirC, "d", n)); got != "old "+n {
			t.Fatalf("%s = %q, must have been skipped", n, got)
		}
	}
}

// 没有同名文件时协商不该多出任何副作用, 也不该要求收方授权。
func TestConflictSendNoConflict(t *testing.T) {
	for _, policy := range []string{ConflictAsk, ConflictSkip, ConflictResume, ConflictOverwrite} {
		t.Run(policy, func(t *testing.T) {
			rig := newConflictRig(t) // 未授权覆盖: 没冲突的文件照样要能收
			local := filepath.Join(t.TempDir(), "fresh.txt")
			writeFile(t, local, "fresh")
			if policy == ConflictAsk {
				setConflictInput(t, "") // 不该被读
			}
			if err := SendFiles(rig.cfgA, "c@example.com", []string{local}, ViaRelay, 1, policy); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := readFileStr(t, filepath.Join(rig.dirC, "fresh.txt")); got != "fresh" {
				t.Fatalf("got %q", got)
			}
		})
	}
}

// 老版本收方不认识 Probe, 也不会回应: 发送方应退回旧的"收方自动改名", 而不是卡住或出错。
func TestProbeUnsupportedFallsBack(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		// 模拟老收方: 读一帧首部(当成一个空文件), 然后什么也不回、直到对端关闭。
		var head fileHead
		_ = readFrame(b, &head, fileFrameMax)
		buf := make([]byte, 1)
		_, _ = b.Read(buf)
	}()
	old := probeAckTimeout
	probeAckTimeout = 200 * time.Millisecond
	defer func() { probeAckTimeout = old }()
	_, err := probeOver(a, fileItem{name: "x", size: 3}, false, nil)
	if err != errProbeUnsupported {
		t.Fatalf("got %v, want errProbeUnsupported", err)
	}
}

// ---------- 端到端: -recv 经中继 ----------

func TestConflictRecvRelay(t *testing.T) {
	const remote = "0123456789"
	cases := []struct {
		name     string
		local    string
		policy   string
		input    string
		wantDest string
		wantDup  string
	}{
		{"identical, skip", remote, ConflictSkip, "", remote, ""},
		{"identical, rename", remote, ConflictRename, "", remote, remote},
		{"identical, overwrite", remote, ConflictOverwrite, "", remote, ""},
		{"identical, resume is complete", remote, ConflictResume, "", remote, ""},
		{"prefix, resume", "01234", ConflictResume, "", remote, ""},
		{"differs, resume -> rename", "abcde", ConflictResume, "", "abcde", remote},
		{"differs, overwrite", "abcde", ConflictOverwrite, "", remote, ""},
		{"local larger, resume -> rename", remote + "zz", ConflictResume, "", remote + "zz", remote},
		{"ask: continue", "01234", ConflictAsk, "c\n", remote, ""},
		{"ask: rename", "abcde", ConflictAsk, "r\n", "abcde", remote},
		{"ask: skip", "abcde", ConflictAsk, "s\n", "abcde", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			rig := newConflictRig(t)
			writeFile(t, filepath.Join(rig.dirC, "x.txt"), remote)
			local := t.TempDir()
			writeFile(t, filepath.Join(local, "x.txt"), c.local)
			if c.input != "" {
				setConflictInput(t, c.input)
			}
			if err := RecvFiles(rig.cfgA, "c@example.com:x.txt", local, ViaRelay, 1, c.policy); err != nil {
				t.Fatalf("recv: %v", err)
			}
			dest := filepath.Join(local, "x.txt")
			if got := readFileStr(t, dest); got != c.wantDest {
				t.Fatalf("x.txt = %q, want %q", got, c.wantDest)
			}
			dup := dupName(dest, 1, runtime.GOOS)
			if c.wantDup == "" {
				if exists(dup) {
					t.Fatalf("unexpected renamed copy %s", dup)
				}
			} else if got := readFileStr(t, dup); got != c.wantDup {
				t.Fatalf("renamed copy = %q, want %q", got, c.wantDup)
			}
			if parts, _ := filepath.Glob(filepath.Join(local, "*"+filePartSuffix)); len(parts) != 0 {
				t.Fatalf("left-over .part files: %v", parts)
			}
		})
	}
}

// ---------- 收方落盘: 续传失败要回滚 / 分块覆盖 ----------

func TestResumeIncomingRollsBack(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "r.bin")
	writeFile(t, dest, "01234")
	head := fileHead{Name: "r.bin", Size: 5, Offset: 5, Conflict: ConflictResume}

	// 尾部摘要不对: 已有文件必须回到原来的 5 字节。
	var wire bytes.Buffer
	wire.WriteString("56789")
	if err := writeFrame(&wire, fileTrailer{SHA256: "deadbeef"}); err != nil {
		t.Fatal(err)
	}
	if _, err := resumeIncoming(dest, &wire, head); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want a checksum error, got %v", err)
	}
	if got := readFileStr(t, dest); got != "01234" {
		t.Fatalf("existing file = %q after a failed resume, want it rolled back", got)
	}

	// 中途断了(只到 3 字节): 同样回滚。
	if _, err := resumeIncoming(dest, strings.NewReader("567"), head); err == nil {
		t.Fatal("a truncated resume must fail")
	}
	if got := readFileStr(t, dest); got != "01234" {
		t.Fatalf("existing file = %q after a truncated resume", got)
	}

	// 文件在协商之后变了长度: 不续。
	writeFile(t, dest, "0123456")
	if _, err := resumeIncoming(dest, strings.NewReader("56789"), head); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("want a 'changed' error, got %v", err)
	}
	if got := readFileStr(t, dest); got != "0123456" {
		t.Fatalf("a refused resume must not touch the file, got %q", got)
	}
}

// 分块覆盖: 成功时替换已有文件; 有一块出错时已有文件必须原封不动。
func TestChunkedOverwrite(t *testing.T) {
	body := make([]byte, 4*chunkMinSize)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(srcPath, body, 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, corrupt bool) (recvDir string, err error) {
		recvDir = t.TempDir()
		writeFile(t, filepath.Join(recvDir, "big.bin"), "precious old data")
		c := newAcceptPeer(t, nil)
		c.cfg.Receive = conf.ClientReceive{Dir: recvDir,
			Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}}
		a := newDialPeer(t)
		a.cfg.Email, a.cfg.UUID = "a@example.com", testUUIDA
		tr, terr := a.ensureTransport()
		if terr != nil {
			t.Fatalf("transport: %v", terr)
		}
		const token = "test-token-chunk-overwrite"
		c.tokens.put(token, directFilePort)
		sess, terr := a.connectPeer(tr, "c@example.com", peerEndpoint(c), c.fingerprint)
		if terr != nil {
			t.Fatalf("connect: %v", terr)
		}
		if terr := a.authenticateSession(sess, token, directFilePort, false, ""); terr != nil {
			t.Fatalf("authenticate: %v", terr)
		}
		items, _ := collectFiles([]string{srcPath})
		it := items[0]
		it.conflict = ConflictOverwrite
		chunks := planChunks(it.size, 4)
		tid, _ := newTransferID()
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i, ch := range chunks {
			wg.Add(1)
			go func(i int, ch chunkRange) {
				defer wg.Done()
				stream, oerr := a.openFileStream(sess)
				var e error = oerr
				if oerr == nil {
					var conn fileConn = stream
					if corrupt && i == 1 {
						conn = &corruptOnceConn{fileConn: stream}
					}
					_, e = sendFileOverRange(conn, it, ch.offset, ch.length, tid, i, len(chunks), nil)
				}
				if e != nil {
					mu.Lock()
					if err == nil {
						err = e
					}
					mu.Unlock()
				}
			}(i, ch)
		}
		wg.Wait()
		return recvDir, err
	}

	t.Run("replaces the existing file", func(t *testing.T) {
		dir, err := run(t, false)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "big.bin")); !bytes.Equal(got, body) {
			t.Fatal("the existing file was not replaced by the new content")
		}
		if parts, _ := filepath.Glob(filepath.Join(dir, "*")); len(parts) != 1 {
			t.Fatalf("expected only big.bin, got %v", parts)
		}
	})
	t.Run("a bad chunk leaves the existing file untouched", func(t *testing.T) {
		dir, err := run(t, true)
		if err == nil {
			t.Fatal("a corrupted chunk should fail the transfer")
		}
		if got := readFileStr(t, filepath.Join(dir, "big.bin")); got != "precious old data" {
			t.Fatalf("existing file = %q, must survive a failed overwrite", got)
		}
		if parts, _ := filepath.Glob(filepath.Join(dir, "*"+filePartSuffix)); len(parts) != 0 {
			t.Fatalf("left-over .part files: %v", parts)
		}
	})
}
