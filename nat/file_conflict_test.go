package nat

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
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

// 目标名上已有完整文件时: 一致 = 改名/覆盖/跳过, 不同 = 改名/跳过; 目标名不接受续传。
func TestDecideFixedPolicies(t *testing.T) {
	same := conflictInfo{name: "a", where: "locally", existing: 5, incoming: 5, same: true}
	differ := conflictInfo{name: "a", where: "locally", existing: 3, incoming: 5}
	cases := []struct {
		policy string
		ci     conflictInfo
		want   string
	}{
		{ConflictRename, same, ConflictRename},
		{ConflictSkip, differ, ConflictSkip},
		{ConflictOverwrite, differ, ConflictOverwrite},
		{ConflictResume, same, ConflictSkip}, // 已经完整了: 没什么可续的
		{ConflictResume, differ, ConflictRename},
	}
	for _, c := range cases {
		r, _ := newTestResolver(c.policy, "")
		got, err := r.decide(c.ci)
		if err != nil || got != c.want {
			t.Errorf("policy %s same=%v: got %q, %v; want %q", c.policy, c.ci.same, got, err, c.want)
		}
	}
}

func TestPromptOptions(t *testing.T) {
	same := conflictInfo{name: "a.zip", where: "on the peer", existing: 5, incoming: 5, same: true, hash: "abcdef0123456789"}
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
		// 目标名不接受续传, 内容不同也不提供覆盖(要覆盖用 -conflict overwrite)。
		{"differ: only rename and skip", differ, "c\no\nr\n", ConflictRename, false, []string{"differs", "[r]ename", "[s]kip"}, []string{"[c]ontinue", "[o]verwrite"}},
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

func TestDecidePart(t *testing.T) {
	r, _ := newTestResolver(ConflictResume, "")
	if got, _ := r.decidePart("a", "locally", 3, 10); got != ConflictResume {
		t.Errorf("policy resume: got %q", got)
	}
	for input, want := range map[string]string{"c\n": ConflictResume, "r\n": ConflictRename, "s\n": ConflictSkip, "\n": ConflictSkip} {
		r, out := newTestResolver(ConflictAsk, input)
		got, err := r.decidePart("a.zip", "on the peer", 3, 10)
		if err != nil || got != want {
			t.Errorf("input %q: got %q, %v; want %q", input, got, err, want)
		}
		if !strings.Contains(out.String(), "interrupted transfer") || !strings.Contains(out.String(), "[c]ontinue from 3B") {
			t.Errorf("prompt should describe the interrupted transfer, got:\n%s", out.String())
		}
	}
	r, _ = newTestResolver(ConflictAsk, "C\n")
	if _, err := r.decidePart("a", "locally", 3, 10); err != nil || r.policy != ConflictResume {
		t.Errorf("uppercase C should make continuing the policy, got policy %q err %v", r.policy, err)
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

// ---------- .part 的识别 ----------

const testTok = "0123456789abcdef"

func TestPartNameOK(t *testing.T) {
	good := []string{"x.zip." + testTok + ".part"}
	bad := []string{
		"x.zip.part",                                  // 没有 token
		"x.zip." + testTok[:8] + ".part",              // token 太短
		"x.zip." + strings.ToUpper(testTok) + ".part", // 只认小写十六进制
		"x.zip." + testTok + ".chunks.part",           // 分块传输的 .part 不能续
		"y.zip." + testTok + ".part",                  // 别的目标名的
		"../x.zip." + testTok + ".part",               // 带目录
		"x.zip." + testTok + ".txt",                   // 后缀不对
		"x.zip.zzzzzzzzzzzzzzzz.part",                 // 不是十六进制
	}
	for _, n := range good {
		if !partNameOK("x.zip", n) {
			t.Errorf("%q should be accepted", n)
		}
	}
	for _, n := range bad {
		if partNameOK("x.zip", n) {
			t.Errorf("%q must be rejected", n)
		}
	}
}

func TestFindResumablePart(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "x.bin")
	mk := func(tok, body string) string {
		p := dest + "." + tok + ".part"
		writeFile(t, p, body)
		return p
	}
	small := mk("1111111111111111", "ab")
	big := mk("2222222222222222", "abcdef")
	mk("3333333333333333", "")                                    // 空的: 没有续传价值
	mk("4444444444444444", "abcdefghijklmnop")                    // 比来件还长
	writeFile(t, dest+".5555555555555555.chunks.part", "abcdefg") // 分块的
	writeFile(t, filepath.Join(dir, "other.bin."+testTok+".part"), "abcdefg")

	p, size := findResumablePart(dest, 10)
	if p != big || size != 6 {
		t.Fatalf("got %q (%d), want the longest usable part %q", p, size, big)
	}
	// 正在被写的不能接管。
	activeParts.Store(big, struct{}{})
	defer activeParts.Delete(big)
	if p, _ := findResumablePart(dest, 10); p != small {
		t.Fatalf("a part in use must be skipped, got %q", p)
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

// conflictCase 一个协商场景: 收方(或取件时的本机)目录里事先摆好什么, 用什么策略, 结果应当是什么。
type conflictCase struct {
	name     string
	final    string // 目标名上已有的完整文件内容, 空 = 没有
	part     string // 上次中断留下的 .part 内容, 空 = 没有
	policy   string
	input    string // 提示时的输入
	wantDest string // 目标名上最后的内容, 空 = 不应存在
	wantDup  string // 改名文件的内容, 空 = 不应有
	wantPart bool   // 事先摆好的 .part 是否应仍在(没被接管)
}

const convSrc = "0123456789" // 来件

func conflictCases() []conflictCase {
	src := convSrc
	return []conflictCase{
		// 目标名上已有完整文件
		{name: "identical, skip", final: src, policy: ConflictSkip, wantDest: src},
		{name: "identical, rename", final: src, policy: ConflictRename, wantDest: src, wantDup: src},
		{name: "identical, overwrite", final: src, policy: ConflictOverwrite, wantDest: src},
		{name: "identical, resume means already complete", final: src, policy: ConflictResume, wantDest: src},
		{name: "differs, resume never continues the final name -> rename", final: "abcde", policy: ConflictResume, wantDest: "abcde", wantDup: src},
		{name: "differs prefix, final name still not resumed -> rename", final: "01234", policy: ConflictResume, wantDest: "01234", wantDup: src},
		{name: "differs, overwrite", final: "abcde", policy: ConflictOverwrite, wantDest: src},
		{name: "differs, skip", final: "abcde", policy: ConflictSkip, wantDest: "abcde"},
		{name: "ask: differs, rename", final: "abcde", policy: ConflictAsk, input: "r\n", wantDest: "abcde", wantDup: src},
		{name: "ask: differs, skip", final: "abcde", policy: ConflictAsk, input: "s\n", wantDest: "abcde"},
		{name: "ask: identical, overwrite", final: src, policy: ConflictAsk, input: "o\n", wantDest: src},
		// 中断留下的 .part
		{name: "part, resume", part: "01234", policy: ConflictResume, wantDest: src},
		{name: "part, ask continue", part: "01234", policy: ConflictAsk, input: "c\n", wantDest: src},
		{name: "part, ask restart", part: "01234", policy: ConflictAsk, input: "r\n", wantDest: src, wantPart: true},
		{name: "part, ask skip", part: "01234", policy: ConflictAsk, input: "s\n", wantPart: true},
		{name: "part with other content is not resumed", part: "abcde", policy: ConflictResume, wantDest: src, wantPart: true},
		{name: "part longer than the file is ignored", part: src + "more", policy: ConflictResume, wantDest: src, wantPart: true},
		{name: "part, resume, final differs -> finished part is renamed, final untouched", final: "abcde", part: "01234", policy: ConflictResume, wantDest: "abcde", wantDup: src},
		{name: "part, ask, final differs: rename then continue", final: "abcde", part: "01234", policy: ConflictAsk, input: "r\nc\n", wantDest: "abcde", wantDup: src},
		{name: "part, overwrite ignores it", part: "01234", policy: ConflictOverwrite, wantDest: src, wantPart: true},
		{name: "part, rename policy ignores it", part: "01234", policy: ConflictRename, wantDest: src, wantPart: true},
	}
}

func checkConflictCase(t *testing.T, c conflictCase, dir string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	dest := filepath.Join(dir, "x.txt")
	if c.wantDest == "" {
		if exists(dest) {
			t.Fatalf("x.txt should not exist, has %q", readFileStr(t, dest))
		}
	} else if got := readFileStr(t, dest); got != c.wantDest {
		t.Fatalf("x.txt = %q, want %q", got, c.wantDest)
	}
	dup := dupName(dest, 1)
	if c.wantDup == "" {
		if exists(dup) {
			t.Fatalf("unexpected renamed copy %s", dup)
		}
	} else if got := readFileStr(t, dup); got != c.wantDup {
		t.Fatalf("renamed copy = %q, want %q", got, c.wantDup)
	}
	// 事先摆好的 .part: 被续传接管就应该没了(已改成目标名), 否则原样还在。
	partPath := dest + "." + testTok + ".part"
	if c.part != "" {
		if c.wantPart {
			if got := readFileStr(t, partPath); got != c.part {
				t.Fatalf("the untouched .part changed to %q", got)
			}
		} else if exists(partPath) {
			t.Fatalf("the resumed .part should be gone, it was renamed to the target")
		}
	}
	// 除了事先摆好的那个, 不该留下别的 .part。
	all, _ := filepath.Glob(filepath.Join(dir, "*"+filePartSuffix))
	for _, p := range all {
		if p != partPath {
			t.Fatalf("unexpected left-over .part: %s", p)
		}
	}
}

func TestConflictSendRelay(t *testing.T) {
	for _, c := range conflictCases() {
		t.Run(c.name, func(t *testing.T) {
			rig := newConflictRig(t)
			dest := filepath.Join(rig.dirC, "x.txt")
			if c.final != "" {
				writeFile(t, dest, c.final)
			}
			if c.part != "" {
				writeFile(t, dest+"."+testTok+".part", c.part)
			}
			local := filepath.Join(t.TempDir(), "x.txt")
			writeFile(t, local, convSrc)
			if c.input != "" {
				setConflictInput(t, c.input)
			}
			err := SendFiles(rig.cfgA, "c@example.com", []string{local}, ViaRelay, 1, c.policy)
			checkConflictCase(t, c, rig.dirC, err)
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

// 没有同名文件、也没有 .part 时协商不该多出任何副作用。
func TestConflictSendNoConflict(t *testing.T) {
	for _, policy := range []string{ConflictAsk, ConflictSkip, ConflictResume, ConflictOverwrite} {
		t.Run(policy, func(t *testing.T) {
			rig := newConflictRig(t)
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

// 传到一半断线: 收方保留 .part, 下一次就能从断点续传, 最终内容与来件一致。
func TestInterruptedSendCanBeResumed(t *testing.T) {
	rig := newConflictRig(t)
	body := strings.Repeat("0123456789", 100000) // 1MB
	local := filepath.Join(t.TempDir(), "big.bin")
	writeFile(t, local, body)

	// 用底层接口模拟中断: 首部声明整份大小, 只发一半就断开(不发尾部摘要)。
	client, err := dialSender(conf.WsClient{Connect: rig.connect, User: "a", Pass: testPassA, Email: "a@example.com", UUID: testUUIDA}, "test")
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := openRelayConn(client.client, "c@example.com", "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	half := len(body) / 2
	if err := writeFrame(conn, fileHead{Name: "big.bin", Size: int64(len(body)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(body[:half])); err != nil {
		t.Fatal(err)
	}
	// 发送方整个掉线(进程被杀/断网): 服务端 B 发现后通知收方, 收方才知道这次传输断了。
	client.close()

	// 等收方把断掉的这条收尾, 留下 .part。
	var parts []string
	for i := 0; i < 100 && len(parts) == 0; i++ {
		parts, _ = filepath.Glob(filepath.Join(rig.dirC, "big.bin.*"+filePartSuffix))
		time.Sleep(50 * time.Millisecond)
	}
	if len(parts) != 1 {
		t.Fatalf("the interrupted transfer should leave exactly one .part, got %v", parts)
	}
	if exists(filepath.Join(rig.dirC, "big.bin")) {
		t.Fatal("an interrupted transfer must not create the target name")
	}
	// 收方要等服务端的断线通知才放开这个 .part(此前它仍算「正在写」, 不能被接管)。
	var got string
	for i := 0; i < 100 && got == ""; i++ {
		got, _ = findResumablePart(filepath.Join(rig.dirC, "big.bin"), int64(len(body)))
		time.Sleep(50 * time.Millisecond)
	}
	if got == "" {
		t.Fatal("the interrupted .part never became resumable")
	}

	if err := SendFiles(rig.cfgA, "c@example.com", []string{local}, ViaRelay, 1, ConflictResume); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := readFileStr(t, filepath.Join(rig.dirC, "big.bin")); got != body {
		t.Fatalf("resumed file differs from the source (%d vs %d bytes)", len(got), len(body))
	}
	if exists(parts[0]) {
		t.Fatal("the .part should have been renamed to the target")
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
	for _, c := range conflictCases() {
		t.Run(c.name, func(t *testing.T) {
			rig := newConflictRig(t)
			writeFile(t, filepath.Join(rig.dirC, "x.txt"), convSrc) // C 共享的来件
			local := t.TempDir()
			dest := filepath.Join(local, "x.txt")
			if c.final != "" {
				writeFile(t, dest, c.final)
			}
			if c.part != "" {
				writeFile(t, dest+"."+testTok+".part", c.part)
			}
			if c.input != "" {
				setConflictInput(t, c.input)
			}
			err := RecvFiles(rig.cfgA, "c@example.com:x.txt", local, ViaRelay, 1, c.policy)
			checkConflictCase(t, c, local, err)
		})
	}
}

// ---------- 收方落盘 ----------

func TestResumeIncoming(t *testing.T) {
	newHead := func(dest, part string, offset int64, size int) fileHead {
		return fileHead{Name: filepath.Base(dest), Size: int64(size), Offset: offset, Conflict: ConflictResume, ResumePart: part}
	}
	wire := func(tail, sum string) *bytes.Buffer {
		var w bytes.Buffer
		w.WriteString(tail)
		if sum != "" {
			if err := writeFrame(&w, fileTrailer{SHA256: sum}); err != nil {
				t.Fatal(err)
			}
		}
		return &w
	}
	tailSum := func(s string) string {
		p := filepath.Join(t.TempDir(), "s")
		writeFile(t, p, s)
		h, _ := hashFilePrefix(p, int64(len(s)))
		return h
	}

	t.Run("completes and renames to the target", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "r.bin")
		partName := "r.bin." + testTok + ".part"
		writeFile(t, dest+"."+testTok+".part", "01234")
		final, err := resumeIncoming(dest, wire("56789", tailSum("56789")), newHead(dest, partName, 5, 5))
		if err != nil || final != dest {
			t.Fatalf("got %q, %v", final, err)
		}
		if got := readFileStr(t, dest); got != "0123456789" {
			t.Fatalf("target = %q", got)
		}
		if exists(dest + "." + testTok + ".part") {
			t.Fatal(".part should be gone")
		}
	})

	t.Run("never overwrites an existing target", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "r.bin")
		writeFile(t, dest, "precious")
		writeFile(t, dest+"."+testTok+".part", "01234")
		final, err := resumeIncoming(dest, wire("56789", tailSum("56789")), newHead(dest, "r.bin."+testTok+".part", 5, 5))
		if err != nil {
			t.Fatal(err)
		}
		if final == dest || readFileStr(t, dest) != "precious" {
			t.Fatalf("the existing target must be untouched, saved as %q", final)
		}
		if readFileStr(t, final) != "0123456789" {
			t.Fatalf("finished file = %q", readFileStr(t, final))
		}
	})

	t.Run("bad tail checksum truncates back and keeps the part", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "r.bin")
		part := dest + "." + testTok + ".part"
		writeFile(t, part, "01234")
		_, err := resumeIncoming(dest, wire("56789", "deadbeef"), newHead(dest, "r.bin."+testTok+".part", 5, 5))
		if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("want a checksum error, got %v", err)
		}
		if got := readFileStr(t, part); got != "01234" {
			t.Fatalf(".part = %q, want it back at its original content", got)
		}
		if exists(dest) {
			t.Fatal("the target must not be created")
		}
	})

	t.Run("a dropped connection keeps what arrived", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "r.bin")
		part := dest + "." + testTok + ".part"
		writeFile(t, part, "01234")
		if _, err := resumeIncoming(dest, strings.NewReader("567"), newHead(dest, "r.bin."+testTok+".part", 5, 5)); err == nil {
			t.Fatal("a truncated resume must fail")
		}
		if got := readFileStr(t, part); got != "01234567" {
			t.Fatalf(".part = %q, want the received bytes kept so the next run can continue", got)
		}
		if exists(dest) {
			t.Fatal("the target must not be created")
		}
	})

	t.Run("refuses when the part changed size", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "r.bin")
		part := dest + "." + testTok + ".part"
		writeFile(t, part, "0123456")
		_, err := resumeIncoming(dest, wire("56789", tailSum("56789")), newHead(dest, "r.bin."+testTok+".part", 5, 5))
		if err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("want a 'changed' error, got %v", err)
		}
		if got := readFileStr(t, part); got != "0123456" {
			t.Fatalf("a refused resume must not touch the part, got %q", got)
		}
	})

	t.Run("refuses names that are not this target's part", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "r.bin")
		writeFile(t, filepath.Join(dir, "victim.txt"), "secret")
		for _, name := range []string{"victim.txt", "../victim.txt", "r.bin.part", ""} {
			if _, err := resumeIncoming(dest, wire("x", ""), newHead(dest, name, 6, 1)); err == nil {
				t.Errorf("resume part %q must be refused", name)
			}
		}
		if got := readFileStr(t, filepath.Join(dir, "victim.txt")); got != "secret" {
			t.Fatalf("victim file was modified: %q", got)
		}
	})

	t.Run("refuses a part that is being written", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "r.bin")
		part := dest + "." + testTok + ".part"
		writeFile(t, part, "01234")
		activeParts.Store(part, struct{}{})
		defer activeParts.Delete(part)
		if _, err := resumeIncoming(dest, wire("56789", tailSum("56789")), newHead(dest, "r.bin."+testTok+".part", 5, 5)); err == nil {
			t.Fatal("a part in use must not be taken over")
		}
	})
}

// 传输中断时已收到的部分要留在 .part 里(续传的前提); 一个字节都没收到则不留。
func TestInterruptedReceiveKeepsPart(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "a.bin")
	if _, _, err := writeIncoming(dest, strings.NewReader("abc"), fileHead{Name: "a.bin", Size: 10}); err == nil {
		t.Fatal("a short body must fail")
	}
	parts, _ := filepath.Glob(dest + ".*" + filePartSuffix)
	if len(parts) != 1 || readFileStr(t, parts[0]) != "abc" {
		t.Fatalf("want one .part holding the received bytes, got %v", parts)
	}
	if !partNameOK("a.bin", filepath.Base(parts[0])) {
		t.Fatalf("the kept part %q must be recognisable as resumable", filepath.Base(parts[0]))
	}
	if exists(dest) {
		t.Fatal("no target on a failed transfer")
	}

	empty := filepath.Join(dir, "e.bin")
	if _, _, err := writeIncoming(empty, strings.NewReader(""), fileHead{Name: "e.bin", Size: 10}); err == nil {
		t.Fatal("an empty body must fail")
	}
	if left, _ := filepath.Glob(empty + ".*" + filePartSuffix); len(left) != 0 {
		t.Fatalf("an empty .part is useless and must be removed: %v", left)
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
