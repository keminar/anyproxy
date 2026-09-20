package nat

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// 同名文件与断点续传的协商。
//
// 两件互相独立的事, 都发生在真正传数据之前:
//
//  1. 目标文件名已存在(收方已经有一份完整的同名文件): 先比对内容(SHA-256), 再问怎么办。
//     内容一致:  改名重传 / 覆盖 / 跳过
//     内容不同:  改名重传 / 跳过
//     「改名」指新传的文件换个名字保存(见 dupName/claimName), 已有文件原封不动。目标文件名
//     **不接受续传**: 传输总是先写 .part、收全并校验后才改成目标名, 目标名上的一定是完整文件。
//
//  2. 上次中断的传输留下了 .part 临时文件(x.zip.<16位十六进制>.part): 如果它恰好是新文件的
//     开头一段(哈希核对过), 可以从断点续传, 收完再改成目标名(重名时照常走 claimName 改名, 不覆盖)。
//
// 覆盖会改动收方已有的文件, 只在使用者明确选择时发生(allow 名单里的发送方本来就有写这个
// 目录的权限, 不再单设开关)。
//
//	-send: 先开一条只带 fileHead{Probe} 的流探一下(收方回目标名与可续传 .part 的情况, 必要时
//	       再回哈希), 发送方在本地比对、问用户, 再带着决定(fileHead.Conflict)发数据。
//	-recv: 本机自己 stat/找 .part, 需要对端哈希时用 pull 的 "hash" 操作取, 决定通过 recvOpts
//	       传给落盘逻辑。

// 同名冲突的处理方式, 同时也是命令行 -conflict 的取值。
const (
	ConflictAsk       = "ask"       // 逐个询问(终端交互时的默认)
	ConflictRename    = "rename"    // 自动改名保存, 不问不探测(非交互时的默认, 也是旧版行为)
	ConflictOverwrite = "overwrite" // 覆盖
	ConflictSkip      = "skip"      // 跳过
	ConflictResume    = "resume"    // 有可续传的 .part 就续传; 目标名上已有一致的完整文件则跳过, 内容不同则改名
)

// ParseConflict 校验 -conflict 的取值。空串交给调用方按环境决定默认。
func ParseConflict(s string) (string, error) {
	switch s {
	case "", ConflictAsk, ConflictRename, ConflictOverwrite, ConflictSkip, ConflictResume:
		return s, nil
	}
	return "", fmt.Errorf("-conflict %q: want ask, rename, overwrite, skip or resume", s)
}

const probeVersion = 1

// probeAckTimeout 等收方回第一帧(只是一次 stat, 应当立刻回)的上限。老版本收方看不懂
// Probe、不会回这一帧, 超时后按"对端不支持"退回旧的自动改名。哈希那几帧不受此限——
// 对端要把整个文件读一遍, 大文件要很久。
var probeAckTimeout = 10 * time.Second

// errProbeUnsupported 对端没有按协议回应探测(多半是老版本)。
var errProbeUnsupported = errors.New("peer does not support the same-name check")

// fileProbe 收方对探测的应答。V 用来把它与老版本的 fileReply 区分开(老版本回的是
// {"err":...}, 没有 v)。
//
// 帧序: 第一帧带 Exists/Size(目标名上的完整文件)与 Part/PartSize(可续传的 .part);
// 之后按需各一帧只带 SHA256: 先是目标名文件的(Exists 且 Size <= 来件大小时), 再是 .part 的
// (Part 非空时)。发送方从第一帧就能知道后面还有几帧。
type fileProbe struct {
	V        int    `json:"v,omitempty"`
	Err      string `json:"err,omitempty"`
	Exists   bool   `json:"exists,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Part     string `json:"part,omitempty"` // 可续传 .part 的文件名(不含目录)
	PartSize int64  `json:"partSize,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// probeResult 探测结果。SHA256 仅在 Exists 且 Size <= 来件大小时有值, PartSHA256 仅在 Part
// 非空时有值, 各自是对应文件整份的哈希。
type probeResult struct {
	Exists     bool
	Size       int64
	SHA256     string
	Part       string
	PartSize   int64
	PartSHA256 string
}

// recvOpts 落盘逻辑(recvFileOver)的调用方给定的策略。
type recvOpts struct {
	// local 为 true 时(-recv 取件), 冲突处理由本机的决定(conflict/resumePart/resumeAt)说了算,
	// 忽略对端首部里带的——被取的一侧无权决定本机怎么处理本机的文件。
	local      bool
	conflict   string
	resumePart string // 续传的 .part 文件名(不含目录)
	resumeAt   int64
}

// probeOver 在一条已建好的文件通道上探测收方的同名文件与可续传的 .part, 用完即关。noHash 为
// true 时只问存不存在、多大, 不让收方去算哈希(也不找 .part)。
func probeOver(conn fileConn, it fileItem, noHash bool, notify func(string)) (*probeResult, error) {
	defer conn.Close()
	// Size 留 0: 老版本收方会把它当成一个空文件的首部, 等不到尾部就清理掉, 不会落下东西。
	if err := writeFrame(conn, fileHead{Name: it.name, Mode: it.mode, Probe: true, ProbeSize: it.size, ProbeNoHash: noHash}); err != nil {
		return nil, fmt.Errorf("send probe: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(probeAckTimeout))
	var p fileProbe
	err := readFrame(conn, &p, fileFrameMax)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, errProbeUnsupported
	}
	if p.Err != "" {
		return nil, errors.New(p.Err)
	}
	if p.V != probeVersion {
		return nil, errProbeUnsupported
	}
	res := &probeResult{Exists: p.Exists, Size: p.Size, Part: p.Part, PartSize: p.PartSize}
	readHash := func(what string) (string, error) {
		if notify != nil {
			notify(fmt.Sprintf("checking the %s of %s on the peer...", what, it.name))
		}
		var h fileProbe
		if err := readFrame(conn, &h, fileFrameMax); err != nil {
			return "", fmt.Errorf("read the peer's hash of the %s: %w", what, err)
		}
		if h.Err != "" {
			return "", errors.New(h.Err)
		}
		return h.SHA256, nil
	}
	if p.Exists && !noHash && p.Size <= it.size {
		if res.SHA256, err = readHash("existing file"); err != nil {
			return nil, err
		}
	}
	if p.Part != "" {
		if res.PartSHA256, err = readHash("interrupted transfer"); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// serveProbe 收方处理一次探测: stat 目标名, 找可续传的 .part, 回第一帧, 再按需算哈希回后续帧。
func serveProbe(conn io.Writer, dir string, head fileHead, logf func(string, ...interface{})) {
	fail := func(msg string) { _ = writeFrame(conn, fileProbe{V: probeVersion, Err: msg}) }
	dest, err := safeJoin(dir, head.Name)
	if err != nil {
		fail(fmt.Sprintf("rejected name %q: %v", head.Name, err))
		return
	}
	out := fileProbe{V: probeVersion}
	if info, err := os.Stat(dest); err == nil && info.Mode().IsRegular() {
		out.Exists, out.Size = true, info.Size()
	} // 不存在, 或是个目录之类占着名字的东西(claimName 会绕开它): 没有可比对的
	var partPath string
	if !head.ProbeNoHash {
		if p, size := findResumablePart(dest, head.ProbeSize); p != "" {
			partPath = p
			out.Part, out.PartSize = partName(p), size
		}
	}
	if err := writeFrame(conn, out); err != nil {
		return
	}
	// 已有文件比来件还大: 一定不同, 不必费力算哈希。
	if out.Exists && !head.ProbeNoHash && out.Size <= head.ProbeSize {
		sum, err := hashFilePrefix(dest, out.Size)
		if err != nil {
			logf("probe %s: hash: %v", head.Name, err)
			fail("cannot read the existing file to compare")
			return
		}
		if err := writeFrame(conn, fileProbe{V: probeVersion, SHA256: sum}); err != nil {
			return
		}
	}
	if partPath != "" {
		sum, err := hashFilePrefix(partPath, out.PartSize)
		if err != nil {
			logf("probe %s: hash part: %v", head.Name, err)
			fail("cannot read the interrupted transfer to compare")
			return
		}
		_ = writeFrame(conn, fileProbe{V: probeVersion, SHA256: sum})
	}
}

// hashFilePrefix 算一个文件前 n 字节的 SHA-256。文件不足 n 字节视为出错。
func hashFilePrefix(path string, n int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	got, err := io.CopyBuffer(h, io.LimitReader(f, n), make([]byte, fileCopyBuf))
	if err != nil {
		return "", err
	}
	if got != n {
		return "", fmt.Errorf("file is shorter than expected: %d of %d bytes", got, n)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------- 决策 ----------

// conflictInfo 目标名上已有完整文件的冲突事实, 交给 conflictResolver 决定怎么办。
type conflictInfo struct {
	name     string
	where    string // "on the peer" / "locally", 只用于提示
	existing int64  // 已有文件大小
	incoming int64  // 来件大小
	same     bool   // 内容完全一致
	hash     string // 已有文件的哈希, 仅用于展示
}

// conflictResolver 按策略(必要时询问用户)决定同名文件怎么处理。
type conflictResolver struct {
	policy string
	in     *bufio.Reader
	out    io.Writer

	warnedUnsupported bool
}

// newConflictResolver 建一个决策器。policy 为空时: 标准输入是终端就逐个询问, 否则自动改名
// (脚本/管道里没人可问, 且这与旧版行为一致)。
func newConflictResolver(policy string, in *os.File, out io.Writer) (*conflictResolver, error) {
	policy, err := ParseConflict(policy)
	if err != nil {
		return nil, err
	}
	if policy == "" {
		policy = ConflictRename
		if isTerminal(in) {
			policy = ConflictAsk
		}
	}
	return &conflictResolver{policy: policy, in: bufio.NewReader(in), out: out}, nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// decide 决定目标名上已有完整文件时怎么办, 返回 ConflictRename / ConflictOverwrite / ConflictSkip。
func (r *conflictResolver) decide(ci conflictInfo) (string, error) {
	if r.policy == ConflictAsk {
		act, sticky, err := r.prompt(ci)
		if err != nil {
			return "", err
		}
		if sticky {
			r.policy = act
		}
		return act, nil
	}
	if r.policy == ConflictResume { // 目标名不接受续传: 一致 = 已经完整, 不同 = 另存
		if ci.same {
			fmt.Fprintf(r.out, "%s: already complete %s, skipping\n", ci.name, ci.where)
			return ConflictSkip, nil
		}
		return ConflictRename, nil
	}
	return r.policy, nil // rename / skip / overwrite
}

// decidePart 决定发现了一个可续传的 .part 时怎么办, 返回 ConflictResume(续传) / ConflictRename
// (放弃它、从头传) / ConflictSkip。
func (r *conflictResolver) decidePart(name, where string, have, total int64) (string, error) {
	if r.policy == ConflictResume {
		return ConflictResume, nil
	}
	if r.policy != ConflictAsk {
		return ConflictRename, nil // 其它策略下不探测 .part, 走到这里只是保险
	}
	fmt.Fprintf(r.out, "\nan interrupted transfer of %q was found %s: %s of %s already received, matching the start of this file.\n",
		name, where, humanBytes(have), humanBytes(total))
	act, sticky, err := r.ask([]option{
		{'c', ConflictResume, fmt.Sprintf("[c]ontinue from %s", humanBytes(have))},
		{'r', ConflictRename, "[r]estart from scratch"},
		{'s', ConflictSkip, "[s]kip (default)"},
	})
	if err != nil {
		return "", err
	}
	if sticky {
		r.policy = act
	}
	return act, nil
}

// prompt 向用户描述目标名上的冲突并读一个选择。大写字母表示对之后所有冲突都这样处理(sticky)。
// 直接回车 = 跳过: 提示的是"已有数据可能被动到", 默认走最不具破坏性、也不多耗流量的一项。
func (r *conflictResolver) prompt(ci conflictInfo) (act string, sticky bool, err error) {
	fmt.Fprintf(r.out, "\n%q already exists %s (%s).\n", ci.name, ci.where, humanBytes(ci.existing))
	opts := []option{{'r', ConflictRename, "[r]ename and transfer again"}}
	if ci.same {
		fmt.Fprintf(r.out, "  identical to the incoming file (sha256 %s).\n", short(ci.hash))
		opts = append(opts, option{'o', ConflictOverwrite, "[o]verwrite"})
	} else {
		fmt.Fprintf(r.out, "  content differs from the incoming file (existing %s, incoming %s).\n",
			humanBytes(ci.existing), humanBytes(ci.incoming))
	}
	opts = append(opts, option{'s', ConflictSkip, "[s]kip (default)"})
	return r.ask(opts)
}

type option struct {
	key byte
	act string
	txt string
}

// ask 显示选项并读一个回答。
func (r *conflictResolver) ask(opts []option) (act string, sticky bool, err error) {
	var parts []string
	for _, o := range opts {
		parts = append(parts, o.txt)
	}
	for {
		fmt.Fprintf(r.out, "  %s   (uppercase = same for all later conflicts): ", strings.Join(parts, "  "))
		line, rerr := r.in.ReadString('\n')
		line = strings.TrimSpace(line)
		if rerr != nil && line == "" {
			return "", false, fmt.Errorf("no answer for the same-name prompt: %w", rerr)
		}
		if line == "" {
			return ConflictSkip, false, nil
		}
		c := line[0]
		lower := c | 0x20
		for _, o := range opts {
			if o.key == lower {
				return o.act, c != lower, nil
			}
		}
		fmt.Fprintf(r.out, "  please answer with one of the letters shown\n")
	}
}

// prepareSend 在发一个文件之前做协商, 并把决定写进 it(conflict/resumePart/resumeAt)。skip 为
// true 表示这个文件不要发了。probe 是「在一条新通道上探测收方」的闭包(直连/中继各自实现)。
func (r *conflictResolver) prepareSend(it *fileItem, probe func(it fileItem, noHash bool) (*probeResult, error)) (skip bool, err error) {
	switch r.policy {
	case ConflictRename:
		return false, nil // 收方自己会改名, 不需要多一趟往返
	case ConflictOverwrite:
		// 不探测直接带覆盖标记发: 收方对不存在的目标会当成普通传输。省掉每个文件一趟往返,
		// 也省掉对端算哈希。
		it.conflict = ConflictOverwrite
		return false, nil
	}
	// ask / skip / resume 都要先探测。skip 只问有没有同名, 不比内容、不找 .part。
	pr, err := probe(*it, r.policy == ConflictSkip)
	if errors.Is(err, errProbeUnsupported) {
		if !r.warnedUnsupported {
			r.warnedUnsupported = true
			fmt.Fprintf(r.out, "note: the peer is too old to check for same-name files; it will rename on conflict\n")
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}

	// 第一步: 目标名上已有完整文件。
	if pr.Exists {
		ci := conflictInfo{name: it.name, where: "on the peer", existing: pr.Size, incoming: it.size}
		if pr.SHA256 != "" {
			local, err := hashFilePrefix(it.path, pr.Size)
			if err != nil {
				return false, fmt.Errorf("hash %s: %w", it.path, err)
			}
			ci.hash = local
			ci.same = local == pr.SHA256 && pr.Size == it.size
		}
		act, err := r.decide(ci)
		if err != nil {
			return false, err
		}
		switch act {
		case ConflictSkip:
			return true, nil
		case ConflictOverwrite:
			it.conflict = ConflictOverwrite
			return false, nil // 覆盖是从头重传, 不用续
		}
	}

	// 第二步: 上次中断留下的 .part(前缀哈希对得上才算)。
	if pr.Part != "" && pr.PartSize > 0 && pr.PartSize < it.size {
		local, err := hashFilePrefix(it.path, pr.PartSize)
		if err != nil {
			return false, fmt.Errorf("hash %s: %w", it.path, err)
		}
		if local == pr.PartSHA256 {
			act, err := r.decidePart(it.name, "on the peer", pr.PartSize, it.size)
			if err != nil {
				return false, err
			}
			switch act {
			case ConflictSkip:
				return true, nil
			case ConflictResume:
				it.conflict, it.resumePart, it.resumeAt = ConflictResume, pr.Part, pr.PartSize
			}
		}
	}
	return false, nil
}

// pullPlan 取一个文件之前协商出的做法。
type pullPlan struct {
	act        string // ConflictRename(按默认走) / ConflictOverwrite / ConflictResume / ConflictSkip
	resumePart string // act 为 ConflictResume 时: 本机 .part 的文件名
	resumeAt   int64
}

// preparePull 取一个文件之前的协商。本机没有冲突时返回默认做法。remoteHash 取对端文件前 n 字节的哈希。
func (r *conflictResolver) preparePull(dir string, e filePullEntry, remoteHash func(n int64) (string, error)) (pullPlan, error) {
	def := pullPlan{act: ConflictRename}
	if r.policy == ConflictRename {
		return def, nil
	}
	dest, err := safeJoin(dir, e.Name)
	if err != nil {
		return def, nil // 名字不合法的话落盘时会如实报错, 这里不抢着报
	}
	needHash := r.policy != ConflictSkip && r.policy != ConflictOverwrite

	// 第一步: 目标名上已有完整文件。
	if info, err := os.Stat(dest); err == nil && info.Mode().IsRegular() {
		ci := conflictInfo{name: e.Name, where: "locally", existing: info.Size(), incoming: e.Size}
		if needHash && info.Size() <= e.Size {
			fmt.Fprintf(r.out, "checking the existing %s...\n", e.Name)
			local, err := hashFilePrefix(dest, info.Size())
			if err != nil {
				return def, fmt.Errorf("hash %s: %w", dest, err)
			}
			remote, err := remoteHash(info.Size())
			if err != nil {
				return def, fmt.Errorf("ask the peer to hash %s: %w", e.Path, err)
			}
			ci.hash = local
			ci.same = local == remote && info.Size() == e.Size
		}
		act, err := r.decide(ci)
		if err != nil {
			return def, err
		}
		switch act {
		case ConflictSkip:
			return pullPlan{act: ConflictSkip}, nil
		case ConflictOverwrite:
			return pullPlan{act: ConflictOverwrite}, nil
		}
	}

	// 第二步: 上次中断留下的 .part。
	if needHash {
		if p, size := findResumablePart(dest, e.Size); p != "" {
			fmt.Fprintf(r.out, "checking the interrupted transfer of %s...\n", e.Name)
			local, err := hashFilePrefix(p, size)
			if err != nil {
				return def, fmt.Errorf("hash %s: %w", p, err)
			}
			remote, err := remoteHash(size)
			if err != nil {
				return def, fmt.Errorf("ask the peer to hash %s: %w", e.Path, err)
			}
			if local == remote {
				act, err := r.decidePart(e.Name, "locally", size, e.Size)
				if err != nil {
					return def, err
				}
				switch act {
				case ConflictSkip:
					return pullPlan{act: ConflictSkip}, nil
				case ConflictResume:
					return pullPlan{act: ConflictResume, resumePart: partName(p), resumeAt: size}, nil
				}
			}
		}
	}
	return def, nil
}

// skippedNote 结束语里附注跳过了几个文件。
func skippedNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d skipped)", n)
}

// conflictIn 询问用户时读的输入; 测试里换成管道。
var conflictIn = os.Stdin
