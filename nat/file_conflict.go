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

// 同名文件的协商。
//
// 落盘的一侧(收方)发现目标已存在时, 默认做法是自动改名保存(见 dupName/claimName), 不碰
// 已有文件。这里在此之上让**人**来决定: 先比对内容(SHA-256), 再问是改名重传、覆盖、续传
// 还是跳过。
//
//	内容一致:   改名重传 / 覆盖 / 跳过
//	内容不同:   续传(已有文件恰好是新文件的开头一段时) / 改名重传 / 跳过
//
// 「改名」指的是新传的文件换一个名字保存, 已有文件原封不动; 覆盖/续传才会改动已有文件, 且
// 只在使用者明确选择时发生(allow 名单里的发送方本来就有写这个目录的权限, 不再单设开关)。
//
// 协商发生在真正传数据之前:
//
//	-send: 先开一条只带 fileHead{Probe} 的流探一下(收方回 stat 结果, 必要时再回已有文件的
//	       哈希), 发送方在本地比对、问用户, 再带着决定(fileHead.Conflict)发数据。
//	-recv: 本机自己 stat, 需要对端哈希时用 pull 的 "hash" 操作取, 决定通过 recvOpts 传给落盘逻辑。

// 同名冲突的处理方式, 同时也是命令行 -conflict 的取值。
const (
	ConflictAsk       = "ask"       // 逐个询问(终端交互时的默认)
	ConflictRename    = "rename"    // 自动改名保存, 不问不探测(非交互时的默认, 也是旧版行为)
	ConflictOverwrite = "overwrite" // 覆盖
	ConflictSkip      = "skip"      // 跳过
	ConflictResume    = "resume"    // 能续传就续传(内容一致则视为已完成、跳过), 不能续传就改名
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
// Probe、不会回这一帧, 超时后按"对端不支持"退回旧的自动改名。哈希那一帧不受此限——
// 对端要把整个已有文件读一遍, 大文件要很久。
var probeAckTimeout = 10 * time.Second

// errProbeUnsupported 对端没有按协议回应探测(多半是老版本)。
var errProbeUnsupported = errors.New("peer does not support the same-name check")

// fileProbe 收方对探测的应答, 两帧共用: 第一帧带 Exists/Size, 第二帧(仅在已有
// 文件不比来件大时)带 SHA256。V 用来把它与老版本的 fileReply 区分开(老版本回的是
// {"err":...}, 没有 v)。
type fileProbe struct {
	V      int    `json:"v,omitempty"`
	Err    string `json:"err,omitempty"`
	Exists bool   `json:"exists,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// probeResult 探测结果。SHA256 仅在 Exists 且 Size <= 来件大小时有值, 是收方已有文件整份的哈希。
type probeResult struct {
	Exists bool
	Size   int64
	SHA256 string
}

// recvOpts 落盘逻辑(recvFileOver)的调用方给定的策略。
type recvOpts struct {
	// local 为 true 时(-recv 取件), 冲突处理由本机的决定(conflict/resumeAt)说了算, 忽略对端
	// 首部里带的——被取的一侧无权决定本机怎么处理本机的文件。
	local    bool
	conflict string
	resumeAt int64
}

// probeOver 在一条已建好的文件通道上探测收方是否已有同名文件, 用完即关。noHash 为 true 时
// 只问存不存在、多大, 不让收方去算哈希。
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
	res := &probeResult{Exists: p.Exists, Size: p.Size}
	if p.Exists && !noHash && p.Size <= it.size {
		if notify != nil {
			notify(fmt.Sprintf("checking the existing %s on the peer...", it.name))
		}
		var h fileProbe
		if err := readFrame(conn, &h, fileFrameMax); err != nil {
			return nil, fmt.Errorf("read the peer's hash of the existing file: %w", err)
		}
		if h.Err != "" {
			return nil, errors.New(h.Err)
		}
		res.SHA256 = h.SHA256
	}
	return res, nil
}

// serveProbe 收方处理一次探测: stat 目标, 回第一帧, 需要时再算哈希回第二帧。
func serveProbe(conn io.Writer, dir string, head fileHead, logf func(string, ...interface{})) {
	fail := func(msg string) { _ = writeFrame(conn, fileProbe{V: probeVersion, Err: msg}) }
	dest, err := safeJoin(dir, head.Name)
	if err != nil {
		fail(fmt.Sprintf("rejected name %q: %v", head.Name, err))
		return
	}
	info, err := os.Stat(dest)
	if err != nil || !info.Mode().IsRegular() {
		// 不存在(或是个目录之类占着名字的东西, claimName 会绕开它): 对发送方来说没有可协商的。
		_ = writeFrame(conn, fileProbe{V: probeVersion})
		return
	}
	if err := writeFrame(conn, fileProbe{V: probeVersion, Exists: true, Size: info.Size()}); err != nil {
		return
	}
	if head.ProbeNoHash || info.Size() > head.ProbeSize {
		return // 已有文件比来件还大: 一定不同、也不可能续传, 不必费力算哈希
	}
	sum, err := hashFilePrefix(dest, info.Size())
	if err != nil {
		logf("probe %s: hash: %v", head.Name, err)
		fail("cannot read the existing file to compare")
		return
	}
	_ = writeFrame(conn, fileProbe{V: probeVersion, SHA256: sum})
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

// conflictInfo 一次同名冲突的事实, 交给 conflictResolver 决定怎么办。
type conflictInfo struct {
	name      string
	where     string // "on the peer" / "locally", 只用于提示
	existing  int64  // 已有文件大小
	incoming  int64  // 来件大小
	same      bool   // 内容完全一致
	resumable bool   // 已有文件恰好是来件的开头一段(且更短、非空)
	hash      string // 已有文件(或其前缀)的哈希, 仅用于展示
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

// decide 返回要对这个文件采取的动作: ConflictRename / ConflictOverwrite / ConflictSkip / ConflictResume。
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
	switch r.policy {
	case ConflictOverwrite:
		return ConflictOverwrite, nil
	case ConflictResume:
		switch {
		case ci.same:
			fmt.Fprintf(r.out, "%s: already complete %s, skipping\n", ci.name, ci.where)
			return ConflictSkip, nil
		case ci.resumable:
			return ConflictResume, nil
		}
		fmt.Fprintf(r.out, "%s: cannot resume (%s), saving under a new name\n", ci.name, noResumeReason(ci))
		return ConflictRename, nil
	}
	return r.policy, nil // rename / skip
}

func noResumeReason(ci conflictInfo) string {
	switch {
	case ci.existing > ci.incoming:
		return "the existing file is larger"
	case ci.existing == 0:
		return "the existing file is empty"
	}
	return "the existing content is not the start of the new file"
}

// prompt 向用户描述冲突并读一个选择。大写字母表示对之后所有冲突都这样处理(sticky)。
// 直接回车 = 跳过: 提示的是"已有数据可能被动到", 默认走最不具破坏性、也不多耗流量的一项。
func (r *conflictResolver) prompt(ci conflictInfo) (act string, sticky bool, err error) {
	fmt.Fprintf(r.out, "\n%q already exists %s (%s).\n", ci.name, ci.where, humanBytes(ci.existing))
	type option struct {
		key byte
		act string
		txt string
	}
	var opts []option
	switch {
	case ci.same:
		fmt.Fprintf(r.out, "  identical to the incoming file (sha256 %s).\n", short(ci.hash))
		opts = append(opts, option{'o', ConflictOverwrite, "[o]verwrite"})
		opts = append([]option{{'r', ConflictRename, "[r]ename and transfer again"}}, opts...)
	default:
		fmt.Fprintf(r.out, "  content differs from the incoming file (existing %s, incoming %s).\n",
			humanBytes(ci.existing), humanBytes(ci.incoming))
		if ci.resumable {
			fmt.Fprintf(r.out, "  the existing file is exactly the first %s of the incoming one, so it can be continued.\n", humanBytes(ci.existing))
			opts = append(opts, option{'c', ConflictResume, fmt.Sprintf("[c]ontinue from %s", humanBytes(ci.existing))})
		} else {
			fmt.Fprintf(r.out, "  cannot continue: %s.\n", noResumeReason(ci))
		}
		opts = append(opts, option{'r', ConflictRename, "[r]ename and transfer again"})
	}
	opts = append(opts, option{'s', ConflictSkip, "[s]kip (default)"})

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

// prepareSend 在发一个文件之前做同名协商, 并把决定写进 it(conflict/resumeAt)。skip 为 true
// 表示这个文件不要发了。probe 是「在一条新通道上探测收方」的闭包(直连/中继各自实现)。
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
	// ask / skip / resume 都要先知道有没有同名。skip 不需要比内容。
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
	if !pr.Exists {
		return false, nil
	}
	ci := conflictInfo{name: it.name, where: "on the peer", existing: pr.Size, incoming: it.size}
	if pr.SHA256 != "" {
		local, err := hashFilePrefix(it.path, pr.Size)
		if err != nil {
			return false, fmt.Errorf("hash %s: %w", it.path, err)
		}
		ci.hash = local
		if local == pr.SHA256 {
			ci.same = pr.Size == it.size
			ci.resumable = pr.Size > 0 && pr.Size < it.size
		}
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
	case ConflictResume:
		it.conflict = ConflictResume
		it.resumeAt = pr.Size
	}
	return false, nil
}

// preparePull 取一个文件之前的同名协商, 返回动作(ConflictRename 表示按默认走)与续传起点。
// 本机没有同名文件时直接返回默认动作。remoteHash 取对端文件前 n 字节的哈希。
func (r *conflictResolver) preparePull(dir string, e filePullEntry, remoteHash func(n int64) (string, error)) (act string, resumeAt int64, err error) {
	if r.policy == ConflictRename {
		return ConflictRename, 0, nil
	}
	dest, err := safeJoin(dir, e.Name)
	if err != nil {
		return ConflictRename, 0, nil // 名字不合法的话落盘时会如实报错, 这里不抢着报
	}
	info, err := os.Stat(dest)
	if err != nil || !info.Mode().IsRegular() {
		return ConflictRename, 0, nil
	}
	ci := conflictInfo{name: e.Name, where: "locally", existing: info.Size(), incoming: e.Size}
	if r.policy != ConflictSkip && r.policy != ConflictOverwrite && info.Size() <= e.Size {
		fmt.Fprintf(r.out, "checking the existing %s...\n", e.Name)
		local, err := hashFilePrefix(dest, info.Size())
		if err != nil {
			return "", 0, fmt.Errorf("hash %s: %w", dest, err)
		}
		remote, err := remoteHash(info.Size())
		if err != nil {
			return "", 0, fmt.Errorf("ask the peer to hash %s: %w", e.Path, err)
		}
		ci.hash = local
		if local == remote {
			ci.same = info.Size() == e.Size
			ci.resumable = info.Size() > 0 && info.Size() < e.Size
		}
	}
	act, err = r.decide(ci)
	if err != nil {
		return "", 0, err
	}
	return act, info.Size(), nil
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
