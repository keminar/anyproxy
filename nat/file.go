package nat

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	quic "github.com/quic-go/quic-go"
)

// 直连上的文件传输。
//
// 为什么不直接用 scp/rsync 走隧道: 那要求对端装了 sshd。跨 Windows 时这条往往不成立
// (OpenSSH 服务器是可选功能, 默认不装), 而"为了传个文件先去装个服务"正是这个功能要
// 省掉的事。所以这里由 anyproxy 自己落盘, 对端机器上不需要任何额外服务。
//
// 一个文件一条 QUIC stream。这样每个文件的结果(存成了什么名字、校验过没有、错在哪)
// 都是独立的, 不会因为中间一个文件出错就把整批的状态搅乱; 而开一条 stream 在 QUIC
// 上几乎不要钱。
//
// 传输本身仍受直连那套鉴权约束: 发送方必须先经服务端信令拿到一次性凭证, 收方再按
// client.receive.allow 决定收不收。

const (
	// directStreamFile 文件传输流。
	directStreamFile = "file"

	// directFilePort 文件传输占用的保留"端口"号。
	//
	// 用 0: 它不是合法 TCP 端口, 所以一定不会跟 client.forward 里的任何一条撞上 ——
	// 凭证是按端口发放和核验的(见 directConn.authorize), 借用一个真实端口号会让"能传
	// 文件"和"能连那个端口的服务"变成同一件事。
	directFilePort = 0

	// fileFrameMax 文件首部/尾部这类控制帧的大小上限。
	fileFrameMax = 8 * 1024

	// filePartSuffix 未完成文件的后缀。先写它、完成后再改名, 中断时留下的是一个一眼
	// 就能看出没传完的文件, 而不是一个看着正常、内容却是半截的。
	filePartSuffix = ".part"

	// fileCopyBuf 搬字节的缓冲。io.Copy 默认 32KB, 千兆下系统调用次数偏多。
	fileCopyBuf = 256 * 1024
)

// fileAuth 直连路径专用: 发送方在 fileHead 之前先声明自己的身份, 供接收方按
// client.receive.allow 核对(email 查表, uuid 是真正比对的凭证, 见 conf.ClientReceive)。
//
// 只有直连需要这一步: 中继路径的身份核对在信令握手阶段就已经用 email 查到 uuid、
// 并用它加密了整个 msgPipe(见 nat/file_relay.go、nat/relay_crypto.go), 走到
// recvFileOver 这一层时早已确认过对方身份, 不需要再单独声明一次。直连没有这样一次
// 独立的握手消息, 所以借流首部自己带一份——QUIC 那条流本身已经端到端加密(自签证书
// + 指纹固定), 明文写这两个字段不存在被 B 窃听的问题, B 全程都摸不到这条流。
type fileAuth struct {
	Email string `json:"email"` // 在对方 receive.allow 里查哪一条, 纯查找/备注用
	UUID  string `json:"uuid"`  // 真正的凭证: 必须与查到的那条一致
}

// fileHead 一条 stream 传一个文件(或文件的一个分块), 这是它的首部。
//
// TransferID 为空是今天的"整份文件"语义, Size 就是文件总大小、Offset 恒为 0 ——
// 单文件分块并行传输(见 file_send.go/file_recv.go 的 parallel 参数)才会填后面
// 四个字段: 同一个 TransferID 标记"这些连接属于同一次传输", ChunkIndex/ChunkCount
// 标记这是第几块/一共几块, Offset 是这一块在整份文件里的起始字节。Size 此时是**这一
// 块**的字节数, 不是整份文件的大小——每条连接只关心自己要发/收多少字节, 不需要知道
// 别的块传到哪了。
type fileHead struct {
	Name       string `json:"name"` //相对路径, 一律用 / 分隔
	Size       int64  `json:"size"`
	Mode       uint32 `json:"mode"` //仅取权限位, Windows 收端会忽略
	TransferID string `json:"tid,omitempty"`
	ChunkIndex int    `json:"ci,omitempty"`
	ChunkCount int    `json:"cc,omitempty"`
	Offset     int64  `json:"off,omitempty"`
}

// fileTrailer 数据发完之后才发的校验信息。
//
// 放在后面而不是首部, 是为了让发送端边读边算: 摘要写在首部的话, 发送前必须把整个
// 文件先完整读一遍算出摘要, 大文件等于白读一遍。
//
// SHA256 校验的是**这条连接上刚发的这些字节**: 不分块时就是整份文件的摘要; 分块时
// 是这一块的摘要, 不是整份文件的——按块校验才能一边收一边算, 不用等所有块都到齐再
// 重新读一遍整份文件。
type fileTrailer struct {
	SHA256 string `json:"sha256"`
}

// fileReply 接收端的结果。
type fileReply struct {
	Saved string `json:"saved"` //实际落盘的文件名(重名时会改), 相对于接收目录
	Err   string `json:"err"`
}

// readOnlyRefusal 对端配了 receive.readonly 时回给发送方的拒绝理由。两条路径同一句,
// 且要说清是**配置**这么定的, 不是网络或权限出了问题 —— 否则对方多半会去查磁盘权限。
const readOnlyRefusal = "peer's receive directory is read-only (websocket.client.receive.readonly is true), it only serves files"

// ---------- 接收端(C) ----------

// fileConn 文件传输发送/接收两侧共用的最小接口。*quic.Stream(直连路径)天然满足;
// 中继路径用 msgPipe(见 file_relay.go)实现同一个接口——核心逻辑不关心底下走的是
// QUIC stream 还是经 B 转发的消息通道, 两条路径("要不要经过 B")只在外面包一层
// 各自的连接建立方式, 核心的首部/校验/落盘逻辑一份代码, 不重复也不容易两边跑偏。
type fileConn interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadDeadline(time.Time) error
}

// authorizeFileSender 读对端在流首部自报的 fileAuth 并按 client.receive.allow 核对,
// 返回核对通过的 email(仅供日志与记账)。收文件(recvFile)与被取文件(servePull)两条
// 路径共用: 两者的信任模型是同一个 —— allow 里配的 uuid 才是凭证, email 只是查表用。
func authorizeFileSender(stream *quic.Stream, cfg conf.ClientReceive) (string, error) {
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	var auth fileAuth
	if err := readFrame(stream, &auth, fileFrameMax); err != nil {
		return "", fmt.Errorf("bad auth head: %v", err)
	}
	_ = stream.SetReadDeadline(time.Time{})

	uuid, ok := cfg.Lookup(auth.Email)
	// uuid 是查表得到的、本机配置的凭证, auth.UUID 是对方自报的; 两个都必须是合法
	// uuid 格式才有资格往下比对——哪怕两边碰巧写了同一个不合法的字符串也不行, 格式
	// 都不对的东西不能当成一次有效的身份匹配。
	if !ok || !conf.IsValidUUID(uuid) || !conf.IsValidUUID(auth.UUID) || uuid != auth.UUID {
		return "", fmt.Errorf("email %s is not in websocket.client.receive.allow, or its uuid does not match", auth.Email)
	}
	return auth.Email, nil
}

// recvFile 处理一条文件流(直连路径的入口)。先读一段 fileAuth 核对身份(见 fileAuth
// 的注释), 通过之后才走 fileHead/数据/fileTrailer 那套核心逻辑(recvFileOver, 与
// 中继路径共用)。
func (dc *directConn) recvFile(stream *quic.Stream, remote string) {
	cfg := dc.peer.cfg.Receive
	logf := dc.peer.logf
	reply := func(r fileReply) {
		if r.Err != "" {
			logf("file from %s: %s", remote, r.Err)
		}
		_ = writeFrame(stream, r)
	}
	if cfg.Dir == "" {
		reply(fileReply{Err: "peer does not accept files (websocket.client.receive.dir is not set)"})
		return
	}
	if cfg.ReadOnly {
		reply(fileReply{Err: readOnlyRefusal})
		return
	}
	email, err := authorizeFileSender(stream, cfg)
	if err != nil {
		reply(fileReply{Err: err.Error()})
		return
	}
	recvFileOver(stream, cfg.Dir, email, remote, logf, nil)
}

// servePullStream 处理一条取件流(直连路径的入口)。身份核对与收文件那条路完全一样,
// 之后交给两条路共用的 servePull(见 nat/file_pull.go)。
func (dc *directConn) servePullStream(stream *quic.Stream, remote string) {
	cfg := dc.peer.cfg.Receive
	logf := dc.peer.logf
	email, err := authorizeFileSender(stream, cfg)
	if err != nil {
		logf("pull from %s: %s", remote, err)
		_ = writeFrame(stream, filePullResp{Err: err.Error()})
		return
	}
	servePull(stream, cfg, email, remote, logf)
}

// recvFileOver 接收文件的核心逻辑, 直连/中继共用。错误一律回给发送端, 让它的退出码
// 和输出能反映真实结果。身份核对由调用方在此之前完成(直连见 recvFile 的 fileAuth
// 比对; 中继见 onFileRelayOpen 的 email 查 uuid + 用它解密, 解密成功本身就是身份
// 证明)——这里只管接收本身, fromEmail 仅用于日志展示。onDone 仅一次性收文件(-recv)
// 用来知道这个文件(不论成败)已经处理完, daemon 场景传 nil。
func recvFileOver(conn fileConn, dir, fromEmail, remote string, logf func(string, ...interface{}), onDone func(fileReply)) {
	reply := func(r fileReply) {
		if r.Err != "" {
			logf("file from %s: %s", remote, r.Err)
		}
		if err := writeFrame(conn, r); err != nil {
			logf("file from %s: cannot reply: %v", remote, err)
		}
		if onDone != nil {
			onDone(r)
		}
	}

	// 首部要有超时: 开了流却不发首部的对端会一直占着它。数据本身不设总时限 ——
	// 大文件在慢链路上传很久是正常的, QUIC 的空闲超时(直连)/msgPipe 的收尾信号
	// (中继)已经能兜住真正断掉的连接。
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var head fileHead
	if err := readFrame(conn, &head, fileFrameMax); err != nil {
		reply(fileReply{Err: fmt.Sprintf("bad file head: %v", err)})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if head.Size < 0 {
		reply(fileReply{Err: "negative file size"})
		return
	}

	// TransferID 非空说明这不是整份文件, 是分块并行传输(见 file_send.go 的 parallel
	// 参数)里的一块, 转交单独的落盘逻辑——多条连接要写同一个目标文件的不同字节区间,
	// 不能像下面这样每条连接各开各的 .part。
	if head.TransferID != "" {
		recvFileChunk(conn, dir, remote, logf, head, reply)
		return
	}

	dest, err := safeJoin(dir, head.Name)
	if err != nil {
		reply(fileReply{Err: fmt.Sprintf("rejected name %q: %v", head.Name, err)})
		return
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		reply(fileReply{Err: fmt.Sprintf("mkdir: %v", err)})
		return
	}

	start := time.Now()
	saved, sum, err := writeIncoming(dest, conn, head)
	if err != nil {
		reply(fileReply{Err: err.Error()})
		return
	}

	// 校验尾部: 摘要对不上说明落盘的内容不是对方发的那份, 必须删掉 —— 留着一个内容
	// 错误、名字正确的文件, 比没收到坏得多。
	var tr fileTrailer
	if err := readFrame(conn, &tr, fileFrameMax); err != nil {
		os.Remove(saved)
		reply(fileReply{Err: fmt.Sprintf("no checksum from sender: %v", err)})
		return
	}
	if tr.SHA256 != sum {
		os.Remove(saved)
		reply(fileReply{Err: fmt.Sprintf("checksum mismatch (got %s, sender says %s), discarded", short(sum), short(tr.SHA256))})
		return
	}

	rel, _ := filepath.Rel(dir, saved)
	logf("file from %s: saved %s (%s in %s)", remote, rel, humanBytes(head.Size), time.Since(start).Round(time.Millisecond))
	reply(fileReply{Saved: filepath.ToSlash(rel)})
}

// ---------- 分块并行传输的落盘(接收端) ----------
//
// 一份分块传输对应多条独立连接、并发到达, 都要写同一个目标文件的不同字节区间——
// 这是 writeIncoming 那套"一条连接从头写到尾"的模型处理不了的, 需要一份跨连接共享
// 的状态, 按 TransferID 关联起来。

const (
	// chunkAssemblyIdleTimeout 一份分块传输多久没有任何一块进展就判定发送方已经
	// 中断(崩溃/网络彻底断开), 回收残留的 .part 与内存状态。常规传输不会撞上这个
	// 值——它只兜底真正卡死不会再有后续块到达的情形。
	chunkAssemblyIdleTimeout = 5 * time.Minute
	chunkAssemblyReapEvery   = 30 * time.Second
)

// chunkAssembly 一次分块传输在接收端的运行时状态, 按 TransferID 索引, 所有块共享。
type chunkAssembly struct {
	mu        sync.Mutex
	f         *os.File
	final     string // 最终落盘名(第一块到达时就定下, 所有块共用, 不重复判重名)
	part      string
	total     int
	remaining int
	seen      map[int]bool
	err       error // 目前为止任意一块出的错, 先到先得——后面的块不会覆盖它
	touched   time.Time
}

// chunkAssemblies 接收端的分块传输注册表。key 是 TransferID。
var chunkAssemblies = struct {
	mu sync.Mutex
	m  map[string]*chunkAssembly
}{m: map[string]*chunkAssembly{}}

var chunkReaperOnce sync.Once

// getOrCreateAssembly 取或建一份分块传输的运行时状态。只有第一个到达的块真正建
// 文件、判重名——后到的块复用同一份结果, 保证一次传输里所有块落到同一个文件名下。
func getOrCreateAssembly(tid string, head fileHead, dir string) (*chunkAssembly, error) {
	chunkReaperOnce.Do(func() { go reapChunkAssemblies() })

	chunkAssemblies.mu.Lock()
	defer chunkAssemblies.mu.Unlock()
	if a, ok := chunkAssemblies.m[tid]; ok {
		return a, nil
	}
	dest, err := safeJoin(dir, head.Name)
	if err != nil {
		return nil, fmt.Errorf("rejected name %q: %w", head.Name, err)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	final := uniquePath(dest)
	part := final + filePartSuffix
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, filePerm(head.Mode))
	if err != nil {
		return nil, fmt.Errorf("create: %w", err)
	}
	a := &chunkAssembly{
		f: f, final: final, part: part,
		total: head.ChunkCount, remaining: head.ChunkCount,
		seen: make(map[int]bool, head.ChunkCount), touched: time.Now(),
	}
	chunkAssemblies.m[tid] = a
	return a, nil
}

// reapChunkAssemblies 周期性收掉长期没有任何一块进展的分块传输, 防止发送方中途
// 崩溃时残留的 .part 文件和内存状态在长驻进程(收文件的守护进程)里一直攒着不释放。
// -send/-recv 这类一次性进程本身很快退出, 用不上这个也不会泄漏, 但复用同一份代码
// 更简单, 不必单独判断"是不是长驻进程"。
func reapChunkAssemblies() {
	for range time.Tick(chunkAssemblyReapEvery) {
		now := time.Now()
		var dead []*chunkAssembly
		chunkAssemblies.mu.Lock()
		for tid, a := range chunkAssemblies.m {
			a.mu.Lock()
			idle := now.Sub(a.touched) > chunkAssemblyIdleTimeout
			a.mu.Unlock()
			if idle {
				delete(chunkAssemblies.m, tid)
				dead = append(dead, a)
			}
		}
		chunkAssemblies.mu.Unlock()
		for _, a := range dead {
			a.f.Close()
			os.Remove(a.part)
			log.Printf("nat file: transfer to %s idle, dropped (%d/%d chunks arrived)", a.final, a.total-a.remaining, a.total)
		}
	}
}

// recvFileChunk 落盘分块并行传输里的一块。remaining 归零(不论成败)的那一块负责
// 收尾: 全部成功就把 .part 改名成最终文件名, 任意一块出过错就整份删掉——和
// writeIncoming 的"校验不过就删除"是同一个原则, 只是判断依据从一条连接扩成了这次
// 传输的所有块。
func recvFileChunk(conn fileConn, dir, remote string, logf func(string, ...interface{}), head fileHead, reply func(fileReply)) {
	if head.ChunkCount < 2 || head.ChunkIndex < 0 || head.ChunkIndex >= head.ChunkCount {
		reply(fileReply{Err: "malformed chunk header"})
		return
	}
	a, err := getOrCreateAssembly(head.TransferID, head, dir)
	if err != nil {
		reply(fileReply{Err: err.Error()})
		return
	}

	a.mu.Lock()
	dup := a.seen[head.ChunkIndex]
	if !dup {
		a.seen[head.ChunkIndex] = true
	}
	a.touched = time.Now()
	a.mu.Unlock()

	var chunkErr error
	switch {
	case dup:
		chunkErr = fmt.Errorf("duplicate chunk %d", head.ChunkIndex)
	default:
		h := sha256.New()
		n, werr := copyN(io.MultiWriter(io.NewOffsetWriter(a.f, head.Offset), h), conn, head.Size)
		switch {
		case werr != nil:
			chunkErr = fmt.Errorf("receive chunk %d: %w", head.ChunkIndex, werr)
		case n != head.Size:
			chunkErr = fmt.Errorf("chunk %d truncated: got %d of %d bytes", head.ChunkIndex, n, head.Size)
		default:
			var tr fileTrailer
			if err := readFrame(conn, &tr, fileFrameMax); err != nil {
				chunkErr = fmt.Errorf("no checksum for chunk %d: %w", head.ChunkIndex, err)
			} else if sum := hex.EncodeToString(h.Sum(nil)); tr.SHA256 != sum {
				chunkErr = fmt.Errorf("chunk %d checksum mismatch (got %s, sender says %s)", head.ChunkIndex, short(sum), short(tr.SHA256))
			}
		}
	}

	a.mu.Lock()
	if chunkErr != nil && a.err == nil {
		a.err = chunkErr
	}
	a.remaining--
	finishing := a.remaining <= 0
	finalErr := a.err
	a.touched = time.Now()
	a.mu.Unlock()

	if finishing {
		chunkAssemblies.mu.Lock()
		delete(chunkAssemblies.m, head.TransferID)
		chunkAssemblies.mu.Unlock()

		closeErr := a.f.Close()
		if finalErr == nil && closeErr != nil {
			finalErr = fmt.Errorf("close: %w", closeErr)
		}
		if finalErr != nil {
			os.Remove(a.part)
		} else if err := os.Rename(a.part, a.final); err != nil {
			os.Remove(a.part)
			finalErr = fmt.Errorf("rename: %w", err)
		} else {
			rel, _ := filepath.Rel(dir, a.final)
			logf("file from %s: saved %s (%d chunks)", remote, filepath.ToSlash(rel), a.total)
		}
	}

	if finalErr != nil {
		reply(fileReply{Err: finalErr.Error()})
		return
	}
	rel, _ := filepath.Rel(dir, a.final)
	reply(fileReply{Saved: filepath.ToSlash(rel)})
}

// writeIncoming 把 stream 上的 head.Size 字节写进 dest, 返回实际落盘路径与摘要。
//
// 先写 .part 再改名: 中断留下的是一眼能看出没传完的文件。改名时若目标已存在, 自动
// 换一个名字而不是覆盖 —— 覆盖会悄无声息地毁掉收方已有的数据, 这个代价太大, 而多
// 出一个 "x (1).zip" 只是有点碍眼。
func writeIncoming(dest string, r io.Reader, head fileHead) (string, string, error) {
	part := dest + filePartSuffix
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm(head.Mode))
	if err != nil {
		return "", "", fmt.Errorf("create: %w", err)
	}
	h := sha256.New()
	n, err := copyN(io.MultiWriter(f, h), r, head.Size)
	closeErr := f.Close()
	if err != nil {
		os.Remove(part)
		return "", "", fmt.Errorf("receive: %w", err)
	}
	if closeErr != nil {
		os.Remove(part)
		return "", "", fmt.Errorf("close: %w", closeErr)
	}
	if n != head.Size {
		os.Remove(part)
		return "", "", fmt.Errorf("truncated: got %d of %d bytes", n, head.Size)
	}

	final := uniquePath(dest)
	if err := os.Rename(part, final); err != nil {
		os.Remove(part)
		return "", "", fmt.Errorf("rename: %w", err)
	}
	return final, hex.EncodeToString(h.Sum(nil)), nil
}

// copyN 读满 n 字节。用自带缓冲而不是 io.CopyN: 后者内部是 32KB, 千兆下系统调用偏多。
func copyN(dst io.Writer, src io.Reader, n int64) (int64, error) {
	if n == 0 {
		return 0, nil
	}
	buf := make([]byte, fileCopyBuf)
	// LimitReader 是必需的防线: 对端可以谎报 Size 之后一直发, 不限死的话收端会一直写。
	written, err := io.CopyBuffer(dst, io.LimitReader(src, n), buf)
	if err == io.EOF {
		err = nil
	}
	return written, err
}

func filePerm(mode uint32) os.FileMode {
	m := os.FileMode(mode).Perm()
	if m == 0 {
		return 0o644
	}
	return m
}

// safeJoin 把对端给的相对路径安全地接到接收目录下。
//
// 这是收文件最危险的一步: 名字是对端说了算的, 不设防的话一个 "../../.ssh/authorized_keys"
// 就能写到目录外面去。所以既做语法检查, 也在拼完之后再确认结果确实落在目录内 ——
// 两道都要, 符号链接、大小写不敏感文件系统这些都可能让单纯的字符串检查失效。
func safeJoin(dir, name string) (string, error) {
	if name == "" {
		return "", errors.New("empty name")
	}
	// 统一按 / 处理; 反斜杠在 Linux 上是合法文件名字符, 放进来会让同一个名字在两个
	// 平台上含义不同。
	if strings.ContainsAny(name, `\:`) {
		return "", errors.New("name must not contain backslash or colon")
	}
	// 顺序很要紧: 必须先看**原始**名字里有没有 .. 和前导 /, 再做规范化。
	// 反过来的话 path.Clean("/"+name) 会把 ".." 直接吃掉(../x 变成 /x), 检查永远不
	// 触发 —— 结果是恶意名字被悄悄改写成一个合法名字收下, 而不是如实拒绝。
	if strings.HasPrefix(name, "/") {
		return "", errors.New("name must be relative")
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", errors.New("name escapes the receive directory")
		}
	}
	// 到这里已经没有 .. 了, Clean 只用来收拾 "." 和重复的 /。
	clean := path.Clean(name)
	if clean == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return "", errors.New("name resolves to nothing")
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(absDir, filepath.FromSlash(clean))
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	if absDest != absDir && !strings.HasPrefix(absDest, absDir+string(os.PathSeparator)) {
		return "", errors.New("name escapes the receive directory")
	}
	return absDest, nil
}

// uniquePath 目标已存在时换一个不冲突的名字: x.zip -> x (1).zip -> x (2).zip。
func uniquePath(p string) string {
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return p
	}
	ext := filepath.Ext(p)
	base := strings.TrimSuffix(p, ext)
	for i := 1; i < 10000; i++ {
		cand := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
	// 一万个重名还没排开就别较劲了, 让调用方按原名去写(多半会失败并如实报错)。
	return p
}

// ---------- 发送端(A) ----------

// fileItem 一个待发送的文件: 本地路径 + 发给对端的相对名。
type fileItem struct {
	path string
	name string
	size int64
	mode uint32
}

// collectFiles 展开命令行给的路径。目录会递归进去, 相对名以该目录本身为根 ——
// 例如 -send D:/data 得到 data/a.txt、data/sub/b.txt, 收端那侧的结构跟这边一致。
func collectFiles(paths []string) ([]fileItem, error) {
	var out []fileItem
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, fileItem{path: p, name: filepath.Base(p), size: info.Size(), mode: uint32(info.Mode().Perm())})
			continue
		}
		root := filepath.Clean(p)
		prefix := filepath.Base(root)
		err = filepath.Walk(root, func(fp string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			// 只发普通文件: 符号链接、设备节点这些跟着传过去没有意义, 也容易在收端
			// 造成意外(比如把链接当普通文件复制一份)。
			if !fi.Mode().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root, fp)
			if err != nil {
				return err
			}
			out = append(out, fileItem{
				path: fp,
				name: path.Join(prefix, filepath.ToSlash(rel)),
				size: fi.Size(),
				mode: uint32(fi.Mode().Perm()),
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, errors.New("nothing to send")
	}
	return out, nil
}

// ---------- 单文件分块并行传输 ----------
//
// 只切一个大文件, 不做多文件并发(那是另一件事, 用户明确不要, 怕多个文件抢同一份
// 带宽反而拖慢每一个)。切块只在文件足够大时才划算: 块太小时握手/首部这些固定开销
// 占比会明显起来, 并行反而更慢。

const (
	// chunkMinSize 单块最小体积。小于两倍这个数的文件不切块——切出来的块比这还小,
	// 并行的收益盖不住多开几条连接的开销。
	chunkMinSize = 4 << 20 // 4MiB

	// transferIDSize 分块传输 ID 的随机字节数, 只用来在接收端把同一次传输的多个块
	// 对上号, 不是秘密, 不需要跟 relay 那套加密 salt 一样的强度。
	transferIDSize = 8
)

// chunkRange 一个分块在文件里的位置。
type chunkRange struct {
	offset int64
	length int64
}

// planChunks 把一个 size 字节的文件切成不超过 want 块, 每块至少 chunkMinSize
// (最后一块除外, 它兜底拿余数, 可能比 chunkMinSize 大)。want<=1 或文件不够大时
// 返回 nil, 调用方应退回不切块的单连接路径。
func planChunks(size int64, want int) []chunkRange {
	if want <= 1 || size < 2*chunkMinSize {
		return nil
	}
	n := int64(want)
	if max := size / chunkMinSize; n > max {
		n = max
	}
	if n <= 1 {
		return nil
	}
	base := size / n
	out := make([]chunkRange, 0, n)
	var off int64
	for i := int64(0); i < n; i++ {
		length := base
		if i == n-1 {
			length = size - off // 最后一块拿余数, 避免整除不尽时漏字节
		}
		out = append(out, chunkRange{offset: off, length: length})
		off += length
	}
	return out
}

// newTransferID 生成一次分块传输的关联 ID, 十六进制编码后放进 fileHead/filePullReq。
func newTransferID() (string, error) {
	var b [transferIDSize]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// sendFile 在已建立的直连上发一个文件, 返回收端存成的名字。先写一段 fileAuth 声明
// 自己是谁(见 fileAuth 的注释), 对端凭它核对 client.receive.allow。
//
// 发之前先校验自己的 uuid 格式: 为空或不是合法 uuid(比如 .uuid 状态文件被手改坏了)
// 时这份凭证本身就没有意义, 对端要么直接拒绝要么比对出一个巧合的假阳性/假阴性,
// 不如在本地就地拒绝, 不打开这条 stream。
func (d *directPeer) sendFile(sess *directSession, it fileItem, onProgress func(sent int64)) (string, error) {
	stream, err := d.openFileStream(sess)
	if err != nil {
		return "", err
	}
	return sendFileOver(stream, it, onProgress)
}

// sendFileChunk 是 sendFile 的分块版: 单独开一条流发文件里的 [offset, offset+length)
// 这一段, 供单文件并行分块传输用(见 file_send.go 的 parallel 参数)。除了多传
// offset/length/tid/chunkIdx/chunkCount, 与 sendFile 完全一样——每个分块各自开一条
// 独立的 QUIC stream, 复用同一个 sess 不用重新打洞。
func (d *directPeer) sendFileChunk(sess *directSession, it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(sent int64)) (string, error) {
	stream, err := d.openFileStream(sess)
	if err != nil {
		return "", err
	}
	return sendFileOverRange(stream, it, offset, length, tid, chunkIdx, chunkCount, onProgress)
}

// openFileStream 开一条文件传输流并写好身份声明, 是 sendFile/sendFileChunk 共用的
// 前半段(见 fileAuth 的注释)。发之前先校验自己的 uuid 格式: 为空或不是合法 uuid
// (比如 .uuid 状态文件被手改坏了)时这份凭证本身就没有意义, 对端要么直接拒绝要么
// 比对出一个巧合的假阳性/假阴性, 不如在本地就地拒绝, 不打开这条 stream。
func (d *directPeer) openFileStream(sess *directSession) (*quic.Stream, error) {
	if !conf.IsValidUUID(d.cfg.UUID) {
		return nil, errors.New("websocket.client.uuid is empty or not a valid uuid, refusing to send")
	}
	stream, err := d.openHeadedStream(sess, directStreamFile, "", directFilePort)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(stream, fileAuth{Email: d.cfg.Email, UUID: d.cfg.UUID}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send auth: %w", err)
	}
	return stream, nil
}

// openPullStream 在已建立的直连上开一条取件流, 并写好身份声明。与 sendFile 的前半段
// 完全对称(同样的 uuid 自检、同样的 fileAuth 帧、同样的 directFilePort), 区别只在
// Kind 和之后的字节流向。
func (d *directPeer) openPullStream(sess *directSession) (*quic.Stream, error) {
	if !conf.IsValidUUID(d.cfg.UUID) {
		return nil, errors.New("websocket.client.uuid is empty or not a valid uuid, refusing to pull")
	}
	stream, err := d.openHeadedStream(sess, directStreamPull, "", directFilePort)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(stream, fileAuth{Email: d.cfg.Email, UUID: d.cfg.UUID}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send auth: %w", err)
	}
	return stream, nil
}

// sendFileOver 发送一整个文件, 是 sendFileOverRange 在"不分块"时的薄包装——
// offset=0、length=文件全长、TransferID 为空, 语义与今天完全一样。
func sendFileOver(conn fileConn, it fileItem, onProgress func(sent int64)) (string, error) {
	return sendFileOverRange(conn, it, 0, it.size, "", 0, 1, onProgress)
}

// sendFileOverRange 发送一个文件的核心逻辑, 不关心 conn 底下是 QUIC stream 还是中继
// 消息通道; 用完即关——直连路径关的是那条 stream, 中继路径关的是 msgPipe(会触发发
// 一个收尾信号给对端)。
//
// offset/length 圈定这次要发文件里的哪一段: 不分块传输时 offset=0、length=整份文件
// 大小; 分块并行传输时(见 file_send.go 的 parallel 参数)每个分块各自打开一条独立
// 连接, 用各自的 offset/length 调这个函数, tid/chunkIdx/chunkCount 让接收端知道这些
// 连接属于同一次传输、该拼在文件的哪个位置。每条连接各自 os.Open 一份文件描述符再
// Seek, 不共享同一个 *os.File——多个 goroutine 共用一个 fd 各自 Seek 会相互踩踏。
func sendFileOverRange(conn fileConn, it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(sent int64)) (string, error) {
	defer conn.Close()

	f, err := os.Open(it.path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return "", fmt.Errorf("seek to %d: %w", offset, err)
		}
	}

	if err := writeFrame(conn, fileHead{
		Name: it.name, Size: length, Mode: it.mode,
		TransferID: tid, ChunkIndex: chunkIdx, ChunkCount: chunkCount, Offset: offset,
	}); err != nil {
		return "", fmt.Errorf("send head: %w", err)
	}

	h := sha256.New()
	// 边发边算摘要: 摘要放在尾部就是为了这个, 不用为了算它先把文件读一遍。
	src := io.TeeReader(&progressReader{r: f, on: onProgress}, h)
	buf := make([]byte, fileCopyBuf)
	sent, err := io.CopyBuffer(conn, io.LimitReader(src, length), buf)
	if err != nil {
		return "", fmt.Errorf("send body: %w", err)
	}
	if sent != length {
		// 传输途中文件被改小了。继续发下去收端只会校验失败, 不如当场说清楚。
		return "", fmt.Errorf("file shrank while sending: sent %d of %d bytes", sent, length)
	}
	if err := writeFrame(conn, fileTrailer{SHA256: hex.EncodeToString(h.Sum(nil))}); err != nil {
		return "", fmt.Errorf("send checksum: %w", err)
	}

	// 收端要把整个文件落盘并校验之后才回, 所以这里不能设短超时。
	var reply fileReply
	if err := readFrame(conn, &reply, fileFrameMax); err != nil {
		return "", fmt.Errorf("no result from peer: %w", err)
	}
	if reply.Err != "" {
		return "", errors.New(reply.Err)
	}
	return reply.Saved, nil
}

// progressReader 在读的过程中回调已读字节数。
type progressReader struct {
	r    io.Reader
	n    int64
	on   func(int64)
	hash hash.Hash
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.n += int64(n)
		if p.on != nil {
			p.on(p.n)
		}
	}
	return n, err
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit && exp < 3; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGT"[exp])
}
