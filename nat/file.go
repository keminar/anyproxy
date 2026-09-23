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
	"sync/atomic"
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

	// directFileTag 文件传输占用的保留 tag。
	//
	// 用空字符串: 不会跟 client.forward 里任何一条配了非空 tag 的规则撞上 ——
	// 凭证是按 tag 发放和核验的(见 directConn.authorize), 借用一个真实 tag 会让"能传
	// 文件"和"能连那条转发规则"变成同一件事。
	directFileTag = ""

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
// 三个字段: 同一个 TransferID 标记"这些连接属于同一次传输", ChunkIndex 标记这是
// 第几块(只用来给接收端的去重 map 当 key 和日志标识, 不保证和字节顺序一致),
// Offset 是这一块在整份文件里的起始字节。Size 此时是**这一块**的字节数, 不是整份
// 文件的大小——每条连接只关心自己要发/收多少字节。TotalSize 才是整份文件的大小,
// 接收端靠它判断分块并行传输是否已经全部收齐(见 chunkAssembly)——之所以不能靠
// "总共几块"来判断, 是因为分块并行现在按各连接实测速度动态决定分片大小(见
// chunkSizeForRate), 总共几块要传完才知道, 没法像以前那样在第一块发出前就定死。
type fileHead struct {
	Name       string `json:"name"` //相对路径, 一律用 / 分隔
	Size       int64  `json:"size"`
	Mode       uint32 `json:"mode"` //仅取权限位, Windows 收端会忽略
	TransferID string `json:"tid,omitempty"`
	ChunkIndex int    `json:"ci,omitempty"`
	Offset     int64  `json:"off,omitempty"`
	TotalSize  int64  `json:"ts,omitempty"` // 整份文件大小, 只在 TransferID 非空时有意义

	// Conflict 同名文件已存在时发送方要求的处理: 空是默认(收方自动改名保存, 见 claimName),
	// "overwrite" 覆盖已有文件(由使用者在协商时明确选择), "resume" 接着上次中断留下的 .part
	// (ResumePart, 不含目录)从 Offset 处续写, 收全后再改成目标名(此时 Size 是剩余字节数、TransferID
	// 为空)。目标名上的完整文件不接受续传。见 file_conflict.go。
	Conflict   string `json:"conflict,omitempty"`
	ResumePart string `json:"resumePart,omitempty"`

	// Probe 表示这不是一次传输, 只是探测收方有没有同名文件(见 file_conflict.go)。ProbeSize
	// 是来件大小(Size 留 0, 见 probeOver), ProbeNoHash 表示不用算哈希。
	Probe       bool  `json:"probe,omitempty"`
	ProbeSize   int64 `json:"probeSize,omitempty"`
	ProbeNoHash bool  `json:"noHash,omitempty"`
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
// 返回核对通过的那条 allow 配置(email 仅供日志与记账; Dir/Wol 供调用方按需使用,
// 见 conf.AllowedSender)。收文件(recvFile)与被取文件(servePull)两条路径共用:
// 两者的信任模型是同一个 —— allow 里配的 uuid 才是凭证, email 只是查表用。
func authorizeFileSender(stream *quic.Stream, cfg conf.ClientReceive) (conf.AllowedSender, error) {
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	var auth fileAuth
	if err := readFrame(stream, &auth, fileFrameMax); err != nil {
		return conf.AllowedSender{}, fmt.Errorf("bad auth head: %v", err)
	}
	_ = stream.SetReadDeadline(time.Time{})

	sender, ok := cfg.LookupSender(auth.Email)
	// uuid 是查表得到的、本机配置的凭证, auth.UUID 是对方自报的; 两个都必须是合法
	// uuid 格式才有资格往下比对——哪怕两边碰巧写了同一个不合法的字符串也不行, 格式
	// 都不对的东西不能当成一次有效的身份匹配。
	if !ok || !conf.IsValidUUID(sender.UUID) || !conf.IsValidUUID(auth.UUID) || sender.UUID != auth.UUID {
		return conf.AllowedSender{}, fmt.Errorf("email %s is not in websocket.client.receive.allow, or its uuid does not match", auth.Email)
	}
	return sender, nil
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
	sender, err := authorizeFileSender(stream, cfg)
	if err != nil {
		reply(fileReply{Err: err.Error()})
		return
	}
	recvFileOver(stream, senderDir(cfg, sender), sender.Email, remote, logf, recvOpts{}, nil)
}

// senderDir 这个发送者上传时该落到哪个目录: 配了 allow[].dir 就用它, 否则落到
// 共享的 Dir。共享 Dir 是否非空这道总开关由调用方在此之前已经检查过。
func senderDir(cfg conf.ClientReceive, sender conf.AllowedSender) string {
	if sender.Dir != "" {
		return sender.Dir
	}
	return cfg.Dir
}

// servePullStream 处理一条取件流(直连路径的入口)。身份核对与收文件那条路完全一样,
// 之后交给两条路共用的 servePull(见 nat/file_pull.go)。取件目录不受 allow[].dir
// 影响——那只覆盖上传落地, 取件看到的仍然是共享 Dir 下的内容(见 conf.AllowedSender.Dir)。
func (dc *directConn) servePullStream(stream *quic.Stream, remote string) {
	cfg := dc.peer.cfg.Receive
	logf := dc.peer.logf
	sender, err := authorizeFileSender(stream, cfg)
	if err != nil {
		logf("pull from %s: %s", remote, err)
		_ = writeFrame(stream, filePullResp{Err: err.Error()})
		return
	}
	servePull(stream, cfg, sender.Email, remote, logf)
}

// recvFileOver 接收文件的核心逻辑, 直连/中继共用。错误一律回给发送端, 让它的退出码
// 和输出能反映真实结果。身份核对由调用方在此之前完成(直连见 recvFile 的 fileAuth
// 比对; 中继见 onFileRelayOpen 的 email 查 uuid + 用它解密, 解密成功本身就是身份
// 证明)——这里只管接收本身, fromEmail 仅用于日志展示。onDone 仅一次性收文件(-recv)
// 用来知道这个文件(不论成败)已经处理完, daemon 场景传 nil。
func recvFileOver(conn fileConn, dir, fromEmail, remote string, logf func(string, ...interface{}), opts recvOpts, onDone func(fileReply)) {
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

	// -recv 取件: 同名怎么处理由本机说了算, 对端首部里带的一律不认。
	if opts.local {
		head.Conflict = opts.conflict
		if head.Conflict == ConflictResume {
			head.Offset, head.ResumePart = opts.resumeAt, opts.resumePart
		}
	}
	// 探测(见 file_conflict.go): 只回 stat/哈希, 不接收任何数据。
	if head.Probe {
		serveProbe(conn, dir, head, logf)
		if onDone != nil {
			onDone(fileReply{})
		}
		return
	}
	switch head.Conflict {
	case "", ConflictOverwrite, ConflictResume:
	default:
		reply(fileReply{Err: fmt.Sprintf("unknown conflict mode %q", head.Conflict)})
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

	// 覆盖: 目标不存在时就是一次普通传输(-conflict overwrite 不探测、对每个文件都带这个
	// 标记)。
	if head.Conflict == ConflictOverwrite {
		if _, statErr := os.Lstat(dest); statErr != nil {
			head.Conflict = ""
		}
	}
	if head.Conflict != "" {
		var saved string
		var err error
		if head.Conflict == ConflictResume {
			saved, err = resumeIncoming(dest, conn, head)
		} else {
			saved, err = writeOverwrite(dest, conn, head)
		}
		if err != nil {
			reply(fileReply{Err: err.Error()})
			return
		}
		rel, _ := filepath.Rel(dir, saved)
		logf("file from %s: %s %s (%s in %s)", remote, head.Conflict, rel, humanBytes(head.Size), time.Since(start).Round(time.Millisecond))
		reply(fileReply{Saved: filepath.ToSlash(rel)})
		return
	}

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
//
// total/remaining 是字节数, 不是块数——分块并行现在按各连接实测速度动态决定分片
// 大小, 总共几块要传完才知道, 没法像以前那样靠"块数倒计数"判断是否收全(见
// fileHead.TotalSize 的注释), 只能靠"收到的字节数是否等于整份文件大小"判断。
type chunkAssembly struct {
	mu        sync.Mutex
	f         *os.File
	final     string // 最终落盘名, 第一块到达时就用 claimName 原子占好(占位文件已在磁盘上), 所有块共用
	claimed   bool   // final 是 claimName 留下的空占位文件(失败时要删); 覆盖模式下 final 是已有文件, 绝不能删
	part      string
	total     int64
	remaining int64
	count     int // 成功收到的块数, 只用来给完成日志打印, 不参与"是否收全"的判断
	seen      map[int]bool
	err       error // 目前为止任意一块出的错, 先到先得——后面的块不会覆盖它
	touched   time.Time
	done      bool // remaining<=0 这个收尾分支是否已经跑过, 见 recvFileChunk 的说明
}

// chunkAssemblies 接收端的分块传输注册表。key 是 TransferID。
var chunkAssemblies = struct {
	mu sync.Mutex
	m  map[string]*chunkAssembly
}{m: map[string]*chunkAssembly{}}

var chunkReaperOnce sync.Once

// abortChunkAssembly abandons an incomplete transfer immediately. This is needed by
// one-shot -recv when one of the parallel connections fails: the process exits before
// the background reaper can reclaim the partial file.
func abortChunkAssembly(tid string) {
	chunkAssemblies.mu.Lock()
	a := chunkAssemblies.m[tid]
	if a != nil {
		delete(chunkAssemblies.m, tid)
	}
	chunkAssemblies.mu.Unlock()
	if a != nil {
		_ = a.f.Close()
		_ = os.Remove(a.part)
		a.dropClaim() // claimName 原子占的位, 传输没完成也要一并收掉
	}
}

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
	// final 在第一块到达时就原子认领下来(见 claimName), 而不是等所有块都收完才决定:
	// 每条并行连接各自收完自己那一块就要独立回复对端"Saved"(不能等其他块), 所以这个
	// 名字必须从一开始就是确定、且不会被并发的另一次同名传输抢走的。
	// 覆盖(见 file_conflict.go): 目标不存在就是普通传输; 存在则最终改名时替换它。
	overwrite := false
	if head.Conflict == ConflictOverwrite {
		if _, statErr := os.Lstat(dest); statErr == nil {
			overwrite = true
		}
	}
	final, claimed := dest, false
	if !overwrite {
		final, err = claimName(dest)
		if err != nil {
			return nil, err
		}
		claimed = true
	}
	// part 带上这次传输自己的 TransferID, 不能只用 final+".part": 发送端异常退出
	// (比如传到一半 Ctrl+C)时, 接收端这个 goroutine 在检测到连接真的断了之前还会
	// 占着旧的 .part 继续等——没有读超时是故意的(见 recvFileOver 的注释), 靠的是
	// QUIC 空闲超时兜底, 但这意味着旧连接的清理和新一次重传可能在时间上重叠。
	// 如果新旧两次都写同名的 xxx.part, 新的这次收完文件、改名时会因为旧 goroutine
	// 还占着那个文件而报 "being used by another process"(哪怕数据本身完全收对了)。
	// 每次传输用自己的 TransferID 单独占一个 .part 文件名, 这类撞名从根上就不会发生。
	part := final + "." + tid + ".chunks" + filePartSuffix
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, filePerm(head.Mode))
	if err != nil {
		if claimed {
			os.Remove(final) // final 已经被 claimName 原子占位了, 这里失败要把占位一起收掉
		}
		return nil, fmt.Errorf("create: %w", err)
	}
	a := &chunkAssembly{
		f: f, final: final, claimed: claimed, part: part,
		total: head.TotalSize, remaining: head.TotalSize,
		seen: make(map[int]bool), touched: time.Now(),
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
			a.dropClaim() // claimName 原子占的位, 传输没完成也要一并收掉
			log.Printf("nat file: transfer to %s idle, dropped (%s/%s received)", a.final, humanBytes(a.total-a.remaining), humanBytes(a.total))
		}
	}
}

// recvFileChunk 落盘分块并行传输里的一块。remaining(按字节数, 不论成败都会扣减,
// 见下面的说明)归零的那一块负责收尾: 全部成功就把 .part 改名成最终文件名, 任意
// 一块出过错就整份删掉——和 writeIncoming 的"校验不过就删除"是同一个原则, 只是
// 判断依据从一条连接扩成了这次传输的所有块。
func recvFileChunk(conn fileConn, dir, remote string, logf func(string, ...interface{}), head fileHead, reply func(fileReply)) {
	if head.TotalSize <= 0 {
		// 分块传输的发送方(sendFileOverRange)一定会把 TotalSize 填成 it.size(>0)。
		// 收到 0 只有一种解释: 对面还是改动前的旧版本, 发的首部里根本没有 TotalSize
		// 这个字段(json 解出来就是零值)——单独给一句好懂的提示, 不要和下面真正
		// "首部字段对不上"的情形共用一句谁也看不懂的 "malformed chunk header"。
		reply(fileReply{Err: "malformed chunk header: missing total size, peer is likely running an older/incompatible anyproxy build (chunk protocol changed) — rebuild and restart both sides with the same version"})
		return
	}
	if head.ChunkIndex < 0 || head.Size <= 0 || head.Size > head.TotalSize {
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
	} else if chunkErr == nil {
		a.count++
	}
	// 不论成败都扣减: 出错的块也要"用掉"它声明的字节数, 不然这次传输会永远收不
	// 齐、只能等 5 分钟空闲回收器兜底删除, 而不是像现在这样立刻报错收尾。
	a.remaining -= head.Size
	// remaining 归零本该只发生一次, 但字节计数比以前的块数倒计数更容易在有 bug
	// 或对端异常(比如声明的 Size 和实际不符)时被越过零点不止一次触发——done
	// 挡住第二次重复跑下面的 close/rename/delete。
	finishing := a.remaining <= 0 && !a.done
	if finishing {
		a.done = true
	}
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
			// 这里的 finalErr 是某一块的传输/校验错误, 落盘内容确实不完整或对不上,
			// 删掉是对的(与下面"改名失败不删 part"不是一回事——那种情况下字节已经
			// 收全, 只是改名这一步被卡住)。a.final 是 claimName 在第一块到达时就
			// 占下的空占位文件, 传输失败了也要一并收掉, 不然会留下一个看着像"传完
			// 了"、其实是空的文件。
			os.Remove(a.part)
			a.dropClaim()
		} else if err := renameWithRetry(a.part, a.final); err != nil {
			// 所有块都收全校验也都过了, 只是改名被卡住(常见于杀毒软件扫描刚落盘的
			// 可执行文件): 把空占位文件收掉(留着会被误认成"传完了但是空文件"), 但
			// 不删 part——数据都在那, 删掉等于逼一次全量重传。
			a.dropClaim()
			finalErr = fmt.Errorf("rename: %w (data kept at %s)", err, a.part)
		} else {
			rel, _ := filepath.Rel(dir, a.final)
			logf("file from %s: saved %s (%s in %d chunks)", remote, filepath.ToSlash(rel), humanBytes(a.total), a.count)
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
// 出一个带序号的名字(命名见 dupName)只是有点碍眼。
//
// part 名字带一段随机 token, 不能只用 dest+".part": 发送端异常退出(比如传到一半
// Ctrl+C)时, 收端这个 goroutine 在检测到连接真的断了之前还占着旧的 .part 继续
// 等——没有读超时是故意的(见 recvFileOver 的注释), 靠 QUIC 空闲超时兜底, 但这意味
// 着旧连接的清理和新一次重传可能在时间上重叠。如果新旧两次都写同名的 xxx.part,
// 新的这次收完文件、改名时会因为旧 goroutine 还占着那个文件而报
// "being used by another process"(哪怕数据本身完全收对了)。每次调用生成自己的
// token, 这类撞名从根上就不会发生。
func writeIncoming(dest string, r io.Reader, head fileHead) (string, string, error) {
	part, sum, err := receiveToPart(dest, r, head)
	if err != nil {
		return "", "", err
	}

	// claimName 而不是"先 Stat 探测、这里再 Rename": 两步分开在两个独立进程之间不
	// 是原子的, 见 claimName 的注释——并发给同一个目标名字发送同名文件时会导致后一个
	// 悄悄覆盖前一个已经回复过"Saved"的文件。
	final, err := claimName(dest)
	if err != nil {
		// 不删 part: 字节已经完整落盘, 删掉等于让对方一份传完的文件白传一遍。
		return "", "", fmt.Errorf("%w (data kept at %s)", err, part)
	}
	if err := renameWithRetry(part, final); err != nil {
		// final 只是 claimName 留下的空占位文件, 收掉它——留着会被误认成"传完了但是
		// 空文件"。不删 part: 字节已经完整落盘且摘要还没来得及核对, 删掉等于让对方
		// 一份传完的文件白传一遍。留着让人凭 part 名字自己认领, 比逼一次几十 MB/几
		// 分钟的重传划算得多。
		os.Remove(final)
		return "", "", fmt.Errorf("rename: %w (data kept at %s)", err, part)
	}
	return final, sum, nil
}

// renameWithRetry 重试版 os.Rename。Windows 上杀毒软件常对刚落盘的可执行文件做
// 实时扫描, 会在我们 Close() 之后、改名之前把这个文件再打开一下, 扫描完才放手,
// 这段时间里 Rename 会报 "being used by another process"(ERROR_SHARING_VIOLATION),
// 文件本身没问题, 等扫描完就能改名成功。用指数退避拉到十几秒总时长——扫一个几十
// MB 的可执行文件不是瞬间的事, 等太短会在文件传得越大时越容易撞上; 反正只在最后
// 这一步偶发, 多等几秒换来不用整份重传划算。非 Windows 平台不会遇到这个问题, 但
// 重试本身无害, 不必用构建标签区分。
func renameWithRetry(oldpath, newpath string) error {
	var err error
	delay := 100 * time.Millisecond
	for i := 0; i < 8; i++ {
		if i > 0 {
			time.Sleep(delay)
			delay *= 2
		}
		if err = os.Rename(oldpath, newpath); err == nil {
			return nil
		}
	}
	return err
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

// claimName 原子地"认领"一个尚未被占用的文件名: 目标已存在就换下一个候选,
// 候选名见 dupName(如 x 1.zip / x 2.zip)。
//
// 不能用"先 os.Stat 探测存不存在、调用方再另外一步 Rename"这种两步走的做法——那两
// 步之间不是原子的。两个独立进程/goroutine 并发给同一个目标名字发送同名文件时,
// 双方都可能在探测那一刻看到"不存在", 都选中同一个名字、都去 Rename, 而 os.Rename
// 对已存在的目标是直接覆盖(Go 在 Windows 上特意用 MOVEFILE_REPLACE_EXISTING 抹平了
// 跟 POSIX rename 的差异, 两边行为一致), 后一个会悄悄吃掉前一个刚落盘、且已经回复
// 过对端"Saved"的文件——回复变成了假话, 数据也丢了。这不是 Windows 特有的问题,
// Linux/macOS 上同样会撞上。
//
// 用 O_CREATE|O_EXCL 建一个 0 字节占位文件来"认领"名字: 这一步本身就是原子的
// (POSIX open(2) 与 Windows CreateFile(CREATE_NEW) 都保证), 抢到的人才能继续, 抢
// 不到(已存在)就跟旧版一样换下一个候选名字重试。调用方应该尽快把真正的内容
// rename 过去覆盖这个占位文件——覆盖自己刚建的占位文件是安全的, 不会有别的调用也
// 认领到同一个名字; 如果调用方最终没有完成这次覆盖(比如后续步骤失败), 记得把这个
// 占位文件删掉, 不然会留下一个看着像"传完了"、其实是空的文件。
func claimName(dest string) (string, error) {
	claim := func(p string) (bool, error) {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if os.IsExist(err) {
				return false, nil
			}
			return false, err
		}
		return true, f.Close()
	}
	if ok, err := claim(dest); err != nil {
		return "", fmt.Errorf("claim %s: %w", dest, err)
	} else if ok {
		return dest, nil
	}

	for i := 1; i < 10000; i++ {
		cand := dupName(dest, i)
		ok, err := claim(cand)
		if err != nil {
			return "", fmt.Errorf("claim %s: %w", cand, err)
		}
		if ok {
			return cand, nil
		}
	}
	// 一万个重名还没排开就别较劲了, 如实报错——跟旧版"退回原名字让调用方写、多半会
	// 失败"的效果一样, 但不用再让调用方自己判断"这到底是不是真的认领到了"。
	return "", fmt.Errorf("too many files named like %s, giving up", filepath.Base(dest))
}

// dupName 给出第 i 个(从 1 起)重名候选: x 1.zip, x 2.zip ——不分收方系统, 统一在文件名
// 主体后面加空格+序号。
func dupName(dest string, i int) string {
	ext := filepath.Ext(dest)
	// 纯数字的".1"多半是版本号(如 anyproxy-amd64-v2.1)而不是后缀名 ——
	// 可执行文件常见这种命名, 按后缀名拆分会把序号插进版本号中间。
	if isNumericExt(ext) {
		ext = ""
	}
	base := strings.TrimSuffix(dest, ext)
	return fmt.Sprintf("%s %d%s", base, i, ext)
}

// isNumericExt 形如 ".1"、".22" 的"后缀"通篇是数字, 真实文件后缀几乎不会这样, 一般是版本号。
func isNumericExt(ext string) bool {
	if len(ext) < 2 {
		return false
	}
	for _, r := range ext[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ---------- 发送端(A) ----------

// fileItem 一个待发送的文件: 本地路径 + 发给对端的相对名。
type fileItem struct {
	path string
	name string
	size int64
	mode uint32

	// 同名协商的结果(见 file_conflict.go): conflict 为空按默认(收方改名); resumeAt 仅
	// conflict=="resume" 时有意义, 是收方已有的字节数、也是本次从哪儿开始发。
	conflict   string
	resumePart string // 续传时收方 .part 的文件名
	resumeAt   int64
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
	// transferIDSize 分块传输 ID 的随机字节数, 只用来在接收端把同一次传输的多个块
	// 对上号, 不是秘密, 不需要跟 relay 那套加密 salt 一样的强度。
	transferIDSize = 8

	// maxParallelConns -parallel 的硬上限, 不管用户传多大的值都会被夹到这个数。
	// 依据: 4 条独立连接对家用 NAT/防火墙毫无压力(远小于浏览器对单域名的默认并发),
	// 丢包驱动的吞吐增益到这个量级基本打平, 再往上更容易撞见对称型 NAT 打洞失败率
	// 上升、以及并发流互相挤占同一段带宽反而抬高整体丢包率这些副作用。这个数封的是
	// **同时打开的连接数**, 不是切成几块——每条连接会按自己的实测速度动态决定分片
	// 大小(见 chunkSizeForRate), 跟连接数没有固定倍数关系。
	maxParallelConns = 4

	// probeChunkSize 每个 worker(独立连接)的第一片, 固定大小, 只用来测这条连接
	// 值不值得用大分片——这个耗时天然包含网络传输和接收端落盘+校验+回包的完整往返
	// (见 sendFileOverRange 的说明), 正是"这条连接该用多大分片"要衡量的东西。
	probeChunkSize = 3 << 20 // 3MiB

	// chunkSizeMin/chunkSizeMax 是 chunkSizeForRate 查表的上下界。
	chunkSizeMin = 2 << 20  // 2MiB
	chunkSizeMax = 30 << 20 // 30MiB
)

// clampParallel 把 -parallel 夹到 [1, maxParallelConns] 区间。<=0 按 1(不并行)处理。
func clampParallel(parallel int) int {
	if parallel <= 1 {
		return 1
	}
	if parallel > maxParallelConns {
		return maxParallelConns
	}
	return parallel
}

// chunkSizeForRate 按一个 worker 探测片的实测吞吐(bytesPerSec)查表, 一次性决定
// 这个 worker 后续所有分片的固定大小——不是持续自适应, 测一次定终身: 一份文件
// 传输通常是几分钟量级, 链路条件中途大幅波动到需要重新测的情况不常见, 没必要为此
// 引入持续采样的复杂度。下边界半开(用 <而不是<=), 卡在整数边界上时落进更快那档。
func chunkSizeForRate(bytesPerSec float64) int64 {
	const KB, MB = 1 << 10, 1 << 20
	switch {
	case bytesPerSec < 100*KB:
		return 2 * MB
	case bytesPerSec < 200*KB:
		return 3 * MB
	case bytesPerSec < 500*KB:
		return 6 * MB
	case bytesPerSec < 1*MB:
		return 15 * MB
	default:
		return 30 * MB
	}
}

// workerChunkSize 把一个 worker 探测片的"发了多少字节、花了多久"换算成吞吐, 再查
// chunkSizeForRate。elapsed<=0 在真实网络/中继上不会发生, 但防止万一(比如测试里
// 塞进一个零耗时的假连接)除零, 按"越快越好"处理。
func workerChunkSize(bytesSent int64, elapsed time.Duration) int64 {
	if elapsed <= 0 {
		return chunkSizeMax
	}
	return chunkSizeForRate(float64(bytesSent) / elapsed.Seconds())
}

// wantParallel 决定一次传输要不要走分块并行路径。workers<=1 说明没请求并行(或者
// 打洞只打通了一条连接); 文件小于两个探测片(2*probeChunkSize)时连一次像样的测速
// 都做不到, 谈不上"自适应", 直接退回单连接路径更简单也更快。
func wantParallel(size int64, workers int) bool {
	return workers > 1 && size >= 2*probeChunkSize
}

// chunkCursor 是分块并行传输里"认领接下来 N 字节"的共享原子游标, 取代过去预先切
// 好的 []chunkRange 数组——分片大小现在要等每个 worker 各自探测完才知道, 没法像
// 以前那样提前一次性算出整个切分方案。
type chunkCursor struct {
	size int64 // 文件总大小, 构造后只读
	next int64 // atomic: 下一个未认领的字节偏移
	idx  int64 // atomic: 下一个分片序号
}

func newChunkCursor(size int64) *chunkCursor {
	return &chunkCursor{size: size}
}

// claim 尝试认领 want 字节, 不够文件剩余部分时 clamp 到剩余量。ok=false 表示文件
// 已经被认领完, 调用方(这个 worker)该收工了。
//
// 用 CAS 循环而不是互斥锁: 最多 maxParallelConns(4) 个 worker 竞争同一个 int64,
// 重试成本比锁低, 也没有锁能提供而这里用不上的东西。
//
// idx 由独立的原子计数器发号, 不保证和字节偏移顺序一致(两个 goroutine 谁先抢到
// offset 的 CAS、谁先抢到下一个 idx, 是两次独立的原子操作, 顺序可能不一样)——无
// 所谓, idx 只用来给 chunkAssembly 的去重 map 当 key、以及日志里标识"是哪一片",
// 不依赖它反映字节位置。
func (c *chunkCursor) claim(want int64) (offset, length int64, idx int, ok bool) {
	for {
		cur := atomic.LoadInt64(&c.next)
		if cur >= c.size {
			return 0, 0, 0, false
		}
		length = want
		if remain := c.size - cur; length > remain {
			length = remain
		}
		if atomic.CompareAndSwapInt64(&c.next, cur, cur+length) {
			return cur, length, int(atomic.AddInt64(&c.idx, 1) - 1), true
		}
	}
}

// runChunkWorkers 是 sendParallel(file_send.go)/recvParallel(file_recv.go) 共用的
// 分块并行编排引擎: 从 chunkCursor 认领字节、"探测片定后续大小"的状态机、
// wg/错误传播这几件事只在这一份里写一次, 两个方向不会因为各自维护一份而慢慢跑偏
// (这两个方向除了 do 具体怎么把一片字节送出去/取回来之外, 逻辑完全一样)。
//
// do 是方向相关的部分: worker 编号、这一片的 offset/length/idx、以及一个进度回调
// (只关心"这个 worker 迄今发/收了多少字节", 不关心分片大小), 返回收方存成的名字
// (非分块场景才有意义, 这里几个 worker 都可能返回同一个值)和错误。
//
// 失败语义与改动前一致: 任意一片出错就让其它 worker 不再认领新的一片(但已经在
// 传的那一片会传完, 不中途打断), 不重试、不跳过。
func runChunkWorkers(size int64, workers int, cp *chunkProgress,
	do func(worker int, offset, length int64, idx int, onProgress func(int64)) (string, error)) (string, error) {
	cursor := newChunkCursor(size)

	var mu sync.Mutex
	var firstErr error
	var saved string
	failed := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return firstErr != nil
	}

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			var done int64 // 这个 worker 迄今已送达/取到的累计字节数, 跨好几片累加
			want := int64(probeChunkSize)
			first := true
			for {
				if failed() {
					return
				}
				offset, length, idx, ok := cursor.claim(want)
				if !ok {
					return
				}
				base := done
				start := time.Now()
				s, err := do(w, offset, length, idx, func(sent int64) { cp.update(w, base+sent) })
				if first {
					// 只测第一片: 后面的片沿用这个大小, 不再重新测(见
					// chunkSizeForRate 的说明)。
					want = workerChunkSize(length, time.Since(start))
					first = false
				}
				done += length
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
				} else if s != "" {
					saved = s
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	if firstErr != nil {
		return "", firstErr
	}
	return saved, nil
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

// probeFile 在直连上开一条流探测收方有没有同名文件(见 file_conflict.go)。
func (d *directPeer) probeFile(sess *directSession, it fileItem, noHash bool, notify func(string)) (*probeResult, error) {
	stream, err := d.openFileStream(sess)
	if err != nil {
		return nil, err
	}
	return probeOver(stream, it, noHash, notify)
}

// sendFileChunk 是 sendFile 的分块版: 单独开一条流发文件里的 [offset, offset+length)
// 这一段, 供单文件并行分块传输用(见 file_send.go 的 parallel 参数)。除了多传
// offset/length/tid/chunkIdx, 与 sendFile 完全一样——每个分块各自开一条独立的
// QUIC stream, 复用同一个 sess 不用重新打洞。
func (d *directPeer) sendFileChunk(sess *directSession, it fileItem, offset, length int64, tid string, chunkIdx int, onProgress func(sent int64)) (string, error) {
	stream, err := d.openFileStream(sess)
	if err != nil {
		return "", err
	}
	return sendFileOverRange(stream, it, offset, length, tid, chunkIdx, onProgress)
}

// openFileStream 开一条文件传输流并写好身份声明, 是 sendFile/sendFileChunk 共用的
// 前半段(见 fileAuth 的注释)。发之前先校验自己的 uuid 格式: 为空或不是合法 uuid
// (比如 .uuid 状态文件被手改坏了)时这份凭证本身就没有意义, 对端要么直接拒绝要么
// 比对出一个巧合的假阳性/假阴性, 不如在本地就地拒绝, 不打开这条 stream。
func (d *directPeer) openFileStream(sess *directSession) (*quic.Stream, error) {
	if !conf.IsValidUUID(d.cfg.UUID) {
		return nil, errors.New("websocket.client.uuid is empty or not a valid uuid, refusing to send")
	}
	stream, err := d.openHeadedStream(sess, directStreamFile, "", directFileTag)
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
// 完全对称(同样的 uuid 自检、同样的 fileAuth 帧、同样的 directFileTag), 区别只在
// Kind 和之后的字节流向。
func (d *directPeer) openPullStream(sess *directSession) (*quic.Stream, error) {
	if !conf.IsValidUUID(d.cfg.UUID) {
		return nil, errors.New("websocket.client.uuid is empty or not a valid uuid, refusing to pull")
	}
	stream, err := d.openHeadedStream(sess, directStreamPull, "", directFileTag)
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
	if it.conflict == ConflictResume {
		// 续传: 只发收方还没有的后半段。摘要(尾部)也只覆盖这一段——前半段已经在协商时
		// 比对过哈希, 收方续写失败时会把文件截回原长度(见 resumeIncoming)。
		return sendFileOverRange(conn, it, it.resumeAt, it.size-it.resumeAt, "", 0, onProgress)
	}
	return sendFileOverRange(conn, it, 0, it.size, "", 0, onProgress)
}

// sendFileOverRange 发送一个文件的核心逻辑, 不关心 conn 底下是 QUIC stream 还是中继
// 消息通道; 用完即关——直连路径关的是那条 stream, 中继路径关的是 msgPipe(会触发发
// 一个收尾信号给对端)。
//
// offset/length 圈定这次要发文件里的哪一段: 不分块传输时 offset=0、length=整份文件
// 大小; 分块并行传输时(见 file_send.go 的 parallel 参数)每个分块各自打开一条独立
// 连接, 用各自的 offset/length 调这个函数, tid/chunkIdx 让接收端知道这些连接属于
// 同一次传输、该拼在文件的哪个位置。TotalSize 直接从 it.size 取, 不需要调用方传——
// 这个函数本来就知道整份文件多大。每条连接各自 os.Open 一份文件描述符再 Seek, 不
// 共享同一个 *os.File——多个 goroutine 共用一个 fd 各自 Seek 会相互踩踏。
func sendFileOverRange(conn fileConn, it fileItem, offset, length int64, tid string, chunkIdx int, onProgress func(sent int64)) (string, error) {
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
		TransferID: tid, ChunkIndex: chunkIdx, Offset: offset, TotalSize: it.size,
		Conflict: it.conflict, ResumePart: it.resumePart,
	}); err != nil {
		return "", fmt.Errorf("send head: %w", err)
	}

	h := sha256.New()
	// 边发边算摘要: 摘要放在尾部就是为了这个, 不用为了算它先把文件读一遍。
	src := io.TeeReader(&progressReader{r: f, on: onProgress}, h)
	buf := make([]byte, fileCopyBuf)
	sent, err := io.CopyBuffer(conn, io.LimitReader(src, length), buf)
	if err != nil {
		// 对端可能提前拒绝了(权限/配置)或收到一半自己出错(比如落盘失败): 它会先写好
		// 一条 fileReply 再断开接收方向(见 nat/direct_accept.go serveStream 的
		// CancelRead), 我们这里的 Write 因此被对端 reset、报出的是 QUIC 层的
		// "stream canceled" 之类的话, 说不清真正原因。趁 conn 的接收方向还活着, 抓紧
		// 看一眼对端是不是已经把那条更明白的回复写过来了, 有就换上它。
		if reason := peerRejectReason(conn); reason != "" {
			return "", errors.New(reason)
		}
		return "", fmt.Errorf("send body: %w", err)
	}
	if sent != length {
		// 传输途中文件被改小了。继续发下去收端只会校验失败, 不如当场说清楚。
		return "", fmt.Errorf("file shrank while sending: sent %d of %d bytes", sent, length)
	}
	if err := writeFrame(conn, fileTrailer{SHA256: hex.EncodeToString(h.Sum(nil))}); err != nil {
		if reason := peerRejectReason(conn); reason != "" {
			return "", errors.New(reason)
		}
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

// peerRejectReason 在给对端写 body/trailer 失败后, 短时间内探一下对端是不是已经把
// 一条 fileReply 写回来了——见 sendFileOverRange 里两处调用点的注释。读不到(真断线,
// 或对端根本没来得及回复)就返回空串, 调用方据此退回原始的底层错误。
//
// 5 秒够用: 对端在我们这次 Write 出错之前就已经调过 reply(), 那条回复早就交给它自己
// 的发送方向了, 这里等的只是"已经在路上的几十字节几时到", 不是要它现算什么。
func peerRejectReason(conn fileConn) string {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var reply fileReply
	err := readFrame(conn, &reply, fileFrameMax)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || reply.Err == "" {
		return ""
	}
	return reply.Err
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
