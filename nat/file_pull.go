package nat

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// 取文件(pull): A 主动把 C 上的文件拉回来, 与 -send 的推送方向相反。
//
// 为什么不需要反转连接方向: sendFileOver / recvFileOver 本来就是一对角色可互换的
// 函数, 而 QUIC stream 与中继的 msgPipe 都是全双工的。所以 A 仍然是拨号方/发起方,
// 只是在流上先说一句"把这个给我", 之后两边的角色互换 —— C 跑 sendFileOver, A 跑
// recvFileOver。落盘、.part 占位、SHA-256 校验、重名不覆盖这些一行都不用重写。
//
// 一次取件的时序(直连与中继共用, 只是 conn 底下是 QUIC stream 还是 msgPipe 的区别):
//
//	A --pull{op:list, path:"backup"}--> C     第一条流: 要一份清单
//	A <--resp{err}--------------------- C     err 非空则到此为止
//	A <--entry----------------------- C     一条一帧, 以空 Path 的帧收尾
//	A --pull{op:get, path:...}-------> C     之后每个文件一条新流
//	A <--resp{err}-------------------- C
//	A <--fileHead/数据/fileTrailer----- C     就是 sendFileOver
//	A --fileReply--------------------> C     就是 recvFileOver
//
// 权限沿用 client.receive 那一份配置, 不另开一块: receive.dir 既是收文件的落地目录,
// 也是可以被取走的根目录; receive.allow 里的人既能往这儿发, 也能从这儿取。这是一次
// 有意的语义扩张(配置注释与文档里写明了), 代价是"允许某人给我发文件"现在顺带意味着
// "允许他读我这个目录", 好处是不必为一个对称的动作维护两份几乎一样的名单。

const (
	// filePullList 要一份清单; filePullGet 取其中一个文件。
	filePullList = "list"
	filePullGet  = "get"

	// filePullMaxEntries 一次清单最多认多少条。对端说了算的东西都要有上限, 不然
	// 一个指向巨大目录(或恶意构造)的清单能让 A 一直读一直攒。
	filePullMaxEntries = 100000

	// filePullReplyTimeout 等对端回应答帧的上限。数据本身不设总时限(大文件在慢链路
	// 上传很久是正常的), 但"请求发出去了却没人应"必须有个头。
	filePullReplyTimeout = 30 * time.Second
)

// filePullReq A 发给 C 的取件请求, 一条流一个。
type filePullReq struct {
	Op   string `json:"op"`   // filePullList / filePullGet
	Path string `json:"path"` // 相对 C 的 receive.dir; 空表示整个 receive.dir
	// Name 仅 op=get: A 希望这个文件在自己这边叫什么, C 原样填进 fileHead.Name。
	// 与 Path 分开是必需的 —— 取单个文件时 Path="backup/db.sql" 而 Name="db.sql",
	// 取整个目录时两者才一致。C 不需要记住上一条流里的根目录是什么, 每条流都自足。
	Name string `json:"name"`

	// 以下四个字段只在单文件分块并行取件时才非零(见 file_recv.go 的 parallel 参数)。
	// A 从清单(Size)已经知道文件大小, 由它规划切几块、每块的范围, C 只管照单发货,
	// 不需要额外一次往返来问。语义与 fileHead 里的同名字段一致, 见那边的注释。
	TransferID string `json:"tid,omitempty"`
	ChunkIndex int    `json:"ci,omitempty"`
	ChunkCount int    `json:"cc,omitempty"`
	Offset     int64  `json:"off,omitempty"`
	// Length 是这一块要发的字节数。放在请求帧里而不是让 C 自己按 Offset 推算到
	// 文件末尾, 是因为"到文件末尾"只对最后一块成立——其余块的长度必须由 A 显式
	// 告诉 C, C 不知道整份切分方案。
	Length int64 `json:"length,omitempty"`
}

// filePullResp C 的应答, 排在任何数据之前。Err 非空表示这次取件到此为止。
type filePullResp struct {
	Err string `json:"err"`
}

// filePullEntry 清单里的一条。
//
// 只有相对路径, 没有 C 侧的绝对路径: 那是对方的目录结构, 取文件的人没有理由知道。
type filePullEntry struct {
	Path string `json:"path"` // 相对 C 的 receive.dir, 取的时候原样带回
	Name string `json:"name"` // 相对 A 的保存目录, 语义同 -send 的相对名
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

// ---------- 被取的一侧(C) ----------

// servePull 处理一条取件流, 直连与中继共用。地位与 recvFileOver 完全对称: 身份核对
// 由调用方在此之前完成(直连见 authorizeFileSender, 中继见 onFileRelayOpen 的解密),
// 这里只管取件本身, fromEmail 仅用于日志。
func servePull(conn fileConn, cfg conf.ClientReceive, fromEmail, remote string, logf func(string, ...interface{})) {
	fail := func(reason string) {
		logf("pull from %s: %s", remote, reason)
		if err := writeFrame(conn, filePullResp{Err: reason}); err != nil {
			logf("pull from %s: cannot reply: %v", remote, err)
		}
	}
	// 先读请求再回应答, 哪怕已经知道要拒绝也一样: 这条流上"一问一答"的顺序必须严格,
	// 抢先写出去的话对端还在写请求、本端已经在写应答, 两边都在等对方读 —— 无缓冲的
	// 通道(中继路径的 msgPipe 就接近这个语义)上这是个死锁。
	//
	// 请求帧要有超时: 开了流却不发请求的对端会一直占着它。
	_ = conn.SetReadDeadline(time.Now().Add(filePullReplyTimeout))
	var req filePullReq
	if err := readFrame(conn, &req, fileFrameMax); err != nil {
		fail(fmt.Sprintf("bad pull request: %v", err))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if cfg.Dir == "" {
		fail("peer does not share files (websocket.client.receive.dir is not set)")
		return
	}

	src, root, err := resolveShared(cfg.Dir, req.Path)
	if err != nil {
		// 回给对端的话里不带 err: 它多半含本机的绝对路径("lstat /srv/data/x: no such
		// file"), 而取文件的人没有理由知道这个目录在对面叫什么。完整原因留在本机日志。
		logf("pull from %s: rejected path %q: %v", remote, req.Path, err)
		if err := writeFrame(conn, filePullResp{Err: fmt.Sprintf("cannot use path %q (no such file, or it is outside the shared directory)", req.Path)}); err != nil {
			logf("pull from %s: cannot reply: %v", remote, err)
		}
		return
	}

	switch req.Op {
	case filePullList:
		items, err := collectFiles([]string{src})
		if err != nil {
			// 同上: collectFiles 的错误里带本机绝对路径, 不外传。
			logf("pull from %s: cannot list %q: %v", remote, req.Path, err)
			if err := writeFrame(conn, filePullResp{Err: fmt.Sprintf("cannot list %q", req.Path)}); err != nil {
				logf("pull from %s: cannot reply: %v", remote, err)
			}
			return
		}
		if err := writeFrame(conn, filePullResp{}); err != nil {
			logf("pull from %s: cannot reply: %v", remote, err)
			return
		}
		for _, it := range items {
			rel, err := filepath.Rel(root, it.path)
			if err != nil {
				logf("pull from %s: skipping %s: %v", remote, it.name, err)
				continue
			}
			e := filePullEntry{Path: filepath.ToSlash(rel), Name: it.name, Size: it.size, Mode: it.mode}
			if err := writeFrame(conn, e); err != nil {
				logf("pull from %s: cannot send listing: %v", remote, err)
				return
			}
		}
		// 空 Path 的一帧是清单结束的信号。不靠 EOF 收尾: EOF 分不清"发完了"和"发到
		// 一半连接断了", 而那两种情况对端的处置完全不同。
		if err := writeFrame(conn, filePullEntry{}); err != nil {
			logf("pull from %s: cannot end listing: %v", remote, err)
			return
		}
		logf("pull from %s: listed %d file(s) under %s", remote, len(items), req.Path)

	case filePullGet:
		info, err := os.Stat(src)
		if err != nil {
			// 同上: 不把本机路径回给对端。
			logf("pull from %s: cannot stat %q: %v", remote, req.Path, err)
			if err := writeFrame(conn, filePullResp{Err: fmt.Sprintf("cannot read %q", req.Path)}); err != nil {
				logf("pull from %s: cannot reply: %v", remote, err)
			}
			return
		}
		// 只发普通文件, 与 collectFiles 的口径一致: 目录要先 list 再逐个取, 设备节点
		// 之类的传过去没有意义。
		if !info.Mode().IsRegular() {
			fail(fmt.Sprintf("%q is not a regular file", req.Path))
			return
		}
		name := req.Name
		if name == "" {
			name = filepath.Base(src)
		}
		if err := writeFrame(conn, filePullResp{}); err != nil {
			logf("pull from %s: cannot reply: %v", remote, err)
			return
		}
		it := fileItem{path: src, name: name, size: info.Size(), mode: uint32(info.Mode().Perm())}
		start := time.Now()
		var saved string
		if req.TransferID != "" {
			// 分块取件(见 file_recv.go 的 parallel 参数): A 已经规划好了范围, 这里
			// 照单发货, 不重新判断切不切块——那是取件方的决定, C 只管配合。
			saved, err = sendFileOverRange(conn, it, req.Offset, req.Length, req.TransferID, req.ChunkIndex, req.ChunkCount, nil)
		} else {
			saved, err = sendFileOver(conn, it, nil)
		}
		if err != nil {
			logf("pull from %s: sending %s failed: %v", remote, req.Path, err)
			return
		}
		logf("pull from %s: sent %s as %s (%s in %s)", remote, req.Path, saved,
			humanBytes(it.size), time.Since(start).Round(time.Millisecond))

	default:
		fail(fmt.Sprintf("unknown pull op %q", req.Op))
	}
}

// resolveShared 把对端请求的相对路径解析成本机的绝对路径, 并确认它确实落在共享目录
// 内。返回解析后的目标与共享目录本身(供 filepath.Rel 用)。
//
// 比收文件那侧多一道 EvalSymlinks: 写入方向创建的是新文件, 符号链接无从谈起; 读取
// 方向不一样 —— 共享目录里放一个指向 /etc/shadow 的软链, 光靠 safeJoin 那套字符串
// 检查是拦不住的(拼出来的路径确实在目录内), 一取就把目录外的东西送出去了。
func resolveShared(dir, name string) (dest, root string, err error) {
	// 共享目录本身也可能经由软链(macOS 的 /tmp -> /private/tmp 就是这样), 所以两边都
	// 解析之后再比, 否则一个完全正常的配置会被误判成越界。
	root, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return "", "", fmt.Errorf("shared directory is not usable: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	if name == "" {
		// 空路径 = 整个共享目录。命令行那侧要求显式写出冒号才会走到这里, 不会因为
		// 手滑漏了路径就把整个目录端出去。
		return root, root, nil
	}
	joined, err := safeJoin(root, name)
	if err != nil {
		return "", "", err
	}
	dest, err = filepath.EvalSymlinks(joined)
	if err != nil {
		return "", "", err
	}
	if dest != root && !strings.HasPrefix(dest, root+string(os.PathSeparator)) {
		return "", "", errors.New("path escapes the shared directory")
	}
	return dest, root, nil
}

// ---------- 取文件的一侧(A) ----------

// pullList 在一条流上要一份清单。
func pullList(conn fileConn, path string) ([]filePullEntry, error) {
	if err := writeFrame(conn, filePullReq{Op: filePullList, Path: path}); err != nil {
		return nil, fmt.Errorf("send list request: %w", err)
	}
	var resp filePullResp
	if err := readPullFrame(conn, &resp); err != nil {
		return nil, err
	}
	if resp.Err != "" {
		return nil, errors.New(resp.Err)
	}
	var out []filePullEntry
	for {
		var e filePullEntry
		if err := readPullFrame(conn, &e); err != nil {
			return nil, fmt.Errorf("read listing: %w", err)
		}
		if e.Path == "" {
			return out, nil
		}
		if len(out) >= filePullMaxEntries {
			return nil, fmt.Errorf("peer is listing more than %d files, refusing", filePullMaxEntries)
		}
		out = append(out, e)
	}
}

// pullFile 在一条流上取一个文件并落盘到 dir, 返回实际存成的名字。
func pullFile(conn fileConn, dir string, e filePullEntry, from, remote string,
	logf func(string, ...interface{}), onProgress func(int64)) (string, error) {
	if err := writeFrame(conn, filePullReq{Op: filePullGet, Path: e.Path, Name: e.Name}); err != nil {
		return "", fmt.Errorf("send get request: %w", err)
	}
	var resp filePullResp
	if err := readPullFrame(conn, &resp); err != nil {
		return "", err
	}
	if resp.Err != "" {
		return "", errors.New(resp.Err)
	}

	var src fileConn = conn
	if onProgress != nil {
		src = &progressConn{fileConn: conn, size: e.Size, on: onProgress}
	}
	// recvFileOver 不返回结果(daemon 场景只记日志), 结果从它的 onDone 回调里接。
	// 它的每一条返回路径都先走 reply(), 所以这个回调一定会被调到一次。
	var got fileReply
	recvFileOver(src, dir, from, remote, logf, func(r fileReply) { got = r })
	if got.Err != "" {
		return "", errors.New(got.Err)
	}
	return got.Saved, nil
}

// pullFileChunk 是 pullFile 的分块版, 在一条独立的流/中继连接上只取文件的
// [offset, offset+length) 这一段, 供单文件并行分块取件用(见 file_recv.go 的
// parallel 参数)。落盘走的还是 recvFileOver——它已经会按 TransferID 转给
// recvFileChunk 做跨连接的拼接, 这里不用重复那套逻辑。
func pullFileChunk(conn fileConn, dir string, e filePullEntry, from, remote string,
	logf func(string, ...interface{}), tid string, chunkIdx, chunkCount int, offset, length int64, onProgress func(int64)) (string, error) {
	req := filePullReq{
		Op: filePullGet, Path: e.Path, Name: e.Name,
		TransferID: tid, ChunkIndex: chunkIdx, ChunkCount: chunkCount, Offset: offset, Length: length,
	}
	if err := writeFrame(conn, req); err != nil {
		return "", fmt.Errorf("send get request: %w", err)
	}
	var resp filePullResp
	if err := readPullFrame(conn, &resp); err != nil {
		return "", err
	}
	if resp.Err != "" {
		return "", errors.New(resp.Err)
	}

	var src fileConn = conn
	if onProgress != nil {
		src = &progressConn{fileConn: conn, size: length, on: onProgress}
	}
	var got fileReply
	recvFileOver(src, dir, from, remote, logf, func(r fileReply) { got = r })
	if got.Err != "" {
		return "", errors.New(got.Err)
	}
	return got.Saved, nil
}

// readPullFrame 带超时读一个控制帧。每次都重设绝对超时, 不能只在循环外设一次——
// 清单可能有很多条, 一个固定的截止时间会在慢链路上把正常的传输判成超时。
func readPullFrame(conn fileConn, v interface{}) error {
	_ = conn.SetReadDeadline(time.Now().Add(filePullReplyTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	if err := readFrame(conn, v, fileFrameMax); err != nil {
		return fmt.Errorf("no answer from peer: %w", err)
	}
	return nil
}

// progressConn 在读的过程中回调已读字节数, 让取大文件也有和 -send 一样的进度条。
//
// 计数从这层建立起算, 因此把文件首部那几十个字节也算了进去; 按 size 截断一下,
// 免得小文件显示出 100% 以上这种一看就不对的数字。
type progressConn struct {
	fileConn
	n    int64
	size int64
	on   func(int64)
}

func (p *progressConn) Read(b []byte) (int, error) {
	n, err := p.fileConn.Read(b)
	if n > 0 {
		p.n += int64(n)
		shown := p.n
		if p.size > 0 && shown > p.size {
			shown = p.size
		}
		p.on(shown)
	}
	return n, err
}
