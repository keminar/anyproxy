package nat

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

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

// fileHead 一条 stream 传一个文件, 这是它的首部。
type fileHead struct {
	Name string `json:"name"` //相对路径, 一律用 / 分隔
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"` //仅取权限位, Windows 收端会忽略
}

// fileTrailer 数据发完之后才发的校验信息。
//
// 放在后面而不是首部, 是为了让发送端边读边算: 摘要写在首部的话, 发送前必须把整个
// 文件先完整读一遍算出摘要, 大文件等于白读一遍。
type fileTrailer struct {
	SHA256 string `json:"sha256"`
}

// fileReply 接收端的结果。
type fileReply struct {
	Saved string `json:"saved"` //实际落盘的文件名(重名时会改), 相对于接收目录
	Err   string `json:"err"`
}

// ---------- 接收端(C) ----------

// recvFile 处理一条文件流。错误一律回给发送端, 让它的退出码和输出能反映真实结果。
func (dc *directConn) recvFile(stream *quic.Stream, remote string) {
	d := dc.peer
	reply := func(r fileReply) {
		if r.Err != "" {
			d.logf("file from %s: %s", remote, r.Err)
		}
		if err := writeFrame(stream, r); err != nil {
			d.logf("file from %s: cannot reply: %v", remote, err)
		}
	}

	cfg := d.cfg.Receive
	if cfg.Dir == "" {
		reply(fileReply{Err: "peer does not accept files (websocket.client.receive.dir is not set)"})
		return
	}
	if !cfg.Allowed(dc.email) {
		reply(fileReply{Err: fmt.Sprintf("email %s is not in websocket.client.receive.allow", dc.email)})
		return
	}

	// 首部要有超时: 开了流却不发首部的对端会一直占着它。数据本身不设总时限 ——
	// 大文件在慢链路上传很久是正常的, QUIC 的空闲超时已经能兜住真正断掉的连接。
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	var head fileHead
	if err := readFrame(stream, &head, fileFrameMax); err != nil {
		reply(fileReply{Err: fmt.Sprintf("bad file head: %v", err)})
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	if head.Size < 0 {
		reply(fileReply{Err: "negative file size"})
		return
	}
	dest, err := safeJoin(cfg.Dir, head.Name)
	if err != nil {
		reply(fileReply{Err: fmt.Sprintf("rejected name %q: %v", head.Name, err)})
		return
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		reply(fileReply{Err: fmt.Sprintf("mkdir: %v", err)})
		return
	}

	start := time.Now()
	saved, sum, err := writeIncoming(dest, stream, head)
	if err != nil {
		reply(fileReply{Err: err.Error()})
		return
	}

	// 校验尾部: 摘要对不上说明落盘的内容不是对方发的那份, 必须删掉 —— 留着一个内容
	// 错误、名字正确的文件, 比没收到坏得多。
	var tr fileTrailer
	if err := readFrame(stream, &tr, fileFrameMax); err != nil {
		os.Remove(saved)
		reply(fileReply{Err: fmt.Sprintf("no checksum from sender: %v", err)})
		return
	}
	if tr.SHA256 != sum {
		os.Remove(saved)
		reply(fileReply{Err: fmt.Sprintf("checksum mismatch (got %s, sender says %s), discarded", short(sum), short(tr.SHA256))})
		return
	}

	rel, _ := filepath.Rel(cfg.Dir, saved)
	d.logf("file from %s: saved %s (%s in %s)", remote, rel, humanBytes(head.Size), time.Since(start).Round(time.Millisecond))
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

// sendFile 在已建立的直连上发一个文件, 返回收端存成的名字。
func (d *directPeer) sendFile(sess *directSession, it fileItem, onProgress func(sent int64)) (string, error) {
	f, err := os.Open(it.path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	stream, err := d.openHeadedStream(sess, directStreamFile, "", directFilePort)
	if err != nil {
		return "", err
	}
	defer stream.Close()

	if err := writeFrame(stream, fileHead{Name: it.name, Size: it.size, Mode: it.mode}); err != nil {
		return "", fmt.Errorf("send head: %w", err)
	}

	h := sha256.New()
	// 边发边算摘要: 摘要放在尾部就是为了这个, 不用为了算它先把文件读一遍。
	src := io.TeeReader(&progressReader{r: f, on: onProgress}, h)
	buf := make([]byte, fileCopyBuf)
	sent, err := io.CopyBuffer(stream, io.LimitReader(src, it.size), buf)
	if err != nil {
		return "", fmt.Errorf("send body: %w", err)
	}
	if sent != it.size {
		// 传输途中文件被改小了。继续发下去收端只会校验失败, 不如当场说清楚。
		return "", fmt.Errorf("file shrank while sending: sent %d of %d bytes", sent, it.size)
	}
	if err := writeFrame(stream, fileTrailer{SHA256: hex.EncodeToString(h.Sum(nil))}); err != nil {
		return "", fmt.Errorf("send checksum: %w", err)
	}

	// 收端要把整个文件落盘并校验之后才回, 所以这里不能设短超时。
	var reply fileReply
	if err := readFrame(stream, &reply, fileFrameMax); err != nil {
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
