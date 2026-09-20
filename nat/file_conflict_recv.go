package nat

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// 收方落盘的覆盖/续传实现(协商见 file_conflict.go)。

// activeParts 本进程里正在被写的 .part(键是完整路径)。续传只接管「没人在写」的 .part:
// 发送端异常退出时, 收端旧连接可能还没察觉、仍占着旧 .part(见 writeIncoming 的注释), 这时
// 不能让新的一次也往同一个文件里写。
var activeParts sync.Map

// partNameOK 报告 name 是不是 base 这个目标名的单连接 .part: base.<16位十六进制>.part。
// 分块并行传输的 .part 带 ".chunks" 标记(见 getOrCreateAssembly), 中间可能有空洞, 不是
// 连续的前缀, 不会匹配。
func partNameOK(base, name string) bool {
	if filepath.Base(name) != name || !strings.HasPrefix(name, base+".") || !strings.HasSuffix(name, filePartSuffix) {
		return false
	}
	tok := strings.TrimSuffix(strings.TrimPrefix(name, base+"."), filePartSuffix)
	if len(tok) != transferIDSize*2 {
		return false
	}
	for _, c := range tok {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func partName(path string) string { return filepath.Base(path) }

// findResumablePart 在 dest 所在目录里找上次中断留下的单连接 .part: 没人在写、非空、比来件
// (incoming 字节)短, 多个时取最长的。内容是不是来件的开头由调用方比哈希, 这里只筛形状。
func findResumablePart(dest string, incoming int64) (path string, size int64) {
	dir, base := filepath.Dir(dest), filepath.Base(dest)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0
	}
	for _, e := range entries {
		if e.IsDir() || !partNameOK(base, e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if _, busy := activeParts.Load(p); busy {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if s := info.Size(); s > 0 && s < incoming && s > size {
			path, size = p, s
		}
	}
	return path, size
}

// receiveToPart 把 stream 上的 head.Size 字节收进 dest 旁边的 .part 临时文件, 返回它的路径与
// 摘要。part 名字带随机 token 的原因见 writeIncoming。
//
// 传输中断(连接断了/收不全)时, 已经收到的部分**保留**在 .part 里而不是删掉, 下次传同一个
// 文件时可以从断点续传(见 findResumablePart); 一个字节都没收到才删。摘要错误由调用方在
// 校验时删除。
func receiveToPart(dest string, r io.Reader, head fileHead) (part, sum string, err error) {
	tok, err := newTransferID()
	if err != nil {
		return "", "", fmt.Errorf("part name: %w", err)
	}
	part = dest + "." + tok + filePartSuffix
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm(head.Mode))
	if err != nil {
		return "", "", fmt.Errorf("create: %w", err)
	}
	activeParts.Store(part, struct{}{})
	defer activeParts.Delete(part)

	h := sha256.New()
	n, err := copyN(io.MultiWriter(f, h), r, head.Size)
	closeErr := f.Close()
	if err != nil || closeErr != nil || n != head.Size {
		if n == 0 {
			os.Remove(part)
		}
		switch {
		case err != nil:
			return "", "", fmt.Errorf("receive: %w", err)
		case closeErr != nil:
			return "", "", fmt.Errorf("close: %w", closeErr)
		}
		return "", "", fmt.Errorf("truncated: got %d of %d bytes", n, head.Size)
	}
	return part, hex.EncodeToString(h.Sum(nil)), nil
}

// writeOverwrite 处理发送方要求覆盖已有文件的单文件传输, 返回落盘路径。与 writeIncoming 的
// 关键区别: 摘要**先**核对、通过了才动已有文件——writeIncoming 是先落到一个新名字再核对
// (不对就删新文件), 这里的目标是已有数据, 不能拿它冒险。
func writeOverwrite(dest string, conn io.Reader, head fileHead) (string, error) {
	part, sum, err := receiveToPart(dest, conn, head)
	if err != nil {
		return "", err
	}
	var tr fileTrailer
	if err := readFrame(conn, &tr, fileFrameMax); err != nil {
		os.Remove(part)
		return "", fmt.Errorf("no checksum from sender: %v (existing file untouched)", err)
	}
	if tr.SHA256 != sum {
		os.Remove(part)
		return "", fmt.Errorf("checksum mismatch (got %s, sender says %s), discarded (existing file untouched)", short(sum), short(tr.SHA256))
	}
	if err := renameWithRetry(part, dest); err != nil {
		return "", fmt.Errorf("rename: %w (data kept at %s)", err, part)
	}
	return dest, nil
}

// resumeIncoming 续传: 把 head.Size 字节接在上次中断留下的 .part(head.ResumePart)的
// head.Offset 处, 收全校验后再改成目标名, 返回最终落盘路径。
//
// 只接管目标名 dest 对应、形状合规、当前没人在写的 .part(名字来自对端, 必须校验, 否则
// 就成了往任意文件里追加); 它必须恰好是 head.Offset 字节——协商时比对的是那个长度的哈希,
// 长度变了说明它在协商之后被动过, 前提不成立, 拒绝。
//
// 改成目标名时与普通传输一样走 claimName: 目标名已被占用就换一个名字, 绝不覆盖已有文件。
// 中途断线保留已收到的部分(下次还能续, 前缀的哈希会在下次协商时重新核对); 尾部摘要不对说明
// 发送方的文件在两次之间变了, 截回 head.Offset。
func resumeIncoming(dest string, conn io.Reader, head fileHead) (string, error) {
	base := filepath.Base(dest)
	if !partNameOK(base, head.ResumePart) {
		return "", fmt.Errorf("bad resume file name %q", head.ResumePart)
	}
	part := filepath.Join(filepath.Dir(dest), head.ResumePart)
	if _, busy := activeParts.LoadOrStore(part, struct{}{}); busy {
		return "", fmt.Errorf("%s is being written by another transfer, try again later", head.ResumePart)
	}
	defer activeParts.Delete(part)

	f, err := os.OpenFile(part, os.O_WRONLY, 0)
	if err != nil {
		return "", fmt.Errorf("open interrupted transfer: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return "", fmt.Errorf("stat interrupted transfer: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != head.Offset {
		f.Close()
		return "", fmt.Errorf("%s is %d bytes, expected %d: it changed after the check, not resuming", head.ResumePart, info.Size(), head.Offset)
	}
	h := sha256.New()
	n, err := copyN(io.MultiWriter(io.NewOffsetWriter(f, head.Offset), h), conn, head.Size)
	closeErr := f.Close()
	switch {
	case err != nil:
		return "", fmt.Errorf("receive: %w (kept %s so far)", err, humanBytes(head.Offset+n))
	case closeErr != nil:
		return "", fmt.Errorf("close: %w", closeErr)
	case n != head.Size:
		return "", fmt.Errorf("truncated: got %d of %d bytes (kept %s so far)", n, head.Size, humanBytes(head.Offset+n))
	}
	var tr fileTrailer
	if err := readFrame(conn, &tr, fileFrameMax); err != nil {
		return "", fmt.Errorf("no checksum from sender: %v", err)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); tr.SHA256 != sum {
		_ = os.Truncate(part, head.Offset)
		return "", fmt.Errorf("checksum mismatch (got %s, sender says %s), the appended data was discarded", short(sum), short(tr.SHA256))
	}

	final, err := claimName(dest)
	if err != nil {
		return "", fmt.Errorf("%w (data kept at %s)", err, part)
	}
	if err := renameWithRetry(part, final); err != nil {
		os.Remove(final) // claimName 留下的空占位
		return "", fmt.Errorf("rename: %w (data kept at %s)", err, part)
	}
	return final, nil
}

// dropClaim 传输失败时收掉 claimName 留下的空占位文件。覆盖模式下 final 是收方已有的文件,
// 绝不能删。
func (a *chunkAssembly) dropClaim() {
	if a.claimed {
		_ = os.Remove(a.final)
	}
}
