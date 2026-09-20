package nat

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// 收方落盘的覆盖/续传实现(协商见 file_conflict.go)。

// receiveToPart 把 stream 上的 head.Size 字节收进 dest 旁边的 .part 临时文件, 返回它的路径与
// 摘要。part 名字带随机 token 的原因见 writeIncoming。出错时 part 已删除。
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
	return part, hex.EncodeToString(h.Sum(nil)), nil
}

// writeModify 处理发送方要求覆盖/续传已有文件(head.Conflict)的单文件传输, 返回落盘路径。
// 与 writeIncoming 的关键区别: 摘要**先**核对、通过了才动已有文件——writeIncoming 是先
// 落到一个新名字再核对(不对就删新文件), 这里的目标是已有数据, 不能拿它冒险。
func writeModify(dest string, conn io.Reader, head fileHead) (string, error) {
	if head.Conflict == ConflictResume {
		return resumeIncoming(dest, conn, head)
	}
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

// resumeIncoming 把 head.Size 字节接在已有文件 dest 的 head.Offset 处(续传)。
//
// 已有文件必须恰好是 head.Offset 字节——协商时比对的是那个长度的哈希, 长度变了说明文件在
// 协商之后被动过, 前提不成立, 拒绝。接收的这一段先写进去、再核对尾部摘要(只覆盖这一段);
// 任何一步失败都把文件截回原长度, 已有的那部分数据原样保住。
func resumeIncoming(dest string, conn io.Reader, head fileHead) (string, error) {
	f, err := os.OpenFile(dest, os.O_WRONLY, 0)
	if err != nil {
		return "", fmt.Errorf("open existing file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return "", fmt.Errorf("stat existing file: %w", err)
	}
	if info.Size() != head.Offset {
		f.Close()
		return "", fmt.Errorf("existing file is %d bytes, expected %d: it changed after the check, not resuming", info.Size(), head.Offset)
	}
	rollback := func() { _ = os.Truncate(dest, head.Offset) }
	h := sha256.New()
	n, err := copyN(io.MultiWriter(io.NewOffsetWriter(f, head.Offset), h), conn, head.Size)
	closeErr := f.Close()
	if err != nil || closeErr != nil || n != head.Size {
		rollback()
		switch {
		case err != nil:
			return "", fmt.Errorf("receive: %w (rolled back to %d bytes)", err, head.Offset)
		case closeErr != nil:
			return "", fmt.Errorf("close: %w (rolled back to %d bytes)", closeErr, head.Offset)
		}
		return "", fmt.Errorf("truncated: got %d of %d bytes (rolled back to %d bytes)", n, head.Size, head.Offset)
	}
	var tr fileTrailer
	if err := readFrame(conn, &tr, fileFrameMax); err != nil {
		rollback()
		return "", fmt.Errorf("no checksum from sender: %v (rolled back)", err)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); tr.SHA256 != sum {
		rollback()
		return "", fmt.Errorf("checksum mismatch (got %s, sender says %s), rolled back", short(sum), short(tr.SHA256))
	}
	return dest, nil
}

// dropClaim 传输失败时收掉 claimName 留下的空占位文件。覆盖模式下 final 是收方已有的文件,
// 绝不能删。
func (a *chunkAssembly) dropClaim() {
	if a.claimed {
		_ = os.Remove(a.final)
	}
}
