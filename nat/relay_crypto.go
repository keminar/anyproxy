package nat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// 中继路径(A<->C 经 B 转发字节)的加密层。
//
// 为什么中继需要单独加一层, 直连不需要: 直连是 QUIC, 已经端到端加密, B 全程看不到
// 任何字节; 中继恰恰相反——字节是明文经 B 转发的, receive.allow 里配的 uuid 如果只
// 当一个"比对值"用, B 转发时能直接看到它, 也就看到了整个身份判断依据。既然这个
// uuid 本身就是 A、C 才知道的共享密钥, 干脆直接拿它加密整段数据: 解密+认证通过,
// 既证明了"对方确实持有这个 uuid"(相当于身份校验), 又顺带把 B 挡在了明文之外——
// 一个动作两件事都办了, 不用再另外维护一条身份声明。
//
// 会话密钥: 静态 uuid 加一个每次传输新生成的随机 salt(见 FileRelayOpen.Salt, 不是
// 秘密, 明文过 B 也无妨——只是用来避免同一个 uuid 在不同文件传输之间重复用同一把
// key, GCM 绝不能对同一把 key 用重复的 nonce/让 key 本身被复用到不相关的两次会话)。
// 单次会话内部再用一个递增计数器当 nonce, 双方按写入顺序独立计数, 不需要在线上
// 传 nonce。
//
// 一个 uuid 对应两把方向各自独立的会话 key(发送方写 / 接收方写), 避免两个方向共用
// 同一把 key 时 nonce 计数器分别从 0 起步而相互撞上。

const (
	relayAEADKeySize   = 32        // AES-256
	relayAEADNonceSize = 12        // GCM 标准 nonce 长度
	relayAEADFrameMax  = 1 << 20   // 单帧密文上限, 防止对端谎报长度撑爆内存
	relaySaltSize      = 16        // 会话 salt 长度(不是秘密, 只为避免 key/nonce 复用)
	relayReadBufChunk  = 32 * 1024 // 每次向底层 fileConn 要多少原始字节
)

// newRelaySalt 生成一次传输用的会话 salt, base64 编码后随信令明文传输(不是秘密)。
func newRelaySalt() (string, error) {
	var b [relaySaltSize]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// deriveRelaySessionKeys 从共享的 uuid + 本次会话的 salt 派生两个方向各自的
// AES-256-GCM key。发起方(A, 文件发送方)用 senderKey 加密自己写出的数据、用
// receiverKey 解密收到的数据(主要是 fileReply); 接收方(C)反过来。
//
// 用两个不同标签的 SHA-256 而不是正经的 HKDF: 这里只需要"从一份共享秘密派生出
// 两把互不相关的定长 key", 域分隔(标签不同)已经足够, 犯不着为此再引入一个新依赖。
func deriveRelaySessionKeys(uuid, salt string) (senderKey, receiverKey [relayAEADKeySize]byte, err error) {
	if uuid == "" {
		return senderKey, receiverKey, errors.New("empty uuid")
	}
	if salt == "" {
		return senderKey, receiverKey, errors.New("empty salt")
	}
	senderKey = sha256.Sum256([]byte(uuid + "|" + salt + "|a2c"))
	receiverKey = sha256.Sum256([]byte(uuid + "|" + salt + "|c2a"))
	return senderKey, receiverKey, nil
}

// aeadConn 把一个 fileConn 包一层 AES-256-GCM: Write 的每次调用整体加密成一帧
// ([4 字节密文长度][密文, 含 16 字节 tag]), Read 反过来拆帧解密。帧边界与调用方
// 的 Write 调用一一对应(不分片), 但 Read 一侧要能应付底层分段到达, 所以自己攒够
// 一整帧才解密。
type aeadConn struct {
	under fileConn
	enc   cipher.AEAD
	dec   cipher.AEAD

	encSeq uint64
	decSeq uint64

	inbuf []byte // 从 under 读到但还没组成完整帧的原始字节
	plain []byte // 已解密但还没被 Read() 取走的明文
}

// newAEADConn 用一对方向 key 包住 under。writeKey 加密本端写出去的数据, readKey
// 解密从 under 读到的数据——调用方按自己的角色传对方向: 发送方传
// (senderKey, receiverKey), 接收方传 (receiverKey, senderKey)。
func newAEADConn(under fileConn, writeKey, readKey [relayAEADKeySize]byte) (*aeadConn, error) {
	enc, err := newGCM(writeKey)
	if err != nil {
		return nil, err
	}
	dec, err := newGCM(readKey)
	if err != nil {
		return nil, err
	}
	return &aeadConn{under: under, enc: enc, dec: dec}, nil
}

func newGCM(key [relayAEADKeySize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// nonceFor 用递增计数器构造 GCM nonce: 前 4 字节固定 0, 后 8 字节是大端计数器。
// 同一把 key 只在一次传输会话内使用(salt 保证不同会话不同 key), 会话内不会发生
// 计数器回绕(64 位, 实际传输量远远达不到), 双方各自独立计数、按写入顺序对应即可,
// 不需要把 nonce 也传一遍。
func nonceFor(seq uint64) []byte {
	var n [relayAEADNonceSize]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

func (a *aeadConn) Write(p []byte) (int, error) {
	nonce := nonceFor(a.encSeq)
	a.encSeq++
	ct := a.enc.Seal(nil, nonce, p, nil)
	frame := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(ct)))
	copy(frame[4:], ct)
	if _, err := a.under.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *aeadConn) Read(p []byte) (int, error) {
	for len(a.plain) == 0 {
		if err := a.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, a.plain)
	a.plain = a.plain[n:]
	return n, nil
}

func (a *aeadConn) readFrame() error {
	lenBuf, err := a.readN(4)
	if err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf)
	if n > relayAEADFrameMax {
		return fmt.Errorf("aead: frame too large (%d)", n)
	}
	ct, err := a.readN(int(n))
	if err != nil {
		return err
	}
	nonce := nonceFor(a.decSeq)
	a.decSeq++
	pt, err := a.dec.Open(nil, nonce, ct, nil)
	if err != nil {
		// 解密/认证失败: 要么是双方 uuid 没对上, 要么数据被篡改——这两种在这里没法
		// 细分, 但都必须当作"对端身份不对"直接拒绝, 不能有任何容错或重试。
		return fmt.Errorf("aead: decrypt/auth failed (uuid mismatch?): %w", err)
	}
	a.plain = pt
	return nil
}

// readN 从 inbuf/under 精确攒够 n 字节, 跨多次底层 Read 拼起来。
func (a *aeadConn) readN(n int) ([]byte, error) {
	for len(a.inbuf) < n {
		buf := make([]byte, relayReadBufChunk)
		m, err := a.under.Read(buf)
		if m > 0 {
			a.inbuf = append(a.inbuf, buf[:m]...)
		}
		if err != nil {
			if len(a.inbuf) >= n {
				break
			}
			return nil, err
		}
	}
	out := a.inbuf[:n]
	a.inbuf = a.inbuf[n:]
	return out, nil
}

func (a *aeadConn) Close() error {
	return a.under.Close()
}

func (a *aeadConn) SetReadDeadline(t time.Time) error {
	return a.under.SetReadDeadline(t)
}
