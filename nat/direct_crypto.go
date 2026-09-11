package nat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// 打洞控制包(PUNCH/PONG)的加密层。
//
// 为什么单独一份, 不复用 relay_crypto.go: 那套的 nonce 是递增计数器, 依赖"双方按
// 写入顺序独立计数"这个前提, 建立在可靠有序的中继流之上; 而打洞是无序、可能丢包、
// 且多个 goroutine 并发发送的裸 UDP(punchAll 并行探测多个候选、punchOnly/punchOne
// 内部各连发 directPunchCount 次), 用计数器同步的风险比"每包独立随机 nonce"更大。
// 密钥派生也用独立的标签(见 deriveDirectSessionKeys), 不与中继会话共享派生密钥空间。
//
// 运营商设备按明文 ASCII 特征串(如 "ANYPROXY-DIRECT-PUNCH")识别并丢弃打洞包, 是
// 打洞失败排查中确认的一个病因; 这层加密去掉这个可被识别的明文特征。纯 opt-in:
// conf.WsClient.DirectEncrypt 不开就完全不受影响(见 prepareDirectCrypto)。

const (
	// directCryptedMagic 加密控制包的首字节, 与明文的 directPacketMagic(0x00) 区分,
	// 两种格式在同一个 socket 上共存, drainNonQUIC 按首字节分流。取值同样要满足
	// "首字节前两位为 0"这条 quic-go 的约束(见 direct_reflect.go directPacketMagic
	// 的注释), 0x01 满足。
	directCryptedMagic = 0x01

	directGCMNonceSize = 12 // GCM 标准 nonce 长度, 每包随机生成, 不复用计数器
	directGCMTagSize   = 16
	directTokenWireLen = 32 // newDirectToken() 的 hex 编码定长, 线格式里无需再编码/加长度前缀

	// directCryptoSessionTTL 会话密钥表条目的存活时间。要盖住一次完整的"请求 offer
	// -> 双方打洞 -> QUIC 拨号"链路(directOfferWait+directPunchWait+directDialWait)
	// 并留有余量, 与 directTokenTTL 同量级, 复用 directTokenStore 那套"put 时懒扫
	// 过期项"的惯例。
	directCryptoSessionTTL = 30 * time.Second
)

// directCryptoSession 一次打洞会话(以 token 为标识)派生出的双向 AEAD。out/in 已经
// 按本机角色分配好方向, 调用方不需要再关心 a2c/c2a 具体是谁对谁。
type directCryptoSession struct {
	out     cipher.AEAD
	in      cipher.AEAD
	expires time.Time
}

// deriveDirectSessionKeys 从共享 uuid + 本次会话 token(充当一次性 salt) 派生两个
// 方向各自的 AES-256-GCM key。手法与 deriveRelaySessionKeys 一致(两个不同标签的
// SHA-256), 但标签独立, 不与中继会话共享派生密钥空间。
func deriveDirectSessionKeys(uuid, token string) (a2c, c2a [32]byte, err error) {
	if uuid == "" {
		return a2c, c2a, errors.New("empty uuid")
	}
	if token == "" {
		return a2c, c2a, errors.New("empty token")
	}
	a2c = sha256.Sum256([]byte(uuid + "|" + token + "|direct-a2c"))
	c2a = sha256.Sum256([]byte(uuid + "|" + token + "|direct-c2a"))
	return a2c, c2a, nil
}

// newDirectCryptoSession 按角色把两个方向 key 分配成 out/in。isInitiator=true 是 A
// (用 a2c 发、c2a 收), false 是 C(反过来), 与 file_relay.go 里 senderKey/receiverKey
// 按角色分配的写法是同一个模式。
func newDirectCryptoSession(uuid, token string, isInitiator bool) (*directCryptoSession, error) {
	a2c, c2a, err := deriveDirectSessionKeys(uuid, token)
	if err != nil {
		return nil, err
	}
	outKey, inKey := c2a, a2c
	if isInitiator {
		outKey, inKey = a2c, c2a
	}
	out, err := newDirectGCM(outKey)
	if err != nil {
		return nil, err
	}
	in, err := newDirectGCM(inKey)
	if err != nil {
		return nil, err
	}
	return &directCryptoSession{out: out, in: in, expires: time.Now().Add(directCryptoSessionTTL)}, nil
}

func newDirectGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealDirectPacket 把一条 "<verb> <nonce>[ <arg>]" payload 加密成完整的线格式包
// (magic+token+GCM nonce+密文)。每次调用都现生成一个新的随机 GCM nonce——不用计数器:
// 打洞是多 goroutine 并发发送、走无序不可靠的 UDP, 用计数器要求双方严格同步, 风险比
// "每包独立随机数"更大; 12 字节随机数在单会话包数量级(至多几十个包)下碰撞概率可
// 忽略不计。
func sealDirectPacket(sess *directCryptoSession, token, payload string) ([]byte, error) {
	// 线格式里 token 字段是定长的(见 peekDirectToken/openDirectPacket 按
	// directTokenWireLen 固定偏移取值), 真正的 token 永远来自 newDirectToken()
	// (16 字节 hex 编码, 固定 32 字符), 这里显式校验而不是悄悄按实际长度拼包——
	// 拼一个长度不对的包只会在对端解析出偏移错乱的垃圾, 排查起来比直接报错难得多。
	if len(token) != directTokenWireLen {
		return nil, fmt.Errorf("direct crypto: token must be %d bytes, got %d", directTokenWireLen, len(token))
	}
	header := make([]byte, 0, 1+directTokenWireLen+directGCMNonceSize)
	header = append(header, directCryptedMagic)
	header = append(header, []byte(token)...)
	nonce := make([]byte, directGCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header = append(header, nonce...)
	// AAD=完整头部(magic+token+nonce): 头部本身不加密, 但要认证, 防止在途篡改。
	ct := sess.out.Seal(nil, nonce, []byte(payload), header)
	return append(header, ct...), nil
}

// peekDirectToken 只读出 token, 不解密——drainNonQUIC 要先凭 token 去会话表里查到
// 该用哪把 key, 才谈得上解密, 这一步天然要在解密之前。
func peekDirectToken(raw []byte) (token string, ok bool) {
	need := 1 + directTokenWireLen + directGCMNonceSize + directGCMTagSize
	if len(raw) < need || raw[0] != directCryptedMagic {
		return "", false
	}
	return string(raw[1 : 1+directTokenWireLen]), true
}

// openDirectPacket 解密一个完整的加密线格式包, 返回内层的 "<verb> <nonce>[ <arg>]"。
func openDirectPacket(sess *directCryptoSession, raw []byte) (string, error) {
	head := 1 + directTokenWireLen + directGCMNonceSize
	if len(raw) < head {
		return "", errors.New("direct crypto: short packet")
	}
	header := raw[:head]
	nonce := raw[1+directTokenWireLen : head]
	ct := raw[head:]
	pt, err := sess.in.Open(nil, nonce, ct, header)
	if err != nil {
		// 解密/认证失败: uuid 没对上、包被篡改、或者干脆是另一个会话的包串进来了——
		// 都算身份不对, 不能有任何容错。
		return "", fmt.Errorf("decrypt/auth failed (uuid mismatch or tampering?): %w", err)
	}
	return string(pt), nil
}

// directCryptoTable 按 token 索引的会话表。与 directTokenStore 的关键区别: 那张表
// 是一次性凭证(取走即删), 这张表要在一次打洞会话期间反复用同一把 key 加密/解密多个
// 包(多候选并行、每条候选连发好几次), get() 只读不删, 只靠 TTL 懒清理。
type directCryptoTable struct {
	mu sync.Mutex
	m  map[string]*directCryptoSession
}

func newDirectCryptoTable() *directCryptoTable {
	return &directCryptoTable{m: make(map[string]*directCryptoSession)}
}

func (t *directCryptoTable) put(token string, sess *directCryptoSession) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	// 顺带清掉过期项: 会话只在一次打洞的短时间内有用, 不清会随请求数无限增长。
	for k, v := range t.m {
		if now.After(v.expires) {
			delete(t.m, k)
		}
	}
	t.m[token] = sess
}

func (t *directCryptoTable) get(token string) (*directCryptoSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	sess, ok := t.m[token]
	if !ok || time.Now().After(sess.expires) {
		return nil, false
	}
	return sess, true
}

// prepareDirectCrypto 在打洞前按需建立本次会话的加密上下文。A(isInitiator=true)和
// C(isInitiator=false)共用同一个函数, 只是取 uuid 的方式不同。encrypt=false 时什么
// 都不做, 直接返回空——这是"opt-in, 不开就零行为变化"的落地点。
//
// 返回非空 errMsg 表示 encrypt=true 但没法满足(uuid 未配置/不合法), 调用方必须直接
// 让这次打洞失败退出, 不能静默退化成明文——退化会让"防 DPI"这个初衷本身失效, 而
// 失败时至少能在日志/DirectReady.Err 里看到明确原因。
func (d *directPeer) prepareDirectCrypto(token string, encrypt bool, isInitiator bool, peerEmail string) (errMsg string) {
	if !encrypt {
		return ""
	}
	var uuid string
	if isInitiator {
		// A: 自己的 uuid 天然就有, 不用查表。
		uuid = d.cfg.UUID
		if !conf.IsValidUUID(uuid) {
			return "directEncrypt is enabled but websocket.client.uuid is empty or not a valid uuid"
		}
	} else {
		// C: 按 A 报上来的 email 去 receive.allow 里查 A 的 uuid。
		u, ok := d.cfg.Receive.Lookup(peerEmail)
		if !ok {
			return fmt.Sprintf("peer %s requested encrypted punch but is not configured in websocket.client.receive.allow", peerEmail)
		}
		if !conf.IsValidUUID(u) {
			return fmt.Sprintf("configured uuid for %s is not a valid uuid", peerEmail)
		}
		uuid = u
	}
	sess, err := newDirectCryptoSession(uuid, token, isInitiator)
	if err != nil {
		return fmt.Sprintf("cannot set up punch encryption: %v", err)
	}
	d.crypto.put(token, sess)
	return ""
}

// encodeDirectPacket 是 punch* 系列函数发包的统一出口: token 对应有会话就加密,
// 没有(没开 Encrypt, 或建立失败从未 put 过)就照旧明文——调用方不需要区分。
func (d *directPeer) encodeDirectPacket(token, payload string) []byte {
	if token != "" {
		if sess, ok := d.crypto.get(token); ok {
			if pkt, err := sealDirectPacket(sess, token, payload); err == nil {
				return pkt
			}
			// GCM Seal 正常不会因输入内容失败, 这里只是留个口子, 出现了也不至于让
			// 打洞彻底哑火。
			d.logf("seal punch packet for token %s failed, sending in plaintext as a fallback", shortToken(token))
		}
	}
	return directPacket(payload)
}

func shortToken(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}
