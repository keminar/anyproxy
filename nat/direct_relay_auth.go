package nat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	quic "github.com/quic-go/quic-go"
)

// 中继连接的 uuid 挑战-应答鉴权(只用于经 VPS 盲转发的连接, 直连不走这套)。
//
// 为什么中继要额外做这个: 直连时对端就是 C, TLS 指纹固定 + token + forward 白名单已够;
// 中继时 VPS 是**不可信中间人**, 需要在 A<->C 的 e2e QUIC 流里让 C 确认对面确是它允许的 A。
// 不把长期秘密 uuid 发上网, 而是挑战-应答证明"我知道 uuid":
//
//	C -> A: 随机 nonce
//	A -> C: HMAC(uuid, nonce || C 的证书指纹)
//	C: 用 receive.allow[A的email] 查到的 uuid 验一遍
//
// 把 **C 的证书指纹**绑进 HMAC 是为防中继层重放: VPS 若录下一段挑战-应答, 想重放到"另一条
// 它冒名顶替的连接"上, 那条连接的对端指纹不同, 应答就对不上——应答只对"对面确是持有该证书
// 私钥的 C"这条 e2e TLS 有效。nonce 每次新的防常规重放。详见 docs/direct-relay-design.md。
//
// A 的 email 不靠 A 自报: C 用的是 B 经打洞消息(DirectPunch.Email)转来的、B 认证过的发起方
// email(见 directTokenEntry.email), A 伪造不了成别的身份。

const (
	// relayAuthNonceSize 挑战随机数长度。32 字节足够, 与派生/HMAC 的安全边际匹配。
	relayAuthNonceSize = 32
	// relayAuthFrameMax 挑战/应答帧的大小上限, 防对端用超长帧撑爆内存。两个帧都很小。
	relayAuthFrameMax = 256
	// relayAuthWait 单个方向读挑战/应答的上限。走的是已建立的 e2e QUIC 流, 正常极快。
	relayAuthWait = 10 * time.Second
)

// relayChallenge C -> A 的挑战帧。Err 非空时表示 C 拒绝了这次鉴权(如 A 的 email 不在
// receive.allow), Nonce 随之留空——这种情况下这一帧就是唯一的一帧, C 写完即关流,
// 不会再等 A 的应答。放在这条已经建立的 e2e QUIC 流上传回去不经 B、也不给中继层
// (VPS 只盲转发不透明字节, 看不懂这一帧)增加信息暴露。
type relayChallenge struct {
	Nonce []byte `json:"nonce"`
	Err   string `json:"err,omitempty"`
}

// relayResponse A -> C 的应答帧。
type relayResponse struct {
	MAC []byte `json:"mac"`
}

// relayAuthMAC 计算 HMAC(uuid, nonce || fingerprint)。两端算法必须一致。
func relayAuthMAC(uuid string, nonce []byte, fingerprint string) []byte {
	m := hmac.New(sha256.New, []byte(uuid))
	m.Write(nonce)
	m.Write([]byte(fingerprint))
	return m.Sum(nil)
}

// verifyRelayPeer C 侧: 在已认证 token 的首条流上发挑战、收应答、按 receive.allow 验对面确是
// 允许的 A。email 是 B 认证过的发起方 email(不采信 A 自报)。fingerprint 是本机(C)的证书指纹。
func verifyRelayPeer(stream *quic.Stream, recv conf.ClientReceive, email, fingerprint string) error {
	uuid, ok := recv.Lookup(email)
	if !ok || !conf.IsValidUUID(uuid) {
		// 没在 receive.allow 里配这个发起方(或配的 uuid 非法): 中继连接一律拒绝。
		// 把原因写回给 A(而不是直接关流让对面只看到一个 EOF): 这条 stream 是 A<->C
		// 端到端的, 中继层看不懂这一帧, 不存在信息暴露给不可信 VPS 的问题。
		errMsg := fmt.Sprintf("relayed sender %s is not allowed (add it to receive.allow)", email)
		_ = writeFrame(stream, relayChallenge{Err: errMsg})
		return errors.New(errMsg)
	}
	nonce := make([]byte, relayAuthNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate challenge nonce: %w", err)
	}
	if err := writeFrame(stream, relayChallenge{Nonce: nonce}); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(relayAuthWait))
	var resp relayResponse
	if err := readFrame(stream, &resp, relayAuthFrameMax); err != nil {
		return fmt.Errorf("read challenge response: %w", err)
	}
	_ = stream.SetReadDeadline(time.Time{})
	want := relayAuthMAC(uuid, nonce, fingerprint)
	if !hmac.Equal(want, resp.MAC) {
		return errors.New("uuid challenge failed (wrong uuid, tampering, or relay-layer replay)")
	}
	return nil
}

// answerRelayChallenge A 侧: 在首条流上收 C 的挑战、用本机 uuid + C 的指纹算 HMAC 回给 C。
// fingerprint 是 C 的证书指纹(A 经 offer 拿到、也用它固定 TLS)。
func answerRelayChallenge(stream *quic.Stream, uuid, fingerprint string) error {
	if !conf.IsValidUUID(uuid) {
		return errors.New("this machine has no valid uuid to authenticate a relayed connection")
	}
	_ = stream.SetReadDeadline(time.Now().Add(relayAuthWait))
	var ch relayChallenge
	if err := readFrame(stream, &ch, relayAuthFrameMax); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	_ = stream.SetReadDeadline(time.Time{})
	if ch.Err != "" {
		// C 主动拒绝(如 receive.allow 里没配我们), 它写完这帧就关流, 不会再有应答。
		return fmt.Errorf("peer rejected: %s", ch.Err)
	}
	if len(ch.Nonce) == 0 {
		return errors.New("peer sent an empty challenge nonce")
	}
	mac := relayAuthMAC(uuid, ch.Nonce, fingerprint)
	if err := writeFrame(stream, relayResponse{MAC: mac}); err != nil {
		return fmt.Errorf("send challenge response: %w", err)
	}
	return nil
}
