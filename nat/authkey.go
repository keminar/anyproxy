package nat

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// 密钥对鉴权(与 user/pass 二选一)。
//
// 为什么另起一套而不是沿用 user/pass:
//
//   - **不依赖时钟**。密码方案把时间戳算进 token 来防重放, 于是两端时钟差超过
//     authSkewLimit 就连不上, 而这在没有 NTP 的机器上很常见。这里改用挑战-应答:
//     服务端每次发一个随机数, 客户端签名, 服务端验签 —— 随机数只用一次, 天然防
//     重放, 完全不看时间。
//   - **服务端不再保存可用于登录的秘密**。密码方案里服务端配置存的就是密码本身,
//     配置泄露即等于凭据泄露; 这里服务端只存公钥, 拿到也登录不了。
//
// 用 Ed25519 而不是 X25519: 这里要的是"证明我持有私钥"(签名), X25519 是密钥交换
// 原语, 拿来做认证得两边都有密钥对再派生共享密钥, 步骤更多而收益(相互认证)在这个
// 场景用不上 —— 客户端本来就用证书指纹之外的方式确认服务端(它主动连的地址)。

// authChallengeSize 挑战随机数长度。32 字节足够, 且一次性使用。
const authChallengeSize = 32

// AuthChallenge 服务端在密钥鉴权时下发的挑战。
type AuthChallenge struct {
	Challenge string `json:"challenge"` //base64 随机数
}

// AuthSignature 客户端对挑战的签名。
type AuthSignature struct {
	Signature string `json:"signature"` //base64 Ed25519 签名
}

// GenerateKeyPair 生成一对 Ed25519 密钥, 返回 base64 编码的(私钥, 公钥)。
// 私钥配在订阅方, 公钥配在服务端。
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// newAuthChallenge 生成一次性挑战。
func newAuthChallenge() (string, []byte, error) {
	b := make([]byte, authChallengeSize)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(b), b, nil
}

// signChallenge 用 base64 私钥对挑战签名, 返回 base64 签名。
func signChallenge(privateKeyB64, challengeB64 string) (string, error) {
	priv, err := parsePrivateKey(privateKeyB64)
	if err != nil {
		return "", err
	}
	challenge, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return "", fmt.Errorf("bad challenge: %w", err)
	}
	if len(challenge) != authChallengeSize {
		return "", fmt.Errorf("bad challenge length %d", len(challenge))
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, challenge)), nil
}

// verifyChallenge 用 base64 公钥校验签名。
func verifyChallenge(publicKeyB64 string, challenge []byte, signatureB64 string) error {
	pub, err := ParsePublicKey(publicKeyB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	if !ed25519.Verify(pub, challenge, sig) {
		return errors.New("signature does not match the configured public key")
	}
	return nil
}

func parsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("bad private key encoding: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad private key length %d, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// ParsePublicKey 解析 base64 公钥, 供配置校验复用。
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("bad public key encoding: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad public key length %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
