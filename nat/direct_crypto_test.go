package nat

import (
	"bytes"
	"testing"
	"time"
)

func TestDeriveDirectSessionKeys(t *testing.T) {
	a2c1, c2a1, err := deriveDirectSessionKeys("uuid-1", "token-1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	a2c2, c2a2, err := deriveDirectSessionKeys("uuid-1", "token-1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if a2c1 != a2c2 || c2a1 != c2a2 {
		t.Fatalf("same input must give same output")
	}
	if a2c1 == c2a1 {
		t.Fatalf("the two directions must not share the same key")
	}

	a2c3, _, err := deriveDirectSessionKeys("uuid-2", "token-1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if a2c3 == a2c1 {
		t.Fatalf("different uuid must give a different key")
	}

	a2c4, _, err := deriveDirectSessionKeys("uuid-1", "token-2")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if a2c4 == a2c1 {
		t.Fatalf("different token must give a different key")
	}

	if _, _, err := deriveDirectSessionKeys("", "token-1"); err == nil {
		t.Fatalf("empty uuid must error")
	}
	if _, _, err := deriveDirectSessionKeys("uuid-1", ""); err == nil {
		t.Fatalf("empty token must error")
	}
}

// 域隔离回归测试: 打洞加密和中继加密不该共享同一份派生密钥空间, 哪怕喂给它们的
// uuid/salt-token 字符串完全相同。防止以后有人图省事把两个函数合并。
func TestDeriveDirectSessionKeysDiffersFromRelay(t *testing.T) {
	directA2C, directC2A, err := deriveDirectSessionKeys("shared-uuid", "shared-salt")
	if err != nil {
		t.Fatalf("derive direct: %v", err)
	}
	relaySender, relayReceiver, err := deriveRelaySessionKeys("shared-uuid", "shared-salt")
	if err != nil {
		t.Fatalf("derive relay: %v", err)
	}
	if directA2C == relaySender || directA2C == relayReceiver ||
		directC2A == relaySender || directC2A == relayReceiver {
		t.Fatalf("direct punch keys must not collide with relay keys under the same uuid/salt")
	}
}

// testDirectToken32 is a stand-in for newDirectToken()'s output: real tokens are
// always exactly 32 hex characters, and sealDirectPacket/openDirectPacket assume
// that fixed length (see directTokenWireLen), so tests must use tokens this size.
const testDirectToken32 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestSealOpenDirectPacketRoundTrip(t *testing.T) {
	const uuid, token = "shared-uuid", testDirectToken32
	initiator, err := newDirectCryptoSession(uuid, token, true)
	if err != nil {
		t.Fatalf("new initiator session: %v", err)
	}
	responder, err := newDirectCryptoSession(uuid, token, false)
	if err != nil {
		t.Fatalf("new responder session: %v", err)
	}

	payload := verbPunch + " " + "some-nonce"
	pkt, err := sealDirectPacket(initiator, token, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if pkt[0] != directCryptedMagic {
		t.Fatalf("wrong magic byte: got %#x", pkt[0])
	}
	if bytes.Contains(pkt, []byte(verbPunch)) {
		t.Fatalf("sealed packet must not leak the plaintext verb: %q", pkt)
	}

	gotToken, ok := peekDirectToken(pkt)
	if !ok || gotToken != token {
		t.Fatalf("peekDirectToken = %q, %v; want %q, true", gotToken, ok, token)
	}

	plain, err := openDirectPacket(responder, pkt)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if plain != payload {
		t.Fatalf("round trip mismatch: got %q want %q", plain, payload)
	}

	verb, nonce, _ := splitPacket(plain)
	if verb != verbPunch || nonce != "some-nonce" {
		t.Fatalf("splitPacket after decrypt: verb=%q nonce=%q", verb, nonce)
	}
}

func TestOpenDirectPacketRejectsWrongUUID(t *testing.T) {
	const token = testDirectToken32
	initiator, err := newDirectCryptoSession("uuid-a", token, true)
	if err != nil {
		t.Fatalf("new initiator session: %v", err)
	}
	responder, err := newDirectCryptoSession("uuid-b", token, false)
	if err != nil {
		t.Fatalf("new responder session: %v", err)
	}

	pkt, err := sealDirectPacket(initiator, token, verbPunch+" nonce")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := openDirectPacket(responder, pkt); err == nil {
		t.Fatalf("decrypting with a mismatched uuid must fail")
	}
}

func TestOpenDirectPacketRejectsTamperedHeader(t *testing.T) {
	const uuid, token = "shared-uuid", testDirectToken32
	initiator, err := newDirectCryptoSession(uuid, token, true)
	if err != nil {
		t.Fatalf("new initiator session: %v", err)
	}
	responder, err := newDirectCryptoSession(uuid, token, false)
	if err != nil {
		t.Fatalf("new responder session: %v", err)
	}
	pkt, err := sealDirectPacket(initiator, token, verbPunch+" nonce")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	tampered := append([]byte(nil), pkt...)
	tampered[len(tampered)-1] ^= 0xFF // 翻转密文最后一个字节(tag 的一部分)
	if _, err := openDirectPacket(responder, tampered); err == nil {
		t.Fatalf("tampered ciphertext must fail authentication")
	}

	tamperedNonce := append([]byte(nil), pkt...)
	tamperedNonce[1+directTokenWireLen] ^= 0xFF // 翻转 nonce 的第一个字节
	if _, err := openDirectPacket(responder, tamperedNonce); err == nil {
		t.Fatalf("tampered nonce (part of AAD) must fail authentication")
	}
}

func TestSealDirectPacketUsesFreshNoncePerCall(t *testing.T) {
	sess, err := newDirectCryptoSession("shared-uuid", testDirectToken32, true)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	p1, err := sealDirectPacket(sess, testDirectToken32, verbPunch+" nonce")
	if err != nil {
		t.Fatalf("seal 1: %v", err)
	}
	p2, err := sealDirectPacket(sess, testDirectToken32, verbPunch+" nonce")
	if err != nil {
		t.Fatalf("seal 2: %v", err)
	}
	n1 := p1[1+directTokenWireLen : 1+directTokenWireLen+directGCMNonceSize]
	n2 := p2[1+directTokenWireLen : 1+directTokenWireLen+directGCMNonceSize]
	if bytes.Equal(n1, n2) {
		t.Fatalf("two seals of the same payload must not reuse the same nonce")
	}
}

func TestPeekDirectToken(t *testing.T) {
	sess, err := newDirectCryptoSession("uuid", "0123456789abcdef0123456789abcdef", true)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	pkt, err := sealDirectPacket(sess, "0123456789abcdef0123456789abcdef", verbPunch+" n")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if tok, ok := peekDirectToken(pkt); !ok || tok != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("peekDirectToken = %q, %v", tok, ok)
	}
	if _, ok := peekDirectToken([]byte{directCryptedMagic, 1, 2, 3}); ok {
		t.Fatalf("a too-short packet must not be accepted")
	}
	if _, ok := peekDirectToken([]byte{directPacketMagic}); ok {
		t.Fatalf("a plaintext-magic packet must not be mistaken for an encrypted one")
	}
}

func TestDirectCryptoTablePutGetNotOneShot(t *testing.T) {
	table := newDirectCryptoTable()
	sess, err := newDirectCryptoSession("uuid", "token", true)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	table.put("token", sess)
	if _, ok := table.get("token"); !ok {
		t.Fatalf("first get should find the session")
	}
	if _, ok := table.get("token"); !ok {
		t.Fatalf("get must not be one-shot: a session is used across many packets in one punch round")
	}
}

func TestDirectCryptoTableExpires(t *testing.T) {
	table := newDirectCryptoTable()
	sess, err := newDirectCryptoSession("uuid", "expired-token", true)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	sess.expires = sess.expires.Add(-time.Hour) // 直接构造一个已过期的会话, 不用真的等
	table.put("expired-token", sess)
	if _, ok := table.get("expired-token"); ok {
		t.Fatalf("an expired session must not be returned")
	}

	fresh, err := newDirectCryptoSession("uuid", "fresh-token", true)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	table.put("fresh-token", fresh) // 触发懒清扫
	table.mu.Lock()
	_, stillThere := table.m["expired-token"]
	table.mu.Unlock()
	if stillThere {
		t.Fatalf("put should have swept the expired entry")
	}
}
