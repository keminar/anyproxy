package nat

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// dribbleConn 包一个 net.Conn, 把每次 Read 限制到最多 dribble 字节, 用来逼
// aeadConn.readN 走跨多次底层 Read 拼帧那条路径, 而不是巧合地一次就读到一整帧。
type dribbleConn struct {
	net.Conn
	dribble int
}

func (d *dribbleConn) Read(p []byte) (int, error) {
	if len(p) > d.dribble {
		p = p[:d.dribble]
	}
	return d.Conn.Read(p)
}

// TestAEADConnRoundTrip 加密端写、解密端读, 应该原样还原, 且跨越多次零碎的底层
// Read 也不受影响(帧长前缀+密文拼接逻辑必须对得上)。
func TestAEADConnRoundTrip(t *testing.T) {
	aUnder, cUnder := net.Pipe()
	defer aUnder.Close()
	defer cUnder.Close()

	senderKey, receiverKey, err := deriveRelaySessionKeys("shared-uuid", "salt-1")
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	aConn, err := newAEADConn(aUnder, senderKey, receiverKey)
	if err != nil {
		t.Fatalf("new sender aead conn: %v", err)
	}
	cConn, err := newAEADConn(&dribbleConn{Conn: cUnder, dribble: 3}, receiverKey, senderKey)
	if err != nil {
		t.Fatalf("new receiver aead conn: %v", err)
	}

	msg := []byte("hello over the relay, encrypted end to end so B never sees it")
	errCh := make(chan error, 1)
	go func() {
		_, err := aConn.Write(msg)
		errCh <- err
	}()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(cConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

// TestAEADConnMultipleFrames 连续多次 Write 各自成一帧, Read 端要能依次、完整地
// 把每一帧内容取回来, 不串帧、不丢字节。
func TestAEADConnMultipleFrames(t *testing.T) {
	aUnder, cUnder := net.Pipe()
	defer aUnder.Close()
	defer cUnder.Close()

	senderKey, receiverKey, err := deriveRelaySessionKeys("shared-uuid", "salt-multi")
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	aConn, err := newAEADConn(aUnder, senderKey, receiverKey)
	if err != nil {
		t.Fatalf("new sender aead conn: %v", err)
	}
	cConn, err := newAEADConn(cUnder, receiverKey, senderKey)
	if err != nil {
		t.Fatalf("new receiver aead conn: %v", err)
	}

	frames := [][]byte{[]byte("first"), []byte("second, a bit longer"), []byte("3")}
	go func() {
		for _, f := range frames {
			if _, err := aConn.Write(f); err != nil {
				return
			}
		}
	}()

	for _, want := range frames {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(cConn, got); err != nil {
			t.Fatalf("read %q: %v", want, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// TestAEADConnRejectsWrongKey 是这一整套设计的安全核心: 解密方用的 key 只要跟加密方
// 对不上(等价于 receive.allow 里配的 uuid 不对), Read 就必须报错, 不能吐出任何明文
// (哪怕是垃圾数据也不行——GCM 的认证标签保证了这一点, 而不是只测"内容对不对")。
func TestAEADConnRejectsWrongKey(t *testing.T) {
	aUnder, cUnder := net.Pipe()
	defer aUnder.Close()
	defer cUnder.Close()

	realKey, _, err := deriveRelaySessionKeys("uuid-real", "salt-x")
	if err != nil {
		t.Fatalf("derive real key: %v", err)
	}
	forgedKey, _, err := deriveRelaySessionKeys("uuid-forged", "salt-x")
	if err != nil {
		t.Fatalf("derive forged key: %v", err)
	}

	aConn, err := newAEADConn(aUnder, realKey, realKey)
	if err != nil {
		t.Fatalf("new sender aead conn: %v", err)
	}
	cConn, err := newAEADConn(cUnder, forgedKey, forgedKey)
	if err != nil {
		t.Fatalf("new receiver aead conn: %v", err)
	}

	go aConn.Write([]byte("payload"))
	buf := make([]byte, 7)
	if _, err := cConn.Read(buf); err == nil {
		t.Fatal("decrypting with a key derived from the wrong uuid must fail, not silently succeed")
	}
}

// TestDeriveRelaySessionKeys 派生要满足: 同样的输入必须每次都一样(两端各自独立算,
// 不通过网络交换 key, 算不出一样的就没法通信); 不同 uuid 或不同 salt 必须给出不同
// 的 key(否则 salt 就白加了, 起不到"避免同一把 key 跨会话复用"的作用); 两个方向的
// key 必须不同(否则两个方向共用一份 nonce 计数空间, 存在 nonce 复用风险)。
func TestDeriveRelaySessionKeys(t *testing.T) {
	s1, r1, err := deriveRelaySessionKeys("uuid-1", "salt-1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	s1Again, r1Again, err := deriveRelaySessionKeys("uuid-1", "salt-1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if s1 != s1Again || r1 != r1Again {
		t.Fatal("same uuid+salt must derive the same keys every time")
	}
	if s1 == r1 {
		t.Fatal("the two directions must not share the same key")
	}

	sDiffUUID, _, _ := deriveRelaySessionKeys("uuid-2", "salt-1")
	if sDiffUUID == s1 {
		t.Fatal("a different uuid must derive a different key")
	}
	sDiffSalt, _, _ := deriveRelaySessionKeys("uuid-1", "salt-2")
	if sDiffSalt == s1 {
		t.Fatal("a different salt must derive a different key")
	}

	if _, _, err := deriveRelaySessionKeys("", "salt-1"); err == nil {
		t.Fatal("an empty uuid must be rejected")
	}
	if _, _, err := deriveRelaySessionKeys("uuid-1", ""); err == nil {
		t.Fatal("an empty salt must be rejected")
	}
}

// TestNewRelaySalt 每次都要是新的、有意义长度的值——它虽不是秘密, 但复用同一个 salt
// 会导致同一个 uuid 在不同会话里派生出同一把 key, 破坏"key 不跨会话复用"这条底线。
func TestNewRelaySalt(t *testing.T) {
	a, err := newRelaySalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	b, err := newRelaySalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	if a == b {
		t.Fatal("two salts must not collide in practice")
	}
	if len(a) < 16 {
		t.Fatalf("salt %q looks too short", a)
	}
}

// TestAEADConnSetReadDeadline 确认 SetReadDeadline 被转发到底层连接、真的能让阻塞的
// Read 按时超时返回, 而不是无限期挂起——中继场景下断连检测全指着这个。
func TestAEADConnSetReadDeadline(t *testing.T) {
	aUnder, cUnder := net.Pipe()
	defer aUnder.Close()
	defer cUnder.Close()

	key, _, err := deriveRelaySessionKeys("uuid-x", "salt-x")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	cConn, err := newAEADConn(cUnder, key, key)
	if err != nil {
		t.Fatalf("new aead conn: %v", err)
	}
	if err := cConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, err = cConn.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("read past the deadline with nothing written should time out")
	}
}
