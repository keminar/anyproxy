package nat

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/tools"
)

func TestGenerateKeyPairRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	challengeB64, challenge, err := newAuthChallenge()
	if err != nil {
		t.Fatalf("newAuthChallenge: %v", err)
	}
	sig, err := signChallenge(priv, challengeB64)
	if err != nil {
		t.Fatalf("signChallenge: %v", err)
	}
	if err := verifyChallenge(pub, challenge, sig); err != nil {
		t.Fatalf("verifyChallenge: %v", err)
	}

	// 换一把公钥就必须验不过, 否则等于谁都能登录。
	_, otherPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := verifyChallenge(otherPub, challenge, sig); err == nil {
		t.Fatal("signature verified against a different public key")
	}
	// 签名绑定的是这一次的随机数, 换个挑战不能复用 —— 这正是防重放的地方。
	_, other, err := newAuthChallenge()
	if err != nil {
		t.Fatalf("newAuthChallenge: %v", err)
	}
	if err := verifyChallenge(pub, other, sig); err == nil {
		t.Fatal("signature replayed onto a different challenge")
	}
}

func TestAuthKeyBadEncoding(t *testing.T) {
	if _, err := signChallenge("not-base64!!", base64.StdEncoding.EncodeToString(make([]byte, authChallengeSize))); err == nil {
		t.Fatal("want error for malformed private key")
	}
	priv, pub, _ := GenerateKeyPair()
	if _, err := signChallenge(base64.StdEncoding.EncodeToString([]byte("short")), "AAAA"); err == nil {
		t.Fatal("want error for short private key")
	}
	if _, err := ParsePublicKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("want error for short public key")
	}
	// 私钥不能当公钥用(长度不同), 配串位置要能报出来。
	if _, err := ParsePublicKey(priv); err == nil {
		t.Fatal("private key accepted as public key")
	}
	if _, err := ParsePublicKey(pub); err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
}

// authHandshake 跑一次真实的 websocket 握手: 服务端按 su 校验, 客户端按 clientPass/
// clientKey 应答, 返回客户端侧看到的结果。这样覆盖的是两端拼在一起的行为, 而不只是
// 各自的分支。
func authHandshakeRaw(t *testing.T, su conf.ServerUser, client func(*websocket.Conn) error) error {
	t.Helper()
	old := conf.RouterConfig
	t.Cleanup(func() { conf.RouterConfig = old })
	conf.RouterConfig = &conf.Router{}
	conf.RouterConfig.Websocket.Server.Users = []conf.ServerUser{su}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		var msg AuthMessage
		if err := c.ReadJSON(&msg); err != nil {
			return
		}
		found, _ := conf.RouterConfig.Websocket.Server.LookupUser(msg.User)
		if err := authClient(c, msg, found); err != nil {
			return
		}
		c.WriteMessage(websocket.TextMessage, []byte("ok"))
	}))
	t.Cleanup(srv.Close)

	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	return client(c)
}

func authHandshake(t *testing.T, su conf.ServerUser, clientPass, clientKey string) error {
	t.Helper()
	return authHandshakeRaw(t, su, func(c *websocket.Conn) error {
		return newClientHandler(c).auth(su.User, clientPass, clientKey, "e@example.com", false)
	})
}

func TestAuthKeyHandshake(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	otherPriv, _, _ := GenerateKeyPair()

	t.Run("ok", func(t *testing.T) {
		if err := authHandshake(t, conf.ServerUser{User: "u", Key: pub}, "", priv); err != nil {
			t.Fatalf("key auth failed: %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		if err := authHandshake(t, conf.ServerUser{User: "u", Key: pub}, "", otherPriv); err == nil {
			t.Fatal("a mismatched private key was accepted")
		}
	})
	// 两端配错方案时不能只是"连不上", 回包要说清是哪一种不匹配。
	t.Run("server wants key", func(t *testing.T) {
		err := authHandshake(t, conf.ServerUser{User: "u", Key: pub}, "pw", "")
		if err == nil || !strings.Contains(err.Error(), "expects key auth") {
			t.Fatalf("want an explanatory error, got %v", err)
		}
	})
	t.Run("server wants pass", func(t *testing.T) {
		err := authHandshake(t, conf.ServerUser{User: "u", Pass: "pw"}, "", priv)
		if err == nil || !strings.Contains(err.Error(), "no key for this user") {
			t.Fatalf("want an explanatory error, got %v", err)
		}
	})
	t.Run("password still works", func(t *testing.T) {
		if err := authHandshake(t, conf.ServerUser{User: "u", Pass: "pw"}, "pw", ""); err != nil {
			t.Fatalf("password auth broke: %v", err)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		if err := authHandshake(t, conf.ServerUser{User: "u", Pass: "pw"}, "bad", ""); err == nil {
			t.Fatal("a wrong password was accepted")
		}
	})
	// 两端都配时优先密钥, 免得以为改了密码就生效。
	t.Run("key wins when both set", func(t *testing.T) {
		if err := authHandshake(t, conf.ServerUser{User: "u", Pass: "pw", Key: pub}, "pw", priv); err != nil {
			t.Fatalf("key auth failed: %v", err)
		}
	})
}

// 密钥方案的全部意义是不看时钟: 时差再大也要能连上, 而同样的时差在密码方案下必须被挡。
func TestAuthKeyIgnoresClockSkew(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	stale := time.Now().Unix() - authSkewLimit - 60

	if err := authHandshake(t, conf.ServerUser{User: "u", Key: pub}, "", priv); err != nil {
		t.Fatalf("key auth rejected despite no clock involvement: %v", err)
	}

	err := authHandshakeRaw(t, conf.ServerUser{User: "u", Pass: "pw"}, func(c *websocket.Conn) error {
		token, err := tools.Md5Str(fmt.Sprintf("%s|%s|%d", "u", "pw", stale))
		if err != nil {
			return err
		}
		h := newClientHandler(c)
		return h.ask(&AuthMessage{User: "u", Token: token, Xtime: stale, Email: "e@example.com"})
	})
	if err == nil || !strings.Contains(err.Error(), "xtime err") {
		t.Fatalf("password auth accepted a %ds-stale timestamp: %v", authSkewLimit+60, err)
	}
}
