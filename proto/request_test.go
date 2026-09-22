package proto

import (
	"crypto/aes"
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

// getAesKey 要把任意长度的配置 token 归一化成 AES-128 能接受的16字节key, 且同一个
// token 每次派生结果必须一致(两端各自调用一次也要能对上), 否则加解密对不上。
func TestGetAesKeyNormalizesAnyLength(t *testing.T) {
	old := conf.RouterConfig()
	t.Cleanup(func() { conf.SetRouterConfig(old) })

	cases := []struct {
		name  string
		token string
	}{
		{"empty falls back to default", ""},
		{"exactly 16 bytes", "anyproxyproxyany"},
		{"shorter than 16", "short"},
		{"single char", "a"},
		{"longer than 16", "this-token-is-way-longer-than-16-bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf.SetRouterConfig(&conf.Router{Token: c.token})
			key := getAesKey()
			if len(key) != 16 {
				t.Fatalf("getAesKey(%q) len = %d, want 16", c.token, len(key))
			}
			if _, err := aes.NewCipher(key); err != nil {
				t.Fatalf("aes.NewCipher(getAesKey(%q)): %v", c.token, err)
			}
			// 同一个 token 必须每次派生出相同的key, 否则两端各自算一遍会对不上。
			if again := getAesKey(); string(again) != string(key) {
				t.Fatalf("getAesKey(%q) not deterministic: %x vs %x", c.token, key, again)
			}
		})
	}
}
