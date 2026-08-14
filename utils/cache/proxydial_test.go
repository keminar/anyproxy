package cache

import (
	"testing"
	"time"
)

func TestProxyDialCache(t *testing.T) {
	c := newProxyDialCache()
	const key = "127.0.0.1:8888"

	// 未标记时不算 bad
	if c.Bad(key) {
		t.Fatal("fresh key should not be bad")
	}

	// 标记不可用后, 有效期内命中
	c.MarkBad(key, time.Minute)
	if !c.Bad(key) {
		t.Fatal("marked key should be bad within TTL")
	}

	// 过期后不再命中, 并顺带删除
	c.MarkBad(key, 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if c.Bad(key) {
		t.Fatal("expired key should not be bad")
	}

	// Clear 立即清除失败标记(代理恢复)
	c.MarkBad(key, time.Minute)
	c.Clear(key)
	if c.Bad(key) {
		t.Fatal("cleared key should not be bad")
	}

	// 空 key 忽略
	c.MarkBad("", time.Minute)
	if c.Bad("") {
		t.Fatal("empty key should never be bad")
	}
}
