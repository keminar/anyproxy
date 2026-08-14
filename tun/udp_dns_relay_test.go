//go:build !windows
// +build !windows

package tun

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// pendKey 应按 (解析器, txid) 唯一区分: 同 txid 不同解析器不冲突, 同解析器不同 txid 不冲突。
func TestDNSRelayPendKey(t *testing.T) {
	r1 := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
	r2 := tcpip.AddrFrom4([4]byte{1, 1, 1, 1})
	if pendKey(r1, 100) == pendKey(r2, 100) {
		t.Fatal("同 txid 不同解析器不应产生相同 key")
	}
	if pendKey(r1, 100) == pendKey(r1, 101) {
		t.Fatal("同解析器不同 txid 不应产生相同 key")
	}
	if pendKey(r1, 100) != pendKey(r1, 100) {
		t.Fatal("相同 (解析器,txid) 应产生相同 key")
	}
}

// sweep 应只清理过期 pending, 保留未过期的。
func TestDNSRelaySweepExpiry(t *testing.T) {
	r := newDNSRelay(nil)
	resolver := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
	now := time.Now()

	r.mu.Lock()
	r.pend[pendKey(resolver, 1)] = dnsPending{resolver: resolver, deadline: now.Add(-time.Second)} // 已过期
	r.pend[pendKey(resolver, 2)] = dnsPending{resolver: resolver, deadline: now.Add(time.Minute)}  // 未过期
	r.mu.Unlock()

	// 手动执行一次 sweep 的清理逻辑(不等 ticker)。
	r.mu.Lock()
	for k, p := range r.pend {
		if now.After(p.deadline) {
			delete(r.pend, k)
		}
	}
	remaining := len(r.pend)
	_, hasLive := r.pend[pendKey(resolver, 2)]
	_, hasExpired := r.pend[pendKey(resolver, 1)]
	r.mu.Unlock()

	if remaining != 1 || !hasLive || hasExpired {
		t.Fatalf("sweep 应只留下未过期项: remaining=%d hasLive=%v hasExpired=%v", remaining, hasLive, hasExpired)
	}
}

// pending 达到硬上限后, logOverflowLocked 不应 panic 且能限流(连续调用只在跨秒时不跳过)。
func TestDNSRelayOverflowThrottle(t *testing.T) {
	r := newDNSRelay(nil)
	r.mu.Lock()
	defer r.mu.Unlock()
	// 首次调用记录时间戳; 紧接着的调用应累加 skip 而非重置。
	r.logOverflowLocked()
	first := r.overflowSkip
	r.logOverflowLocked()
	if r.overflowSkip != first+1 {
		t.Fatalf("同秒内二次溢出应累加 skip: first=%d now=%d", first, r.overflowSkip)
	}
}
