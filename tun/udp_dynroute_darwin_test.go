//go:build darwin
// +build darwin

package tun

import (
	"sync"
	"testing"
	"time"

	"github.com/keminar/anyproxy/config"
)

// 注入假 route 操作, 纯逻辑验证 udpDynRoute 的 TTL 缓存生命周期, 无需 root。
func installFakeUDPRouteOps(t *testing.T) (*fakeUDPRouteOps, func()) {
	t.Helper()
	f := &fakeUDPRouteOps{}
	oldAdd, oldDel := macUDPRouteAdd, macUDPRouteDel
	macUDPRouteAdd, macUDPRouteDel = f.add, f.del
	return f, func() { macUDPRouteAdd, macUDPRouteDel = oldAdd, oldDel }
}

type fakeUDPRouteOps struct {
	mu       sync.Mutex
	adds     []string
	dels     []string
}

func (f *fakeUDPRouteOps) add(cidr, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds = append(f.adds, cidr)
	return nil
}

func (f *fakeUDPRouteOps) del(cidr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dels = append(f.dels, cidr)
	return nil
}

func (f *fakeUDPRouteOps) countAdd() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.adds) }
func (f *fakeUDPRouteOps) countDel() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.dels) }

func setGW(t *testing.T, gw string) {
	t.Helper()
	old := config.TUNBypassGW
	config.TUNBypassGW = gw
	t.Cleanup(func() { config.TUNBypassGW = old })
}

// TestUDPDynRouteTTL 验证 TTL 缓存: 首次 ensure 加路由, TTL 内重复不重复加,
// 过期后重新加并懒清理旧路由。
func TestUDPDynRouteTTL(t *testing.T) {
	f, restore := installFakeUDPRouteOps(t)
	defer restore()
	setGW(t, "192.168.1.1")

	d := &udpDynRoute{ttl: 50 * time.Millisecond, rt: map[string]time.Time{}}
	const ip = "8.8.8.8"

	d.ensure(ip) // 首次: 加路由
	if f.countAdd() != 1 || f.countDel() != 0 {
		t.Fatalf("first ensure: add=%d del=%d, want 1/0", f.countAdd(), f.countDel())
	}

	d.ensure(ip) // TTL 内: 不重复加
	if f.countAdd() != 1 {
		t.Fatalf("TTL-in ensure should reuse route: add=%d", f.countAdd())
	}

	time.Sleep(60 * time.Millisecond) // 越过 TTL

	// 换一个目标 ensure, 触发懒清理: 过期项被删, 新目标加路由
	const ip2 = "1.1.1.1"
	d.ensure(ip2)
	if f.countDel() != 1 {
		t.Fatalf("lazy cleanup should delete expired route: del=%d, dels=%v", f.countDel(), f.dels)
	}
	if f.countAdd() != 2 {
		t.Fatalf("after expiry + new target: add=%d, want 2", f.countAdd())
	}
	d.mu.Lock()
	_, hasOld := d.rt[ip]
	_, hasNew := d.rt[ip2]
	d.mu.Unlock()
	if hasOld {
		t.Fatalf("expired entry %s should be removed from map", ip)
	}
	if !hasNew {
		t.Fatalf("new entry %s missing", ip2)
	}
}

// TestUDPDynRouteSkips 验证: 无网关 / IPv6 / 非 IP 目标不产生路由操作。
func TestUDPDynRouteSkips(t *testing.T) {
	f, restore := installFakeUDPRouteOps(t)
	defer restore()
	setGW(t, "192.168.1.1")

	d := &udpDynRoute{ttl: time.Minute, rt: map[string]time.Time{}}

	d.ensure("2001:db8::1")
	d.ensure("not-an-ip")
	if f.countAdd() != 0 {
		t.Fatalf("IPv6/non-IP should not add route: %v", f.adds)
	}

	setGW(t, "") // 无网关
	d.ensure("1.2.3.4")
	if f.countAdd() != 0 {
		t.Fatalf("no-gateway should not add route: %v", f.adds)
	}
}

// TestCleanupUDPDynRoutes 验证 TUN 退出时兜底清理所有残留路由。
func TestCleanupUDPDynRoutes(t *testing.T) {
	f, restore := installFakeUDPRouteOps(t)
	defer restore()
	setGW(t, "192.168.1.1")

	macUDPDynRoute.mu.Lock()
	macUDPDynRoute.rt = map[string]time.Time{}
	macUDPDynRoute.mu.Unlock()

	macUDPDynRoute.ensure("8.8.8.8")
	macUDPDynRoute.ensure("1.1.1.1")
	if f.countAdd() != 2 {
		t.Fatalf("setup: add=%d want 2", f.countAdd())
	}

	CleanupUDPDynRoutes()

	if f.countDel() != 2 {
		t.Fatalf("cleanup should delete both: del=%d", f.countDel())
	}
	macUDPDynRoute.mu.Lock()
	left := len(macUDPDynRoute.rt)
	macUDPDynRoute.mu.Unlock()
	if left != 0 {
		t.Fatalf("rt should be empty after cleanup: %d", left)
	}
}
