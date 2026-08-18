//go:build darwin
// +build darwin

package proto

import (
	"sync"
	"testing"

	"github.com/keminar/anyproxy/config"
)

// 用注入的假 route 操作替换真实 `route` 命令(真实命令需 root),
// 纯逻辑验证 dynRoute 的引用计数生命周期, 无需 root 可在 CI 直接跑。
func installFakeRouteOps(t *testing.T) (*fakeRouteOps, func()) {
	t.Helper()
	f := &fakeRouteOps{}
	oldAdd, oldDel := macRouteAdd, macRouteDel
	macRouteAdd = f.add
	macRouteDel = f.del
	return f, func() { macRouteAdd, macRouteDel = oldAdd, oldDel }
}

type fakeRouteOps struct {
	mu   sync.Mutex
	adds []string // 记录的 cidr
	dels []string
}

func (f *fakeRouteOps) add(cidr, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds = append(f.adds, cidr)
	return nil
}

func (f *fakeRouteOps) del(cidr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dels = append(f.dels, cidr)
	return nil
}

func (f *fakeRouteOps) countAdd() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.adds) }
func (f *fakeRouteOps) countDel() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.dels) }

// TestDynRouteLifecycle 验证: 首次 acquire 加路由, 重复 acquire 不重复加,
// 引用归零才删路由(连接关闭即删的副作用控制)。
func TestDynRouteLifecycle(t *testing.T) {
	f, restore := installFakeRouteOps(t)
	defer restore()

	oldGW := config.TUNBypassGW
	config.TUNBypassGW = "192.168.1.1"
	defer func() { config.TUNBypassGW = oldGW }()

	d := &dynRoute{refs: map[string]int{}}
	const ip = "183.47.99.22"

	d.acquire(ip) // refs 0->1, 首次 add
	if f.countAdd() != 1 || f.countDel() != 0 {
		t.Fatalf("after first acquire: add=%d del=%d, want add=1 del=0", f.countAdd(), f.countDel())
	}

	d.acquire(ip) // refs 1->2, 不重复 add
	if f.countAdd() != 1 {
		t.Fatalf("second acquire should not re-add: add=%d", f.countAdd())
	}

	d.release(ip) // refs 2->1, 不删
	if f.countDel() != 0 {
		t.Fatalf("release with refs>0 should not delete: del=%d", f.countDel())
	}

	d.release(ip) // refs 1->0, 删
	if f.countDel() != 1 || f.countAdd() != 1 {
		t.Fatalf("final release: add=%d del=%d, want 1/1", f.countAdd(), f.countDel())
	}
	if len(d.refs) != 0 {
		t.Fatalf("refs should be empty after final release: %v", d.refs)
	}
}

// TestDynRouteSkipsNonIPv4 验证: 无网关 / IPv6 / 非 IP 目标不产生路由操作。
func TestDynRouteSkipsNonIPv4(t *testing.T) {
	f, restore := installFakeRouteOps(t)
	defer restore()

	oldGW := config.TUNBypassGW
	config.TUNBypassGW = "192.168.1.1"
	defer func() { config.TUNBypassGW = oldGW }()

	d := &dynRoute{refs: map[string]int{}}

	d.acquire("2001:db8::1") // IPv6
	d.acquire("not-an-ip")   // 非 IP
	if f.countAdd() != 0 {
		t.Fatalf("IPv6/non-IP should not add route: %v", f.adds)
	}

	config.TUNBypassGW = "" // 无网关
	d.acquire("1.2.3.4")
	if f.countAdd() != 0 {
		t.Fatalf("no-gateway should not add route: %v", f.adds)
	}
	config.TUNBypassGW = oldGW
}

// TestDynRouteConcurrent 验证并发 acquire/release 同一目标, 路由恰好加一次删一次。
func TestDynRouteConcurrent(t *testing.T) {
	f, restore := installFakeRouteOps(t)
	defer restore()

	oldGW := config.TUNBypassGW
	config.TUNBypassGW = "192.168.1.1"
	defer func() { config.TUNBypassGW = oldGW }()

	d := &dynRoute{refs: map[string]int{}}
	const ip = "183.47.99.22"
	const n = 100

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.acquire(ip)
			d.release(ip)
		}()
	}
	wg.Wait()

	if f.countAdd() != 1 || f.countDel() != 1 {
		t.Fatalf("concurrent 100 acquire/release: add=%d del=%d, want exactly 1/1", f.countAdd(), f.countDel())
	}
	if len(d.refs) != 0 {
		t.Fatalf("refs should drain to empty: %v", d.refs)
	}
}

// TestCleanupDynRoutes 验证 TUN 退出时兜底清理所有残留路由。
func TestCleanupDynRoutes(t *testing.T) {
	f, restore := installFakeRouteOps(t)
	defer restore()

	oldGW := config.TUNBypassGW
	config.TUNBypassGW = "192.168.1.1"
	defer func() { config.TUNBypassGW = oldGW }()

	macDynRoute.mu.Lock()
	macDynRoute.refs = map[string]int{}
	macDynRoute.mu.Unlock()

	macDynRoute.acquire("1.1.1.1")
	macDynRoute.acquire("8.8.8.8")
	if f.countAdd() != 2 {
		t.Fatalf("setup: add=%d want 2", f.countAdd())
	}

	CleanupDynRoutes()

	if f.countDel() != 2 {
		t.Fatalf("cleanup should delete both: del=%d", f.countDel())
	}
	macDynRoute.mu.Lock()
	left := len(macDynRoute.refs)
	macDynRoute.mu.Unlock()
	if left != 0 {
		t.Fatalf("refs should be empty after cleanup: %v", left)
	}
}
