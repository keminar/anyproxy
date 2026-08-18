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

// TestDynRouteConcurrent 验证 N 个「并发连接」(先全部 acquire 持有, 再全部释放)
// 时, 路由恰好加一次删一次——模拟真实场景: 连接有持有期, refs 从 0 涨到 N,
// 最后一个连接关闭才跌回 0。
//
// 注意: 不能写成「acquire 后立即 release」的背靠背并发——那会让 refs 在 0↔1
// 间振荡, 每轮振荡都触发一次 add/del(短连接场景的真实行为, 可接受), 测不出
// 并发连接的正确性。
func TestDynRouteConcurrent(t *testing.T) {
	f, restore := installFakeRouteOps(t)
	defer restore()

	oldGW := config.TUNBypassGW
	config.TUNBypassGW = "192.168.1.1"
	defer func() { config.TUNBypassGW = oldGW }()

	d := &dynRoute{refs: map[string]int{}}
	const ip = "183.47.99.22"
	const n = 100

	// 阶段一: 并发建立 n 个连接(全部 acquire, 持有中)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d.acquire(ip)
		}()
	}
	close(start)
	wg.Wait()

	d.mu.Lock()
	if d.refs[ip] != n {
		d.mu.Unlock()
		t.Fatalf("after %d concurrent acquires: refs=%d, want %d", n, d.refs[ip], n)
	}
	d.mu.Unlock()
	if f.countAdd() != 1 {
		t.Fatalf("concurrent acquires should add exactly once: add=%d", f.countAdd())
	}

	// 阶段二: 并发关闭 n 个连接(全部 release)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.release(ip)
		}()
	}
	wg.Wait()

	if f.countAdd() != 1 || f.countDel() != 1 {
		t.Fatalf("concurrent %d conns: add=%d del=%d, want exactly 1/1", n, f.countAdd(), f.countDel())
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
