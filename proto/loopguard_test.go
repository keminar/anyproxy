package proto

import (
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

func newTestGuard() *loopGuard {
	return &loopGuard{
		active: make(map[string]int),
		noted:  make(map[string]bool),
	}
}

// 闸门未到(total < minActive)时恒放行, 不做占比计算。
func TestLoopGuardGateClosed(t *testing.T) {
	conf.RouterConfig = &conf.Router{LoopGuard: conf.LoopGuard{MinActive: 100, Ratio: 80}}
	g := newTestGuard()
	// 造 50 个都在同一目标, 但未达闸门 100
	for i := 0; i < 50; i++ {
		g.enter("a:80")
	}
	if ok, tripped, _, _ := g.allow("a:80"); !ok || tripped {
		t.Fatalf("below gate: got (ok=%v,tripped=%v), want (true,false)", ok, tripped)
	}
}

// 闸门开启且单目标占比超阈值时判为环路; 首次 tripped=true, 之后 false(不刷屏)。
func TestLoopGuardTrip(t *testing.T) {
	conf.RouterConfig = &conf.Router{LoopGuard: conf.LoopGuard{MinActive: 100, Ratio: 80}}
	g := newTestGuard()
	// 总 100: a:80 占 85(85%>=80%), 其余 15 分散
	for i := 0; i < 85; i++ {
		g.enter("a:80")
	}
	for i := 0; i < 15; i++ {
		g.enter("other")
	}
	// 首次判定 -> 拒绝且 tripped
	ok, tripped, keyActive, total := g.allow("a:80")
	if ok || !tripped {
		t.Fatalf("trip: got (ok=%v,tripped=%v), want (false,true)", ok, tripped)
	}
	if keyActive != 85 || total != 100 {
		t.Fatalf("snapshot: got keyActive=%d total=%d, want 85/100", keyActive, total)
	}
	// 再次判定 -> 仍拒绝但不再 tripped(避免日志刷屏)
	if ok, tripped, _, _ := g.allow("a:80"); ok || tripped {
		t.Fatalf("repeat: got (ok=%v,tripped=%v), want (false,false)", ok, tripped)
	}
}

// 未占大头的目标即便闸门开启也放行。
func TestLoopGuardMinorityAllowed(t *testing.T) {
	conf.RouterConfig = &conf.Router{LoopGuard: conf.LoopGuard{MinActive: 100, Ratio: 80}}
	g := newTestGuard()
	for i := 0; i < 95; i++ {
		g.enter("a:80")
	}
	for i := 0; i < 10; i++ {
		g.enter("b:80")
	}
	// b:80 只占 10/105, 放行
	if ok, tripped, _, _ := g.allow("b:80"); !ok || tripped {
		t.Fatalf("minority: got (ok=%v,tripped=%v), want (true,false)", ok, tripped)
	}
	// a:80 占大头, 拒绝
	if ok, _, _, _ := g.allow("a:80"); ok {
		t.Fatal("a:80 dominates, should be blocked")
	}
}

// drain 后 total 回落到闸门下, 自动恢复放行, 且 noted 被清除。
func TestLoopGuardRecover(t *testing.T) {
	conf.RouterConfig = &conf.Router{LoopGuard: conf.LoopGuard{MinActive: 100, Ratio: 80}}
	g := newTestGuard()
	for i := 0; i < 100; i++ {
		g.enter("a:80")
	}
	if ok, _, _, _ := g.allow("a:80"); ok {
		t.Fatal("should be blocked at full occupancy")
	}
	// drain 到闸门下
	for i := 0; i < 100; i++ {
		g.leave("a:80")
	}
	if g.total != 0 || len(g.active) != 0 || len(g.noted) != 0 {
		t.Fatalf("after drain: total=%d active=%d noted=%d, want 0/0/0", g.total, len(g.active), len(g.noted))
	}
	if ok, tripped, _, _ := g.allow("a:80"); !ok || tripped {
		t.Fatalf("recovered: got (ok=%v,tripped=%v), want (true,false)", ok, tripped)
	}
}

// minActive<0 关闭熔断器, 恒放行。
func TestLoopGuardDisabled(t *testing.T) {
	conf.RouterConfig = &conf.Router{LoopGuard: conf.LoopGuard{MinActive: -1}}
	g := newTestGuard()
	for i := 0; i < 10000; i++ {
		g.enter("a:80")
	}
	if ok, tripped, _, _ := g.allow("a:80"); !ok || tripped {
		t.Fatalf("disabled guard should always allow, got (ok=%v,tripped=%v)", ok, tripped)
	}
}

// MinActive==0 / Ratio==0 使用内置默认(默认开启)。
func TestLoopGuardDefaults(t *testing.T) {
	conf.RouterConfig = &conf.Router{LoopGuard: conf.LoopGuard{}}
	g := newTestGuard()
	// 造满足默认闸门(200)且默认占比(80%)的场景
	for i := 0; i < loopGuardDefaultMinActive; i++ {
		g.enter("a:80")
	}
	if ok, tripped, _, _ := g.allow("a:80"); ok || !tripped {
		t.Fatalf("default-on: got (ok=%v,tripped=%v), want (false,true)", ok, tripped)
	}
}

// key 为空的 enter/leave 被忽略(如 tcpcopy 未经 handshake)。
func TestLoopGuardEmptyKey(t *testing.T) {
	conf.RouterConfig = &conf.Router{LoopGuard: conf.LoopGuard{MinActive: 1, Ratio: 80}}
	g := newTestGuard()
	g.enter("")
	g.leave("")
	if g.total != 0 || len(g.active) != 0 {
		t.Fatalf("empty key should be ignored, total=%d active=%d", g.total, len(g.active))
	}
}
