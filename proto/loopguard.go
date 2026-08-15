package proto

import (
	"sync"

	"github.com/keminar/anyproxy/utils/conf"
)

// loopguard 是同机 A(mode=tun)+B(mode=bypass, 仅Linux) 部署下的死循环兜底熔断器。
// 正常应由 bypass 从路由层根治环路; 本熔断器仅作最后防线。
//
// 判定思路(避免对每个域名做每秒计数的浪费):
//   1. 便宜的闸门: 只有整个进程的在传连接数达到 minActive 时才启用检查;
//      常态下总数不高, allow 只做一次 int 比较, 零额外计算。
//   2. 占比判定: 闸门开启后, 若某个目标(host:port)已占用的在传连接数超过
//      total*ratio%, 说明句柄都堆在这一个目标上(环路特征), 拒绝其新连接。
// 拒绝新连接后, 上游(B)对该目标的后续连接会被 A 拒绝而失败, 环路链条随之解开,
// 存量在传连接逐步 drain, total 回落, 闸门自动重新放开, 无需 ban 计时。

const (
	loopGuardDefaultMinActive = 1000 // MinActive==0(未配置) 时的内置闸门, 即默认开启; 需 ulimit -n 远大于其 2 倍
	loopGuardDefaultRatio     = 80  // 单目标占比百分比阈值默认值
)

type loopGuard struct {
	mu     sync.Mutex
	active map[string]int  // 每个 host:port 当前在传连接数
	total  int             // 全局在传连接数
	noted  map[string]bool // 已就该目标打过环路日志, 避免刷屏; leave 归零时清除
}

var guard = &loopGuard{
	active: make(map[string]int),
	noted:  make(map[string]bool),
}

// loopGuardConf 解析配置。minActive<0 表示关闭。
func loopGuardConf() (minActive, ratio int) {
	c := conf.RouterConfig.LoopGuard
	minActive = c.MinActive
	if minActive == 0 {
		minActive = loopGuardDefaultMinActive
	}
	ratio = c.Ratio
	if ratio <= 0 {
		ratio = loopGuardDefaultRatio
	}
	return
}

// allow 在新建代理连接前调用。返回:
//
//	ok      -- 是否放行
//	tripped -- 是否本轮首次判定该目标为环路(供调用方打印一次日志)
//	keyActive/total -- 判定时的在传连接快照(供日志/调优)
func (g *loopGuard) allow(key string) (ok, tripped bool, keyActive, total int) {
	minActive, ratio := loopGuardConf()
	if minActive < 0 { // 关闭
		return true, false, 0, 0
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	total = g.total
	// 闸门未到: 常态零额外计算, 直接放行
	if total < minActive {
		return true, false, 0, total
	}
	keyActive = g.active[key]
	if keyActive*100 >= total*ratio {
		if !g.noted[key] {
			g.noted[key] = true
			tripped = true
		}
		return false, tripped, keyActive, total
	}
	return true, false, keyActive, total
}

// enter 记录一条到 key 的在传连接。key 为空(如 tcpcopy 未经 handshake)时跳过。
func (g *loopGuard) enter(key string) {
	if key == "" {
		return
	}
	g.mu.Lock()
	g.total++
	g.active[key]++
	g.mu.Unlock()
}

// leave 释放一条到 key 的在传连接。
func (g *loopGuard) leave(key string) {
	if key == "" {
		return
	}
	g.mu.Lock()
	if g.total > 0 {
		g.total--
	}
	if n := g.active[key] - 1; n <= 0 {
		delete(g.active, key)
		delete(g.noted, key)
	} else {
		g.active[key] = n
	}
	g.mu.Unlock()
}
