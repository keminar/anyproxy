package nat

import (
	"sync"
	"time"
)

// trafficMeter 累计上下行字节/包数, 并能算出"自上次汇报以来"的瞬时速率。
//
// UDP 通路(直连的 UDP 入口、UDP 中继)没有 TCP 那种"连接关闭"事件可以借来打一行
// 汇总, 唯一能看出"数据有没有在走、走多快"的办法就是周期性地跟自己上一次的快照
// 比一比。约定俗成: up = 朝内网目标方向的流量, down = 朝外部客户端方向的流量,
// 与 Bridge.Stats() 的方向约定一致(见 bridge.go)。
type trafficMeter struct {
	mu                 sync.Mutex
	upBytes, downBytes int64
	upPkts, downPkts   int64
	lastAt             time.Time
	lastUp, lastDown   int64
}

// addUp/addDown 记一笔流量。n 是这一个包的业务负载字节数, 不含帧头/协议开销——跟
// direct_udp.go 原有的计数口径保持一致, 度量的是"实际传输了多少数据", 不是"占用了
// 多少带宽"。
func (m *trafficMeter) addUp(n int) {
	m.mu.Lock()
	m.upBytes += int64(n)
	m.upPkts++
	m.mu.Unlock()
}

func (m *trafficMeter) addDown(n int) {
	m.mu.Lock()
	m.downBytes += int64(n)
	m.downPkts++
	m.mu.Unlock()
}

// stats 取累计总量(快照, 非增量)。
func (m *trafficMeter) stats() (upBytes, upPkts, downBytes, downPkts int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upBytes, m.upPkts, m.downBytes, m.downPkts
}

// trafficSnapshot 一次周期性汇报要用到的数据: 累计总量 + 这一轮的瞬时速率。
type trafficSnapshot struct {
	UpBytes, UpPkts     int64
	DownBytes, DownPkts int64
	UpRate, DownRate    string // 形如 "1.2MB/s"; 上一轮没有新流量时汇报会被跳过, 不会拿到零值速率
}

// snapshot 取一次"自上次调用以来"的增量, 换算成瞬时速率。ok=false 表示这一轮跟上一轮
// 相比完全没有新流量, 调用方应跳过打印——否则空闲期会一直刷屏, 看不出真正有数据在走
// 的时刻在哪。
//
// 速率是瞬时的, 不是从连接建立到现在的累计平均: 排查"是不是被限速/拥塞退避"时要看的
// 是"现在多快", 累计平均会把早期的高速和后期的骤降拉平, 看不出变化过程(与 -send
// 进度条改瞬时速率是同一个理由, 见 nat/file_send.go 的 progress.update)。
func (m *trafficMeter) snapshot() (trafficSnapshot, bool) {
	m.mu.Lock()
	up, upPkts, down, downPkts := m.upBytes, m.upPkts, m.downBytes, m.downPkts
	now := time.Now()
	if m.lastAt.IsZero() {
		// 第一次调用: 还没有"上一轮"可比, 没法算速率, 只记个基准, 这一轮先不报——
		// 下一轮就有完整的时间区间可用了, 空等一轮比报一个假速率(或干脆不报速率
		// 只报累计量)更简单一致。
		m.lastAt, m.lastUp, m.lastDown = now, up, down
		m.mu.Unlock()
		return trafficSnapshot{}, false
	}
	if up == m.lastUp && down == m.lastDown {
		m.mu.Unlock()
		return trafficSnapshot{}, false
	}
	elapsed := now.Sub(m.lastAt)
	deltaUp, deltaDown := up-m.lastUp, down-m.lastDown
	m.lastAt, m.lastUp, m.lastDown = now, up, down
	m.mu.Unlock()
	return trafficSnapshot{
		UpBytes: up, UpPkts: upPkts, DownBytes: down, DownPkts: downPkts,
		UpRate: rate(deltaUp, elapsed), DownRate: rate(deltaDown, elapsed),
	}, true
}
