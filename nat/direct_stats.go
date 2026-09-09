package nat

import (
	"context"
	"fmt"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// 直连 QUIC 连接的收发统计。
//
// 存在的理由: 直连传文件慢的时候, 光看"多少 MB 用了多久"没法判断该查哪儿 —— 是链路
// 在丢包(拥塞窗口压根长不起来), 还是我们自己这侧有问题(比如 socket 缓冲没设上)。
// 这两种情况的处理方向完全相反, 靠猜会来回折腾很久, 所以直接把 quic-go 内部的丢包
// 计数、RTT 与拥塞窗口取出来打一行。
//
// 判读方法:
//   - 丢包率高(比如 >1%)且 cwnd 一直很小 → 链路问题, 代码这边没什么可救的。
//     参考: 吞吐上限约等于 cwnd/RTT, cwnd 若一直贴着初始值(约 10 个包、12KB 上下),
//     在 100ms RTT 下就只有 120KB/s 左右, 跟"传得很慢"的观感能对上。
//   - 丢包率很低但 cwnd 仍然不涨 → 那才轮到查我们自己(发送侧是不是喂不满、
//     UDP 缓冲是不是太小)。
//
// quic-go v0.59 把连接内部指标统一走 qlog 事件出口, 所以这里实现一个只统计、不落盘
// 的 qlogwriter.Trace: 事件来了按类型累加几个计数器就丢掉, 不做任何编码或 IO。
type directStats struct {
	mu     sync.Mutex
	sent   uint64
	lost   uint64
	minRTT time.Duration
	sRTT   time.Duration
	cwnd   int
	inFlt  int

	// logf 非空时, 在 -debug 下按 statsLogInterval 打点 cwnd/inflight, 用来看清一次
	// 传输里拥塞窗口是"从头到尾没涨过"还是"涨到一半又掉了下去"——只有 summary() 那
	// 一个终值区分不了这两种情况, 而它们对应的排查方向完全不同(见上面的判读方法)。
	logf    func(string, ...interface{})
	lastLog time.Time
}

// statsLogInterval 拥塞窗口打点间隔。1 个 RTT 打一次太密, 拉到 1s 够看出趋势又不刷屏。
const statsLogInterval = time.Second

// AddProducer 实现 qlogwriter.Trace。每条连接可能有多个 producer, 共用同一份计数。
func (s *directStats) AddProducer() qlogwriter.Recorder { return &directStatsRecorder{stats: s} }

// SupportsSchemas 实现 qlogwriter.Trace: 只认 quic 事件本身, 不掺 http3 那些。
func (s *directStats) SupportsSchemas(schema string) bool { return schema == qlog.EventSchema }

type directStatsRecorder struct{ stats *directStats }

func (r *directStatsRecorder) Close() error { return nil }

// RecordEvent 只挑三种事件, 其余直接丢弃 —— 这是数据路径上的热点(每个包一次),
// 不能在这里做任何编码或分配。
func (r *directStatsRecorder) RecordEvent(e qlogwriter.Event) {
	switch ev := e.(type) {
	case qlog.PacketSent:
		r.stats.mu.Lock()
		r.stats.sent++
		r.stats.mu.Unlock()
	case qlog.PacketLost:
		r.stats.mu.Lock()
		r.stats.lost++
		r.stats.mu.Unlock()
	case qlog.MetricsUpdated:
		r.stats.mu.Lock()
		// 这个事件只带"变化了的"字段, 没变的是零值, 所以不能无脑覆盖。
		if ev.MinRTT != 0 {
			r.stats.minRTT = ev.MinRTT
		}
		if ev.SmoothedRTT != 0 {
			r.stats.sRTT = ev.SmoothedRTT
		}
		if ev.CongestionWindow != 0 {
			r.stats.cwnd = ev.CongestionWindow
		}
		if ev.BytesInFlight != 0 {
			r.stats.inFlt = ev.BytesInFlight
		}
		var due bool
		if r.stats.logf != nil && time.Since(r.stats.lastLog) >= statsLogInterval {
			r.stats.lastLog = time.Now()
			due = true
		}
		sent, lost, cwnd, inFlt := r.stats.sent, r.stats.lost, r.stats.cwnd, r.stats.inFlt
		r.stats.mu.Unlock()
		if due {
			r.stats.logf("quic cwnd=%s inflight=%s sent=%dpkt lost=%dpkt",
				humanBytes(int64(cwnd)), humanBytes(int64(inFlt)), sent, lost)
		}
	}
}

// summary 一行可读的汇总; 没采到任何包时返回空串(调用方据此不打这行)。
func (s *directStats) summary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sent == 0 {
		return ""
	}
	lossPct := float64(s.lost) * 100 / float64(s.sent)
	// 取到微秒: 毫秒粒度在回环/同城这种亚毫秒链路上会显示成 0s, 看着像没采到。
	return fmt.Sprintf("sent=%dpkt lost=%dpkt(%.2f%%) rtt=%s/%s(min/smoothed) cwnd=%s inflight=%s",
		s.sent, s.lost, lossPct,
		s.minRTT.Round(time.Microsecond), s.sRTT.Round(time.Microsecond),
		humanBytes(int64(s.cwnd)), humanBytes(int64(s.inFlt)))
}

// directQUICConfigWithStats 在共用参数基础上挂一个统计用的 tracer。
// 拨号侧(A)用它, 监听侧不挂——统计是给"这次传输为什么慢"服务的, 发起方看得到就够了。
func directQUICConfigWithStats(stats *directStats) *quic.Config {
	cfg := directQUICConfig()
	cfg.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return stats }
	return cfg
}
