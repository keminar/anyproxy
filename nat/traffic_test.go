package nat

import (
	"testing"
	"time"
)

func TestTrafficMeterAccumulates(t *testing.T) {
	var m trafficMeter
	m.addUp(100)
	m.addUp(50)
	m.addDown(30)
	up, upPkts, down, downPkts := m.stats()
	if up != 150 || upPkts != 2 {
		t.Fatalf("up = %d/%d pkt, want 150/2", up, upPkts)
	}
	if down != 30 || downPkts != 1 {
		t.Fatalf("down = %d/%d pkt, want 30/1", down, downPkts)
	}
}

// 第一次 snapshot 还没有"上一轮"可比, 没法算速率, 不该报——报一个假速率(比如把
// 整个连接生命周期当分母)比不报更容易把人带偏。
func TestTrafficMeterFirstSnapshotSkipped(t *testing.T) {
	var m trafficMeter
	m.addUp(1000)
	if _, ok := m.snapshot(); ok {
		t.Fatal("the first snapshot should be skipped (no prior baseline to diff against)")
	}
}

// 没有新流量的轮次要能跳过, 否则空闲期会一直刷屏, 找不出真正有数据在走的时刻。
func TestTrafficMeterSkipsWhenNoNewTraffic(t *testing.T) {
	var m trafficMeter
	m.addUp(1000)
	m.snapshot() // 建立基准

	if _, ok := m.snapshot(); ok {
		t.Fatal("a round with zero new traffic should be skipped")
	}

	m.addDown(500)
	snap, ok := m.snapshot()
	if !ok {
		t.Fatal("new traffic (even in only one direction) should trigger a report")
	}
	if snap.UpBytes != 1000 || snap.DownBytes != 500 {
		t.Fatalf("cumulative totals wrong: up=%d down=%d", snap.UpBytes, snap.DownBytes)
	}
}

// 速率算的是"这一轮"的增量, 不是从头到现在的累计平均——这是它存在的全部意义:
// 排查限速/拥塞退避要看的是"现在多快", 不是被早期高速拉高的整体平均。
func TestTrafficMeterRateIsPerRoundNotCumulativeAverage(t *testing.T) {
	var m trafficMeter
	m.addUp(10 << 20) // 头一轮冲得很快: 10MB
	m.snapshot()      // 建立基准(第一次不报)

	time.Sleep(50 * time.Millisecond)
	m.snapshot() // 这一轮上行没有新增量, 只是推进基准; down 还是 0, 整体无新流量应跳过
	// (刻意不断言这一步的返回值: 关键行为在下面第二段验证)

	m.addUp(1 << 10) // 后面骤降到 1KB
	time.Sleep(50 * time.Millisecond)
	snap, ok := m.snapshot()
	if !ok {
		t.Fatal("want a report for the new (small) increment")
	}
	// 累计平均会是 10MB+1KB 除以整个耗时, 数值上仍然很大; 瞬时速率只看这最后 1KB
	// 那一小段, 必须小得多——这个差异就是这个类型存在的理由。
	if snap.UpBytes != 10<<20+1<<10 {
		t.Fatalf("cumulative up = %d, want %d", snap.UpBytes, 10<<20+1<<10)
	}
	if snap.UpRate == "" {
		t.Fatal("want a non-empty rate string")
	}
}

func TestTrafficMeterConcurrentAdds(t *testing.T) {
	var m trafficMeter
	done := make(chan struct{})
	const n = 200
	for i := 0; i < n; i++ {
		go func() {
			m.addUp(1)
			m.addDown(1)
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
	up, upPkts, down, downPkts := m.stats()
	if up != n || upPkts != n || down != n || downPkts != n {
		t.Fatalf("got up=%d/%d down=%d/%d, want all %d", up, upPkts, down, downPkts, n)
	}
}
