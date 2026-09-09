package nat

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"
)

// observeConn 包装 UDP socket, 把进程收到的**每一个** datagram 都记录一行日志。
//
// 动机: punch 包如果被 quic-go 判定为 QUIC 报文而吞掉, drainNonQUIC 永远看不见
// (它只能拿到 quic-go 认定的"非 QUIC 包"), 而动态端口又让 tcpdump 过滤很麻烦。
// 在 socket 层包一层, 就能看到进程视角的完整收包序列, 直接回答"对端的 punch
// 到底有没有到本进程"。
//
// 代价: quic-go 对非 *net.UDPConn 的 Conn 会退化为逐包收发, 失去批量收包的
// 性能优化。所以只在 debug 级别(-debug 2)时才套上这层包装, 常规运行保持
// 原生 socket 不变。
type observeConn struct {
	net.PacketConn
	d *directPeer

	mu         sync.Mutex
	shown      int // 已逐条详列的包数, 超过后转入限速摘要模式
	suppressed int
	last       time.Time
}

// observeVerboseMax 前这么多包逐条详列 —— 打洞阶段包量很小, 正好完整可见。
const observeVerboseMax = 20

// observeInterval 详列阶段结束后, 同类日志至多每秒一行。
const observeInterval = time.Second

func (o *observeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := o.PacketConn.ReadFrom(p)
	if err == nil && n > 0 {
		o.note(n, addr, p[:n])
	}
	return n, addr, err
}

// note 分类并限速打印一个收到的 datagram。
func (o *observeConn) note(n int, addr net.Addr, pkt []byte) {
	kind := "quic"
	verb := ""
	if len(pkt) > 0 && pkt[0] == directPacketMagic {
		payload := pkt[1:]
		if bytes.HasPrefix(payload, []byte("ANYPROXY-DIRECT-")) {
			kind = "direct"
			if i := bytes.IndexByte(payload, ' '); i > 0 {
				verb = string(payload[16:i]) // 跳过 "ANYPROXY-DIRECT-" 前缀
			}
		} else {
			kind = "direct-magic"
		}
	} else if len(pkt) > 0 && pkt[0]&0x80 != 0 {
		kind = "quic-long"
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	if o.shown >= observeVerboseMax && now.Sub(o.last) < observeInterval {
		o.suppressed++
		return
	}
	sup := o.suppressed
	o.suppressed = 0
	o.shown++
	o.last = now
	extra := ""
	if sup > 0 {
		extra = fmt.Sprintf(", +%d similar suppressed", sup)
	}
	if verb != "" {
		o.d.logf("recv %d bytes from %s (%s %s)%s", n, addr, kind, verb, extra)
		return
	}
	o.d.logf("recv %d bytes from %s (%s)%s", n, addr, kind, extra)
}
