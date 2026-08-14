//go:build !windows
// +build !windows

package tun

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/keminar/anyproxy/config"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// ── DNS 中继 ────────────────────────────────────────────────────────────────
//
// 问题: DNS 查询从**大量临时源口**发出(每个应用查询换一个源口), 但只发往 **1~3 个
// 解析器**。主 NAT 表按 srcIP:srcPort 建键, 于是每个 DNS 查询各占一个会话=一个内核
// socket, 挤占 maxUDPSessions=256 预算, 在 Windows 上加剧 WSAENOBUFS。
//
// 解法: 每个**解析器**维护一个共享的未连接 socket, 所有客户端的 DNS 查询都从这个
// socket 发出; 回包按 (解析器, txid) 解复用回原客户端。于是 DNS socket 数 = 不同
// 解析器数(1~3), 与查询数、源口数完全无关, 彻底移出会话预算。
//
// txid 解复用的正确性: 解析器会原样回显查询的 16 位 txid, 这正是操作系统 stub
// resolver 自己解复用的依据, 与一切 DNS NAT/转发器做法一致。冲突(同解析器、同 txid、
// 并发在传)时后者覆盖前者的 pending, 前者回包投递到后者坐标→源口不符→前者查询静默
// 超时, 应用重试(DNS 幂等、可重试)。窗口仅为 RTT(~ms)~TTL(5s), 冲突概率极低且后果有界。

const (
	// dnsPendingTTL 一条 pending 查询的存活上限。解析器无响应(NXDOMAIN drop / 死解析器)
	// 时靠它回收, 不让 pending 表无限增长。
	dnsPendingTTL = 5 * time.Second
	// maxDNSPending pending 表硬上限。洪泛下超过则拒绝新查询(限流日志), 护住内存,
	// 与主表负缓存同哲学。正常浏览远达不到。
	maxDNSPending = 4096
	// dnsSockIdleTimeout 共享 socket 空闲多久后关闭回收。解析器少而稳定, 给一个较长值。
	dnsSockIdleTimeout = 60 * time.Second
)

// dnsPending 记录一条在传 DNS 查询的客户端坐标, 供回包按 txid 反查回灌方向。
type dnsPending struct {
	srcIP    tcpip.Address // 客户端源 IP
	srcPort  uint16        // 客户端源口
	resolver tcpip.Address // 解析器 IP(回包 src, 即客户端原 dst)
	deadline time.Time
}

// dnsResolverSock 一个解析器对应的共享 socket 及其读循环状态。
type dnsResolverSock struct {
	conn     *net.UDPConn
	lastUsed time.Time
}

// dnsRelay 管理"每解析器一个共享 socket"与"按 (解析器,txid) 解复用"的 pending 表。
type dnsRelay struct {
	dev Device

	mu    sync.Mutex
	socks map[string]*dnsResolverSock // key: 解析器 IP 字符串
	pend  map[string]dnsPending       // key: "解析器IP|txid"

	// 限流: pending 溢出日志每秒最多一条。
	overflowLast time.Time
	overflowSkip int
}

func newDNSRelay(dev Device) *dnsRelay {
	r := &dnsRelay{
		dev:   dev,
		socks: make(map[string]*dnsResolverSock),
		pend:  make(map[string]dnsPending),
	}
	go r.sweepLoop()
	return r
}

// pendKey 组合解析器 IP 与 txid 为 pending 表键。
func pendKey(resolver tcpip.Address, txid uint16) string {
	return fmt.Sprintf("%s|%d", resolver.String(), txid)
}

// forward 把一条 hosts 未命中的 DNS 查询经共享 socket 发往解析器。
// payload 是 DNS 报文(已由上层保证非空); srcIP/srcPort 是客户端源; dstIP 是解析器;
// dstPort 恒为 53(回灌时作 src port)。
func (r *dnsRelay) forward(payload []byte, srcIP, dstIP tcpip.Address, srcPort, dstPort uint16) {
	if len(payload) < 12 { // DNS 头 12 字节, 不足则非法, 丢弃
		return
	}
	txid := binary.BigEndian.Uint16(payload[0:2])
	resolverKey := dstIP.String()

	r.mu.Lock()
	// 硬上限保护: pending 过多说明解析器普遍无响应或遭洪泛, 拒新并限流告警。
	if len(r.pend) >= maxDNSPending {
		r.logOverflowLocked()
		r.mu.Unlock()
		return
	}
	rs := r.socks[resolverKey]
	if rs == nil {
		// 复用 listenUDP: 与普通 UDP 转发一样绑物理网卡出接口(逃出 TUN 的 0/1)。
		conn, err := listenUDP(fmt.Sprintf("%s:%d", resolverKey, dnsPort))
		if err != nil {
			r.mu.Unlock()
			logDialErr(resolverKey+":53", err)
			return
		}
		rs = &dnsResolverSock{conn: conn, lastUsed: time.Now()}
		r.socks[resolverKey] = rs
		go r.readLoop(dstIP, conn)
	}
	rs.lastUsed = time.Now()
	r.pend[pendKey(dstIP, txid)] = dnsPending{
		srcIP:    srcIP,
		srcPort:  srcPort,
		resolver: dstIP,
		deadline: time.Now().Add(dnsPendingTTL),
	}
	conn := rs.conn
	r.mu.Unlock()

	a := dstIP.As4()
	if _, err := conn.WriteToUDP(payload, &net.UDPAddr{IP: net.IP(a[:]), Port: dnsPort}); err != nil {
		log.Printf("dns relay write to %s err: %v", resolverKey, err)
	}
}

// readLoop 读某解析器共享 socket 上的所有回包, 按回包 txid 反查 pending, 回灌客户端。
// resolver 是该 socket 绑定的解析器(仅接受来自它的回包)。
func (r *dnsRelay) readLoop(resolver tcpip.Address, conn *net.UDPConn) {
	bufp := udpBufPool.Get().(*[]byte)
	buf := *bufp
	defer udpBufPool.Put(bufp)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(dnsSockIdleTimeout))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			// 超时或关闭: 从表中摘除并关闭, 让下次查询重建。
			r.closeSock(resolver.String(), conn)
			return
		}
		if n < 12 {
			continue
		}
		// 只认来自本解析器的回包(防串扰)。
		fromV4 := from.IP.To4()
		if fromV4 == nil || tcpip.AddrFrom4Slice(fromV4) != resolver {
			continue
		}
		txid := binary.BigEndian.Uint16(buf[0:2])
		key := pendKey(resolver, txid)

		r.mu.Lock()
		p, ok := r.pend[key]
		if ok {
			delete(r.pend, key)
		}
		if rs := r.socks[resolver.String()]; rs != nil {
			rs.lastUsed = time.Now()
		}
		r.mu.Unlock()
		if !ok {
			continue // 迟到/重复/未知 txid, 丢弃
		}

		// 回灌: src=解析器, dst=客户端源。
		pkt := buildUDPv4Packet(p.resolver, p.srcIP, dnsPort, p.srcPort, buf[:n])
		if err := r.dev.WritePacket(pkt); err != nil {
			return
		}
	}
}

// closeSock 从表中摘除并关闭指定解析器的共享 socket(仅当仍是同一个 conn 时)。
func (r *dnsRelay) closeSock(resolverKey string, conn *net.UDPConn) {
	r.mu.Lock()
	if rs := r.socks[resolverKey]; rs != nil && rs.conn == conn {
		delete(r.socks, resolverKey)
	}
	r.mu.Unlock()
	conn.Close()
}

// sweepLoop 周期清理过期 pending(解析器无响应的查询), 避免表泄漏。
func (r *dnsRelay) sweepLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		r.mu.Lock()
		for k, p := range r.pend {
			if now.After(p.deadline) {
				delete(r.pend, k)
			}
		}
		r.mu.Unlock()
	}
}

// logOverflowLocked 在持有 mu 时调用: pending 溢出限流日志, 每秒最多一条。
func (r *dnsRelay) logOverflowLocked() {
	now := time.Now()
	if !r.overflowLast.IsZero() && now.Sub(r.overflowLast) < time.Second {
		r.overflowSkip++
		return
	}
	skipped := r.overflowSkip
	r.overflowSkip = 0
	r.overflowLast = now
	if config.DebugLevel >= config.LevelDebug {
		log.Printf("dns relay pending overflow (>=%d), dropping new queries (+%d suppressed)", maxDNSPending, skipped)
	}
}
