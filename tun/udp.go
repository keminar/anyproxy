//go:build !windows
// +build !windows

package tun

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/cache"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// 普通 UDP(如 QUIC)会话空闲超时
	udpSessionTimeout = 30 * time.Second
	// DNS 是一问一答，收到响应即可回收，用短超时快速释放 goroutine/conn/buffer，
	// 避免大量 DNS 查询(含 NXDOMAIN)各驻留 30s 累积内存
	udpDNSSessionTimeout = 5 * time.Second
	// UDP 读缓冲大小。每个会话 readLoop goroutine 独占一块，若用 64KB 满额，
	// 几百个并发会话就吃掉几十 MB。8KB 足够覆盖 DNS(≤4KB EDNS)和 QUIC(≤1500)，
	// 权衡: 超过 8KB 的 UDP 数据报(依赖 IP 分片，实际罕见)会被截断
	udpReadBufSize = 8 * 1024
	// 建 socket 失败(如 Windows 缓冲耗尽)后的负缓存时长：冷却期内该源口直接丢包、
	// 不再每包重试 listen，避免重试风暴自我加剧；到期后清除，允许再次尝试。
	udpNegCacheTTL = 2 * time.Second
	// 并发 UDP 会话(=真实内核 socket)上限。P2P/PCDN 客户端会「每个 peer 换一个源口」，
	// 源口去重挡不住，会瞬间开出成千上万个真实 socket 把系统非分页池撑爆(Windows
	// WSAENOBUFS，甚至连累 TCP 连接被 abort)。此处硬性封顶，满了淘汰最旧空闲会话腾位。
	// 256 足够正常浏览+少量 QUIC；被误淘汰的活跃流下个包会自动重建。
	maxUDPSessions = 256
)

// udpBufPool 复用 UDP 读缓冲，跨会话复用、会话结束即归还，降低 GC 压力。
var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpReadBufSize)
		return &b
	},
}

type udpSession struct {
	// conn 为「未连接」的 UDP socket，按客户端源(srcIP:srcPort)一个，
	// 用 WriteToUDP 发往任意多目标、用 ReadFromUDP 收所有目标的回包。
	// 这样应用层「1 个源口对 N 个 peer」不会被放大成 N 个内核 socket。
	conn  *net.UDPConn
	timer *time.Timer
	// last 最近活动时间，会话表满时据此淘汰最久空闲的会话(近似 LRU)。
	last time.Time
	// isDNS 标记该会话首包目标端口为 53，仅供普查统计 DNS/非 DNS 占比用。
	isDNS bool
}

// udpForwarder 维护一张 NAT 表，把 TUN 读到的 UDP 包转发到真实目标，
// 把响应包构造成原始 IP 包写回 TUN 设备。
type udpForwarder struct {
	mu       sync.Mutex
	sessions map[string]*udpSession
	dev      Device
	dnsRelay *dnsRelay // DNS 中继: 每解析器一个共享 socket, 把 DNS 移出会话表

	// 普查计数(均在持有 mu 时累加)：诊断 UDP socket 是否被打爆、DNS 占比、淘汰频率。
	dnsSessCreated    uint64 // 累计创建的 DNS 会话数
	nonDNSSessCreated uint64 // 累计创建的非 DNS 会话数
	evictions         uint64 // 累计因会话表满而 LRU 淘汰的次数
	lastEvictions     uint64 // 上次普查时的 evictions 值，用于算增量
}

func newUDPForwarder(dev Device) *udpForwarder {
	f := &udpForwarder{
		sessions: make(map[string]*udpSession),
		dev:      dev,
	}
	f.dnsRelay = newDNSRelay(dev)
	// 普查 goroutine：每 10s 打一行会话概况，零每包开销。仅 LevelDebug 开启。
	go f.censusLoop()
	return f
}

// censusLoop 周期性打印 UDP 会话普查，用于观测 socket 是否接近上限、DNS 占多少、
// 淘汰是否频繁。10s 一行，只在 LevelDebug 下输出，不影响正常运行。
func (f *udpForwarder) censusLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if config.DebugLevel < config.LevelDebug {
			continue
		}
		f.mu.Lock()
		var dnsNow int
		for _, s := range f.sessions {
			if s.isDNS {
				dnsNow++
			}
		}
		total := len(f.sessions)
		dnsCreated := f.dnsSessCreated
		nonDNSCreated := f.nonDNSSessCreated
		evict := f.evictions
		evictDelta := evict - f.lastEvictions
		f.lastEvictions = evict
		f.mu.Unlock()
		log.Printf("udp census: sessions=%d/%d dns=%d nondns=%d created(dns/nondns)=%d/%d evicted=%d(+%d/10s)",
			total, maxUDPSessions, dnsNow, total-dnsNow, dnsCreated, nonDNSCreated, evict, evictDelta)
	}
}

// evictOldestLocked 淘汰最久空闲的一个会话(关 socket、停定时器)，给新会话腾位。
// 调用方须持有 f.mu。会话数封顶用，n=maxUDPSessions 时的线性扫描开销可忽略；
// 被误淘汰的活跃流下个包会自动重建(至多丢一两个包)。
func (f *udpForwarder) evictOldestLocked() {
	var oldKey string
	var oldSess *udpSession
	for k, s := range f.sessions {
		if oldSess == nil || s.last.Before(oldSess.last) {
			oldKey, oldSess = k, s
		}
	}
	if oldSess == nil {
		return
	}
	oldSess.timer.Stop()
	if oldSess.conn != nil {
		oldSess.conn.Close()
	}
	delete(f.sessions, oldKey)
	f.evictions++
}

// isUDP 判断原始 IP 包是否为 IPv4 UDP。
func isUDP(pkt []byte) bool {
	if len(pkt) < header.IPv4MinimumSize {
		return false
	}
	if pkt[0]>>4 != 4 {
		return false
	}
	return header.IPv4(pkt).Protocol() == uint8(header.UDPProtocolNumber)
}

func (f *udpForwarder) handle(pkt []byte) {
	ipHdr := header.IPv4(pkt)
	ipHdrLen := int(ipHdr.HeaderLength())

	udpPayloadStart := ipHdrLen + header.UDPMinimumSize
	if len(pkt) < udpPayloadStart {
		return
	}
	udpHdr := header.UDP(pkt[ipHdrLen:])
	udpPayloadLen := int(udpHdr.Length()) - header.UDPMinimumSize
	if udpPayloadLen < 0 || udpPayloadStart+udpPayloadLen > len(pkt) {
		return
	}
	payload := pkt[udpPayloadStart : udpPayloadStart+udpPayloadLen]

	srcIP := ipHdr.SourceAddress()
	dstIP := ipHdr.DestinationAddress()
	srcPort := udpHdr.SourcePort()
	dstPort := udpHdr.DestinationPort()

	// 忽略广播包（255.255.255.255 及子网广播如 10.9.0.255），不尝试 dial
	if dstIP == header.IPv4Broadcast || dstIP.As4()[3] == 0xff {
		return
	}

	// 丢弃局域网服务/发现类噪声(NetBIOS/mDNS/LLMNR/SSDP)与组播，避免无谓 dial
	// 在 Windows 上耗尽 socket 缓冲触发 WSAENOBUFS。非 windows 平台恒为 false。
	if dropNoiseUDP(dstIP, dstPort) {
		return
	}

	// DNS 拦截: 目标端口为 53 时，检查 hosts 配置是否有域名->IP 的映射。
	// 如果匹配到，直接构造 DNS 响应写回 TUN 设备，不转发到真实 DNS 服务器。
	// 这样 TUN 模式下 hosts 中配置了 ip 的域名(如内网域名)就能正常解析。
	if dstPort == dnsPort {
		if f.handleDNS(payload, srcIP, dstIP, srcPort, dstPort) {
			return
		}
		// hosts 未命中: 交给 DNS 中继(每解析器一个共享 socket, 按 txid 解复用)，
		// 不再为每个查询源口建独立会话——DNS 从大量临时源口发出但只发往 1~3 个解析器,
		// 逐源口建 socket 会挤占 maxUDPSessions 预算并在 Windows 触发 WSAENOBUFS。
		f.dnsRelay.forward(payload, srcIP, dstIP, srcPort, dstPort)
		return
	}

	// QUIC(UDP443) 阻断: 命中 hosts(配了ip)域名的 UDP 443 直接 drop，
	// 逼客户端回退 TCP 443 走已有的 TCP+SNI 代理链，避免劫持域名的 QUIC 绕过代理。
	// 默认开启，可用 tun.blockQUIC: false 关闭。
	if dstPort == httpsPort && blockQUICEnabled() && hostBlocksUDP(dstIP.String()) {
		if config.DebugLevel >= config.LevelDebug {
			log.Printf("udp drop QUIC to %s:%d (hosts rule, force TCP fallback)", dstIP, dstPort)
		}
		return
	}

	// NAT 表按「客户端源(srcIP:srcPort)」建键，不含目标：一个源口共用一个 socket，
	// socket 数 = 不同源口数(与应用层直连一致)，而非目标数，避免 P2P 洪泛把
	// 内核 socket 打爆(Windows WSAENOBUFS)。
	key := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dstAddr := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)

	// DNS 会话用短超时快速回收，其余(QUIC 等长连接)用常规超时
	sessTimeout := udpSessionTimeout
	if dstPort == dnsPort {
		sessTimeout = udpDNSSessionTimeout
	}

	now := time.Now()

	f.mu.Lock()
	sess, ok := f.sessions[key]
	if !ok {
		// 会话表满：淘汰最久空闲的会话腾位，把真实 socket 数硬性封顶，
		// 避免 P2P/PCDN「每 peer 换源口」瞬间开爆系统非分页池。
		if len(f.sessions) >= maxUDPSessions {
			f.evictOldestLocked()
		}
		// 首个目标用于决定是否绑物理网卡(落在本机直连子网则无需绑)。
		conn, err := listenUDP(dstAddr)
		if err != nil {
			// 建 socket 失败：写入负缓存(conn=nil)，冷却期内该源口丢包不再重试，
			// 避免每个包都重试 listen 形成风暴、反过来加剧缓冲耗尽与日志刷屏。
			neg := &udpSession{last: now}
			neg.timer = time.AfterFunc(udpNegCacheTTL, func() {
				f.mu.Lock()
				delete(f.sessions, key)
				f.mu.Unlock()
			})
			f.sessions[key] = neg
			f.mu.Unlock()
			logDialErr(dstAddr, err)
			return
		}
		sess = &udpSession{conn: conn, last: now, isDNS: dstPort == dnsPort}
		sess.timer = time.AfterFunc(sessTimeout, func() {
			f.mu.Lock()
			delete(f.sessions, key)
			f.mu.Unlock()
			conn.Close()
		})
		f.sessions[key] = sess
		if sess.isDNS {
			f.dnsSessCreated++
		} else {
			f.nonDNSSessCreated++
		}
		go f.readLoop(conn, srcIP, srcPort)
	} else if sess.conn == nil {
		// 负缓存冷却期内，直接丢包
		f.mu.Unlock()
		return
	} else {
		sess.last = now
		sess.timer.Reset(sessTimeout)
	}
	conn := sess.conn
	f.mu.Unlock()

	// DNS 目标加 /32 例外路由(darwin), 逃出 0/1 全量路由恢复 UDP 直连;
	// 其余平台空操作(linux SO_BINDTODEVICE 有效)。仅 DNS(53) 加, 不碰 QUIC。
	if dstPort == dnsPort {
		ensureUDPDynRoute(dstIP.String())
	}
	a := dstIP.As4()
	if _, err := conn.WriteToUDP(payload, &net.UDPAddr{IP: net.IP(a[:]), Port: int(dstPort)}); err != nil {
		log.Printf("udp forward write %s err: %v", dstAddr, err)
		// 路由层瞬时错误(no route to host / network unreachable): 该 socket 绑死的源此刻
		// 无可用路由。淘汰本会话并关掉 socket, 使下一个包重建 socket 重新绑定/选路,
		// 避免一次瞬断把整条 UDP 会话钉死(如 DHCP 续租、路由缓存瞬态)。
		if isRouteErr(err) {
			f.mu.Lock()
			if cur, ok := f.sessions[key]; ok && cur == sess {
				delete(f.sessions, key)
				if sess.timer != nil {
					sess.timer.Stop()
				}
			}
			f.mu.Unlock()
			conn.Close()
		}
	}
}

// isRouteErr 判断是否为路由层不可达错误(EHOSTUNREACH / ENETUNREACH)。
func isRouteErr(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH)
}

// readLoop 读该源口 socket 上所有目标的回包，按回包源地址(from)解复用：
// 回包方向 src=远端目标(from)、dst=客户端源，据此构造 IP 包写回 TUN。
func (f *udpForwarder) readLoop(conn *net.UDPConn, srcIP tcpip.Address, srcPort uint16) {
	bufp := udpBufPool.Get().(*[]byte)
	buf := *bufp
	defer udpBufPool.Put(bufp)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		fromV4 := from.IP.To4()
		if fromV4 == nil {
			continue
		}
		fromIP := tcpip.AddrFrom4Slice(fromV4)
		pkt := buildUDPv4Packet(fromIP, srcIP, uint16(from.Port), srcPort, buf[:n])
		if err := f.dev.WritePacket(pkt); err != nil {
			return
		}
	}
}

// dstInBypassNet 判断目标是否落在本机直连子网(内核已有比 TUN 的 0/1 更具体的路由)。
// 命中则 socket 无需绑定物理网卡，各平台 listenUDP 用它决定是否绑。
func dstInBypassNet(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range config.TUNBypassNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// dialErr 日志限流：P2P/DHT 洪泛下 listen/bind 偶发失败时避免刷屏，
// 每秒最多打一条，并附带被抑制的条数。
var (
	dialErrMu   sync.Mutex
	dialErrLast time.Time
	dialErrSkip int
)

func logDialErr(dstAddr string, err error) {
	dialErrMu.Lock()
	now := time.Now()
	if !dialErrLast.IsZero() && now.Sub(dialErrLast) < time.Second {
		dialErrSkip++
		dialErrMu.Unlock()
		return
	}
	skipped := dialErrSkip
	dialErrSkip = 0
	dialErrLast = now
	dialErrMu.Unlock()
	if skipped > 0 {
		log.Printf("udp forward dial %s err: %v (+%d suppressed)", dstAddr, err, skipped)
	} else {
		log.Printf("udp forward dial %s err: %v", dstAddr, err)
	}
}

// buildUDPv4Packet 构造 IPv4+UDP 原始包（src/dst 已是响应方向），写回 TUN 设备。
func buildUDPv4Packet(srcIP, dstIP tcpip.Address, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := uint16(header.UDPMinimumSize + len(payload))
	totalLen := header.IPv4MinimumSize + int(udpLen)
	pkt := make([]byte, totalLen)

	// IPv4 header
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcIP,
		DstAddr:     dstIP,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// UDP header + payload
	udp := header.UDP(pkt[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  udpLen,
	})
	copy(pkt[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	// UDP checksum: 伪头 + UDP header(checksum=0) + payload
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, udpLen)
	xsum = checksum.Checksum(pkt[header.IPv4MinimumSize:], xsum)
	udp.SetChecksum(^xsum)

	return pkt
}

// handleDNS 处理 DNS 查询拦截。
// 如果查询的域名在 hosts 配置中匹配到 ip 映射，构造 DNS 响应写回 TUN 设备并返回 true。
// 如果匹配到 deny 规则，返回 NXDOMAIN。
// 未匹配则返回 false，走正常 UDP 转发。
func (f *udpForwarder) handleDNS(payload []byte, srcIP, dstIP tcpip.Address, srcPort, dstPort uint16) bool {
	domain, qtype := parseDNSQuery(payload)
	if domain == "" {
		return false
	}

	hostIP, deny, matched := matchHostDNS(domain)
	if !matched {
		return false
	}

	var dnsResp []byte
	switch {
	case deny:
		dnsResp = buildDNSNXDomain(payload)
		log.Printf("dns hijack NXDOMAIN: %s (deny)", domain)
	case hostIP != "" && qtype == dnsTypeA:
		// A 查询：返回配置的 IPv4
		dnsResp = buildDNSResponse(payload, domain, hostIP)
		log.Printf("dns hijack: %s -> %s", domain, hostIP)
		// 记录 ip->域名，供 TCP 预连接嗅探不到域名时还原真实域名
		cache.SniffName.Store(hostIP, domain, 10*time.Minute)
	case hostIP != "" && qtype == dnsTypeAAAA:
		// AAAA 查询：域名已配 IPv4，返回 NOERROR 空应答让浏览器回退到 A 记录，
		// 不能转发真实 DNS(内网域名会拿到 NXDOMAIN 污染整个解析导致访问失败)
		dnsResp = buildDNSEmpty(payload)
		log.Printf("dns hijack AAAA empty: %s", domain)
	default:
		// 匹配到规则但无 ip 映射(如 target=remote)，不拦截，走正常 DNS
		return false
	}

	if dnsResp == nil {
		return false
	}

	// 构造响应 IP+UDP 包，src/dst 互换
	respPkt := buildUDPv4Packet(dstIP, srcIP, dstPort, srcPort, dnsResp)
	if err := f.dev.WritePacket(respPkt); err != nil {
		log.Printf("dns hijack write err: %v", err)
	}
	return true
}
