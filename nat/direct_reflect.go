package nat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

// 直连用的 UDP 反射器与探测协议。
//
// 为什么非要有反射器: websocket 是 TCP, 服务端从这条连接上看到的源地址是订阅方**TCP
// socket** 的地址; 而 QUIC 走的是另一个 UDP socket。一台机器常同时持有多个地址(IPv6
// 的稳定地址 + 会轮换的隐私临时地址, 或多张网卡), 内核按 RFC 6724 **按目的地分别选源**
// —— 去 B 的 TCP 用哪个地址, 不代表去 A 的 UDP 也用同一个; 外网端口同理由沿途 NAT 决定。
//
// 所以端点只能由订阅方**用 QUIC 那个 socket 本身**去问反射器要。这跟
// examples/nat-punch 的结论是同一条: 本机自报的地址不可靠, 只有对端观测到的才作数。
//
// 报文都带一个 nonce, 因为现在是**多条路并行探测**: 同一时刻可能有 v4 反射器、v6
// 反射器、以及若干个对端候选的探测同时在飞, 光靠来源地址区分不开(对端的多个候选可能
// 共用一个地址), 回包也未必按发出顺序回来。

const (
	// directPacketMagic 是我们自己那些非 QUIC 报文(探测/回包/打洞包)的首字节。
	//
	// 不能随便取值: 这些包与 QUIC 报文共用同一个 socket, quic-go 只把**首字节前两位
	// 都为 0**(即 <= 0x3F)的报文交给 ReadNonQUICPacket, 其余一律按 QUIC 报文处理并丢弃。
	// 直接用 "WHOAMI"/"PUNCH" 这类可见字符开头('W'=0x57, 'a'=0x61)第二位是 1, 会被
	// quic-go 吞掉, 探测永远收不到回包。
	directPacketMagic = 0x00

	// 报文动词。格式统一为 "<verb> <nonce>[ <参数>]"。
	verbWhoami = "ANYPROXY-DIRECT-WHOAMI" //-> 反射器: 我在你眼里是什么地址
	verbSeen   = "ANYPROXY-DIRECT-SEEN"   //<- 反射器: nonce + 观测到的端点
	verbPunch  = "ANYPROXY-DIRECT-PUNCH"  //-> 对端: 打洞, 同时兼作 RTT 探测的 ping
	verbPong   = "ANYPROXY-DIRECT-PONG"   //<- 对端: 打洞包的回执

	// directProbeWait 单次探测等待回包的上限。
	directProbeWait = 3 * time.Second
	// directProbeTries 探测重试次数: UDP 会丢包, 一次没回不代表对端不可达。
	directProbeTries = 3
)

// directPacket 给自定义报文加上 magic 前缀。
func directPacket(payload string) []byte {
	b := make([]byte, 0, len(payload)+1)
	b = append(b, directPacketMagic)
	return append(b, payload...)
}

// directPayload 剥掉 magic 前缀; 不是我们的包则返回 false。
func directPayload(b []byte) (string, bool) {
	if len(b) < 1 || b[0] != directPacketMagic {
		return "", false
	}
	return string(b[1:]), true
}

// newNonce 生成一次探测的关联号。
func newNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 退化到时间戳: nonce 只用于同一进程内关联并发的探测, 不承担安全职责。
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// StartDirectReflector 在服务端起 UDP 反射器。绑在与 websocket 相同的端口号上
// (TCP/UDP 互不冲突), 订阅方据此可直接从 websocket 的连接地址推出反射器地址, 不用额外配置。
//
// 绑双栈通配地址, 两个地址族都答: 订阅方要同时问出自己的 IPv4 与 IPv6 端点, 才能把
// 两条路都作为候选拿去竞争。
func StartDirectReflector(wsListen string) {
	_, port, err := net.SplitHostPort(wsListen)
	if err != nil {
		log.Printf("nat direct reflector: bad websocket listen address %s: %v", wsListen, err)
		return
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("", port))
	if err != nil {
		log.Printf("nat direct reflector: resolve :%s: %v", port, err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("nat direct reflector: listen udp :%s: %v (direct endpoint discovery unavailable)", port, err)
		return
	}
	log.Printf("nat direct reflector listening on udp %s", conn.LocalAddr())
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("nat direct reflector read: %v", err)
				return
			}
			payload, ok := directPayload(buf[:n])
			if !ok {
				continue
			}
			verb, nonce, _ := splitPacket(payload)
			if verb != verbWhoami {
				continue
			}
			// 与 websocket 接入、裸TCP转发入口同一套来源白名单。不做限制的话, 这里
			// 就成了一个人人可用的地址反射服务(响应比请求略大, 可被拿来做反射放大)。
			if !serverIPAllowed(from.IP.String()) {
				continue
			}
			// 回包也要带 magic: 对端是用 QUIC 的那个 socket 收的, 不带前缀会被
			// quic-go 当成 QUIC 报文丢掉。nonce 原样带回供对端关联。
			reply := directPacket(fmt.Sprintf("%s %s %s", verbSeen, nonce, from.String()))
			if _, err := conn.WriteToUDP(reply, from); err != nil {
				log.Printf("nat direct reflector reply to %s: %v", from, err)
			}
		}
	}()
}

// splitPacket 拆 "<verb> <nonce> <参数>"。缺字段的返回空串, 由调用方判断。
func splitPacket(payload string) (verb, nonce, arg string) {
	parts := strings.SplitN(payload, " ", 3)
	switch len(parts) {
	case 3:
		return parts[0], parts[1], parts[2]
	case 2:
		return parts[0], parts[1], ""
	case 1:
		return parts[0], "", ""
	}
	return "", "", ""
}

// reflectorAddrs 由 websocket 的连接地址推出反射器的 IPv4 与 IPv6 地址(同主机、同端口号、
// UDP)。两个都要: 订阅方要分别问出自己在两个地址族下的端点。任一族解析不出就返回 nil,
// 不算错误 —— 那只说明这台机器(或服务端)没有那一族的地址, 少一个候选而已。
func reflectorAddrs(wsConnect string) (v4, v6 *net.UDPAddr, err error) {
	host, port, err := net.SplitHostPort(wsConnect)
	if err != nil {
		return nil, nil, fmt.Errorf("bad websocket connect address %s: %w", wsConnect, err)
	}
	joined := net.JoinHostPort(host, port)
	if a, e := net.ResolveUDPAddr("udp4", joined); e == nil {
		v4 = a
	}
	if a, e := net.ResolveUDPAddr("udp6", joined); e == nil {
		v6 = a
	}
	if v4 == nil && v6 == nil {
		return nil, nil, fmt.Errorf("cannot resolve %s as a udp address", wsConnect)
	}
	return v4, v6, nil
}

// probeReply 一次探测的回包。
type probeReply struct {
	endpoint string        //whoami 时为反射器观测到的端点; pong 时为空
	from     string        //回包来源
	rtt      time.Duration //从发出到收到
}

// probeWaiter 一次在飞的探测。
type probeWaiter struct {
	ch   chan probeReply
	sent time.Time
}

// addWaiter 登记一个等待者, 返回注销函数。
func (d *directPeer) addWaiter(nonce string) (chan probeReply, func()) {
	ch := make(chan probeReply, 1)
	d.probeMu.Lock()
	if d.waiters == nil {
		d.waiters = map[string]*probeWaiter{}
	}
	d.waiters[nonce] = &probeWaiter{ch: ch, sent: time.Now()}
	d.probeMu.Unlock()
	return ch, func() {
		d.probeMu.Lock()
		delete(d.waiters, nonce)
		d.probeMu.Unlock()
	}
}

// deliver 把回包交给对应的等待者。找不到就丢弃(多半是已经超时退出了)。
func (d *directPeer) deliver(nonce, endpoint, from string) bool {
	d.probeMu.Lock()
	w := d.waiters[nonce]
	d.probeMu.Unlock()
	if w == nil {
		return false
	}
	select {
	case w.ch <- probeReply{endpoint: endpoint, from: from, rtt: time.Since(w.sent)}:
	default:
	}
	return true
}

// deliverLegacy 兼容旧版反射器: 它回的是裸的 "host:port", 没有 verb 也没有 nonce。
// 只有当前恰好只有一个在飞的探测时才认, 多个并发时无从关联, 宁可让它超时。
func (d *directPeer) deliverLegacy(endpoint, from string) bool {
	d.probeMu.Lock()
	if len(d.waiters) != 1 {
		d.probeMu.Unlock()
		return false
	}
	var w *probeWaiter
	for _, v := range d.waiters {
		w = v
	}
	d.probeMu.Unlock()
	select {
	case w.ch <- probeReply{endpoint: endpoint, from: from, rtt: time.Since(w.sent)}:
	default:
	}
	return true
}

// probeReflector 用 QUIC 那个 socket 去问反射器"我在你眼里是什么地址"。必须用同一个
// socket: 换个 socket 问出来的端口就不是 QUIC 实际用的那个了。
func (d *directPeer) probeReflector(raddr *net.UDPAddr) (string, error) {
	tr, err := d.ensureTransport()
	if err != nil {
		return "", err
	}
	var lastErr error
	for i := 0; i < directProbeTries; i++ {
		nonce := newNonce()
		ch, done := d.addWaiter(nonce)
		if _, err := tr.WriteTo(directPacket(verbWhoami+" "+nonce), raddr); err != nil {
			done()
			lastErr = fmt.Errorf("send probe to %s: %w", raddr, err)
			continue
		}
		select {
		case r := <-ch:
			done()
			return r.endpoint, nil
		case <-time.After(directProbeWait):
			done()
			lastErr = fmt.Errorf("no reply from reflector %s", raddr)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("endpoint probe failed")
	}
	return "", lastErr
}

// gatherCandidates 收集本机的全部候选端点, **并行**探测:
//
//	反射器 IPv4 端点 / 反射器 IPv6 端点 / 端口映射(UPnP·PCP) / 本机接口地址
//
// 任何一路失败都只是少一个候选, 不影响其它路 —— 这正是多候选的意义: 以前只探 IPv6,
// 探不到整条直连就废了。全部失败才算失败。
func (d *directPeer) gatherCandidates() ([]directCandidate, error) {
	if _, err := d.ensureTransport(); err != nil {
		return nil, err
	}
	port := d.localUDPPort()

	var (
		mu    sync.Mutex
		cands []directCandidate
		fails []string
		wg    sync.WaitGroup
	)
	add := func(c directCandidate) {
		mu.Lock()
		cands = append(cands, c)
		mu.Unlock()
	}
	fail := func(what string, err error) {
		mu.Lock()
		fails = append(fails, fmt.Sprintf("%s: %v", what, err))
		mu.Unlock()
	}

	v4, v6, err := reflectorAddrs(d.cfg.Connect)
	if err != nil {
		fail("reflector address", err)
	}
	for _, r := range []struct {
		addr *net.UDPAddr
		src  string
	}{{v4, candSrcReflectV4}, {v6, candSrcReflectV6}} {
		if r.addr == nil {
			continue
		}
		wg.Add(1)
		go func(addr *net.UDPAddr, src string) {
			defer wg.Done()
			ep, err := d.probeReflector(addr)
			if err != nil {
				fail(src, err)
				return
			}
			add(directCandidate{Addr: ep, Source: src})
		}(r.addr, r.src)
	}

	// 端口映射与本机接口地址都不依赖反射器, 一起并行。
	wg.Add(1)
	go func() {
		defer wg.Done()
		ep, err := mapPort(port)
		if err != nil {
			fail(candSrcPortmap, err)
			return
		}
		add(directCandidate{Addr: ep, Source: candSrcPortmap})
	}()

	for _, c := range localCandidates(int(port)) {
		add(c)
	}

	wg.Wait()
	cands = dedupCandidates(cands)
	if len(cands) == 0 {
		return nil, fmt.Errorf("no usable local endpoint (%s)", strings.Join(fails, "; "))
	}
	if len(fails) > 0 {
		// 有候选就继续, 但把没成的那几路记下来: "IPv6 那路一直不出候选"这种事只有
		// 在日志里看得见才查得动。
		d.logf("candidates %v (unavailable: %s)", cands, strings.Join(fails, "; "))
	} else {
		d.logf("candidates %v", cands)
	}
	return cands, nil
}

// punchAll 朝对端的**所有**候选同时打洞, 并按回执测 RTT。
//
// 打洞与测速是同一个动作: 发出去的包在本机这侧的有状态防火墙/NAT 上开出返回通道
// (IPv6 没有 NAT 但家用路由器默认拦主动入站, 同样需要), 对端收到后回一个 pong,
// 这一来一回就是这条路的 RTT。
//
// 不串行逐条试: 串行的话前面几条不通就要各等一个超时, 等到能用的那条时入口连接早
// 超时了。并行发出去, 谁先回谁先被观测到。
func (d *directPeer) punchAll(cands []directCandidate) []candidateResult {
	tr, err := d.ensureTransport()
	if err != nil {
		out := make([]candidateResult, 0, len(cands))
		for _, c := range cands {
			out = append(out, candidateResult{Cand: c, Err: err})
		}
		return out
	}

	results := make([]candidateResult, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		results[i].Cand = c
		addr, err := net.ResolveUDPAddr("udp", c.Addr)
		if err != nil {
			results[i].Err = fmt.Errorf("bad address: %w", err)
			continue
		}
		wg.Add(1)
		go func(i int, addr *net.UDPAddr) {
			defer wg.Done()
			rtt, err := d.punchOne(tr, addr)
			results[i].RTT, results[i].Err = rtt, err
		}(i, addr)
	}
	wg.Wait()
	return results
}

// punchOnly 朝所有候选打洞但不等回执。C 侧用: 它不需要知道哪条更快(择优由 A 做),
// 只需要把每条路上的返回通道开出来。等回执会白白拖住给 A 的应答近一秒。
func (d *directPeer) punchOnly(cands []directCandidate) {
	tr, err := d.ensureTransport()
	if err != nil {
		d.logf("punch: no transport: %v", err)
		return
	}
	for _, c := range cands {
		addr, err := net.ResolveUDPAddr("udp", c.Addr)
		if err != nil {
			d.logf("punch: bad candidate %s: %v", c, err)
			continue
		}
		go func(addr *net.UDPAddr, c directCandidate) {
			for i := 0; i < directPunchCount; i++ {
				// 经 Transport 发: 这个 socket 已经交给 quic-go 了, 直接 WriteToUDP 是
				// 它明确禁止的用法。带 magic 前缀, 对端才能从 ReadNonQUICPacket 收到。
				if _, err := tr.WriteTo(directPacket(verbPunch+" "+newNonce()), addr); err != nil {
					// 发不出去多半是本机根本没有那一族的地址, 重试无益。
					d.logf("punch to %s failed: %v", c, err)
					return
				}
				time.Sleep(directPunchGap)
			}
		}(addr, c)
	}
}

// punchOne 朝一个候选连发几个打洞包, 收到 pong 即认为这条通, 返回 RTT。
//
// 连发而不是只发一个: UDP 会丢包, 而且对端可能还没起好监听 —— 头一两个包打空是常态。
func (d *directPeer) punchOne(tr *quic.Transport, addr *net.UDPAddr) (time.Duration, error) {
	var lastErr error
	for i := 0; i < directPunchCount; i++ {
		nonce := newNonce()
		ch, done := d.addWaiter(nonce)
		if _, err := tr.WriteTo(directPacket(verbPunch+" "+nonce), addr); err != nil {
			done()
			// 发不出去多半是路由层面就不通(如本机没有 IPv6 却有 IPv6 候选), 重试无益。
			return 0, fmt.Errorf("send punch: %w", err)
		}
		select {
		case r := <-ch:
			done()
			return r.rtt, nil
		case <-time.After(directPunchGap):
			done()
			lastErr = errors.New("no answer")
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no answer")
	}
	return 0, lastErr
}

// drainNonQUIC 收 QUIC socket 上的非 QUIC 报文并分发。不读的话这些包会一直堆在
// quic-go 的内部队列里。
func (d *directPeer) drainNonQUIC(tr *quic.Transport) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := tr.ReadNonQUICPacket(context.Background(), buf)
		if err != nil {
			return
		}
		payload, ok := directPayload(buf[:n])
		if !ok {
			continue // 不是我们的包
		}
		from := ""
		if addr != nil {
			from = addr.String()
		}
		verb, nonce, arg := splitPacket(payload)
		switch verb {
		case verbSeen:
			if looksLikeEndpoint(arg) {
				d.deliver(nonce, arg, from)
			}
		case verbPong:
			d.deliver(nonce, "", from)
		case verbPunch:
			// 对端在朝我们打洞。回一个 pong: 对它而言这既是"这条路通了"的确认, 也是
			// 它测这条路 RTT 的依据。我们自己也顺带知道对端确实发过包了。
			if addr != nil {
				if _, err := tr.WriteTo(directPacket(verbPong+" "+nonce), addr); err != nil {
					d.logf("pong to %s failed: %v", from, err)
				}
			}
		default:
			// 旧版反射器回的是裸 "host:port"。
			if looksLikeEndpoint(payload) {
				d.deliverLegacy(payload, from)
			}
		}
	}
}

// looksLikeEndpoint 粗筛端点串: 必须能拆成 host:port。
func looksLikeEndpoint(s string) bool {
	if len(s) == 0 || len(s) > 128 || strings.Contains(s, " ") {
		return false
	}
	_, _, err := net.SplitHostPort(s)
	return err == nil
}
