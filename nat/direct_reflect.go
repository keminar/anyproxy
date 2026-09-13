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

// reflectorLogState 反射器日志的去重/限速表: key -> 上次记录时间。every == 0 表示
// "本进程只记一次"。没有它就只能全静默或全打印, 前者让客户端侧完全无从排查。
type reflectorLogState struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// reflectorLogMaxKeys 表大小上限。公网上的扫描流量不该把这张表撑爆; 满了就清空,
// 代价只是下一轮多记几条日志, 无害。
const reflectorLogMaxKeys = 4096

func (s *reflectorLogState) allow(key string, every time.Duration) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	if len(s.seen) > reflectorLogMaxKeys {
		s.seen = map[string]time.Time{}
	}
	if last, ok := s.seen[key]; ok && (every == 0 || now.Sub(last) < every) {
		return false
	}
	s.seen[key] = now
	return true
}

var reflectorLog reflectorLogState

// reflectorDeniedLogEvery 被拒/无法识别的包按来源限速记日志的间隔。
const reflectorDeniedLogEvery = 5 * time.Minute

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
		// SIGHUP 平滑重启时新旧进程会短暂重叠, 旧进程的反射器 socket 又没有像
		// grace.Server 的 TCP listener 那样传给新进程。此时第一次绑定必然得到
		// EADDRINUSE；若直接返回, 等旧进程退出后新进程也不会再监听这个端口，直连
		// 端点发现会一直坏到下一次重启。放到后台沿用 direct 入口的重试窗口，既等得
		// 到旧进程释放端口，也不阻塞 websocket 服务本身启动。
		log.Printf("nat direct reflector: listen udp :%s: %v; retrying for %s",
			port, err, directListenRetryWindow)
		go func() {
			var retryConn *net.UDPConn
			retryErr := bindRetry(func() error {
				var listenErr error
				retryConn, listenErr = net.ListenUDP("udp", addr)
				return listenErr
			})
			if retryErr != nil {
				log.Printf("nat direct reflector: listen udp :%s: %v (direct endpoint discovery unavailable)", port, retryErr)
				return
			}
			serveDirectReflector(retryConn)
		}()
		return
	}
	serveDirectReflector(conn)
}

// serveDirectReflector 在已经绑定好的 socket 上启动反射器读循环。把绑定和服务拆开，
// 让 SIGHUP 重叠期的后台重试成功后能走回与首次启动完全相同的路径。
func serveDirectReflector(conn *net.UDPConn) {
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
				// 不带 ANYPROXY-DIRECT-* magic 的包不属于本协议(扫描, 或用 `nc -u` 之类
				// 探活的)。静默丢弃会让人误判成"端口不通/服务没起"——包明明到了。限速记一行。
				if reflectorLog.allow("payload|"+from.IP.String(), reflectorDeniedLogEvery) {
					log.Printf("nat direct reflector: %d-byte packet from %s has no %s magic, ignored (generic UDP health checks cannot validate this endpoint; use a protocol probe)",
						n, from, verbWhoami)
				}
				continue
			}
			verb, nonce, _ := splitPacket(payload)
			if verb != verbWhoami {
				continue
			}
			// 与 websocket 接入、裸TCP转发入口同一套来源白名单。不做限制的话, 这里
			// 就成了一个人人可用的地址反射服务(响应比请求略大, 可被拿来做反射放大)。
			if !serverIPAllowed(from.IP.String()) {
				// 静默丢弃会让客户端只看到"反射器没回包"——与"反射器没起""本机 UDP 被拦"
				// 完全同形, 无从区分。限速记一行, 服务端日志即可自证"包到了, 是被白名单拒的"。
				if reflectorLog.allow("denied|"+from.IP.String(), reflectorDeniedLogEvery) {
					log.Printf("nat direct reflector: whoami from %s dropped — %s is not allowed by websocket.server.allowIP",
						from, from.IP.String())
				}
				continue
			}
			// 回包也要带 magic: 对端是用 QUIC 的那个 socket 收的, 不带前缀会被
			// quic-go 当成 QUIC 报文丢掉。nonce 原样带回供对端关联。
			reply := directPacket(fmt.Sprintf("%s %s %s", verbSeen, nonce, from.String()))
			if _, err := conn.WriteToUDP(reply, from); err != nil {
				log.Printf("nat direct reflector reply to %s: %v", from, err)
				continue
			}
			// 成功回包按来源限速记(见 reflectorDeniedLogEvery): 全记会刷屏, 全不记则客户端报
			// "反射器没回包"时分不清是服务端没答还是回包在路上丢了。
			// 注意**不能用"本进程只记一次"**: 同一台机器重试时就不再出这行, 而排查清单恰恰
			// 把"完全没有 whoami 记录"判成"包没到"——那会给出错误结论。限速版在窗口内始终
			// 如实反映"答复过"。
			if reflectorLog.allow("answered|"+from.IP.String(), reflectorDeniedLogEvery) {
				log.Printf("nat direct reflector: whoami from %s answered with %s", from, reply)
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
// UDP)。两个都要: 订阅方要分别问出自己在两个地址族下的端点。
//
// 常见的坑: `connect` 填的是**字面量 IP**(比如 `[2001:db8::1]:3002`)时, 只有那一族
// 能解出来 —— 字面量 IPv6 地址天然不可能解出 IPv4, 反之亦然, 这跟网络通不通无关,
// 纯语法层面就注定了。真要两族都探到, `connect` 得填一个**同时有 A 和 AAAA 记录的
// 域名**, 让 DNS 分别给出两族地址; 服务端本身有没有对应的地址族监听是另一回事,
// 这里只负责"推出地址", 通不通交给后面的探测去回答。
//
// v4Err/v6Err 是各自那族解析失败的原因(某族成功时另一族的错误依然要报出来, 不能被
// "反正有一族成功了"盖过去 —— 不然"为什么没有 IPv4 候选"这种问题永远查不到)。
func reflectorAddrs(wsConnect string) (v4, v6 *net.UDPAddr, v4Err, v6Err error) {
	host, port, err := net.SplitHostPort(wsConnect)
	if err != nil {
		err = fmt.Errorf("bad websocket connect address %s: %w", wsConnect, err)
		return nil, nil, err, err
	}
	joined := net.JoinHostPort(host, port)
	v4, v4Err = net.ResolveUDPAddr("udp4", joined)
	v6, v6Err = net.ResolveUDPAddr("udp6", joined)
	return v4, v6, v4Err, v6Err
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
//	反射器 IPv4 端点 / 反射器 IPv6 端点 / 端口映射(UPnP·PCP)
//
// 不收本机接口地址: 那一类候选只在"两台机器同网段"时才有用, 而这里面向的场景是
// 跨网(两台机器分处不同网络, 中间要么隔着运营商 NAT/CGNAT, 要么就是真正的公网),
// 同网段直连不是要解决的问题, 报出去只会占服务端候选上限的名额、干扰排查。真到了
// 需要同网段优化的时候再加回来。
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

	v4, v6, v4Err, v6Err := reflectorAddrs(d.cfg.Connect)
	// 每一族解析失败都要单独报出来, 不能因为另一族成功了就吞掉——"为什么没有 v4
	// 候选"这种问题, 答案往往就是这里没打出来的一行 fail。
	if v4 == nil && v4Err != nil {
		fail(candSrcReflectV4+" address", v4Err)
	}
	if v6 == nil && v6Err != nil {
		fail(candSrcReflectV6+" address", v6Err)
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

	// 端口映射不依赖反射器, 一起并行。默认关闭(见 conf.DirectSettings.Portmap): 命中率低
	// 又要等三个协议的超时, 多数机器上只是白等一两秒。
	if d.cfg.Direct.Portmap {
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
	}

	// 用户手工配置的局域网地址(websocket.client.direct.lanAddrs), 不用探测, 直接拼上
	// 本机当前 QUIC 端口就是一条候选——不做网卡扫描(见 conf.DirectSettings.LanAddrs
	// 的注释)。
	for _, ip := range d.cfg.Direct.LanAddrs {
		if net.ParseIP(ip) == nil {
			fail(candSrcLocal, fmt.Errorf("%q is not a valid IP literal", ip))
			continue
		}
		add(directCandidate{Addr: net.JoinHostPort(ip, fmt.Sprintf("%d", port)), Source: candSrcLocal})
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
func (d *directPeer) punchAll(token string, cands []directCandidate) []candidateResult {
	return d.punchAllThen(token, cands, nil)
}

// punchAllThen 同 punchAll; afterFirst 非空时, 在**第一个打洞包确实从本机发出去之后**回调
// 一次(只调一次, 由这里的 once 保证)。
//
// 中继腿需要它: 居民必须"先发包、再经 B 通知 VPS", 顺序不能靠 goroutine 调度去赌——回调
// 打在 WriteTo 成功返回之后, nudge 才发出去, 顺序是硬保证的(见 direct_entry.go 与
// direct_accept.go 的 sendRelayNudge)。
func (d *directPeer) punchAllThen(token string, cands []directCandidate, afterFirst func()) []candidateResult {
	var once sync.Once
	fire := func() {
		if afterFirst != nil {
			once.Do(afterFirst)
		}
	}
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
			rtt, err := d.punchOneThen(tr, token, addr, fire)
			results[i].RTT, results[i].Err = rtt, err
		}(i, addr)
	}
	wg.Wait()
	return results
}

// punchOnly 朝所有候选各连发几个打洞包, 不等回执。C 侧用: 它不需要知道哪条更快(择优
// 由 A 做), 只需要把每条路上的返回通道开出来。等回执会白白拖住给 A 的应答近一秒。
//
// 只发 directPunchCount 个就够, 不必持续打: 打洞在本机 NAT/安全组上开出的表项是有状态
// 的映射, 一旦建立能存活数十秒(CGNAT)乃至更久, A 随后的 QUIC Initial 到达时洞仍在。
// 真正决定成败的是**顺序**——必须让受限 CGNAT 侧先发第一个包, 见 docs/direct-punch-order.md
// 与 direct_accept.go 的 onPunch(order Y 时本侧会等对端 nudge 再调本函数)。
func (d *directPeer) punchOnly(token string, cands []directCandidate) {
	d.punchOnlyThen(token, cands, nil)
}

// punchOnlyThen 同 punchOnly; afterFirst 在**第一个包确实发出去之后**回调一次(once 保证),
// 用于中继腿"先打洞、后经 B 发 nudge"的严格顺序(见 direct_accept.go 的 Relay 分支)。
func (d *directPeer) punchOnlyThen(token string, cands []directCandidate, afterFirst func()) {
	tr, err := d.ensureTransport()
	if err != nil {
		d.logf("punch: no transport: %v", err)
		return
	}
	var once sync.Once
	fire := func() {
		if afterFirst != nil {
			once.Do(afterFirst)
		}
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
				// 它明确禁止的用法。encodeDirectPacket 按 token 是否配了加密会话决定
				// 加密还是走现有的明文 magic 前缀。
				if _, err := tr.WriteTo(d.encodeDirectPacket(token, verbPunch+" "+newNonce()), addr); err != nil {
					// 发不出去多半是本机根本没有那一族的地址, 重试无益。
					d.logf("punch to %s failed: %v", c, err)
					return
				}
				fire() // 包确实出去了, 回调只生效一次
				time.Sleep(directPunchGap)
			}
		}(addr, c)
	}
}

// punchOne 朝一个候选连发几个打洞包, 收到任一 pong 即认为这条通, 返回 RTT。
//
// 连发而不是只发一个: UDP 会丢包, 而且对端可能还没起好监听 —— 头一两个包打空是常态。
// 等待用**总预算**而不是逐包短窗: pong 要走完整条链路的往返, 按 150ms/包做窗口的话,
// RTT>150ms 的链路(跨省/跨境的常态)上每个 pong 都会迟到几毫秒, 打洞永远失败。
func (d *directPeer) punchOne(tr *quic.Transport, token string, addr *net.UDPAddr) (time.Duration, error) {
	return d.punchOneThen(tr, token, addr, nil)
}

// punchOneThen 同 punchOne; afterFirst 在第一个包发送成功后立即回调(调用方负责 once)。
func (d *directPeer) punchOneThen(tr *quic.Transport, token string, addr *net.UDPAddr, afterFirst func()) (time.Duration, error) {
	deadline := time.Now().Add(directPunchWait)
	replies := make(chan probeReply, directPunchCount)

	for i := 0; i < directPunchCount; i++ {
		nonce := newNonce()
		ch, done := d.addWaiter(nonce)
		if _, err := tr.WriteTo(d.encodeDirectPacket(token, verbPunch+" "+nonce), addr); err != nil {
			done()
			// 发不出去多半是路由层面就不通(如本机没有 IPv6 却有 IPv6 候选), 重试无益。
			return 0, fmt.Errorf("send punch: %w", err)
		}
		if afterFirst != nil {
			afterFirst()
		}
		// 每一发的等待者都保持登记到总预算结束: 这一发的 pong 可能"迟到"几毫秒,
		// 也可能被前面的突发丢包拖到几百毫秒后 —— 都算数。goroutine 自己收尾,
		// 最长再活 directPunchWait, 不阻塞本函数返回。
		go func(ch chan probeReply, done func()) {
			select {
			case r := <-ch:
				done()
				replies <- r
			case <-time.After(directPunchWait):
				done()
			}
		}(ch, done)

		// pacing: 距下一发留 directPunchGap, 但给剩余各发留足预算, 不越过总期限。
		if sleep := min(directPunchGap, time.Until(deadline)-time.Duration(directPunchCount-1-i)*directPunchGap); sleep > 0 {
			select {
			case r := <-replies: // pacing 期间 pong 到了, 提前收工
				return r.rtt, nil
			case <-time.After(sleep):
			}
		} else {
			break // 预算只够等回包, 不够再发新的了
		}
	}

	select {
	case r := <-replies:
		return r.rtt, nil
	case <-time.After(time.Until(deadline)):
		return 0, errors.New("no answer")
	}
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
		raw := buf[:n]
		from := ""
		if addr != nil {
			from = addr.String()
		}

		var payload, token string
		var encrypted bool
		switch {
		case len(raw) > 0 && raw[0] == directPacketMagic:
			p, ok := directPayload(raw)
			if !ok {
				continue // 不是我们的包
			}
			payload = p
		case len(raw) > 0 && raw[0] == directCryptedMagic:
			tok, ok := peekDirectToken(raw)
			if !ok {
				d.logf("dropped malformed encrypted control packet from %s (too short to contain a token)", from)
				continue
			}
			sess, ok := d.crypto.get(tok)
			if !ok {
				// 最常见的两个原因: 对端配了 encrypt 但本机没在 receive.allow 里配对方
				// 的 uuid(或反过来), 或者会话已经过了 directCryptoSessionTTL——两者都
				// 值得打成日志, 不能静默丢掉让人误以为是网络问题。
				d.logf("dropped encrypted control packet from %s: unknown or expired session token %s "+
					"(peer uuid not configured in receive.allow? or session already timed out?)", from, shortToken(tok))
				continue
			}
			pt, err := openDirectPacket(sess, raw)
			if err != nil {
				d.logf("dropped encrypted control packet from %s: %v", from, err)
				continue
			}
			payload, token = pt, tok
			encrypted = true
		default:
			continue // 既不是明文也不是加密的我们的包
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
			// 这行日志是排查"punch 无应答"的关键证据: 有它说明包穿过了 quic-go 的
			// 过滤与 magic 校验; 没有它说明包根本没到本进程, 或者被当噪音丢了。
			d.logf("got punch from %s (encrypted=%v), replying pong", from, encrypted)
			if addr != nil {
				// 回包格式跟随收到包的格式: token=="" 时(收到的是明文) encodeDirectPacket
				// 会自动退回明文, 不会给一个不认识加密协议的旧版对端回一个它解不了的包。
				pkt := d.encodeDirectPacket(token, verbPong+" "+nonce)
				if _, err := tr.WriteTo(pkt, addr); err != nil {
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
