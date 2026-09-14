package nat

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// VPS 盲转发中继(directRelay)。一台公网 VPS 在 A、C 两个居民之间做传输层盲转发:
//
//   - 每一对 A-C(以一次会话的 token 为标识)开一个**专用 UDP socket**;
//   - 用这个 socket 问反射器探到自己的公网中继端点 E, 经 B 报给 A 和 C;
//   - A、C 都朝 E 打洞(各自是居民、先打), VPS 收到 B 转来的两腿候选后朝它们打回去开洞;
//   - 之后在 A、C 两个来源地址之间**盲转发**不透明 UDP 包。
//
// QUIC/TLS 连接是 A<->C 端到端的, VPS 不终结 TLS、不解 QUIC, 全程看不到明文(见
// docs/direct-relay-design.md)。所以这里没有任何"数据解析", 只有"按来源地址对转"。
//
// 与 direct_accept.go 的 C 侧 QUIC 监听是两码事: 那边 VPS(若同时开 directAccept)用共享
// 的 quic.Transport 收 QUIC; 这里每对中继各用一个独立的裸 *net.UDPConn, 互不相干。

// relayBinding 一对 A-C 的中继绑定。持有专用 socket, 记住两腿(A、C)各自的候选与学到的
// 实际地址, 在两者之间盲转发。
type relayBinding struct {
	peer      *directPeer
	token     string
	conn      *net.UDPConn
	endpoints []string // 报给 B 的中继端点 E(可能 v4/v6 各一条, 同一个 socket)

	mu          sync.Mutex
	legs        map[string]*relayLeg // 居民 email -> 腿
	nudgedEarly map[string]bool      // 腿还没登记就先到的 nudge(email), 登记时立即触发

	lastUse   atomic.Int64 // unix nano, 最近一次转发流量
	closeOnce sync.Once
	done      chan struct{}
}

// relayLeg 中继的一条腿(A 或 C 一侧)。
type relayLeg struct {
	email     string
	candIPs   map[string]bool // 允许的来源 IP(注入防护: 只在两腿的候选 IP 之间对转)
	candAddrs []*net.UDPAddr  // B 告知的候选, VPS 朝它们打洞、并作为学到实际地址前的初始转发目标
	addr      atomic.Pointer[net.UDPAddr]
	fire      chan struct{} // 收到本腿 nudge(居民已先打)后关闭, 触发 VPS 朝本腿打洞
	once      sync.Once
}

// touch 刷新最近使用时间。
func (rb *relayBinding) touch() { rb.lastUse.Store(time.Now().UnixNano()) }

func (rb *relayBinding) idleFor() time.Duration {
	return time.Since(time.Unix(0, rb.lastUse.Load()))
}

// hasRelay 本机是否已为该 token 开好中继绑定(即本机是这次会话的 VPS 中继)。用于在
// onPunch/onPunching 里区分"我是 VPS 中继节点"和"我是被通知朝 E 打洞的居民 C"。
func (d *directPeer) hasRelay(token string) bool {
	d.relayMu.Lock()
	defer d.relayMu.Unlock()
	_, ok := d.relays[token]
	return ok
}

// onRelayOpen 处理 B 转来的 d_relay_open(VPS 侧): 开专用 socket、探中继端点 E, 用 d_ready
// 把 E 报回 B。VPS 记住 token->绑定, 之后按 d_punch(Relay=true)朝两腿打洞并盲转发。
func (d *directPeer) onRelayOpen(msg *Message) {
	reply := func(r DirectReady) {
		if err := d.send(METHOD_DIRECT_READY, msg.ID, r); err != nil {
			d.logf("relay: reply relay-open ready failed: %v", err)
		}
	}
	var open DirectRelayOpen
	if err := decodeDirect(msg.Body, &open); err != nil {
		d.logf("relay: bad relay-open: %v", err)
		reply(DirectReady{Err: "bad relay-open payload"})
		return
	}
	if open.Token == "" {
		reply(DirectReady{Err: "incomplete relay-open"})
		return
	}
	if !d.cfg.Direct.Relay {
		reply(DirectReady{Err: "directRelay is not enabled on this relay"})
		return
	}
	rb, err := d.openRelay(open.Token)
	if err != nil {
		d.logf("relay: open for token %s failed: %v", shortToken(open.Token), err)
		reply(DirectReady{Err: fmt.Sprintf("cannot open relay endpoint: %v", err)})
		return
	}
	d.logf("relay: opened binding for token %s, endpoint(s) %v", shortToken(open.Token), rb.endpoints)
	// 复用 d_ready 把 E 报回: 中继不终结 TLS, 无证书指纹(留空)。B 按这条 pending 是中继
	// 会话处理, 不校验指纹(见 direct_broker.go onReady)。
	reply(DirectReady{Candidates: candsFromAddrs(rb.endpoints), Endpoint: firstOf(rb.endpoints)})
}

// openRelay 建好某个 token 的中继绑定: 开专用 socket、探 E、起转发循环。已存在则复用。
func (d *directPeer) openRelay(token string) (*relayBinding, error) {
	d.relayMu.Lock()
	if rb, ok := d.relays[token]; ok {
		d.relayMu.Unlock()
		return rb, nil
	}
	d.relayMu.Unlock()

	conn, eps, err := d.newRelaySocket()
	if err != nil {
		return nil, err
	}
	// 中继要扛 A<->C 的全部数据吞吐, 收包缓冲给足, 免得在高 BDP 链路上收包侧丢包。
	if err := conn.SetReadBuffer(udpReadBufferSize); err != nil {
		d.logf("relay: set read buffer: %v", err)
	}
	rb := &relayBinding{
		peer:        d,
		token:       token,
		conn:        conn,
		endpoints:   eps,
		legs:        make(map[string]*relayLeg),
		nudgedEarly: make(map[string]bool),
		done:        make(chan struct{}),
	}
	rb.touch()

	d.relayMu.Lock()
	// 极小概率的并发 open: 别人先建好了就用它的, 关掉自己刚建的。
	if existing, ok := d.relays[token]; ok {
		d.relayMu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	d.relays[token] = rb
	d.relayMu.Unlock()

	go rb.forwardLoop()
	return rb, nil
}

// newRelaySocket 为一次中继绑定建好专用 UDP socket, 并给出报给 A、C 的公网端点 E。
//
// 两条路: 配了 DirectRelayPublic 就用静态端点、绑定到端点里的固定端口(见 newStaticRelaySocket);
// 否则开随机端口的 socket, 靠反射器探出口映射(默认, 适用 1:1 公网/EIM NAT)。
func (d *directPeer) newRelaySocket() (*net.UDPConn, []string, error) {
	if len(d.cfg.Direct.RelayPublic) > 0 {
		return d.newStaticRelaySocket()
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, nil, fmt.Errorf("listen relay udp: %w", err)
	}
	eps, err := d.gatherRelayEndpoints(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, eps, nil
}

// newStaticRelaySocket 用 DirectRelayPublic 配的静态端点建 socket: 跳过反射器, 把 socket 绑到
// 端点里的固定端口(DNAT/防火墙据此放行), 直接用配置端点当 E。一个端口一个 socket, 所以按
// 端口分组、挑一个当前空闲(能绑上)的端口用——都被占说明并发对数超过了配置的端点数。
func (d *directPeer) newStaticRelaySocket() (*net.UDPConn, []string, error) {
	byPort := make(map[int][]string)
	var order []int
	for _, ep := range d.cfg.Direct.RelayPublic {
		if err := checkDirectEndpoint(ep); err != nil {
			d.logf("relay: skip invalid directRelayPublic %q: %v", ep, err)
			continue
		}
		_, ps, _ := net.SplitHostPort(ep)
		port, err := strconv.Atoi(ps)
		if err != nil {
			d.logf("relay: skip directRelayPublic %q: bad port", ep)
			continue
		}
		if _, ok := byPort[port]; !ok {
			order = append(order, port)
		}
		byPort[port] = append(byPort[port], ep)
	}
	if len(order) == 0 {
		return nil, nil, errors.New("no valid directRelayPublic endpoint configured")
	}
	var tried []string
	for _, port := range order {
		// 绑固定端口: 已被别的中继绑定占着就换下一个配置端口(一个端口一对并发)。
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			tried = append(tried, fmt.Sprintf(":%d busy(%v)", port, err))
			continue
		}
		return conn, dedupStrings(byPort[port]), nil
	}
	return nil, nil, fmt.Errorf("all %d configured relay port(s) busy — add more directRelayPublic entries for more concurrent pairs (%s)",
		len(order), strings.Join(tried, "; "))
}

// gatherRelayEndpoints 用专用 socket 问反射器探到自己的公网中继端点(v4/v6 各试一次)。
// VPS 本地绑的地址通常不是公网地址(如腾讯云本地 10.x、公网 49.x), 只能靠反射器探。
func (d *directPeer) gatherRelayEndpoints(conn *net.UDPConn) ([]string, error) {
	v4, v6, v4Err, v6Err := reflectorAddrs(d.cfg.Connect)
	var (
		eps   []string
		fails []string
	)
	if v4 == nil && v4Err != nil {
		fails = append(fails, fmt.Sprintf("%s: %v", candSrcReflectV4, v4Err))
	}
	if v6 == nil && v6Err != nil {
		fails = append(fails, fmt.Sprintf("%s: %v", candSrcReflectV6, v6Err))
	}
	for _, r := range []*net.UDPAddr{v4, v6} {
		if r == nil {
			continue
		}
		ep, err := probeReflectorConn(conn, r)
		if err != nil {
			fails = append(fails, err.Error())
			continue
		}
		eps = append(eps, ep)
	}
	eps = dedupStrings(eps)
	if len(eps) == 0 {
		return nil, fmt.Errorf("no relay endpoint (%s)", strings.Join(fails, "; "))
	}
	return eps, nil
}

// probeReflectorConn 在一个裸 *net.UDPConn 上做一次 whoami 往返(同步), 问反射器"我在你
// 眼里是什么地址"。与 directPeer.probeReflector 的区别: 那个走已交给 quic-go 的共享 socket、
// 靠 drainNonQUIC 按 nonce 投递; 中继的专用 socket 没交给 quic-go, 直接 ReadFromUDP 即可。
func probeReflectorConn(conn *net.UDPConn, raddr *net.UDPAddr) (string, error) {
	var lastErr error
	for i := 0; i < directProbeTries; i++ {
		nonce := newNonce()
		if _, err := conn.WriteToUDP(directPacket(verbWhoami+" "+nonce), raddr); err != nil {
			lastErr = fmt.Errorf("send probe to %s: %w", raddr, err)
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(directProbeWait))
		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				lastErr = fmt.Errorf("no reply from reflector %s", raddr)
				break // 超时: 换下一次重试
			}
			payload, ok := directPayload(buf[:n])
			if !ok {
				continue
			}
			verb, gotNonce, arg := splitPacket(payload)
			if verb == verbSeen && gotNonce == nonce && looksLikeEndpoint(arg) {
				_ = conn.SetReadDeadline(time.Time{})
				return arg, nil
			}
			// 别的包(旧探测的迟到回包等): 继续读, 直到读到本次 nonce 或超时。
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if lastErr == nil {
		lastErr = fmt.Errorf("relay endpoint probe failed")
	}
	return "", lastErr
}

// registerRelayLeg VPS 收到 B 转来的 d_punch(Relay=true)时登记一条腿: 记下这条腿(A 或 C)
// 的候选, 停着一次朝它的打洞, 等这条腿的 nudge(居民已先打)再打(见 fireRelayLeg)。
func (d *directPeer) registerRelayLeg(token, email string, cands []directCandidate) {
	d.relayMu.Lock()
	rb := d.relays[token]
	d.relayMu.Unlock()
	if rb == nil {
		d.logf("relay: leg %s for unknown token %s (open not done yet or expired)", email, shortToken(token))
		return
	}
	leg := &relayLeg{
		email:   email,
		candIPs: make(map[string]bool),
		fire:    make(chan struct{}),
	}
	for _, c := range cands {
		host, _, err := net.SplitHostPort(c.Addr)
		if err != nil {
			continue
		}
		leg.candIPs[host] = true
		if addr, err := net.ResolveUDPAddr("udp", c.Addr); err == nil {
			leg.candAddrs = append(leg.candAddrs, addr)
		}
	}
	if len(leg.candAddrs) == 0 {
		d.logf("relay: leg %s has no usable candidate, ignoring", email)
		return
	}
	rb.mu.Lock()
	rb.legs[email] = leg
	early := rb.nudgedEarly[email]
	delete(rb.nudgedEarly, email)
	rb.mu.Unlock()
	rb.touch()
	if early {
		// nudge 比本腿的登记先到(B 把 C 的 nudge 转来时本腿还没登记): 补触发一次。
		leg.once.Do(func() { close(leg.fire) })
	}
	d.logf("relay: registered leg %s (token %s), holding punch until its nudge (or %s fallback)",
		email, shortToken(token), directPunchFirstDelay)

	// 停着等居民先打: 居民收到"朝 E 打洞"的指令后会先打并发 nudge; VPS 收到 nudge 才朝居民
	// 打回去(开自己安全组的返回通道)。nudge 丢了则兜底延迟到点也打。VPS 是公网侧, 顺序上
	// 必须后打, 否则会毒化居民的 CGNAT 映射(见 docs/direct-punch-order.md、direct-relay-design.md)。
	go func() {
		select {
		case <-leg.fire:
			d.logf("relay: got nudge for leg %s, punching toward it now", email)
		case <-time.After(directPunchFirstDelay):
			d.logf("relay: nudge for leg %s not received in %s, punching anyway (fallback)", email, directPunchFirstDelay)
		case <-rb.done:
			return
		}
		rb.punchLeg(leg)
	}()
}

// fireRelayLeg VPS 收到某条腿的 nudge(经 B 保留 email 转来)时, 触发那条腿停着的打洞。
func (d *directPeer) fireRelayLeg(token, email string) {
	d.relayMu.Lock()
	rb := d.relays[token]
	d.relayMu.Unlock()
	if rb == nil {
		return
	}
	rb.mu.Lock()
	leg := rb.legs[email]
	if leg == nil {
		// nudge 先于本腿的登记到达: 记下, 登记时补触发(见 registerRelayLeg)。
		rb.nudgedEarly[email] = true
		rb.mu.Unlock()
		return
	}
	rb.mu.Unlock()
	leg.once.Do(func() { close(leg.fire) })
}

// punchLeg 朝一条腿的所有候选各连发几个打洞包, 只为在 VPS 自己这侧的安全组/防火墙上开出
// 朝该居民的返回通道(居民的 CGNAT 洞它自己先打时已开)。内容无所谓, 用 verbPunch 形态便于
// 抓包辨认; 居民收到后即使回 pong, 被盲转发到对侧也只是对侧不认的 nonce, 丢弃即可。
func (rb *relayBinding) punchLeg(leg *relayLeg) {
	for _, addr := range leg.candAddrs {
		go func(addr *net.UDPAddr) {
			for i := 0; i < directPunchCount; i++ {
				select {
				case <-rb.done:
					return
				default:
				}
				if _, err := rb.conn.WriteToUDP(directPacket(verbPunch+" "+newNonce()), addr); err != nil {
					rb.peer.logf("relay: punch leg %s to %s failed: %v", leg.email, addr, err)
					return
				}
				time.Sleep(directPunchGap)
			}
		}(addr)
	}
}

// forwardLoop 中继的收发核心: 从专用 socket 收包, 按来源 IP 认出是哪条腿, 转给另一条腿的
// 学到地址。只在两腿的候选 IP 之间对转, 其它来源一律丢(注入防护)。
func (rb *relayBinding) forwardLoop() {
	d := rb.peer
	buf := make([]byte, 64*1024) // 单个 UDP 数据报上限, QUIC datagram/Initial 都在其内
	for {
		select {
		case <-rb.done:
			return
		default:
		}
		n, src, err := rb.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-rb.done:
			default:
				d.logf("relay: read on token %s stopped: %v", shortToken(rb.token), err)
			}
			return
		}
		from, to := rb.classify(src)
		if from == nil || to == nil {
			continue // 来源不属于任何一腿, 或对侧地址还没学到 —— 丢弃
		}
		from.addr.Store(src) // 学习/刷新本腿的实际地址(来源 IP 已通过校验)
		dst := to.addr.Load()
		if dst == nil {
			// 对侧实际地址还没学到, 先用它的候选兜底(通常与实际一致: 同一 socket 同一映射)。
			if len(to.candAddrs) > 0 {
				dst = to.candAddrs[0]
			} else {
				continue
			}
		}
		if _, err := rb.conn.WriteToUDP(buf[:n], dst); err != nil {
			d.logf("relay: forward %s->%s on token %s failed: %v", from.email, to.email, shortToken(rb.token), err)
			continue
		}
		rb.touch()
	}
}

// classify 按来源地址认出这是哪条腿(from)以及该转给哪条腿(to)。
//
// 先按**完整地址**(ip:port)精确命中: 支持 EIM/锥形 NAT 下"居民在 VPS 眼里的来源 == 反射器
// 观测到的候选"这一常态, 也能区分两腿恰好共用一个 IP 的情形(如同一 CGNAT 下、或测试里都在
// 回环)。精确不中再退到"唯一 IP 命中"兜底(端口偶有轻微漂移、但该 IP 只属于一条腿时)。都不中
// 就丢弃——注入防护: 只在两腿的候选之间对转。
func (rb *relayBinding) classify(src *net.UDPAddr) (from, to *relayLeg) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if len(rb.legs) < 2 {
		return nil, nil // 两腿都登记好才谈得上对转
	}
	srcStr := src.String()
	ip := src.IP.String()
	// 精确地址命中(候选地址, 或已学到的实际地址)。
	for _, leg := range rb.legs {
		if leg.matchesAddr(srcStr) {
			from = leg
			break
		}
	}
	// 兜底: 唯一 IP 命中(该 IP 只落在一条腿的候选里)。
	if from == nil {
		var hits []*relayLeg
		for _, leg := range rb.legs {
			if leg.candIPs[ip] {
				hits = append(hits, leg)
			}
		}
		if len(hits) == 1 {
			from = hits[0]
		}
	}
	if from == nil {
		return nil, nil
	}
	for _, leg := range rb.legs {
		if leg != from {
			to = leg
			break
		}
	}
	return from, to
}

// matchesAddr 该腿的候选地址或已学到的实际地址里是否有 addr(完整 ip:port 串比较)。
func (leg *relayLeg) matchesAddr(addr string) bool {
	for _, a := range leg.candAddrs {
		if a.String() == addr {
			return true
		}
	}
	if learned := leg.addr.Load(); learned != nil && learned.String() == addr {
		return true
	}
	return false
}

// closeRelay 关掉某个 token 的中继绑定并从表里摘除。
func (d *directPeer) closeRelay(token string) {
	d.relayMu.Lock()
	rb := d.relays[token]
	delete(d.relays, token)
	d.relayMu.Unlock()
	if rb != nil {
		rb.close()
	}
}

func (rb *relayBinding) close() {
	rb.closeOnce.Do(func() {
		close(rb.done)
		_ = rb.conn.Close()
	})
}

// reapRelay 周期回收空闲的中继绑定。A<->C 的 e2e QUIC 有 20s 保活, 活着的中继每 20s 有
// 包过、永不误判空闲; 只有 e2e QUIC 真死了才在 directRelayIdle 之后被回收。
func (d *directPeer) reapRelay() {
	t := time.NewTicker(directReapEvery)
	defer t.Stop()
	for range t.C {
		var stale []string
		d.relayMu.Lock()
		for token, rb := range d.relays {
			if rb.idleFor() > directRelayIdle {
				stale = append(stale, token)
			}
		}
		for _, token := range stale {
			rb := d.relays[token]
			delete(d.relays, token)
			go func(token string, rb *relayBinding) {
				d.logf("relay: closing idle binding token %s (idle %s)", shortToken(token), rb.idleFor().Round(time.Second))
				rb.close()
			}(token, rb)
		}
		d.relayMu.Unlock()
	}
}

// candsFromAddrs 把地址串包成候选(源标为反射器观测——中继端点本就是反射器探来的)。
func candsFromAddrs(addrs []string) []directCandidate {
	out := make([]directCandidate, 0, len(addrs))
	for _, a := range addrs {
		src := candSrcReflectV6
		if host, _, err := net.SplitHostPort(a); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				src = candSrcReflectV4
			}
		}
		out = append(out, directCandidate{Addr: a, Source: src})
	}
	return out
}

func firstOf(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
