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
//   - A、C 各自**先**朝 E 打洞(两条腿都是居民, 必须先发第一个包);
//   - 打完第一发后, 它们经 B 给 VPS 捎一个 nudge(d_punching, Email 由 B 填成它认证过的腿标
//     签)。VPS **只在这个 nudge 之后**才朝那条腿的候选主动发包(见 punchLeg)。这一步不能省:
//     VPS 自己这台机器前面往往还有一层有状态防火墙/安全组/出口 SNAT, 只放行"本机先朝某个
//     具体地址发过包"之后的回程; 它不主动朝外发这一下, 居民先打的那几个包一个都进不来
//     (实测: 曾把这里改成"VPS 彻底不主动发包", 原本能通的线路直接断了)。
//   - 反过来, VPS **绝不抢在某条腿说话之前**发包。nudge 就是"这条腿已经打过了"的确定信号,
//     走已鉴权的 websocket 控制面, 不靠猜时间。早先这里还有个"多久没等到 nudge 就兜底打"的
//     定时器, 它一踩空就会在居民真正打洞之前把包打过去, 直接毒化居民的 CGNAT 映射(实测
//     复现过, 见 docs/direct-punch-order.md), 所以现在**没有**兜底定时器 —— 等不到 nudge 就
//     宁可不发。
//   - 于是"主路径"是 nudge 驱动的那一下主动发包, 而"先听到某条腿再反过来朝它发包"
//     (primeLeg)只是**补充**: 居民的包能不能到 VPS 取决于 VPS 自己的防火墙, 听不到才是常态
//     里的常态, 不能指望它。两者都不违反"绝不抢先" —— 都是在该腿自己发过包之后才发。
//   - 两条主被动发送都会尽早收手: punchLeg 从第二发起每发之前看这条腿是不是已经被听到,
//     听到了就停(它要开的洞已经开了, 再发只是噪声); primeLeg 只在学到的真实地址**不在**候选
//     里(端口漂了)时才发, 否则等于把 punchLeg 刚发过的包重发一遍。
//   - 两条腿都被听到过之后, 才在两者之间**盲转发**收到的不透明 UDP 包(含打洞探测包本身);
//     只往亲耳听到过的真实地址转, 不退回候选去猜。
//   - 副作用: 转发天然不区分打洞探测包与真实 QUIC 数据 —— A、C 的打洞包若按 Direct.Encrypt
//     加过密, 原样转发过去对面也是加密的, VPS 完全不需要知道、也不需要派生密钥。VPS 自己
//     主动发的那几个开洞包仍是明文: 它们是不承载任何数据的占位包, 见
//     docs/direct-relay-design.md §"打洞包加密"的说明。
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
	candAddrs []*net.UDPAddr  // B 告知的候选: 既是识别"这是哪条腿"的依据, 也是 VPS 收到 nudge 后
	// 主动发包(nudge 证明这条腿已经打过了)的目标地址。
	addr atomic.Pointer[net.UDPAddr] // 实际收到过该腿的包后学到的真实地址; 没学到前是 nil,
	// forwardLoop 绝不往 nil 的腿转发(不会退回 candAddrs 瞎猜), 见下面的说明。

	fire chan struct{} // 本腿的 nudge(居民已先打)到达后关闭, 触发 VPS 朝它主动发包
	once sync.Once
}

// candHasAddr 学到的真实地址是否就是候选之一。是则说明 VPS 已经朝这个**确切**地址主动发过
// 包了(punchLeg 正是朝所有候选发的), 不需要再 primeLeg 一遍; 只有真实地址不在候选里(端口
// 漂移了)时, 朝真实地址补一次主动发送才有意义。
func (leg *relayLeg) candHasAddr(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	for _, c := range leg.candAddrs {
		if c != nil && c.IP.Equal(addr.IP) && c.Port == addr.Port {
			return true
		}
	}
	return false
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
	// 准入检查放在 openRelay 之前: 一旦开下去就占了一个专用 UDP socket 和一轮端点探测,
	// 拒绝一个本就不该进来的请求不该先付这份代价。
	//
	// 配了名单却拿不到身份 = 不放行。空 Email 只有一种来源: 对面的 B 还是不带这个字段的
	// 老版本(见 DirectRelayOpen.Email)。此时"放过去只打条日志"等于让名单对老版本 B 静默
	// 失效——而"名单看着生效、实际没拦住"正是这个字段改名重做前的老毛病, 不能换个形式
	// 再来一遍。没配 relayEmail 的部署走不到这两个分支, 行为完全不变。
	if len(d.cfg.Direct.RelayEmail) > 0 && open.Email == "" {
		d.logf("relay: refused relay-open for token %s: relayEmail is configured but the server sent no requester email (old server?)", shortToken(open.Token))
		reply(DirectReady{Err: "relayEmail is configured on this relay but the signaling server did not provide the requester email; upgrade server B"})
		return
	}
	if !d.cfg.Direct.RelayEmailAllowed(open.Email) {
		// 日志里记完整 email: 运维要照着它决定加不加名单。回给对端的话不带 email, 与
		// file_pull.go 回错时不外传本机细节是同一个口径——对面自己是谁它清楚, 本机的
		// 名单配成什么样没有理由告诉它。
		d.logf("relay: refused relay-open for token %s from %s: not in relayEmail", shortToken(open.Token), open.Email)
		reply(DirectReady{Err: "this relay does not accept relay requests from your email"})
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
// 三条路: RelayPublic 只写 IP 时用随机端口组合多个显式公网 IP；写 IP:port 时用固定端点；
// 没配置时开随机端口并靠反射器探出口映射。
func (d *directPeer) newRelaySocket() (*net.UDPConn, []string, error) {
	if len(d.cfg.Direct.RelayPublic) > 0 {
		dynamic, fixed := false, false
		for _, raw := range d.cfg.Direct.RelayPublic {
			s := strings.TrimSpace(raw)
			switch {
			case net.ParseIP(s) != nil:
				dynamic = true
			case checkDirectEndpoint(s) == nil:
				fixed = true
			}
		}
		if dynamic && fixed {
			return nil, nil, errors.New("direct.relayPublic cannot mix bare IPs (random port) with IP:port endpoints (fixed port)")
		}
		if dynamic {
			return d.newDynamicPublicRelaySocket()
		}
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

// newDynamicPublicRelaySocket 在随机端口上监听，并把这个端口与配置的每个公网 IP 组合成
// 候选。一个 binding 一个随机端口，所以旧 binding 尚未回收也不会挡住下一次连接。
func (d *directPeer) newDynamicPublicRelaySocket() (*net.UDPConn, []string, error) {
	var ips []net.IP
	for _, raw := range d.cfg.Direct.RelayPublic {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.IsUnspecified() {
			d.logf("relay: skip invalid IP-only directRelayPublic entry %q: want a concrete IP address", raw)
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, nil, errors.New("no valid IP-only directRelayPublic entry configured")
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, nil, fmt.Errorf("listen relay udp: %w", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	eps := make([]string, 0, len(ips))
	for _, ip := range ips {
		eps = append(eps, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	eps = dedupStrings(eps)
	d.logf("relay: using random local port %d with configured public IPs, endpoint(s) %v", port, eps)
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
		fails = append(fails, reflectorUnavailable(candSrcReflectV4, d.cfg.Connect, v4Err))
	}
	if v6 == nil && v6Err != nil {
		fails = append(fails, reflectorUnavailable(candSrcReflectV6, d.cfg.Connect, v6Err))
	}
	var targets []*net.UDPAddr
	for _, r := range []*net.UDPAddr{v4, v6} {
		if r != nil {
			targets = append(targets, r)
		}
	}
	// "问哪个反射器、从哪个本地端口问"都记下来: 中继端点只能靠反射器问出来, 这一步失败
	// 整条中继就开不出来, 排查时要能和服务端反射器日志、本机 `ss`、安全组逐项对上。
	d.logf("relay: probing reflector(s) %v for our public endpoint (local socket %s)", targets, conn.LocalAddr())
	for _, r := range targets {
		ep, err := probeReflectorConn(conn, r)
		if err != nil {
			fails = append(fails, err.Error())
			continue
		}
		d.logf("relay: reflector %s sees us as %s", r, ep)
		eps = append(eps, ep)
	}
	eps = dedupStrings(eps)
	if len(eps) == 0 {
		// 客户端拿不到回包时分不清是"反射器没起 / 包没到 / 被白名单拒 / 回包丢在路上",
		// 服务端日志(见 StartDirectReflector 的 whoami 记录)能区分, 这里把排查顺序写清楚。
		d.logf("relay: cannot learn our public endpoint — check in order: "+
			"(1) confirm the server log contains 'nat direct reflector listening on udp ...' and `ss -ulnp` shows that UDP port; "+
			"(2) check the server log for 'whoami from <client-egress-IP> answered': if present, the server received and answered the probe, so the return path to this host is blocked by an inbound security group or firewall; "+
			"this message is rate-limited per source to once every 5 minutes, so no repeated message does not mean no response; "+
			"no whoami message means the packet did not arrive (outbound UDP is blocked here, or the server is not listening on that address family); "+
			"a 'dropped — ... is not allowed by websocket.server.allowIP' message means the server allowlist excludes this host's egress IP; "+
			"(3) if none applies, configure a static direct.relayPublic endpoint to bypass reflector discovery (connect=%s)",
			d.cfg.Connect)
		return nil, fmt.Errorf("no relay endpoint (%s)", strings.Join(fails, "; "))
	}
	return eps, nil
}

// reflectorUnavailable 描述一族反射器地址为何不可用。connect 填的是**字面量 IP** 时, 另一族
// 在语法上就解不出来(与网络通不通无关, 见 reflectorAddrs 的说明), 明确标成 skipped, 免得它
// 和"探测没回包"混在一条错误里, 让人误以为那一族的链路有问题。
func reflectorUnavailable(src, wsConnect string, err error) string {
	if host, _, sErr := net.SplitHostPort(wsConnect); sErr == nil && net.ParseIP(host) != nil {
		return fmt.Sprintf("%s: skipped (connect uses the IP literal %s, so a reflector for this address family cannot be derived)", src, host)
	}
	return fmt.Sprintf("%s: %v", src, err)
}

// probeReflectorConn 在一个裸 *net.UDPConn 上做一次 whoami 往返(同步), 问反射器"我在你
// 眼里是什么地址"。与 directPeer.probeReflector 的区别: 那个走已交给 quic-go 的共享 socket、
// 靠 drainNonQUIC 按 nonce 投递; 中继的专用 socket 没交给 quic-go, 直接 ReadFromUDP 即可。
func probeReflectorConn(conn *net.UDPConn, raddr *net.UDPAddr) (string, error) {
	var (
		lastErr error
		noReply bool
	)
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
				// 记下"确实一次回包都没等到"(而不是发不出去): 两者成因完全不同, 报错要能区分。
				noReply = true
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
	switch {
	case noReply:
		// 带上发射用的本地 socket 与重试次数, 便于和服务端反射器日志、本机 `ss`/安全组对照。
		return "", fmt.Errorf("no reply from reflector %s in %d tries × %s (probing from local %s)",
			raddr, directProbeTries, directProbeWait, conn.LocalAddr())
	case lastErr != nil:
		return "", lastErr
	}
	return "", fmt.Errorf("relay endpoint probe failed")
}

// registerRelayLeg VPS 收到 B 转来的 d_punch(Relay=true)时登记一条腿: 记下这条腿(A 或 C)
// 的候选, 既用于识别之后从这个来源到达的包是哪条腿的, 也作为"收到该腿 nudge 后朝哪发"的
// 目标。登记这一步本身**不发送任何东西** —— 该腿自己会主动朝 E 打洞(是居民、必须先发),
// 它打完第一发后经 B 捎来的 nudge 才触发 VPS 主动发包(见 fireRelayLeg/punchLeg 与文件头)。
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
	// 把这条腿登记的候选原样记下来(含来源标记 cands, 以及解析后的 ip:port)。这是后面判断
	// "primeLeg 为什么被触发"的基准: 拿它和 VPS 实际看到的来源地址对比, 一眼能看出是端口
	// 不同(真漂移)、IP 不同(多出口/换池), 还是两者一致(那才是真的不该触发)。
	d.logf("relay: registered leg %s (token %s) with candidates %v -> %v, holding punch until its nudge",
		email, shortToken(token), cands, leg.candAddrs)

	// 停着等这条腿的 nudge(居民朝 E 打过第一发后经 B 转来)才朝它发包。
	//
	// **没有兜底定时器**: 早先"等 directPunchFirstDelay 没等到 nudge 就自己打"的兜底一旦踩得
	// 比另一条腿的信令来回还短, VPS 就会在那条腿真正打洞之前抢先发包过去, 直接毒化居民的
	// CGNAT 映射(见文件头与 docs/direct-punch-order.md)。nudge 走的是已鉴权的 websocket, 丢了
	// 就说明这条腿没打或控制面断了 —— 那时朝一个没验证过的候选盲打只会更糟, 宁可不发。
	go func() {
		select {
		case <-leg.fire:
		case <-rb.done:
			return
		}
		rb.punchLeg(leg)
		// punchLeg 的发包窗口只有 directPunchCount*directPunchGap(~900ms); 再给一点余量等
		// pong 走完一趟往返。窗口到点这条腿仍没被听到, 就是这次中继里注定连不上——这里主动
		// 说清楚可能的原因, 不然只能看着 A 那头几秒后"quic dial race ... no answer", 却查不出
		// 是哪条腿、为什么: 最常见的是候选清一色是本中继够不着的地址族(比如中继没有 IPv6 出口,
		// 这条腿却只报了 v6/仅局域网候选), 其次是候选本身没问题但那次打洞恰好丢包/对方短暂
		// 掉线——同一条腿在别的会话里成功过就多半是后者。
		select {
		case <-time.After(directPunchCount*directPunchGap + time.Second):
		case <-rb.done:
			return
		}
		if leg.addr.Load() == nil {
			rb.peer.logf("relay: leg %s never answered any of its candidates %v — this relay could not reach it "+
				"(check: are any of them a public address this relay can actually route to? a private/LAN-only "+
				"candidate is never reachable from a public relay; if this relay has no IPv6 route, a v6-only "+
				"candidate list is equally unreachable — see this relay's own reflector-probe log for which "+
				"address families it can use; otherwise this is likely transient packet loss on %s's side during "+
				"candidate discovery, worth retrying); both legs must be reachable for the relay to work "+
				"(docs/direct-relay-design.md §7)",
				leg.email, leg.candAddrs, leg.email)
		}
	}()
}

// fireRelayLeg VPS 收到某条腿的 nudge(经 B 保留 email 当腿标签转来)时, 触发那条腿停着的发包。
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

// punchLeg 收到某条腿的 nudge(即它已朝 E 打过第一发)后, VPS 朝这条腿的所有候选各连发几个包。
//
// 目的只有一个: 在 VPS **自己这侧**开出朝该居民的回程通道。VPS 前面那层有状态防火墙/安全组
// 通常只放行"本机先朝某个具体地址发过包"之后的回程, 它不主动发这一下, 居民先打的洞在 VPS
// 眼里等于不存在 —— 居民的包一个都进不来, VPS 也就永远听不到这条腿, 中继直接死掉。
//
// 安全性: 此刻这条腿已经发过包(nudge 就是证明), 它的 NAT/CGNAT 映射已经建立, 朝它发包不存在
// "抢在居民之前"的问题; 那个坑专指对着**未验证的候选**、在对方还没发声之前抢先发送。
// 内容无所谓, 用 verbPunch 形态只是便于抓包辨认: 对面若回了 pong, 被盲转发到对侧也只是个
// 对侧不认的 nonce, 丢弃即可。
//
// 已知边界: 这里只能朝候选发 —— 此刻还没听到这条腿, 没有真实地址。对称 NAT 下居民的候选端口
// 与它实际用的源端口不一致, 这一发会打空, 中继打不通。这是打洞的固有边界, 不做兜底, 见
// docs/direct-relay-design.md §7「已知不支持」。
func (rb *relayBinding) punchLeg(leg *relayLeg) {
	rb.peer.logf("relay: leg %s nudged, punching toward it at %v (until it answers)", leg.email, leg.candAddrs)
	rb.punchAddrs(leg, leg.candAddrs, true)
}

// forwardLoop 中继的收发核心: 从专用 socket 收包, 按来源 IP 认出是哪条腿, 转给另一条腿的
// 学到地址。只在两腿的候选 IP 之间对转, 其它来源一律丢(注入防护)。
//
// 关键不变式: 只往一条腿**已经学到的真实地址**转发, 绝不退回它的候选地址去猜。这条腿的
// 候选是信令阶段报上来的、没验证过的地址——如果它本人还没主动发过包证明"这个地址上
// 确实有我在收", VPS 就不该抢先朝它发任何东西: 那正是"VPS 先于居民发包, 把居民的 CGNAT
// 映射毒坏"这个坑的成因(以前靠 nudge + 兜底定时器去协调"谁先打", 掐的时间点一旦踩不准
// 就会复现; 现在 VPS 只有在收到 nudge 或亲耳听到之后才会发, 这个问题自然消失)。代价是两条
// 腿都必须先各自主动朝 E 打过至少一个包, 转发才能开始——这本就是两个居民一直在做的事
// (punchOnly 打洞探测包 + 后续真实 QUIC 握手包都会主动发出), 不需要额外动作。
//
// "绝不抢先"不等于"绝不主动": VPS 主动发包的两个时机见 punchLeg(收到 nudge 后朝候选发,
// 主路径)与 primeLeg(第一次听到某条腿后朝它的真实地址发, 补充), 两者都发生在该腿自己
// 发过包之后, 顺序永远是居民先、VPS 后。
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
			continue // 来源不属于任何一腿, 或对侧还没登记 —— 丢弃
		}
		// Swap 而不是 Store: 既要每次都刷新成最新来源(端口可能漂移), 又要知道这是不是
		// "第一次听到这条腿"——只有这一刻才安全地反过来主动朝它发包(见 primeLeg)。
		if prev := from.addr.Swap(src); prev == nil {
			// 真实地址就是候选之一时, punchLeg(被这条腿的 nudge 触发的)已经朝这个**确切**
			// 地址主动发过包了——VPS 这侧的回程通道正是它开出来的, 再 primeLeg 一遍只是把
			// 同样的几个包重发一次、换来同样几个 pong 被盲转给对侧再丢掉。只有真实地址不在
			// 候选里(端口漂移了)时, "朝真实地址补一次主动发送"才有意义。
			if from.candHasAddr(src) {
				d.logf("relay: first packet from leg %s (token %s) at %s, matches its candidate, no priming needed",
					from.email, shortToken(rb.token), src)
			} else {
				d.logf("relay: first packet from leg %s (token %s) at %s, NOT among candidates %v, priming our own path back to it",
					from.email, shortToken(rb.token), src, from.candAddrs)
				go rb.primeLeg(from, src)
			}
		}
		dst := to.addr.Load()
		if dst == nil {
			continue // 对侧还没亲自发过包证明这个地址通, 不猜、不转发
		}
		if _, err := rb.conn.WriteToUDP(buf[:n], dst); err != nil {
			d.logf("relay: forward %s->%s on token %s failed: %v", from.email, to.email, shortToken(rb.token), err)
			continue
		}
		rb.touch()
	}
}

// primeLeg 一条腿的地址第一次被学到、且这个真实地址**不在**它的候选集合里(端口漂了)时,
// VPS 朝这个已验证的真实地址连发几个包。
//
// 这是 punchLeg(nudge 驱动, 朝候选发)之外的**补充**, 不是主路径: 主路径解决的是"VPS 自己的
// 防火墙不放行进来的包"这个鸡生蛋问题, 而这里只在 VPS 确实听到了这条腿时才可能发生。
// 真实地址命中某个候选时调用方会跳过这里(candHasAddr): 那种情况下 punchLeg 已经朝这个确切
// 地址主动发过了, 重复一遍只是把同样的包再发一次、换来同样几个 pong 被盲转给对侧再丢掉。
//
// 安全性同 punchLeg: 这条腿此刻已经证明了"它先发的"(forwardLoop 正是收到它的包才调用这里),
// 时间顺序上 VPS 永远是后发的那一个。
func (rb *relayBinding) primeLeg(leg *relayLeg, addr *net.UDPAddr) {
	rb.punchAddrs(leg, []*net.UDPAddr{addr}, false)
}

// punchAddrs 朝一组地址各连发几个打洞包(每个地址一个 goroutine, 不等回执)。
//
// 内容无所谓, 用 verbPunch 形态只是便于抓包辨认; 对面收到后就算回 pong, 被盲转发到对侧也
// 只是个对侧不认的 nonce, 丢弃即可。
//
// stopWhenLearned 为 true 时(nudge 驱动的 punchLeg 走这条路), **从第二发起**, 每发之前先看
// 这条腿是不是已经被**亲耳听到**了(leg.addr 非 nil), 听到了就立刻停下: VPS 朝一条腿发包的
// 唯一目的是"让自己这台机器的防火墙放行它的包", 既然已经收到它的包, 这个目的就达成了, 剩下
// 的几发是白送的噪声——它们换回来的 pong 还会被盲转给对侧、再被对侧查不到 nonce 丢掉, 全都
// 发生在 QUIC 握手的头一秒里。
//
// 第一发(i==0)不受这个检查约束: "VPS 主动朝这条腿发过一次包"正是整个机制的核心, 不能因为
// 这条腿的包凑巧先到(VPS 的防火墙恰好放行了)就一发不发, 把这层保险吃掉。
//
// primeLeg 传 false: 它本就是在听到之后才触发的, 再拿"已听到"当停止条件会一发都发不出去,
// 而它要补的正是"朝真实地址主动发一次"这个动作。
func (rb *relayBinding) punchAddrs(leg *relayLeg, addrs []*net.UDPAddr, stopWhenLearned bool) {
	var logged sync.Once
	for _, addr := range addrs {
		go func(addr *net.UDPAddr) {
			for i := 0; i < directPunchCount; i++ {
				select {
				case <-rb.done:
					return
				default:
				}
				// i > 0: 第一发无论如何要发出去——"VPS 自己主动朝这条腿发过包"正是整个机制
				// 的核心, 不能因为这条腿的包凑巧已经先到(比如 VPS 防火墙恰好放行)就一发不发。
				// 从第二发起才谈"目的已达成就别再噪声了"。
				if stopWhenLearned && i > 0 && leg.addr.Load() != nil {
					logged.Do(func() {
						rb.peer.logf("relay: leg %s answered after %d punch(es), our path back to it is open, stopping",
							leg.email, i)
					})
					return
				}
				if _, err := rb.conn.WriteToUDP(directPacket(verbPunch+" "+newNonce()), addr); err != nil {
					rb.peer.logf("relay: punch leg %s at %s failed: %v", leg.email, addr, err)
					return
				}
				time.Sleep(directPunchGap)
			}
		}(addr)
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
	//
	// 走到这条兜底就说明"精确 ip:port 没命中、但该 IP 属于这条腿"——也就是**来源端口与登记
	// 候选不同**。这正是 candHasAddr 随后返回 false、primeLeg 被触发的唯一成因, 所以这里必须
	// 留下证据。只在第一包/漂移包上出现(学到真实地址后精确匹配会命中 learned addr), 不会刷屏。
	if from == nil {
		var hits []*relayLeg
		for _, leg := range rb.legs {
			if leg.candIPs[ip] {
				hits = append(hits, leg)
			}
		}
		switch len(hits) {
		case 1:
			from = hits[0]
			rb.peer.logf("relay: classify %s -> leg %s by unique-IP fallback (port differs from candidates %v), token %s",
				srcStr, from.email, from.candAddrs, shortToken(rb.token))
		case 0:
			// 完全陌生的来源: 丢弃(注入防护)。不记日志, 免得被扫描噪声刷屏。
		default:
			names := make([]string, 0, len(hits))
			for _, l := range hits {
				names = append(names, l.email)
			}
			rb.peer.logf("relay: classify %s matches %d legs' candidate IPs %v, ambiguous, dropping (token %s)",
				srcStr, len(hits), names, shortToken(rb.token))
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
