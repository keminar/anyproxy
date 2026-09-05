package nat

import (
	"crypto/subtle"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// UDP 中继的服务端(B)侧。一条 forward 规则一个 udpRelay, 监听地址与该规则的 TCP 入口
// 同一个 host:port(不同协议, 互不冲突), 客户端不用改配置。

// udpRelaySession B 上的一条会话: 一个客户端端点(mstsc 的源地址)对应一个会话号,
// 号码写在 B->C 的包头里, C 靠它把回包送回同一个客户端。
type udpRelaySession struct {
	id   uint32
	addr *net.UDPAddr
	last atomic.Int64 // unix nano, 双向都算
}

func (s *udpRelaySession) touch() { s.last.Store(time.Now().UnixNano()) }

// udpRelay 一条 forward 规则的 UDP 中继。
type udpRelay struct {
	rule conf.ServerForward
	port uint16 // 入口端口, 也是 C 用来查 client.forward 的键
	conn *net.UDPConn

	mu       sync.Mutex
	sessions map[string]*udpRelaySession // 客户端端点 -> 会话
	byID     map[uint32]*udpRelaySession
	inc      uint32

	// C 的上行状态。upAddr 是 B 观测到的 C 的 UDP 端点(即 C 那侧 NAT 的映射), 只有从
	// 这个端点来的包才当上行处理。
	upAddr  *net.UDPAddr
	upToken string
	upAt    time.Time
	opening bool     // 已经发过 u_open, 正在等 C 注册
	pending [][]byte // 等上行期间暂存的客户端数据报(已拼好包头)
}

// relayRegistry 入口端口 -> 中继, 供 u_ready 信令回查。
var relayRegistry sync.Map // uint16 -> *udpRelay

// StartRelayUDP 为配了 udp/both 的 forward 规则起 UDP 中继入口。
func StartRelayUDP(rules []conf.ServerForward) {
	for _, r := range rules {
		if r.Listen == "" || !r.WantUDP() {
			continue
		}
		if !r.ValidProtocol() {
			log.Printf("nat relay udp: forward %s has unknown protocol %q, skipped", r.Listen, r.Protocol)
			continue
		}
		go listenRelayUDP(r)
	}
}

// newUDPRelay 起一个中继的监听 socket。端口取**实际绑定到的**端口而不是配置里写的:
// 配 :0 时内核才分配, 用配置值会得到 0, 后面拿它当 forward 键就全对不上了。
func newUDPRelay(r conf.ServerForward) (*udpRelay, error) {
	addr, err := net.ResolveUDPAddr("udp", r.Listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &udpRelay{
		rule:     r,
		port:     uint16(conn.LocalAddr().(*net.UDPAddr).Port),
		conn:     conn,
		sessions: map[string]*udpRelaySession{},
		byID:     map[uint32]*udpRelaySession{},
	}, nil
}

func listenRelayUDP(r conf.ServerForward) {
	u, err := newUDPRelay(r)
	if err != nil {
		log.Printf("nat relay udp listen %s err: %v", r.Listen, err)
		return
	}
	relayRegistry.Store(u.port, u)
	log.Printf("nat relay udp listening on %s -> email %s", r.Listen, r.Email)
	go u.reap()
	u.readLoop()
}

func (u *udpRelay) readLoop() {
	buf := make([]byte, relayUDPBufSize)
	for {
		n, from, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("nat relay udp read %s err: %v", u.rule.Listen, err)
			return
		}
		pkt := buf[:n]
		// 上行包要两个条件都满足: 带魔数, 且来自已注册的那个端点。只看魔数的话, 任何人
		// 发个 0xA5 开头的包都能往客户端方向注入数据。
		if hasRelayUDPMagic(pkt) {
			if u.isUplink(from) {
				u.onUplink(pkt)
				continue
			}
			if u.tryRegister(pkt, from) {
				continue
			}
		}
		u.onClient(pkt, from)
	}
}

func (u *udpRelay) isUplink(from *net.UDPAddr) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.upAddr != nil && u.upAddr.IP.Equal(from.IP) && u.upAddr.Port == from.Port
}

// tryRegister 处理 C 的注册包。token 必须与本次 u_open 下发的一致 —— 端点是 C 现场
// 报上来的, 没有凭证的话谁都能把自己注册成上行, 把别人的流量接走。
func (u *udpRelay) tryRegister(pkt []byte, from *net.UDPAddr) bool {
	h, payload, err := decodeRelayUDP(pkt)
	if err != nil || h.kind != relayKindRegister {
		return false
	}
	u.mu.Lock()
	// 常量时间比对: token 是网络上送来的, 逐字节短路比较会把"前几位对了"的信息
	// 漏进响应时机里。UDP 上做时序测量很吃力, 但这个防护是免费的。
	if u.upToken == "" || subtle.ConstantTimeCompare(payload, []byte(u.upToken)) != 1 {
		u.mu.Unlock()
		log.Printf("nat relay udp %s: register from %s rejected, token mismatch", u.rule.Listen, from)
		return true
	}
	u.upAddr = from
	u.upAt = time.Now()
	u.opening = false
	u.upToken = "" // 一次性: 注册完就作废, 要重建时 B 会重新下发
	flush := u.pending
	u.pending = nil
	u.mu.Unlock()

	log.Printf("nat relay udp %s: uplink registered from %s (email %s), flushing %d pending",
		u.rule.Listen, from, u.rule.Email, len(flush))
	for _, p := range flush {
		u.conn.WriteToUDP(p, from)
	}
	return true
}

// onUplink C 发来的包: 数据按会话号回送给对应客户端, 保活只刷新时间。
func (u *udpRelay) onUplink(pkt []byte) {
	h, payload, err := decodeRelayUDP(pkt)
	if err != nil {
		return
	}
	switch h.kind {
	case relayKindKeepalive:
		u.mu.Lock()
		u.upAt = time.Now()
		u.mu.Unlock()
	case relayKindData:
		u.mu.Lock()
		s := u.byID[h.session]
		u.upAt = time.Now()
		u.mu.Unlock()
		if s == nil {
			return // 会话已回收, 丢掉即可: UDP 本来就不保证送达
		}
		s.touch()
		u.conn.WriteToUDP(payload, s.addr)
	}
}

// onClient 客户端(mstsc)的数据报: 打上会话号发给 C; 上行还没建好就先让 C 建, 并暂存。
func (u *udpRelay) onClient(pkt []byte, from *net.UDPAddr) {
	s := u.session(from)
	if s == nil {
		return // 被 allowIP 挡掉
	}
	s.touch()
	frame := encodeRelayUDP(relayUDPHead{kind: relayKindData, session: s.id, port: u.port}, pkt)

	u.mu.Lock()
	if u.upAddr != nil {
		up := u.upAddr
		u.mu.Unlock()
		u.conn.WriteToUDP(frame, up)
		return
	}
	// 上行没建好: 暂存少量数据报, 并触发一次 u_open。
	if len(u.pending) < relayUDPPendingMax {
		u.pending = append(u.pending, frame)
	}
	need := !u.opening
	if need {
		u.opening = true
	}
	u.mu.Unlock()
	if need {
		go u.openUplink()
	}
}

// session 取(或新建)一个客户端端点对应的会话。allowIP 只在新建时判一次: 这是个逐包
// 调用的热路径, 而 serverIPAllowed 每次都要重新解析配置里的 CIDR; 语义上这个白名单
// 管的也是"谁可以开始用这条中继", 会话既已建立就不必每包重判。
// 返回 nil 表示来源不在白名单里。
func (u *udpRelay) session(from *net.UDPAddr) *udpRelaySession {
	key := from.String()
	u.mu.Lock()
	defer u.mu.Unlock()
	if s, ok := u.sessions[key]; ok {
		return s
	}
	// server.allowIP 同样约束 UDP 入口, 否则这个端口对公网全开。
	// 不打日志: UDP 无连接, 扫描器一秒能灌几百条, 打日志等于自己刷屏。
	if !serverIPAllowed(from.IP.String()) {
		return nil
	}
	u.inc++
	// from 可以直接留存: ReadFromUDP 每次调用都新分配一个 UDPAddr, 不是复用的缓冲。
	s := &udpRelaySession{id: u.inc, addr: from}
	u.sessions[key] = s
	u.byID[s.id] = s
	log.Printf("nat relay udp %s: new session %d from %s", u.rule.Listen, s.id, from)
	return s
}

// openUplink 通过 websocket 让 C 建上行。失败(对端不在线/编码失败/超时)要清掉暂存并
// 复位 opening, 否则会永远卡在"正在建"的状态, 后面的数据报再也不会重试。
func (u *udpRelay) openUplink() {
	fail := func(reason string) {
		log.Printf("nat relay udp %s: uplink not ready, %s", u.rule.Listen, reason)
		u.mu.Lock()
		u.opening = false
		u.pending = nil
		u.upToken = ""
		u.mu.Unlock()
	}
	if !serverStart || ServerHub == nil {
		fail("server hub not ready")
		return
	}
	peer := ServerHub.GetClientByEmail(u.rule.Email)
	if peer == nil {
		fail("no subscriber online for email " + u.rule.Email)
		return
	}
	token, err := newDirectToken()
	if err != nil {
		fail("token: " + err.Error())
		return
	}
	body, err := encodeDirect(RelayUDPOpen{Port: u.port, Token: token})
	if err != nil {
		fail("encode: " + err.Error())
		return
	}
	u.mu.Lock()
	u.upToken = token
	u.mu.Unlock()

	peer.hub.broadcast <- &CMessage{client: peer, message: &Message{Type: ConnTCP, Method: METHOD_RELAY_UDP_OPEN, Body: body}}
	log.Printf("nat relay udp %s: asked email %s to open an uplink", u.rule.Listen, u.rule.Email)

	// 注册包是从 UDP 那侧来的(由 tryRegister 处理), 这里只做超时兜底。
	deadline := time.Now().Add(relayUDPOpenWait)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		u.mu.Lock()
		ok := u.upAddr != nil
		u.mu.Unlock()
		if ok {
			return
		}
	}
	fail("timeout waiting for peer to register")
}

// onReady C 回报建不起来时立刻放弃, 不用干等到超时。
func (u *udpRelay) onReady(r RelayUDPReady) {
	if r.Err == "" {
		return
	}
	log.Printf("nat relay udp %s: peer email %s refused, %s", u.rule.Listen, u.rule.Email, r.Err)
	u.mu.Lock()
	u.opening = false
	u.pending = nil
	u.upToken = ""
	u.mu.Unlock()
}

// handleRelayUDPServer 处理订阅方发来的 UDP 中继信令(在 B 上执行)。
func handleRelayUDPServer(c *Client, msg *Message) bool {
	if !isRelayUDPMethod(msg.Method) {
		return false
	}
	if msg.Method != METHOD_RELAY_UDP_READY {
		// u_open 是 B 下发给订阅方的方向, 订阅方不该往上发。
		log.Printf("nat relay udp: unexpected %s from client email %s", msg.Method, c.Email)
		return true
	}
	var r RelayUDPReady
	if err := decodeDirect(msg.Body, &r); err != nil {
		log.Printf("nat relay udp: bad ready from email %s: %v", c.Email, err)
		return true
	}
	if v, ok := relayRegistry.Load(r.Port); ok {
		v.(*udpRelay).onReady(r)
	}
	return true
}

// reap 回收空闲会话; 会话全没了且上行也长期没动静时, 连上行一起忘掉 —— 下次有数据报
// 再让 C 重新建, 免得 C 无限期为一条早已没人用的中继发保活包。
func (u *udpRelay) reap() {
	t := time.NewTicker(relayUDPReapEvery)
	defer t.Stop()
	for now := range t.C {
		u.reapOnce(now, relayUDPSessionIdle)
	}
}

func (u *udpRelay) reapOnce(now time.Time, idle time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for key, s := range u.sessions {
		if now.Sub(time.Unix(0, s.last.Load())) > idle {
			delete(u.sessions, key)
			delete(u.byID, s.id)
			log.Printf("nat relay udp %s: session %d from %s idle, dropped", u.rule.Listen, s.id, s.addr)
		}
	}
	if len(u.sessions) == 0 && u.upAddr != nil && now.Sub(u.upAt) > idle {
		log.Printf("nat relay udp %s: no session left, forgetting uplink %s", u.rule.Listen, u.upAddr)
		u.upAddr = nil
	}
}
