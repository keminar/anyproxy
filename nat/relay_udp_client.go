package nat

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UDP 中继的订阅方(C)侧: 按 B 的要求建一条到 B 的 UDP 上行, 把收到的数据报按包头里的
// 端口查 client.forward 落到内网目标, 再把回包打上同一个会话号送回 B。
//
// 上行由 C 主动发起, 所以 C 在 NAT 后面也没问题: 第一个包(注册)出去时就在自己 NAT 上
// 开出映射, B 之后顺着这条映射回发即可, 不需要打洞。映射会老化, 所以要保活。

// relayLocalSession C 上的一条会话: 对应 B 那侧的一个客户端, 各自一个到内网目标的
// UDP socket —— 不能共用一个, 否则内网目标看到的所有客户端都是同一个源端口。
type relayLocalSession struct {
	id     uint32
	conn   *net.UDPConn
	target string
	last   atomic.Int64
}

// udpUplink C 侧的上行运行时, 挂在 wsClientConn 上。整条上行是按需建的: 收到 u_open
// 才建, 空闲一段后自己撤掉。
type udpUplink struct {
	tag     string
	connect string            // 本条 server 连接的 connect 地址, 取主机名用
	forward map[uint16]string // 端口 -> 内网目标, 与 websocket 转发路径共用同一张白名单

	mu       sync.Mutex
	conn     *net.UDPConn // 到 B 的上行 socket
	sessions map[uint32]*relayLocalSession
	stop     chan struct{} // 随 conn 一起换, 用来收掉保活/回收 goroutine
	last     atomic.Int64  // 上行最近一次收发时间
}

func newUDPUplink(tag, connect string, forward map[uint16]string) *udpUplink {
	return &udpUplink{tag: tag, connect: connect, forward: forward, sessions: map[uint32]*relayLocalSession{}}
}

func (u *udpUplink) logf(format string, args ...interface{}) {
	log.Printf("[%s] nat relay udp: %s", u.tag, fmt.Sprintf(format, args...))
}

// handleRelayUDPClient 订阅方侧处理服务端下发的 UDP 中继信令。
func handleRelayUDPClient(c *Client, msg *Message) bool {
	if !isRelayUDPMethod(msg.Method) {
		return false
	}
	u := c.uplinkOf()
	if u == nil {
		log.Printf("nat relay udp: got %s but this connection has no uplink runtime", msg.Method)
		return true
	}
	if msg.Method != METHOD_RELAY_UDP_OPEN {
		u.logf("unexpected %s from server", msg.Method)
		return true
	}
	var open RelayUDPOpen
	if err := decodeDirect(msg.Body, &open); err != nil {
		u.logf("bad open: %v", err)
		return true
	}
	go u.onOpen(c, open)
	return true
}

// onOpen 按 B 的要求建上行。端口不在本机 forward 白名单里就直接回绝, 让 B 立刻放弃,
// 而不是让客户端一路等到超时。
func (u *udpUplink) onOpen(c *Client, open RelayUDPOpen) {
	target, ok := u.forward[open.Port]
	if !ok {
		u.reply(c, RelayUDPReady{Port: open.Port, Err: fmt.Sprintf("no forward target for entry port %d", open.Port)})
		return
	}
	if err := u.ensureConn(open); err != nil {
		u.reply(c, RelayUDPReady{Port: open.Port, Err: err.Error()})
		return
	}
	u.logf("uplink ready for entry port %d -> %s", open.Port, target)
	u.reply(c, RelayUDPReady{Port: open.Port})
}

func (u *udpUplink) reply(c *Client, r RelayUDPReady) {
	body, err := encodeDirect(r)
	if err != nil {
		u.logf("encode ready: %v", err)
		return
	}
	// 与数据面共用 hub.broadcast, 理由同直连信令(见 directPeer.send)。
	c.hub.broadcast <- &CMessage{client: c, message: &Message{Type: ConnTCP, Method: METHOD_RELAY_UDP_READY, Body: body}}
}

// ensureConn 建上行 socket 并注册。已经有上行时也要重新注册一次: B 会在忘掉上行之后
// 重新发 u_open, 那时它手上的 token 是新的, 不重发注册包 B 就认不出这个端点。
func (u *udpUplink) ensureConn(open RelayUDPOpen) error {
	host, _, err := net.SplitHostPort(u.connect)
	if err != nil {
		host = u.connect // connect 没带端口时按纯主机名处理
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(open.Port)))
	if err != nil {
		return fmt.Errorf("resolve relay addr: %w", err)
	}

	u.mu.Lock()
	conn := u.conn
	if conn == nil {
		// Dial 而不是 ListenUDP: 连接态 socket 只收这个对端的包, 内核替我们挡掉了
		// 别处灌进来的数据报。
		conn, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			u.mu.Unlock()
			return fmt.Errorf("dial relay: %w", err)
		}
		stop := make(chan struct{})
		u.conn, u.stop = conn, stop
		u.touch()
		u.mu.Unlock()
		u.logf("uplink socket %s -> %s", conn.LocalAddr(), raddr)
		go u.readLoop(conn, stop)
		go u.keepalive(conn, stop)
		go u.reap(conn, stop)
	} else {
		u.mu.Unlock()
	}

	_, err = conn.Write(encodeRelayUDP(relayUDPHead{kind: relayKindRegister, port: open.Port}, []byte(open.Token)))
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	return nil
}

func (u *udpUplink) touch() { u.last.Store(time.Now().UnixNano()) }

// readLoop 收 B 发来的数据报, 按会话号落到内网目标。
func (u *udpUplink) readLoop(conn *net.UDPConn, stop chan struct{}) {
	buf := make([]byte, relayUDPBufSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			select {
			case <-stop:
			default:
				u.logf("uplink read err: %v", err)
				u.closeConn(conn)
			}
			return
		}
		u.touch()
		h, payload, err := decodeRelayUDP(buf[:n])
		if err != nil {
			continue
		}
		switch h.kind {
		case relayKindData:
			u.toLocal(conn, h, payload)
		case relayKindClose:
			u.dropSession(h.session)
		}
	}
}

// toLocal 把一个数据报送到内网目标。会话不存在就现建一个。
func (u *udpUplink) toLocal(conn *net.UDPConn, h relayUDPHead, payload []byte) {
	s, err := u.session(conn, h)
	if err != nil {
		u.logf("session %d: %v", h.session, err)
		return
	}
	s.last.Store(time.Now().UnixNano())
	if _, err := s.conn.Write(payload); err != nil {
		u.logf("session %d write to %s: %v", h.session, s.target, err)
	}
}

func (u *udpUplink) session(conn *net.UDPConn, h relayUDPHead) (*relayLocalSession, error) {
	u.mu.Lock()
	if s, ok := u.sessions[h.session]; ok {
		u.mu.Unlock()
		return s, nil
	}
	// 目标每个包都查一次而不是只查首包: UDP 会乱序, 首包未必先到。
	target, ok := u.forward[h.port]
	if !ok {
		u.mu.Unlock()
		return nil, fmt.Errorf("no forward target for entry port %d", h.port)
	}
	u.mu.Unlock()

	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", target, err)
	}
	local, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}

	u.mu.Lock()
	// 再查一次: 上面 dial 期间锁是放开的。目前 readLoop 是单 goroutine, 走不到这里,
	// 但真走到时"一条会话两个 socket"是很难查的故障, 这个兜底不值得省。
	if s, ok := u.sessions[h.session]; ok {
		u.mu.Unlock()
		local.Close()
		return s, nil
	}
	s := &relayLocalSession{id: h.session, conn: local, target: target}
	s.last.Store(time.Now().UnixNano())
	u.sessions[h.session] = s
	u.mu.Unlock()

	u.logf("session %d -> %s (entry port %d)", h.session, target, h.port)
	go u.fromLocal(conn, s, h.port)
	return s, nil
}

// fromLocal 收内网目标的回包, 打上同一个会话号送回 B。
func (u *udpUplink) fromLocal(conn *net.UDPConn, s *relayLocalSession, port uint16) {
	buf := make([]byte, relayUDPBufSize)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			u.dropSession(s.id)
			return
		}
		s.last.Store(time.Now().UnixNano())
		u.touch()
		frame := encodeRelayUDP(relayUDPHead{kind: relayKindData, session: s.id, port: port}, buf[:n])
		if _, err := conn.Write(frame); err != nil {
			u.logf("session %d write uplink: %v", s.id, err)
			return
		}
	}
}

func (u *udpUplink) dropSession(id uint32) {
	u.mu.Lock()
	s, ok := u.sessions[id]
	if ok {
		delete(u.sessions, id)
	}
	u.mu.Unlock()
	if ok {
		s.conn.Close()
	}
}

// keepalive 维持 C 侧的 NAT 映射。上行是按需建的, 所以这个包只在真有中继在用时才发。
func (u *udpUplink) keepalive(conn *net.UDPConn, stop chan struct{}) {
	t := time.NewTicker(relayUDPKeepalive)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if _, err := conn.Write(encodeRelayUDP(relayUDPHead{kind: relayKindKeepalive}, nil)); err != nil {
				u.logf("keepalive: %v", err)
				u.closeConn(conn)
				return
			}
		}
	}
}

// reap 回收空闲会话; 整条上行都没动静时把 socket 一起撤掉, 不再发保活包。
func (u *udpUplink) reap(conn *net.UDPConn, stop chan struct{}) {
	t := time.NewTicker(relayUDPReapEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			var dead []*relayLocalSession
			u.mu.Lock()
			for id, s := range u.sessions {
				if now.Sub(time.Unix(0, s.last.Load())) > relayUDPSessionIdle {
					delete(u.sessions, id)
					dead = append(dead, s)
				}
			}
			idle := len(u.sessions) == 0 && now.Sub(time.Unix(0, u.last.Load())) > relayUDPSessionIdle
			u.mu.Unlock()
			for _, s := range dead {
				u.logf("session %d to %s idle, dropped", s.id, s.target)
				s.conn.Close()
			}
			if idle {
				u.logf("uplink idle, closing socket")
				u.closeConn(conn)
				return
			}
		}
	}
}

// close 撤掉当前上行(如果有)。websocket 断开或进程收尾时用。
func (u *udpUplink) close() {
	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()
	if conn != nil {
		u.closeConn(conn)
	}
}

// closeConn 撤掉上行。只在 conn 还是当前那个时才动手, 免得关掉别人刚重建的那条。
func (u *udpUplink) closeConn(conn *net.UDPConn) {
	u.mu.Lock()
	if u.conn != conn {
		u.mu.Unlock()
		return
	}
	sessions := u.sessions
	stop := u.stop
	u.conn, u.stop, u.sessions = nil, nil, map[uint32]*relayLocalSession{}
	u.mu.Unlock()

	if stop != nil {
		close(stop)
	}
	conn.Close()
	for _, s := range sessions {
		s.conn.Close()
	}
}
