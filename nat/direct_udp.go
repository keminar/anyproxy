package nat

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	quic "github.com/quic-go/quic-go"
)

// 直连的 UDP 通路: 用户 UDP -> A 入口 -> QUIC datagram -> C -> UDP 到内网目标, 回程同理。
//
// 为什么用 datagram 而不是 stream: QUIC 的 stream 是可靠有序的, 拿它扛 UDP 等于给 UDP
// 强加重传与保序, 把我们特意要避开的队头阻塞又请回来, 语义也不对。datagram(RFC 9221)
// 不可靠、不保序, 正好对得上 UDP。
//
// 这条通路对 RDP 尤其有用: RDP 8+ 的 Enhanced RDP 会用 UDP 3389 走图形通道专门对抗
// 卡顿, 只转发 TCP 等于把它堵死。

const (
	// directDatagramHead datagram 首部长度: sessionID(4) + port(2)。
	directDatagramHead = 6
	// directUDPIdle UDP 会话空闲多久回收。UDP 无连接, 只能靠空闲判定。
	directUDPIdle = 2 * time.Minute
	// directUDPBuf 单个 UDP 包读缓冲。QUIC datagram 受 MTU 约束(约 1200 字节),
	// 超过的包送不出去, 这里留够读、由发送端判断并丢弃。
	directUDPBuf = 64 * 1024
)

// directConn C 侧一条 QUIC 连接的状态: 鉴权结果与该连接上的 UDP 会话表。
type directConn struct {
	peer *directPeer
	conn *quic.Conn

	authed atomic.Bool

	udpMu       sync.Mutex
	udpSessions map[uint32]*directUDPTarget
	udpClosed   bool
}

// directUDPTarget C 侧一条 UDP 会话: 对应对端某个用户源地址, 连到一个内网目标。
type directUDPTarget struct {
	conn *net.UDPConn
	port uint16
}

// authorize 连接级鉴权。首条 stream 必须出示服务端提前经打洞消息交给我们的一次性凭证;
// 通过后这条连接即被标记为已认证, 后续 stream 可不带凭证, datagram 也随之放行。
func (dc *directConn) authorize(token string, port uint16) bool {
	if dc.authed.Load() {
		return true
	}
	wantPort, ok := dc.peer.tokens.take(token)
	if !ok {
		return false
	}
	if wantPort != port {
		dc.peer.logf("token was issued for port %d but stream asks for %d", wantPort, port)
		return false
	}
	dc.authed.Store(true)
	return true
}

// receiveDatagrams C 侧收对端发来的 UDP 数据, 转成真正的 UDP 包发给内网目标。
func (dc *directConn) receiveDatagrams() {
	d := dc.peer
	remote := dc.conn.RemoteAddr()
	for {
		msg, err := dc.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		sessionID, port, payload, err := parseDatagram(msg)
		if err != nil {
			d.logf("datagram from %s: %v", remote, err)
			continue
		}
		// datagram 不做逐包鉴权, 但连接必须先经首条 stream 认证过。
		if !dc.authed.Load() {
			d.logf("datagram from %s before the connection was authenticated, dropped", remote)
			continue
		}
		target, err := dc.udpTarget(sessionID, port)
		if err != nil {
			d.logf("datagram from %s: %v", remote, err)
			continue
		}
		if _, err := target.conn.Write(payload); err != nil {
			d.logf("udp forward to target failed: %v", err)
		}
	}
}

// udpTarget 取(或新建)某个会话到内网目标的 UDP socket。新建时同样要过 forward 白名单。
func (dc *directConn) udpTarget(sessionID uint32, port uint16) (*directUDPTarget, error) {
	dc.udpMu.Lock()
	defer dc.udpMu.Unlock()
	if dc.udpClosed {
		return nil, errors.New("connection is closing")
	}
	if dc.udpSessions == nil {
		dc.udpSessions = make(map[uint32]*directUDPTarget)
	}
	if t, ok := dc.udpSessions[sessionID]; ok {
		if t.port != port {
			return nil, fmt.Errorf("session %d already bound to port %d, refusing port %d", sessionID, t.port, port)
		}
		return t, nil
	}
	// 与 TCP 通路共用同一张白名单。
	addr, ok := dc.peer.forward[port]
	if !ok {
		return nil, fmt.Errorf("no forward target for port %d", port)
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp target %s: %w", addr, err)
	}
	// 已连接的 socket: 只收该目标的回包, 也省掉每次发送重复解析地址。
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial udp target %s: %w", addr, err)
	}
	t := &directUDPTarget{conn: conn, port: port}
	dc.udpSessions[sessionID] = t
	dc.peer.logf("udp session %d -> %s (port %d)", sessionID, addr, port)
	go dc.pumpTargetReplies(sessionID, t)
	return t, nil
}

// pumpTargetReplies 把内网目标的回包封成 datagram 送回对端。
func (dc *directConn) pumpTargetReplies(sessionID uint32, t *directUDPTarget) {
	defer func() {
		dc.udpMu.Lock()
		if cur, ok := dc.udpSessions[sessionID]; ok && cur == t {
			delete(dc.udpSessions, sessionID)
		}
		dc.udpMu.Unlock()
		t.conn.Close()
	}()
	buf := make([]byte, directUDPBuf)
	for {
		// UDP 无连接, 只能靠空闲超时回收。
		_ = t.conn.SetReadDeadline(time.Now().Add(directUDPIdle))
		n, err := t.conn.Read(buf)
		if err != nil {
			return
		}
		if err := sendDatagram(dc.conn, sessionID, t.port, buf[:n]); err != nil {
			dc.peer.logf("udp reply for session %d dropped: %v", sessionID, err)
		}
	}
}

func (dc *directConn) closeUDPSessions() {
	dc.udpMu.Lock()
	sessions := dc.udpSessions
	dc.udpSessions = nil
	dc.udpClosed = true
	dc.udpMu.Unlock()
	for _, t := range sessions {
		t.conn.Close()
	}
}

// ---------- A 侧 ----------

// directUDPEntry A 侧一条 UDP 入口监听的状态。用户的每个源地址算一个会话, 用一个
// sessionID 在 QUIC datagram 里区分。
type directUDPEntry struct {
	peer *directPeer
	rule conf.ClientDirect
	conn *net.UDPConn

	mu       sync.Mutex
	byAddr   map[string]uint32
	byID     map[uint32]*net.UDPAddr
	lastSeen map[uint32]time.Time
	nextID   uint32
}

// listenUDPEntry 起 UDP 入口。与 TCP 入口一样, 只在进程启动时起一次。
func (d *directPeer) listenUDPEntry(r conf.ClientDirect) {
	addr, err := net.ResolveUDPAddr("udp", r.Listen)
	if err != nil {
		d.logf("direct udp entry %s: resolve failed: %v", r.Listen, err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		d.logf("direct udp entry listen %s failed: %v", r.Listen, err)
		return
	}
	e := &directUDPEntry{
		peer:     d,
		rule:     r,
		conn:     conn,
		byAddr:   make(map[string]uint32),
		byID:     make(map[uint32]*net.UDPAddr),
		lastSeen: make(map[uint32]time.Time),
	}
	d.logf("direct udp entry listening on %s -> email %s (port %d)", r.Listen, r.Email, r.Port)
	go e.run()
}

func (e *directUDPEntry) run() {
	// 每个包都要有一条已认证的 QUIC 连接: 已有就复用, 没有或已失效则重新走信令并拨号。
	e.pump(func() (*directSession, error) { return e.peer.udpSession(e.rule, e) })
}

// pump 收用户 UDP 包并转成 datagram 发走。会话获取做成参数, 便于测试直接注入一条
// 现成的连接, 不必把 websocket 信令也搭起来。
func (e *directUDPEntry) pump(getSession func() (*directSession, error)) {
	buf := make([]byte, directUDPBuf)
	for {
		n, from, err := e.conn.ReadFromUDP(buf)
		if err != nil {
			e.peer.logf("direct udp entry %s read: %v", e.rule.Listen, err)
			return
		}
		sessionID := e.sessionFor(from)
		sess, err := getSession()
		if err != nil {
			e.peer.logf("direct udp entry %s: %v", e.rule.Listen, err)
			continue
		}
		if err := sendDatagram(sess.conn, sessionID, e.rule.Port, buf[:n]); err != nil {
			e.peer.logf("direct udp entry %s: send failed: %v", e.rule.Listen, err)
		}
	}
}

// sessionFor 给用户源地址分配(或复用)一个 sessionID。
func (e *directUDPEntry) sessionFor(from *net.UDPAddr) uint32 {
	key := from.String()
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if id, ok := e.byAddr[key]; ok {
		e.lastSeen[id] = now
		return id
	}
	// 顺带回收空闲会话, 免得表随源地址无限增长。
	for id, seen := range e.lastSeen {
		if now.Sub(seen) > directUDPIdle {
			if addr, ok := e.byID[id]; ok {
				delete(e.byAddr, addr.String())
			}
			delete(e.byID, id)
			delete(e.lastSeen, id)
		}
	}
	e.nextID++
	id := e.nextID
	e.byAddr[key] = id
	e.byID[id] = from
	e.lastSeen[id] = now
	return id
}

// deliver 把对端回来的 datagram 写回对应的用户源地址。
func (e *directUDPEntry) deliver(sessionID uint32, payload []byte) {
	e.mu.Lock()
	addr, ok := e.byID[sessionID]
	if ok {
		e.lastSeen[sessionID] = time.Now()
	}
	e.mu.Unlock()
	if !ok {
		return // 会话已回收, 丢弃
	}
	if _, err := e.conn.WriteToUDP(payload, addr); err != nil {
		e.peer.logf("direct udp entry %s: reply to %s failed: %v", e.rule.Listen, addr, err)
	}
}

// ---------- datagram 编解码 ----------

func sendDatagram(conn *quic.Conn, sessionID uint32, port uint16, payload []byte) error {
	msg := make([]byte, directDatagramHead+len(payload))
	binary.BigEndian.PutUint32(msg[0:4], sessionID)
	binary.BigEndian.PutUint16(msg[4:6], port)
	copy(msg[directDatagramHead:], payload)
	err := conn.SendDatagram(msg)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		// QUIC datagram 必须装进单个 QUIC 包, 装不下的只能丢 —— 这与 UDP 本身"过大即丢"
		// 的语义一致, 但要记出来, 免得表现成莫名其妙的丢包。
		return fmt.Errorf("udp payload %d bytes exceeds the datagram limit %d, dropped", len(payload), tooLarge.MaxDatagramPayloadSize)
	}
	return err
}

func parseDatagram(msg []byte) (sessionID uint32, port uint16, payload []byte, err error) {
	if len(msg) < directDatagramHead {
		return 0, 0, nil, fmt.Errorf("datagram too short: %d bytes", len(msg))
	}
	sessionID = binary.BigEndian.Uint32(msg[0:4])
	port = binary.BigEndian.Uint16(msg[4:6])
	return sessionID, port, msg[directDatagramHead:], nil
}
