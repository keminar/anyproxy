package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/trace"
	quic "github.com/quic-go/quic-go"
)

// A 侧: 在本机起裸TCP入口监听, 每条进来的连接向服务端要一次对端端点, 然后用 QUIC
// 直接连过去。数据全程不经服务端。
//
// 与服务端上的 forward 入口(nat/forward.go)相比, 这里少了 bridge 那一整套, 因为字节
// 是直连的, 不需要在 websocket 消息里搬运。

// startEntries 起所有 client.direct 入口监听。只在进程启动时调一次: 监听不能随
// websocket 重连反复创建。
func (d *directPeer) startEntries(rules []conf.ClientDirect) {
	for _, r := range rules {
		if r.Listen == "" || r.Email == "" {
			d.logf("skip direct rule with empty listen/email: %+v", r)
			continue
		}
		if !r.ValidProtocol() {
			// 写错协议名不能静默按 tcp 处理: 配了 udp 却只起 TCP, 现象是"RDP 能连但
			// 依旧卡", 极难往配置上想。
			d.logf("skip direct rule %s: unknown protocol %q (want tcp/udp/both)", r.Listen, r.Protocol)
			continue
		}
		if r.WantTCP() {
			go d.listenEntry(r)
		}
		if r.WantUDP() {
			go d.listenUDPEntry(r)
		}
	}
}

func (d *directPeer) listenEntry(r conf.ClientDirect) {
	ln, err := net.Listen("tcp", r.Listen)
	if err != nil {
		d.logf("direct entry listen %s failed: %v", r.Listen, err)
		return
	}
	d.logf("direct entry listening on %s -> email %s (port %d)", r.Listen, r.Email, r.Port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			d.logf("direct entry accept %s: %v", r.Listen, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go d.handleEntry(conn, r)
	}
}

// handleEntry 一条入口连接: 要端点 -> 直连 -> 开流 -> 搬字节。
// 按约定这里不做中继回落, 直连不成就关掉这条连接并把原因写进日志。
func (d *directPeer) handleEntry(conn net.Conn, r conf.ClientDirect) {
	defer conn.Close()
	id := uint(forwardInc.ID())
	src := conn.RemoteAddr()
	start := time.Now()
	log.Println(trace.ID(id), fmt.Sprintf("nat direct entry accept %s -> email %s (port %d)", src, r.Email, r.Port))

	sess, stream, err := d.openStream(r)
	if err != nil {
		log.Println(trace.ID(id), fmt.Sprintf("nat direct entry %s failed: %v", src, err))
		return
	}
	defer stream.Close()
	// 计入引用: 连接空闲回收要靠它区分"没人用"和"用着但暂时没数据"(RDP 常有长时间静默)。
	sess.acquire()
	defer sess.release()

	up, down := directCopy(conn, stream)
	log.Println(trace.ID(id), fmt.Sprintf("nat direct entry closed %s up=%d down=%d dur=%s",
		src, up, down, time.Since(start).Round(time.Second)))
}

// openStream 拿到一条承载数据的 QUIC stream, 并一并返回它所属的连接(调用方要
// acquire/release 以参与空闲回收的判断)。
func (d *directPeer) openStream(r conf.ClientDirect) (*directSession, *quic.Stream, error) {
	sess, err := d.ensureSession(r)
	if err != nil {
		return nil, nil, err
	}
	// 连接已在 ensureSession 里认证过, 数据流不必再带凭证。QUIC 的 stream 相互独立,
	// 一条连接上并发多个会话不会像单条 TCP 复用那样互相队头阻塞。
	stream, err := d.openHeadedStream(sess, directStreamData, "", r.Port)
	if err == nil {
		return sess, stream, nil
	}
	// 连接可能已被对端关掉、空闲回收掉或超时老化, 丢弃后完整重建一次。
	d.dropSession(r.Email, sess)
	d.logf("reusing quic session to %s failed (%v), rebuilding", r.Email, err)
	sess, err = d.ensureSession(r)
	if err != nil {
		return nil, nil, err
	}
	stream, err = d.openHeadedStream(sess, directStreamData, "", r.Port)
	if err != nil {
		return nil, nil, err
	}
	return sess, stream, nil
}

// ensureSession 取一条**已认证**的 QUIC 连接: 有就复用, 没有就走一遍信令 + 拨号 + 鉴权。
// TCP 与 UDP 两条通路共用它。
func (d *directPeer) ensureSession(r conf.ClientDirect) (*directSession, error) {
	if sess := d.session(r.Email); sess != nil {
		return sess, nil
	}
	// A 侧也需要自己的 socket: QUIC 从它拨出去, 它的端点还要报给服务端, 好让 C 朝它
	// 打洞。没开 directAccept 的机器在这里按需建一个; 开了的复用监听那一个。
	tr, err := d.ensureTransport()
	if err != nil {
		return nil, fmt.Errorf("prepare local udp socket: %w", err)
	}
	token, offer, err := d.requestPeer(r)
	if err != nil {
		return nil, err
	}
	// 多条候选同时打洞, 按 RTT + 地址类型偏置选出最优的那条, 再只对它做一次 QUIC 拨号。
	// 不对每条候选都拨 QUIC: 那是 N 次完整握手, 而打洞包一来一回就够判断通不通与快慢。
	winner, err := d.pickPeerAddr(r.Email, offer.PeerAddrs)
	if err != nil {
		return nil, err
	}
	sess, err := d.connectPeer(tr, r.Email, winner.Addr, offer.Fingerprint)
	if err != nil {
		return nil, err
	}
	if err := d.authenticateSession(sess, token, r.Port); err != nil {
		d.dropSession(r.Email, sess)
		return nil, err
	}
	// 回程 datagram 的分发依赖这条 goroutine, TCP-only 的连接上它只是空转等关闭。
	go d.receiveDatagrams(sess)
	return sess, nil
}

// authenticateSession 开一条纯鉴权流出示凭证, 并等对端确认。
//
// 必须等确认: 认证完成前对端会丢弃 datagram, 不等就发 UDP 会静默掉包。
func (d *directPeer) authenticateSession(sess *directSession, token string, port uint16) error {
	stream, err := d.openHeadedStream(sess, directStreamAuth, token, port)
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(directDialWait))
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil {
		return fmt.Errorf("peer did not accept our token: %w", err)
	}
	return nil
}

// receiveDatagrams A 侧收回程 UDP 数据, 按端口找到对应入口投递回用户。
func (d *directPeer) receiveDatagrams(sess *directSession) {
	for {
		msg, err := sess.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		sessionID, port, payload, err := parseDatagram(msg)
		if err != nil {
			d.logf("bad datagram from %s: %v", sess.addr, err)
			continue
		}
		entry := sess.udpEntry(port)
		if entry == nil {
			continue // 没有对应入口(规则已撤或端口对不上), 丢弃
		}
		entry.deliver(sessionID, payload)
	}
}

// udpSession 给 UDP 入口取一条已认证的连接, 并登记好回程分发。
func (d *directPeer) udpSession(r conf.ClientDirect, e *directUDPEntry) (*directSession, error) {
	sess, err := d.ensureSession(r)
	if err != nil {
		return nil, err
	}
	sess.bindUDPEntry(r.Port, e)
	return sess, nil
}

// requestPeer 走一趟信令: 生成一次性凭证、把本机端点报给服务端(服务端据此让对端朝我们
// 打洞)、等回对端的端点与指纹。返回的 token 就是本次要在流首部出示的那个。
func (d *directPeer) requestPeer(r conf.ClientDirect) (string, DirectOffer, error) {
	var offer DirectOffer
	token, err := newDirectToken()
	if err != nil {
		return "", offer, err
	}
	// 每次都重新收集候选: 隐私临时地址会轮换、NAT 映射会老化重建, 上一次的结果可能
	// 已经作废。多条路并行探, 少一条不影响其它条。
	myCands, err := d.gatherCandidates()
	if err != nil {
		return "", offer, fmt.Errorf("determine my own quic endpoints: %w", err)
	}
	d.setMyCandidates(myCands)

	offerCh := make(chan DirectOffer, 1)
	d.mu.Lock()
	d.reqInc++
	reqID := uint(d.reqInc)
	d.offers[reqID] = offerCh
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.offers, reqID)
		d.mu.Unlock()
	}()

	// 把本端的地址都打出来: 本地 socket 端口用于抓包定位, 各候选用于判断哪些路探到了、
	// 哪些没探到 —— 排查直连问题时这些缺一不可。
	d.logf("requesting %s: local socket port %d, my candidates %v", r.Email, d.localUDPPort(), myCands)

	req := DirectRequest{Email: r.Email, Port: r.Port, Token: token,
		Candidates: myCands, Endpoint: firstAddr(myCands)}
	if err := d.send(METHOD_DIRECT_REQUEST, reqID, req); err != nil {
		return "", offer, fmt.Errorf("ask server for peer endpoint: %w", err)
	}

	select {
	case offer = <-offerCh:
	case <-time.After(directOfferWait):
		return "", offer, errors.New("timed out waiting for peer endpoint from server")
	}
	if offer.Err != "" {
		return "", offer, errors.New(offer.Err)
	}
	offer.PeerAddrs = mergeCandidates(offer.PeerAddrs, offer.PeerAddr)
	if len(offer.PeerAddrs) == 0 || offer.Fingerprint == "" {
		return "", offer, errors.New("server returned an incomplete offer")
	}
	d.logf("server says %s has candidates %v (fingerprint %s)",
		r.Email, offer.PeerAddrs, shortFP(offer.Fingerprint))
	return token, offer, nil
}

// pickPeerAddr 朝对端的所有候选同时打洞并测 RTT, 再按 RTT + 地址类型偏置选一条。
//
// 并行而不是逐条试: 逐条的话前面几条不通就要各等一个超时, 轮到能用的那条时入口连接
// 早就超时了。并行发出去, 谁先回谁先被观测到; 多条都回才谈优先级。
func (d *directPeer) pickPeerAddr(email string, cands []directCandidate) (directCandidate, error) {
	results := d.punchAll(cands)
	winner, err := selectCandidate(results)
	if err != nil {
		return directCandidate{}, fmt.Errorf("no path to %s: %w", email, err)
	}
	// 把每条候选的 RTT、偏置、得分都打出来。选了哪条、为什么选它, 不打就只能靠猜;
	// 而"为什么没走 IPv6"这类问题恰恰只有这一行答得了。
	d.logf("path selection for %s: %s", email, describeResults(results, winner))
	return winner, nil
}

// connectPeer 按服务端给的端点与指纹建立 QUIC 连接并登记复用。信令之外的部分独立成
// 一个方法, 便于不经 websocket 直接测试数据路径。
func (d *directPeer) connectPeer(tr *quic.Transport, email, peerAddr, fingerprint string) (*directSession, error) {
	// udp 而不是 udp6: socket 是双栈的, IPv4 与 IPv6 候选都可能胜出。
	udpAddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("peer endpoint %s is not a usable address: %w", peerAddr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), directDialWait)
	defer cancel()
	conn, err := tr.Dial(ctx, udpAddr, directClientTLS(fingerprint), directQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("quic dial %s: %w", peerAddr, err)
	}
	d.logf("quic connected to email %s at %s", email, peerAddr)
	sess := &directSession{conn: conn, addr: peerAddr}
	d.putSession(email, sess)
	return sess, nil
}

// openHeadedStream 在已建立的连接上开一条流并写好首部。
func (d *directPeer) openHeadedStream(sess *directSession, kind, token string, port uint16) (*quic.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), directDialWait)
	defer cancel()
	stream, err := sess.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open quic stream: %w", err)
	}
	if err := writeStreamHead(stream, directStreamHead{Kind: kind, Token: token, Port: port}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write stream head: %w", err)
	}
	return stream, nil
}

// onOffer 把服务端回的 offer 交给等待中的请求。
func (d *directPeer) onOffer(msg *Message) {
	var offer DirectOffer
	if err := decodeDirect(msg.Body, &offer); err != nil {
		d.logf("bad offer: %v", err)
		return
	}
	d.mu.Lock()
	ch, ok := d.offers[msg.ID]
	d.mu.Unlock()
	if !ok {
		d.logf("offer for unknown request id %d (timed out already?)", msg.ID)
		return
	}
	select {
	case ch <- offer:
	default: // 等待方已经超时退出, 丢弃即可
	}
}

func (d *directPeer) session(email string) *directSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessions[email]
}

func (d *directPeer) putSession(email string, s *directSession) {
	d.mu.Lock()
	d.sessions[email] = s
	d.mu.Unlock()
}

// reapSessions 周期性关掉不再使用的 QUIC 连接。
//
// 必须自己收: 活跃期间要开 keep-alive 焐住 IPv6 防火墙的洞, 而 keep-alive 会一直把
// QUIC 自己的空闲超时顶回去, 连接不会自然死亡。不收的话, 每台连过本机的对端都会留下
// 一条永久连接和永不停歇的保活包。
func (d *directPeer) reapSessions() {
	t := time.NewTicker(directReapEvery)
	defer t.Stop()
	for range t.C {
		d.logUDPTraffic()
		var stale []string
		d.mu.Lock()
		for email, s := range d.sessions {
			if s.idleFor() > directSessionIdle {
				stale = append(stale, email)
			}
		}
		for _, email := range stale {
			s := d.sessions[email]
			delete(d.sessions, email)
			// 在锁内取出、锁外关闭, 避免关连接的耗时挡住其它请求。
			go func(email string, s *directSession) {
				d.logf("closing idle quic session to %s (idle %s)", email, s.idleFor().Round(time.Second))
				_ = s.conn.CloseWithError(0, "idle")
			}(email, s)
		}
		d.mu.Unlock()
	}
}

// logUDPTraffic 周期汇报各 UDP 入口的累计流量。
//
// TCP 那条路每条连接关闭时会打一行 up/down 汇总, 但 UDP 没有"关闭"事件, 不主动汇报
// 就完全看不出数据有没有在走 —— 排查"mstsc 到底用上 UDP 图形通道没有"时, 这是唯一
// 能直接回答的依据。只在有变化时打, 免得空闲期刷屏。
func (d *directPeer) logUDPTraffic() {
	d.mu.Lock()
	entries := make(map[uint16]*directUDPEntry)
	for _, s := range d.sessions {
		s.udpMu.Lock()
		for port, e := range s.udpEntries {
			entries[port] = e
		}
		s.udpMu.Unlock()
	}
	d.mu.Unlock()

	for _, e := range entries {
		up, upPkts, down, downPkts := e.stats()
		if up == 0 && down == 0 {
			continue
		}
		last := e.lastReported.Swap(up + down)
		if last == up+down {
			continue // 这一轮没有新流量
		}
		d.logf("direct udp %s -> email %s: sessions=%d up=%dB/%dpkt down=%dB/%dpkt",
			e.rule.Listen, e.rule.Email, e.sessionCount(), up, upPkts, down, downPkts)
	}
}

// dropSession 仅在当前记录仍是这条失效连接时删除, 避免把别的 goroutine 刚建好的新连接误删。
func (d *directPeer) dropSession(email string, stale *directSession) {
	d.mu.Lock()
	if d.sessions[email] == stale {
		delete(d.sessions, email)
	}
	d.mu.Unlock()
	if stale != nil && stale.conn != nil {
		_ = stale.conn.CloseWithError(0, "rebuilding")
	}
}
