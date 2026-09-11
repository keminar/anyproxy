package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
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
			d.logf("skip direct rule %s: unknown protocol %q (want tcp://, udp://, both://, or no prefix for tcp)", r.Listen, r.Protocol())
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
	ln, err := net.Listen("tcp", r.Addr())
	if err != nil {
		d.logf("direct entry listen %s failed: %v", r.Listen, err)
		return
	}
	d.logf("direct entry listening on %s -> email %s (port %d)", r.Listen, r.Email, r.ForwardPort)
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
	log.Println(trace.ID(id), fmt.Sprintf("nat direct entry accept %s -> email %s (port %d)", src, r.Email, r.ForwardPort))

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
	dur := time.Since(start)
	log.Println(trace.ID(id), fmt.Sprintf("nat direct entry closed %s up=%d(%s) down=%d(%s) dur=%s",
		src, up, rate(up, dur), down, rate(down, dur), dur.Round(time.Second)))
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
	stream, err := d.openHeadedStream(sess, directStreamData, "", r.ForwardPort)
	if err == nil {
		return sess, stream, nil
	}
	// 连接可能已被对端关掉、空闲回收掉或超时老化, 丢弃后完整重建一次。
	d.dropSession(r.Email, sess, r.ForwardPort)
	d.logf("reusing quic session to %s failed (%v), rebuilding", r.Email, err)
	sess, err = d.ensureSession(r)
	if err != nil {
		return nil, nil, err
	}
	stream, err = d.openHeadedStream(sess, directStreamData, "", r.ForwardPort)
	if err != nil {
		return nil, nil, err
	}
	return sess, stream, nil
}

// ensureSession 取一条**已认证**的 QUIC 连接: 有就复用, 没有就走一遍信令 + 拨号 + 鉴权。
// TCP 与 UDP 两条通路共用它。
func (d *directPeer) ensureSession(r conf.ClientDirect) (*directSession, error) {
	if sess := d.session(r.Email, r.ForwardPort); sess != nil {
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
	// 不是每条候选都拨 QUIC: 打洞包一来一回就够判断通不通与快慢, 通常犯不着为选路
	// 多付出 N 次完整握手的成本。
	var sess *directSession
	winner, punchErr := d.pickPeerAddr(r.Email, token, offer.PeerAddrs)
	if punchErr == nil {
		sess, err = d.connectPeer(tr, r.Email, winner.Addr, offer.Fingerprint, r.ForwardPort)
	} else {
		// 打洞全灭才退这一步: 有状态防火墙/运营商设备可能按明文特征拦了自定义 PUNCH
		// 协议, 但同一个 socket 上真实的 QUIC Initial 包(标准 TLS 1.3 握手)不容易被
		// 针对性拦截。不再像以前那样从候选列表里盲选一条去赌, 而是对**所有**候选并行
		// 发起真实拨号竞速, 谁先握手成功用谁(见 raceQUICDial)。
		d.logf("path selection for %s: punch all failed (%v), falling back to a quic dial race across all candidates",
			r.Email, punchErr)
		sess, err = d.raceQUICDial(tr, r.Email, offer.Fingerprint, offer.PeerAddrs, r.ForwardPort)
	}
	if err != nil {
		return nil, err
	}
	if err := d.authenticateSession(sess, token, r.ForwardPort); err != nil {
		d.dropSession(r.Email, sess, r.ForwardPort)
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
	sess.bindUDPEntry(r.ForwardPort, e)
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
	// 打洞加密准备放在最前面: 配置有误(uuid 缺失/非法)就直接失败, 不用先浪费一趟
	// 候选收集与信令往返。isInitiator=true: 用自己的 uuid, 不需要查表。按 client
	// 一次性开关(d.cfg.DirectEncrypt), 不是按 r 这条规则单独配——同一个 uuid 身份
	// 发起的所有打洞(direct[] 规则或 -send/-recv)共用同一个决定。
	if errMsg := d.prepareDirectCrypto(token, d.cfg.DirectEncrypt, true, ""); errMsg != "" {
		return "", offer, errors.New(errMsg)
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
	// 哪些没探到 —— 排查直连问题时这些缺一不可。encrypt 一起打出来, 排查"punch 是不是
	// 用了加密"不用再翻配置反推。
	d.logf("requesting %s: local socket port %d, my candidates %v, encrypt=%v",
		r.Email, d.localUDPPort(), myCands, d.cfg.DirectEncrypt)

	req := DirectRequest{Email: r.Email, Port: r.ForwardPort, Token: token,
		Candidates: myCands, Endpoint: firstAddr(myCands), Encrypt: d.cfg.DirectEncrypt}
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
// 全灭(没有一条候选打洞成功)时把 selectCandidate 的错误原样返回, 是否转入
// raceQUICDial 兜底由调用方(ensureSession)决定。
//
// 并行而不是逐条试: 逐条的话前面几条不通就要各等一个超时, 轮到能用的那条时入口连接
// 早就超时了。并行发出去, 谁先回谁先被观测到; 多条都回才谈优先级。
func (d *directPeer) pickPeerAddr(email, token string, cands []directCandidate) (directCandidate, error) {
	results := d.punchAll(token, cands)
	winner, err := selectCandidate(results)
	if err != nil {
		return directCandidate{}, err
	}
	// 把每条候选的 RTT、偏置、得分都打出来。选了哪条、为什么选它, 不打就只能靠猜;
	// 而"为什么没走 IPv6"这类问题恰恰只有这一行答得了。
	d.logf("path selection for %s: %s", email, describeResults(results, winner))
	return winner, nil
}

// connectPeer 按服务端给的端点与指纹建立 QUIC 连接并登记复用。信令之外的部分独立成
// 一个方法, 便于不经 websocket 直接测试数据路径。
func (d *directPeer) connectPeer(tr *quic.Transport, email, peerAddr, fingerprint string, port ...uint16) (*directSession, error) {
	sess, err := d.dialQUIC(tr, email, peerAddr, fingerprint)
	if err != nil {
		return nil, err
	}
	// Token 鉴权绑定到端口；按 email+port 复用，避免已鉴权连接跨端口访问。
	d.putSession(email, sess, port...)
	return sess, nil
}

// dialQUIC 只做拨号, 不登记进 d.sessions。单独拆出来是给 raceQUICDial 用的: 竞速时
// 可能不止一条候选握手成功, 只有最终选中的那条才该进 sessions 表——提前登记的话,
// 后一条握手成功的连接会覆盖掉先登记的那条, 调用方手里攥着的"赢家"引用就和
// sessions 表里的实际记录对不上了。
func (d *directPeer) dialQUIC(tr *quic.Transport, email, peerAddr, fingerprint string) (*directSession, error) {
	// udp 而不是 udp6: socket 是双栈的, IPv4 与 IPv6 候选都可能胜出。
	udpAddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("peer endpoint %s is not a usable address: %w", peerAddr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), directDialWait)
	defer cancel()
	stats := &directStats{logf: d.logf}
	conn, err := tr.Dial(ctx, udpAddr, directClientTLS(fingerprint), directQUICConfigWithStats(stats))
	if err != nil {
		return nil, fmt.Errorf("quic dial %s: %w", peerAddr, err)
	}
	d.logf("quic connected to email %s at %s", email, peerAddr)
	return &directSession{conn: conn, addr: peerAddr, stats: stats}, nil
}

// directDialAttempt 一次候选拨号竞速的结果。
type directDialAttempt struct {
	sess *directSession
	addr string
	err  error
}

// raceQUICDial 打洞全灭之后的兜底: 对**所有**候选并行发起真实 QUIC 拨号, 谁先握手
// 成功就用谁。比以前"从候选列表里盲选第一条去赌"更彻底——有状态防火墙/运营商设备
// 可能按明文特征拦了自定义 PUNCH 协议, 但走同一个 socket 的真实 QUIC Initial 包
// (标准 TLS 1.3 握手)不容易被针对性拦截, 值得每条候选都真的试一次握手, 而不是赌
// 赌看蒙对的是不是那条能通的。
//
// 可能不止一条候选握手成功(比如两条网络当时都通): 谁先答应谁当选, 其余晚到的一律
// 关掉(见 drainDialRace)——这里只负责兜底最坏情况, 犯不着为一个小概率的"两条都通"
// 场景做更复杂的比较/保留逻辑。
func (d *directPeer) raceQUICDial(tr *quic.Transport, email, fingerprint string, cands []directCandidate, port uint16) (*directSession, error) {
	resultCh := make(chan directDialAttempt, len(cands))
	attempted := 0
	for _, c := range cands {
		if _, err := net.ResolveUDPAddr("udp", c.Addr); err != nil {
			continue // 本机就解析不了的候选(如没有那一族地址), 重试无益, 直接跳过
		}
		attempted++
		go func(c directCandidate) {
			d.logf("quic dial race for %s: trying %s", email, c.Addr)
			sess, err := d.dialQUIC(tr, email, c.Addr, fingerprint)
			resultCh <- directDialAttempt{sess: sess, addr: c.Addr, err: err}
		}(c)
	}
	if attempted == 0 {
		return nil, fmt.Errorf("no path to %s: no usable candidate to dial", email)
	}

	var errs []string
	for i := 0; i < attempted; i++ {
		r := <-resultCh
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.addr, r.err))
			continue
		}
		d.logf("quic dial race for %s: %s answered first, using it", email, r.addr)
		d.putSession(email, r.sess, port)
		// 剩下还在飞的拨号不用等在这里: 赢家已经能用了, 让它们在后台各自收尾。
		go d.drainDialRace(email, r.addr, resultCh, attempted-i-1)
		return r.sess, nil
	}
	return nil, fmt.Errorf("quic dial race for %s: all %d candidate(s) failed (%s)", email, attempted, strings.Join(errs, "; "))
}

// drainDialRace 赢家已经决出后, 后台把还没返回的拨号结果收尾: 握手成功的多余连接
// 直接关掉(赢家已经在用了, 留着就是纯粹的连接和 keep-alive 泄漏), 失败的只打个日志。
func (d *directPeer) drainDialRace(email, winnerAddr string, ch <-chan directDialAttempt, remaining int) {
	for i := 0; i < remaining; i++ {
		r := <-ch
		if r.err != nil {
			d.logf("quic dial race for %s: %s failed (winner %s already in use): %v", email, r.addr, winnerAddr, r.err)
			continue
		}
		d.logf("quic dial race for %s: %s also answered after %s already won, closing the extra connection",
			email, r.addr, winnerAddr)
		_ = r.sess.conn.CloseWithError(0, "quic dial race: a faster candidate already won")
	}
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

func sessionKey(email string, port ...uint16) string {
	if len(port) == 0 {
		return email // compatibility for tests and legacy internal callers
	}
	return fmt.Sprintf("%s#%d", email, port[0])
}

func (d *directPeer) session(email string, port ...uint16) *directSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessions[sessionKey(email, port...)]
}

func (d *directPeer) putSession(email string, s *directSession, port ...uint16) {
	d.mu.Lock()
	d.sessions[sessionKey(email, port...)] = s
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
		snap, ok := e.traffic.snapshot()
		if !ok {
			continue // 这一轮没有新流量, 或还没有上一轮可比
		}
		d.logf("direct udp %s -> email %s: sessions=%d up=%dB/%dpkt(%s) down=%dB/%dpkt(%s)",
			e.rule.Listen, e.rule.Email, e.sessionCount(),
			snap.UpBytes, snap.UpPkts, snap.UpRate, snap.DownBytes, snap.DownPkts, snap.DownRate)
	}
}

// dropSession 仅在当前记录仍是这条失效连接时删除, 避免把别的 goroutine 刚建好的新连接误删。
func (d *directPeer) dropSession(email string, stale *directSession, port ...uint16) {
	d.mu.Lock()
	key := sessionKey(email, port...)
	if d.sessions[key] == stale {
		delete(d.sessions, key)
	}
	d.mu.Unlock()
	if stale != nil && stale.conn != nil {
		_ = stale.conn.CloseWithError(0, "rebuilding")
	}
}
