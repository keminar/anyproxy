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
		if r.Listen == "" || r.Forward.Email == "" {
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

// bindRetry 在 directListenRetryWindow 窗口内重试 try, 用于扛过 kill -HUP 平滑重启时
// 旧进程还没退出、端口暂时被占用的重叠期, 避免第一次绑定失败就永久放弃入口监听。
func bindRetry(try func() error) error {
	deadline := time.Now().Add(directListenRetryWindow)
	err := try()
	for err != nil && time.Now().Before(deadline) {
		time.Sleep(directListenRetryInterval)
		err = try()
	}
	return err
}

func (d *directPeer) listenEntry(r conf.ClientDirect) {
	var ln net.Listener
	err := bindRetry(func() (err error) {
		ln, err = net.Listen("tcp", r.Addr())
		return err
	})
	if err != nil {
		d.logf("direct entry listen %s failed: %v", r.Listen, err)
		return
	}
	d.logf("direct entry listening on %s -> email %s (tag %q)", r.Listen, r.Forward.Email, r.Forward.Tag)
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
	log.Println(trace.ID(id), fmt.Sprintf("nat direct entry accept %s -> email %s (tag %q)", src, r.Forward.Email, r.Forward.Tag))

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
	route := sessionRouteForRule(r)
	sess, err := d.ensureSession(r)
	if err != nil {
		return nil, nil, err
	}
	// 连接已在 ensureSession 里认证过, 数据流不必再带凭证。QUIC 的 stream 相互独立,
	// 一条连接上并发多个会话不会像单条 TCP 复用那样互相队头阻塞。
	stream, err := d.openDataStream(sess, r.Forward.Tag)
	if err == nil {
		return sess, stream, nil
	}
	// 对端明确拒绝(配置问题, 比如 tag 没有 forward 映射)不代表连接坏了: session 留着
	// 复用, 不重建——重建了下一条流照样会被拒, 只是白白重打一次洞。
	var rejected *directRejectedError
	if errors.As(err, &rejected) {
		return nil, nil, err
	}
	// 连接可能已被对端关掉、空闲回收掉或超时老化, 丢弃后完整重建一次。
	d.dropSession(r.Forward.Email, sess, route)
	d.logf("reusing quic session to %s failed (%v), rebuilding", r.Forward.Email, err)
	sess, err = d.ensureSession(r)
	if err != nil {
		return nil, nil, err
	}
	stream, err = d.openDataStream(sess, r.Forward.Tag)
	if err != nil {
		return nil, nil, err
	}
	return sess, stream, nil
}

// ensureSession 取一条**已认证**的 QUIC 连接: 有就复用, 没有就走一遍信令 + 拨号 + 鉴权。
// TCP 与 UDP 两条通路共用它。
func (d *directPeer) ensureSession(r conf.ClientDirect) (*directSession, error) {
	route := sessionRouteForRule(r)
	if sess := d.session(r.Forward.Email, route); sess != nil {
		return sess, nil
	}
	sess, err := d.newDirectSession(r)
	if err != nil {
		return nil, err
	}
	d.putSession(r.Forward.Email, sess, route)
	return sess, nil
}

// ensureParallelSessions 拿到最多 n 条相互独立的 QUIC 连接, 供单次文件传输把不同的
// 分块分摊到不同连接上跑, 不共享同一条连接的拥塞窗口——链路有丢包时单流的拥塞窗口
// 长不大(实测见 -parallel 相关讨论), 独立连接各自维护自己的窗口, 聚合吞吐能接近
// 线性提升。
//
// n<=1 时完全退化成 ensureSession, 走查缓存/复用那条老路——非并行调用方、以及文件
// 不够大不需要切块的场景, 行为分毫不变。
//
// n>1 时并发发起 n 次独立打洞/QUIC 拨号, 都不进 d.sessions 复用缓存(见
// newDirectSession 的注释): 这些连接是这一次传输独占使用的, 不该被其它请求当现成
// 连接捞走, 也不该被 reapSessions 当成"空闲太久"的普通连接收掉。
//
// 失败策略是"能打通几条就用几条": 至少 1 条成功就返回, 其余打不通的记日志跳过,
// 不因为个别候选路径不通(现实中很常见, 比如某几条网络确实互相到不了)就让整个
// 传输失败——这跟 n<=1 时"唯一一条打不通就报错"的下限是一致的, 只是下限从"必须
// 那 1 条"变成"至少要有 1 条"。
func (d *directPeer) ensureParallelSessions(r conf.ClientDirect, n int) ([]*directSession, error) {
	if n <= 1 {
		sess, err := d.ensureSession(r)
		if err != nil {
			return nil, err
		}
		return []*directSession{sess}, nil
	}
	type dialResult struct {
		sess *directSession
		err  error
	}
	results := make(chan dialResult, n)
	for i := 0; i < n; i++ {
		go func() {
			sess, err := d.newDirectSession(r)
			results <- dialResult{sess: sess, err: err}
		}()
	}
	var sessions []*directSession
	var errs []string
	for i := 0; i < n; i++ {
		res := <-results
		if res.err != nil {
			errs = append(errs, res.err.Error())
			continue
		}
		sessions = append(sessions, res.sess)
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("all %d parallel connect attempt(s) to %s failed: %s", n, r.Forward.Email, strings.Join(errs, "; "))
	}
	if len(errs) > 0 {
		d.logf("parallel connect to %s: %d/%d independent connection(s) established, %d failed (%s)",
			r.Forward.Email, len(sessions), n, len(errs), strings.Join(errs, "; "))
	}
	return sessions, nil
}

// newDirectSession 打一次洞、建一条全新的、已认证的 QUIC 连接, 不查也不占用
// d.sessions 那张单槽位的复用缓存——ensureSession(单连接、要复用)与
// ensureParallelSessions(n>1、每条都要独立、不给复用)共用这同一段"怎么连上对面"
// 的逻辑, 缓存要不要收编交给调用方决定。
//
// 底层的 connectPeer/raceQUICDial 仍会在拨通的一瞬间把连接短暂写进 d.sessions(这是
// 它们对所有调用方统一的收尾动作, 不值得为这一个新增用途去改这两个被广泛调用的
// 函数)——建完这里立刻用 dropSession 撤销登记, 确保方法返回时这条连接不残留在
// reapSessions 会扫到的那张表里。
func (d *directPeer) newDirectSession(r conf.ClientDirect) (*directSession, error) {
	route := sessionRouteForRule(r)
	// A 侧也需要自己的 socket: QUIC 从它拨出去, 它的端点还要报给服务端, 好让 C 朝它
	// 打洞。没开 directAccept 的机器在这里按需建一个; 开了的复用监听那一个。
	tr, err := d.ensureTransport()
	if err != nil {
		return nil, fmt.Errorf("prepare local udp socket: %w", err)
	}
	token, hs, err := d.requestPeer(r)
	if err != nil {
		return nil, err
	}
	// 两种 nudge 的**时机相反**, 别混:
	//
	// order Y(普通直连 + directPunchFirst): 对端正停着等信号(见 direct_accept.go 的 parkPunch),
	//   所以 nudge 必须**早于**本机第一个 UDP 包发出去, 对端才会在本机打之前就开始打; nudge
	//   丢了也不卡: 对端有 directPunchFirstDelay 兜底。详见 docs/direct-punch-order.md。
	//
	// 中继(r.Via 非空): 反过来, 必须**本机先朝 E 打出第一个包**, 再经 B 告知 VPS"我打过了",
	//   VPS 收到才敢朝本侧打回来(它自己前面那层有状态防火墙/安全组只放行"本机先发过"的
	//   回程, 见 direct_relay.go 的 punchLeg)。顺序靠 punchAllThen 的回调硬保证——回调打在
	//   第一个 UDP 包 WriteTo 成功之后, 不靠"直达比经 B 转一圈快"这种调度上的侥幸。
	var afterFirstPunch func()
	switch {
	case r.Via != "":
		afterFirstPunch = func() {
			if err := d.sendRelayNudge(token); err != nil {
				d.logf("relay: send nudge for token %s failed: %v", shortToken(token), err)
			}
		}
	case d.cfg.Direct.PunchFirst:
		if err := d.send(METHOD_DIRECT_PUNCHING, 0, DirectPunching{Email: r.Forward.Email, Token: token}); err != nil {
			d.logf("send punch-first nudge to %s failed: %v (peer will fall back to its timed delay)", r.Forward.Email, err)
		}
	}
	// **端点一到就先打洞**, 不等指纹: 两段式 offer(中继)里第一段只带中继端点 E, 而 C 那边的
	// "朝 E 打洞 -> 回候选与指纹"还要绕 B 一圈(实测秒级), A 现在就能边打边等, 两段重叠。
	// 直连、或服务端不支持两段时, 这里就是收到完整 offer 的那一刻, 与以前完全一致。
	//
	// 中继腿的发包窗口要给满 directPunchWait(见 punchSendSpan): 早打意味着很可能在 C 打出
	// 第一发、VPS 登记好那条腿之前就开打, 而转发要等两腿都被听到 —— 这段时间里"没有 pong"
	// 只说明中间层还没就绪, 所以必须一直敲到预算结束, 而不是发满 6 个就干等/退到兜底。
	run := d.startPunchAllFor(token, hs.addrs, afterFirstPunch, punchSendSpan(r.Via != ""))
	final, err := hs.waitFinal(directOfferWait)
	hs.close()
	if err != nil {
		return nil, err
	}
	// 多条候选同时打洞, 按 RTT + 地址类型偏置选出最优的那条, 再只对它做一次 QUIC 拨号。
	// 不是每条候选都拨 QUIC: 打洞包一来一回就够判断通不通与快慢, 通常犯不着为选路
	// 多付出 N 次完整握手的成本。择优**不等所有候选**(见 pickPeerAddr)。
	var sess *directSession
	winner, punchErr := d.pickPeerAddr(r.Forward.Email, run)
	if punchErr == nil {
		sess, err = d.connectPeer(tr, r.Forward.Email, winner.Addr, final.Fingerprint, route)
	} else {
		// 打洞全灭才退这一步: 有状态防火墙/运营商设备可能按明文特征拦了自定义 PUNCH
		// 协议, 但同一个 socket 上真实的 QUIC Initial 包(标准 TLS 1.3 握手)不容易被
		// 针对性拦截。不再像以前那样从候选列表里盲选一条去赌, 而是对**所有**候选并行
		// 发起真实拨号竞速, 谁先握手成功用谁(见 raceQUICDial)。
		d.logf("path selection for %s: punch all failed (%v), falling back to a quic dial race across all candidates",
			r.Forward.Email, punchErr)
		sess, err = d.raceQUICDial(tr, r.Forward.Email, final.Fingerprint, hs.addrs, route)
	}
	if err != nil {
		return nil, err
	}
	if err := d.authenticateSession(sess, token, r.Forward.Tag, r.Via != "", final.Fingerprint); err != nil {
		d.dropSession(r.Forward.Email, sess, route)
		return nil, err
	}
	// 回程 datagram 的分发依赖这条 goroutine, TCP-only 的连接上它只是空转等关闭。
	go d.receiveDatagrams(sess)
	// 撤销 connectPeer/raceQUICDial 刚才做的登记: 这个方法不负责决定要不要复用,
	// 交给调用方(ensureSession 会重新登记一次, ensureParallelSessions 不会)。
	//
	// 不能用 dropSession——它是给"连接确实坏了、该整个关掉重建"这个场景用的, 除了
	// 摘缓存还会顺手把连接关掉(CloseWithError); 这里连接刚握手成功、完全健康,
	// 只是不想让它赖在复用缓存里, 用 unregisterSession 只摘缓存记录, 不碰连接本身。
	d.unregisterSession(r.Forward.Email, sess, route)
	return sess, nil
}

// authenticateSession 开一条纯鉴权流出示凭证, 并等对端确认。
//
// 必须等确认: 认证完成前对端会丢弃 datagram, 不等就发 UDP 会静默掉包。
//
// 中继连接(relay=true)在出示 token 之后、等确认之前, 还要应答 C 的 uuid 挑战(见
// direct_relay_auth.go): C 经不可信 VPS 转来, 要靠这步确认对面确是允许的 A。fingerprint 是
// C 的证书指纹(A 用它固定 TLS, 也把它绑进应答防中继层重放)。
func (d *directPeer) authenticateSession(sess *directSession, token string, tag string, relay bool, fingerprint string) error {
	stream, err := d.openHeadedStream(sess, directStreamAuth, token, tag)
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	defer stream.Close()
	if relay {
		if err := answerRelayChallenge(stream, d.cfg.UUID, fingerprint); err != nil {
			return fmt.Errorf("relay auth: %w", err)
		}
	}
	_ = stream.SetReadDeadline(time.Now().Add(directDialWait))
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil {
		return fmt.Errorf("peer did not accept our token: %w", err)
	}
	if ack[0] != directAuthACK {
		return fmt.Errorf("peer returned invalid auth ack %d", ack[0])
	}
	// 新版 C 在兼容旧版单字节 ACK 的前提下追加一个能力字节。旧版 C 写完一个字节就关流，
	// 这里会立刻读到 EOF，仍视为鉴权成功，只是不启用 ready ACK。
	var capability [1]byte
	if _, capErr := io.ReadFull(stream, capability[:]); capErr == nil && capability[0] == directCapReadyACK {
		sess.streamReady.Store(true)
	}
	_ = stream.SetReadDeadline(time.Time{})
	return nil
}

// receiveDatagrams A 侧收回程 UDP 数据, 投递回这条连接绑定的那个入口(一条 session
// 严格对应一条规则, 见 directSession.boundUDPEntry 的注释)。
func (d *directPeer) receiveDatagrams(sess *directSession) {
	for {
		msg, err := sess.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		sessionID, payload, err := parseDatagram(msg)
		if err != nil {
			d.logf("bad datagram from %s: %v", sess.addr, err)
			continue
		}
		entry := sess.udpEntry()
		if entry == nil {
			continue // 没有绑定的入口(规则已撤), 丢弃
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
	sess.bindUDPEntry(e)
	return sess, nil
}

// peerHandshake 一次信令拿到的对端信息。
//
// 中继会话里它是**两段到达**的(见 DirectRequest.TwoPhase): 第一段只有中继端点 E、指纹还没
// 到, 第二段才是带指纹的完整 offer。直连(或服务端不支持两段)时第一段就已经完整, done 非
// nil, waitFinal 立即返回。
//
// addrs 在第一段就齐了 —— 正是靠它, A 可以在等指纹的同时先把打洞跑起来(见 ensureSession)。
type peerHandshake struct {
	addrs []directCandidate
	done  *DirectOffer     //非 nil: 第一段就完整(指纹已就位)
	ch    chan DirectOffer //后续段

	release func() // 两段式时撤销 offers 登记; waitFinal 结束后调用, 可为 nil
}

// close 撤销等第二段用的登记, 幂等。
func (h *peerHandshake) close() {
	if h.release != nil {
		h.release()
	}
}

// waitFinal 等带指纹的那一段; 已经拿到就立即返回。
func (h *peerHandshake) waitFinal(timeout time.Duration) (DirectOffer, error) {
	if h.done != nil {
		return *h.done, nil
	}
	select {
	case offer := <-h.ch:
		if offer.Err != "" {
			return offer, errors.New(offer.Err)
		}
		offer.PeerAddrs = mergeCandidates(offer.PeerAddrs, offer.PeerAddr)
		if offer.Fingerprint == "" || len(offer.PeerAddrs) == 0 {
			return offer, errors.New("server returned an incomplete offer")
		}
		return offer, nil
	case <-time.After(timeout):
		return DirectOffer{}, errors.New("timed out waiting for the peer certificate fingerprint from server")
	}
}

// registerOffer 登记一个等 offer 的请求, 返回请求 ID、接收通道和撤销函数。
func (d *directPeer) registerOffer() (uint, chan DirectOffer, func()) {
	// 容量 2: 两段式 offer 会有两条都进这个通道, 容量 1 时第二段会被 onOffer 当成
	// "等待方已退出"直接丢掉。
	ch := make(chan DirectOffer, 2)
	d.mu.Lock()
	d.reqInc++
	id := uint(d.reqInc)
	d.offers[id] = ch
	d.mu.Unlock()
	return id, ch, func() {
		d.mu.Lock()
		delete(d.offers, id)
		d.mu.Unlock()
	}
}

// requestPeer 走一趟信令: 生成一次性凭证、把本机端点报给服务端(服务端据此让对端朝我们
// 打洞)、拿到对端的端点与指纹。返回的 token 就是本次要在流首部出示的那个。
//
// 中继会话里会主动声明 TwoPhase: 服务端把中继端点 E 先发一段过来, 调用方立刻就能开打,
// 指纹随后补上(见 peerHandshake)。声明而不是直接发两段, 是为了老客户端仍然只收到完整
// 的一段(见 DirectRequest.TwoPhase 的注释)。
func (d *directPeer) requestPeer(r conf.ClientDirect) (string, *peerHandshake, error) {
	token, err := newDirectToken()
	if err != nil {
		return "", nil, err
	}
	// 打洞加密准备放在最前面: 配置有误(uuid 缺失/非法)就直接失败, 不用先浪费一趟
	// 候选收集与信令往返。isInitiator=true: 用自己的 uuid, 不需要查表。按 client
	// 一次性开关(d.cfg.Direct.Encrypt), 不是按 r 这条规则单独配——同一个 uuid 身份
	// 发起的所有打洞(direct[] 规则或 -send/-recv)共用同一个决定。
	if errMsg := d.prepareDirectCrypto(token, d.cfg.Direct.Encrypt, true); errMsg != "" {
		return "", nil, errors.New(errMsg)
	}
	// 每次都重新收集候选: 隐私临时地址会轮换、NAT 映射会老化重建, 上一次的结果可能
	// 已经作废。多条路并行探, 少一条不影响其它条。
	myCands, err := d.gatherCandidates()
	if err != nil {
		return "", nil, fmt.Errorf("determine my own quic endpoints: %w", err)
	}
	d.setMyCandidates(myCands)

	reqID, offerCh, release := d.registerOffer()
	// 两段式时第二段(带指纹)要在本函数返回**之后**才到, 登记项必须活到 waitFinal 结束,
	// 否则 onOffer 会把它当成"未知请求"丢掉, A 就一直等到指纹超时。
	keep := false
	defer func() {
		if !keep {
			release()
		}
	}()

	// 把本端的地址都打出来: 本地 socket 端口用于抓包定位, 各候选用于判断哪些路探到了、
	// 哪些没探到 —— 排查直连问题时这些缺一不可。encrypt 一起打出来, 排查"punch 是不是
	// 用了加密"不用再翻配置反推。
	d.logf("requesting %s: local socket port %d, my candidates %v, encrypt=%v",
		r.Forward.Email, d.localUDPPort(), myCands, d.cfg.Direct.Encrypt)

	req := DirectRequest{Email: r.Forward.Email, Tag: r.Forward.Tag, Token: token,
		Candidates: myCands, Endpoint: firstAddr(myCands), Encrypt: d.cfg.Direct.Encrypt,
		PunchFirst: d.cfg.Direct.PunchFirst, Via: r.Via, TwoPhase: r.Via != ""}
	if err := d.send(METHOD_DIRECT_REQUEST, reqID, req); err != nil {
		return "", nil, fmt.Errorf("ask server for peer endpoint: %w", err)
	}

	first, err := waitOffer(offerCh, directOfferWait, "peer endpoint")
	if err != nil {
		return "", nil, err
	}
	hs, err := handshakeFromOffer(first, offerCh, release)
	if err != nil {
		return "", nil, err
	}
	if hs.done != nil {
		d.logf("server says %s has candidates %v (fingerprint %s)",
			r.Forward.Email, hs.addrs, shortFP(hs.done.Fingerprint))
	} else {
		// 半截 offer: 端点已经够开打了, 指纹还在路上 —— 让调用方立刻开始打洞, 与对端
		// 那边的信令重叠。
		d.logf("server sent the endpoint %v ahead of the peer certificate, punching while its fingerprint is still on the way",
			hs.addrs)
		keep = true
	}
	return token, hs, nil
}

// handshakeFromOffer 把服务端回的**第一段** offer 变成 peerHandshake: 半截的(EndpointOnly)
// 返回"还要等第二段"的形态, 完整的直接带上指纹。
//
// 单独拆出来是为了这段判定能被用例直接覆盖: 它决定"要不要现在就开打", 判错就会去拨一个
// 指纹还没到的对端。
//
// release 只在半截 offer 时挂到返回值上(由调用方在 waitFinal 后 close), 其余情形仍由调用方自己撤销。
func handshakeFromOffer(first DirectOffer, ch chan DirectOffer, release func()) (*peerHandshake, error) {
	if first.Err != "" {
		return nil, errors.New(first.Err)
	}
	first.PeerAddrs = mergeCandidates(first.PeerAddrs, first.PeerAddr)
	if len(first.PeerAddrs) == 0 {
		return nil, errors.New("server returned an incomplete offer")
	}
	if first.EndpointOnly {
		return &peerHandshake{addrs: first.PeerAddrs, ch: ch, release: release}, nil
	}
	if first.Fingerprint == "" {
		return nil, errors.New("server returned an incomplete offer")
	}
	return &peerHandshake{addrs: first.PeerAddrs, done: &first}, nil
}

// waitOffer 从 offer 通道里取一段, 超时即失败。
func waitOffer(ch <-chan DirectOffer, timeout time.Duration, what string) (DirectOffer, error) {
	select {
	case offer := <-ch:
		return offer, nil
	case <-time.After(timeout):
		return DirectOffer{}, fmt.Errorf("timed out waiting for %s from server", what)
	}
}

// pickPeerAddr 从一次已经跑起来的打洞里选出最优的一条候选。
//
// **不等所有候选**: 第一条路回包之后再留 directPunchSettle 的收敛窗, 在"窗内或此刻已有
// 结论"的候选里择优; 还没回包的按 pending 跳过, 它们的探测继续在后台跑完(不阻塞拨号)。
// 以前是等齐全部候选: 只要有一条从头不回包(中继那组 E 端点里常见), 第一条路 16ms 就通了
// 也要为它把 directPunchWait 预算等满 —— 实测那 3s 是整次连接 5.3s 里最长的一段。
//
// 全灭(预算用尽仍没有一条通)时把错误返回, 是否转入 raceQUICDial 兜底由调用方决定。
func (d *directPeer) pickPeerAddr(email string, run *punchRun) (directCandidate, error) {
	if !run.waitFirst(directPunchWait) {
		return directCandidate{}, fmt.Errorf("no candidate answered: %s", describeFailures(run.snapshot()))
	}
	run.waitSettle(directPunchSettle)
	results := run.snapshot()
	winner, err := selectCandidate(results)
	if err != nil {
		return directCandidate{}, err
	}
	// 把每条候选的 RTT、偏置、得分都打出来。选了哪条、为什么选它, 不打就只能靠猜;
	// 而"为什么没走 IPv6"这类问题恰恰只有这一行答得了。收敛窗结束时还在探的候选会标成
	// still probing —— 与"探过且失败"区分开, 免得误判成对方不可达。
	d.logf("path selection for %s: %s", email, describeResults(results, winner))
	return winner, nil
}

// connectPeer 按服务端给的端点与指纹建立 QUIC 连接并登记复用。信令之外的部分独立成
// 一个方法, 便于不经 websocket 直接测试数据路径。
func (d *directPeer) connectPeer(tr *quic.Transport, email, peerAddr, fingerprint string, route ...directSessionRoute) (*directSession, error) {
	sess, err := d.dialQUIC(tr, email, peerAddr, fingerprint)
	if err != nil {
		return nil, err
	}
	// Token 鉴权绑定到端口；按 email+port 复用，避免已鉴权连接跨端口访问。
	d.putSession(email, sess, route...)
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
	sess := &directSession{conn: conn, addr: peerAddr, stats: stats}
	// 必须马上 touch: lastUse 是 atomic.Int64 零值(unix 纪元), 不touch的话这条刚
	// 拨通、还没来得及 acquire 的连接在 reapSessions 眼里"已经空闲了 50 多年"——
	// 若这中间 authenticateSession(含中继 uuid 挑战-应答, 可能耗时数秒)与
	// reapSessions 的 30s 检查点撞上, 连接会被当场关掉, 鉴权流读到一半收到
	// "Application error 0x0 (remote): idle"。
	sess.touch()
	return sess, nil
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
func (d *directPeer) raceQUICDial(tr *quic.Transport, email, fingerprint string, cands []directCandidate, route directSessionRoute) (*directSession, error) {
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
		d.putSession(email, r.sess, route)
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
func (d *directPeer) openHeadedStream(sess *directSession, kind, token, tag string) (*quic.Stream, error) {
	return d.openStreamWithHead(sess, directStreamHead{Kind: kind, Token: token, Tag: tag})
}

func (d *directPeer) openStreamWithHead(sess *directSession, head directStreamHead) (*quic.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), directDialWait)
	defer cancel()
	stream, err := sess.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open quic stream: %w", err)
	}
	if err := writeStreamHead(stream, head); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write stream head: %w", err)
	}
	return stream, nil
}

// openDataStream 在新版对端上等待 ready ACK。这个往返既确认 C 已成功 dial 落地目标，也能
// 识别“VPS 已重启、A 却还缓存着指向旧 relay binding 的 QUIC session”：旧路径上本地开流
// 可能成功，但 ACK 不会回来，调用方随后会 dropSession 并完整重建一次。
func (d *directPeer) openDataStream(sess *directSession, tag string) (*quic.Stream, error) {
	head := directStreamHead{Kind: directStreamData, Tag: tag, Ready: sess.streamReady.Load()}
	stream, err := d.openStreamWithHead(sess, head)
	if err != nil || !head.Ready {
		return stream, err
	}
	_ = stream.SetReadDeadline(time.Now().Add(directDialWait))
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, fmt.Errorf("wait for data stream ready ack: %w", err)
	}
	_ = stream.SetReadDeadline(time.Time{})
	switch ack[0] {
	case directAuthACK:
		return stream, nil
	case directRejectACK:
		// C 明确拒绝了这条流(比如 tag 没有 forward 映射), 不是连接坏了——原因紧跟在
		// 这个字节后面, 读不到也不至于卡住(给个短超时, 读不出就用个兜底文案)。
		_ = stream.SetReadDeadline(time.Now().Add(directDialWait))
		var reject directStreamReject
		_ = readFrame(stream, &reject, directStreamHeadMax)
		stream.CancelRead(0)
		_ = stream.Close()
		reason := reject.Reason
		if reason == "" {
			reason = "rejected by peer"
		}
		return nil, &directRejectedError{reason: reason}
	default:
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, fmt.Errorf("invalid data stream ready ack %d", ack[0])
	}
}

// directRejectedError C 明确拒绝了这条数据流(比如 tag 没有 forward 映射、落地目标拨不通)。
// 这是对端的配置/落地问题, 不是这条 QUIC 连接坏了——调用方(见 openStream)不应据此
// dropSession 重建, 那只会白白重打一次洞, 下一条流照样被拒。
type directRejectedError struct {
	reason string
}

func (e *directRejectedError) Error() string {
	return "peer rejected: " + e.reason
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

// directSessionRoute 是一条可复用 QUIC session 的完整入口/路由身份。同一个 C/tag 经不同
// VPS 是不同的 UDP 路径；不同 listen 也必须隔离，因为 UDP 回程入口挂在 session 上，复用会
// 让同 tag 的后一条本地监听覆盖前一条。
type directSessionRoute struct {
	listen string
	tag    string
	via    string
}

func sessionRouteForRule(r conf.ClientDirect) directSessionRoute {
	return directSessionRoute{listen: r.Listen, tag: r.Forward.Tag, via: r.Via}
}

func sessionKey(email string, route ...directSessionRoute) string {
	if len(route) == 0 {
		return email // compatibility for tests and legacy internal callers
	}
	return fmt.Sprintf("%s#%s#via=%s#listen=%s", email, route[0].tag, route[0].via, route[0].listen)
}

func (d *directPeer) session(email string, route ...directSessionRoute) *directSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessions[sessionKey(email, route...)]
}

func (d *directPeer) putSession(email string, s *directSession, route ...directSessionRoute) {
	d.mu.Lock()
	d.sessions[sessionKey(email, route...)] = s
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
	entries := make([]*directUDPEntry, 0, len(d.sessions))
	for _, s := range d.sessions {
		s.udpMu.Lock()
		if s.boundUDPEntry != nil {
			entries = append(entries, s.boundUDPEntry)
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
			e.rule.Listen, e.rule.Forward.Email, e.sessionCount(),
			snap.UpBytes, snap.UpPkts, snap.UpRate, snap.DownBytes, snap.DownPkts, snap.DownRate)
	}
}

// unregisterSession 只把这一条记录从复用缓存里摘掉(前提是它还在里面), 完全不碰底层
// 连接——专供 newDirectSession 在一条全新连接刚握手成功时用: 这条连接是健康的, 只是
// 不该被当成"可复用的那一条"留在缓存里(调用方要么马上用 putSession 重新登记一次,
// 要么就是要拿去单独使用, 见 ensureSession/ensureParallelSessions)。跟 dropSession
// 不是一回事: 那个是给连接确实坏了、要整个关掉重建的场景用的, 会顺手关连接, 用在
// 这里会把刚建好、完全健康的连接也关掉。
func (d *directPeer) unregisterSession(email string, sess *directSession, route ...directSessionRoute) {
	d.mu.Lock()
	key := sessionKey(email, route...)
	if d.sessions[key] == sess {
		delete(d.sessions, key)
	}
	d.mu.Unlock()
}

// dropSession 仅在当前记录仍是这条失效连接时删除, 避免把别的 goroutine 刚建好的新连接误删。
func (d *directPeer) dropSession(email string, stale *directSession, route ...directSessionRoute) {
	d.mu.Lock()
	key := sessionKey(email, route...)
	if d.sessions[key] == stale {
		delete(d.sessions, key)
	}
	d.mu.Unlock()
	if stale != nil && stale.conn != nil {
		_ = stale.conn.CloseWithError(0, "rebuilding")
	}
}
