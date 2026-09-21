package nat

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// 服务端(B)侧的直连信令中转。B 不碰任何数据面字节, 只做一件事: 把 A 的连接请求转交给
// 目标订阅方 C, 等 C 起好监听并报回自己的端点后, 再把端点转给 A。
//
// B 不缓存端点: 端点由 C 在收到请求时**当场探测**得到(见 nat/direct_reflect.go)。
// 外网地址(隐私临时地址轮换)与外网端口(NAT 映射老化重建)都可能变, 缓存下来的端点
// 随时可能已经作废, 而 B 无从得知。

// directPendingTTL B 等 C 回 d_ready 的上限。超时即回错误给 A, 不让入口连接干等。
const directPendingTTL = 15 * time.Second

// directRelaySessionTTL 中继会话在 B 上的登记存活时间: 覆盖"open->两腿打洞->A 拨号"整段,
// 期间要靠它把 A、C 的 nudge 路由到 VPS。取值给足并明显大于 directPendingTTL。
const directRelaySessionTTL = 60 * time.Second

// directBroker 记录已转交给 C、还在等 C 回话的请求。
type directBroker struct {
	mu      sync.Mutex
	pending map[uint]*directPending
	nextID  uint

	// relays 进行中的中继会话, 按 token 索引。B 只用它做两件事: 把 open/punch 的 d_ready
	// 归位到正确的会话, 以及把两腿的 d_punching nudge 路由给 VPS(见 onPunching)。数据面
	// 完全不经 B。
	relays map[string]*relaySession
}

// directPending 一次转交的上下文: 记住是谁问的, 以便把 C 的回复送回去。
//
// 中继场景下同一个会话会产生两条 pending(向 VPS 的 relay-open、向 C 的 punch), 各自的
// d_ready 回来时靠 relay!=nil + role 分派到中继状态机(见 onReady), 不再走"直接回 offer 给
// A"那条路。
type directPending struct {
	asker    *Client
	askerID  uint // A 那侧的请求 ID, 回 offer 时要原样带回, A 才能对上是哪条入口连接
	email    string
	deadline time.Time

	relay *relaySession // 非空表示这条 pending 属于一次中继会话
	role  int           // relayRoleOpen(VPS 回 E) / relayRolePunchC(C 回候选+指纹)
}

const (
	relayRoleOpen   = iota // 向 VPS 发的 relay-open, 等它回 E
	relayRolePunchC        // 向 C 发的 punch, 等它回候选+指纹
)

// relaySession B 侧一次中继会话的上下文。只保存路由/协调需要的最少信息。
type relaySession struct {
	token    string  // 本次会话标识(A 生成)
	asker    *Client // A
	askerID  uint    // A 侧请求 ID
	aEmail   string  // A 的 email(B 认证过的 c.Email)
	cEmail   string  // 最终目标 C
	vpsEmail string  // 中继 VPS
	vps      *Client // VPS 连接
	aCands   []directCandidate
	endpoint []directCandidate // VPS 报回的中继端点 E
	tag      string
	encrypt  bool
	// twoPhase A 声明了支持两段式 offer(见 DirectRequest.TwoPhase): 拿到中继端点 E 之后
	// 先把 E 单独发给 A 让它立刻开打, C 的证书指纹到了再补一条完整 offer。
	twoPhase bool
	deadline time.Time
}

var serverBroker = &directBroker{
	pending: make(map[uint]*directPending),
	relays:  make(map[string]*relaySession),
}

// handleDirectServer 处理订阅方发来的直连信令(在 B 上执行)。返回 true 表示消息已被
// 直连逻辑消费, 调用方不应再送进数据面的 BridgeHub。
func handleDirectServer(c *Client, msg *Message) bool {
	if !isDirectMethod(msg.Method) {
		return false
	}
	switch msg.Method {
	case METHOD_DIRECT_REQUEST:
		serverBroker.onRequest(c, msg)
	case METHOD_DIRECT_READY:
		serverBroker.onReady(c, msg)
	case METHOD_DIRECT_PUNCHING:
		serverBroker.onPunching(c, msg)
	default:
		// d_punch / d_offer 是 B 下发给订阅方的方向, 订阅方不该往上发。
		log.Printf("nat direct: unexpected %s from client email %s", msg.Method, c.Email)
	}
	return true
}

// onPunching 把 nudge 转给该收到它的一方。B 不做别的: 收方只在 Token 对上时才动作, 而 Token
// 是本次会话的一次性秘密, 伪造不了。两种路由:
//   - 中继会话: 转给这次会话的 VPS, 并**用发出方 B 认证过的 c.Email 当"腿"标签**(不采信
//     p.Email, 免得被伪造成别的腿)——VPS 靠它认出该朝哪条腿主动发包(见 direct_relay.go 的
//     fireRelayLeg/punchLeg)。
//   - 普通直连的 order Y(A 声明了 directPunchFirst): 按 p.Email 路由给对端 C。
func (b *directBroker) onPunching(c *Client, msg *Message) {
	var p DirectPunching
	if err := decodeDirect(msg.Body, &p); err != nil {
		log.Printf("nat direct: bad punching from email %s: %v", c.Email, err)
		return
	}
	if p.Token == "" {
		return
	}
	if rs := b.relaySession(p.Token); rs != nil {
		if rs.vps == nil {
			return
		}
		body, err := encodeDirect(DirectPunching{Email: c.Email, Token: p.Token})
		if err != nil {
			return
		}
		rs.vps.hub.broadcast <- &CMessage{client: rs.vps, message: &Message{Type: ConnTCP, Method: METHOD_DIRECT_PUNCHING, Body: body}}
		return
	}
	if p.Email == "" || p.Email == c.Email {
		// 空: 普通直连 order Y 没带目标, 静默即可。
		// 等于自己: 不该朝自己转发 nudge。中继 nudge 在 relaySession 还没在 B 上登记
		// 的窗口里也会走到这条分支, 此时收方就是发出方, 转发回去纯属静默空转。
		return
	}
	peer := c.hub.GetClientByEmail(p.Email)
	if peer == nil {
		return // 对端不在线; C 那边有 directPunchFirstDelay 兜底, 这里静默即可
	}
	body, err := encodeDirect(DirectPunching{Token: p.Token})
	if err != nil {
		return
	}
	peer.hub.broadcast <- &CMessage{client: peer, message: &Message{Type: ConnTCP, Method: METHOD_DIRECT_PUNCHING, Body: body}}
}

// onRequest A 请求连接某 email: 转交给 C, 等它回端点。
func (b *directBroker) onRequest(c *Client, msg *Message) {
	var req DirectRequest
	if err := decodeDirect(msg.Body, &req); err != nil {
		log.Printf("nat direct: bad request from email %s: %v", c.Email, err)
		return
	}
	if req.Email == "" || req.Token == "" || req.Endpoint == "" {
		replyOffer(c, msg.ID, DirectOffer{Err: "incomplete direct request"})
		return
	}
	reqCands, err := checkDirectCandidates(mergeCandidates(req.Candidates, req.Endpoint))
	if err != nil {
		replyOffer(c, msg.ID, DirectOffer{Err: fmt.Sprintf("requester announced no usable endpoint: %v", err)})
		return
	}
	// 不允许连自己, 否则 A 会给自己发 punch 再拨自己, 徒增困惑的失败。
	if req.Email == c.Email {
		replyOffer(c, msg.ID, DirectOffer{Err: "cannot direct-connect to self"})
		return
	}
	// 中继模式: A 指定了经某 VPS(req.Via)盲转发到 C。走另一套三方协调状态机。
	if req.Via != "" {
		b.onRelayRequest(c, msg, req, reqCands)
		return
	}
	peer := c.hub.GetClientByEmail(req.Email)
	if peer == nil {
		replyOffer(c, msg.ID, DirectOffer{Err: fmt.Sprintf("no subscriber online for email %s", req.Email)})
		return
	}

	// 用 B 自己的 ID 与 C 通信: A 那侧的 ID 是各 A 自行采番的, 不同 A 会撞号。
	id := b.track(c, msg.ID, req.Email)
	// Email 用 c.Email(B 自己认证过的身份), 不是 req 里的字段——A 没法在这里伪造成
	// 别的 email, C 才能放心拿它去查 receive.allow 派生打洞加密密钥(见 DirectPunch
	// 的字段注释)。
	punch := DirectPunch{PeerAddrs: reqCands, PeerAddr: firstAddr(reqCands),
		Token: req.Token, Tag: req.Tag, Email: c.Email, Encrypt: req.Encrypt, PunchFirst: req.PunchFirst}
	body, err := encodeDirect(punch)
	if err != nil {
		b.take(id)
		replyOffer(c, msg.ID, DirectOffer{Err: "server encode punch failed"})
		return
	}
	peer.hub.broadcast <- &CMessage{client: peer, message: &Message{ID: id, Type: ConnTCP, Method: METHOD_DIRECT_PUNCH, Body: body}}
	log.Printf("nat direct: email %s -> %s, asked peer to listen and punch toward %v", c.Email, req.Email, reqCands)
}

// onReady C 报回自己的端点: 找到当初的请求方, 把端点转给它。
func (b *directBroker) onReady(c *Client, msg *Message) {
	var ready DirectReady
	if err := decodeDirect(msg.Body, &ready); err != nil {
		log.Printf("nat direct: bad ready from email %s: %v", c.Email, err)
		return
	}
	p := b.take(msg.ID)
	if p == nil {
		log.Printf("nat direct: ready from email %s for unknown/expired request %d", c.Email, msg.ID)
		return
	}
	if p.relay != nil {
		b.onRelayReady(c, p, ready)
		return
	}
	if ready.Err != "" {
		replyOffer(p.asker, p.askerID, DirectOffer{Err: fmt.Sprintf("peer %s cannot accept a direct connection: %s", p.email, ready.Err)})
		return
	}
	readyCands, err := checkDirectCandidates(mergeCandidates(ready.Candidates, ready.Endpoint))
	if err != nil {
		replyOffer(p.asker, p.askerID, DirectOffer{Err: fmt.Sprintf("peer %s reported no usable endpoint: %v", p.email, err)})
		return
	}
	if ready.Fingerprint == "" {
		replyOffer(p.asker, p.askerID, DirectOffer{Err: fmt.Sprintf("peer %s reported no certificate fingerprint", p.email)})
		return
	}
	log.Printf("nat direct: email %s is ready with candidates %v", c.Email, readyCands)
	replyOffer(p.asker, p.askerID, DirectOffer{
		PeerAddrs: readyCands, PeerAddr: firstAddr(readyCands), Fingerprint: ready.Fingerprint})
}

// onRelayRequest A 请求经 VPS(req.Via)盲转发到 C(req.Email): 起中继会话, 先让 VPS 开
// 中继 socket 探端点 E(见 docs/direct-relay-design.md 的信令流程)。
func (b *directBroker) onRelayRequest(c *Client, msg *Message, req DirectRequest, aCands []directCandidate) {
	if req.Via == c.Email {
		replyOffer(c, msg.ID, DirectOffer{Err: "relay via cannot be self"})
		return
	}
	if req.Via == req.Email {
		replyOffer(c, msg.ID, DirectOffer{Err: "relay via and target must be different peers"})
		return
	}
	vps := c.hub.GetClientByEmail(req.Via)
	if vps == nil {
		replyOffer(c, msg.ID, DirectOffer{Err: fmt.Sprintf("no relay subscriber online for email %s", req.Via)})
		return
	}
	target := c.hub.GetClientByEmail(req.Email)
	if target == nil {
		replyOffer(c, msg.ID, DirectOffer{Err: fmt.Sprintf("no subscriber online for email %s", req.Email)})
		return
	}
	rs := &relaySession{
		token: req.Token, asker: c, askerID: msg.ID, aEmail: c.Email, cEmail: req.Email,
		vpsEmail: req.Via, vps: vps, aCands: aCands, tag: req.Tag, encrypt: req.Encrypt,
		twoPhase: req.TwoPhase,
		deadline: time.Now().Add(directRelaySessionTTL),
	}
	b.mu.Lock()
	now := time.Now()
	for t, s := range b.relays {
		if now.After(s.deadline) {
			delete(b.relays, t)
		}
	}
	b.relays[req.Token] = rs
	b.mu.Unlock()

	// 第一步: 让 VPS 开中继 socket、探端点 E, 用 d_ready 回来(role=open)。
	id := b.trackRelay(rs, relayRoleOpen)
	body, err := encodeDirect(DirectRelayOpen{Token: req.Token})
	if err != nil {
		b.take(id)
		b.dropRelay(req.Token)
		replyOffer(c, msg.ID, DirectOffer{Err: "server encode relay-open failed"})
		return
	}
	vps.hub.broadcast <- &CMessage{client: vps, message: &Message{ID: id, Type: ConnTCP, Method: METHOD_DIRECT_RELAY_OPEN, Body: body}}
	log.Printf("nat direct relay: email %s -> %s via %s, asked relay to open an endpoint", c.Email, req.Email, req.Via)
}

// onRelayReady 分派中继会话里两类 d_ready: VPS 报回的中继端点 E(role=open), C 报回的候选
// +证书指纹(role=punchC)。
func (b *directBroker) onRelayReady(c *Client, p *directPending, ready DirectReady) {
	rs := p.relay
	switch p.role {
	case relayRoleOpen:
		if ready.Err != "" {
			b.failRelay(rs, fmt.Sprintf("relay %s cannot open an endpoint: %s", rs.vpsEmail, ready.Err))
			return
		}
		eCands, err := checkDirectCandidates(mergeCandidates(ready.Candidates, ready.Endpoint))
		if err != nil {
			b.failRelay(rs, fmt.Sprintf("relay %s reported no usable endpoint: %v", rs.vpsEmail, err))
			return
		}
		rs.endpoint = eCands
		log.Printf("nat direct relay: %s opened endpoint %v for %s<->%s", rs.vpsEmail, eCands, rs.aEmail, rs.cEmail)
		// 在 VPS 上登记 A 腿(此刻已有 A 的候选): VPS 收到 A 的 nudge 后朝 A 打洞。
		b.sendRelayLeg(rs, rs.aEmail, rs.aCands)
		// 两段式(A 声明了 TwoPhase): 此刻 E 已经到手, 而 C 的指纹还要绕一圈(B->C 打洞 ->
		// C 回 d_ready), 所以先把 E 单独发给 A —— A 立刻朝 E 打洞 + nudge, 与下面那段信令
		// 重叠。实测"等 C 的指纹"是秒级的一段, 正好盖住 A 的打洞。
		//
		// 顺序: 上面那条 A 腿登记必须**先**发出去, 否则 A 的 nudge 可能先于它到达 VPS,
		// VPS 就不知道该腿的候选(那种情况下 VPS 侧靠 nudgedEarly 兜底, 但先登记才是正常
		// 路径)。
		if rs.twoPhase {
			replyOffer(rs.asker, rs.askerID, DirectOffer{
				PeerAddrs: eCands, PeerAddr: firstAddr(eCands), EndpointOnly: true})
			log.Printf("nat direct relay: session %s sent endpoint %v to %s ahead of the peer certificate",
				shortToken(rs.token), eCands, rs.aEmail)
		}
		// 让 C 朝 E 打洞(Relay=true: C 立即打并发 nudge)并回自己的候选+指纹(role=punchC)。
		punch := DirectPunch{PeerAddrs: eCands, PeerAddr: firstAddr(eCands), Token: rs.token,
			Tag: rs.tag, Email: rs.aEmail, Encrypt: rs.encrypt, Relay: true}
		body, err := encodeDirect(punch)
		if err != nil {
			b.failRelay(rs, "server encode relay punch failed")
			return
		}
		id := b.trackRelay(rs, relayRolePunchC)
		cClient := b.clientByEmail(c, rs.cEmail)
		if cClient == nil {
			b.take(id)
			b.failRelay(rs, fmt.Sprintf("no subscriber online for email %s", rs.cEmail))
			return
		}
		cClient.hub.broadcast <- &CMessage{client: cClient, message: &Message{ID: id, Type: ConnTCP, Method: METHOD_DIRECT_PUNCH, Body: body}}

	case relayRolePunchC:
		if ready.Err != "" {
			b.failRelay(rs, fmt.Sprintf("peer %s cannot accept a relayed connection: %s", rs.cEmail, ready.Err))
			return
		}
		cCands, err := checkDirectCandidates(mergeCandidates(ready.Candidates, ready.Endpoint))
		if err != nil {
			b.failRelay(rs, fmt.Sprintf("peer %s reported no usable endpoint: %v", rs.cEmail, err))
			return
		}
		if ready.Fingerprint == "" {
			b.failRelay(rs, fmt.Sprintf("peer %s reported no certificate fingerprint", rs.cEmail))
			return
		}
		// 在 VPS 上登记 C 腿: VPS 收到 C 的 nudge 后朝 C 打洞。
		b.sendRelayLeg(rs, rs.cEmail, cCands)
		// 把中继端点 E + C 的指纹回给 A: A 朝 E 打洞并拨号, TLS 期望 C 的指纹, e2e QUIC 经
		// VPS 盲转发在 A<->C 完成。
		replyOffer(rs.asker, rs.askerID, DirectOffer{
			PeerAddrs: rs.endpoint, PeerAddr: firstAddr(rs.endpoint), Fingerprint: ready.Fingerprint})
		log.Printf("nat direct relay: session %s ready, offered endpoint %v to %s", shortToken(rs.token), rs.endpoint, rs.aEmail)
	}
}

// sendRelayLeg 通知 VPS 登记一条腿(A 或 C)的候选, 让它朝那腿打洞。复用 d_punch 的形状,
// Relay=true + Email 标明是哪条腿。fire-and-forget(VPS 不回 d_ready)。
func (b *directBroker) sendRelayLeg(rs *relaySession, legEmail string, cands []directCandidate) {
	if rs.vps == nil {
		return
	}
	punch := DirectPunch{PeerAddrs: cands, PeerAddr: firstAddr(cands), Token: rs.token, Email: legEmail, Relay: true}
	body, err := encodeDirect(punch)
	if err != nil {
		return
	}
	rs.vps.hub.broadcast <- &CMessage{client: rs.vps, message: &Message{Type: ConnTCP, Method: METHOD_DIRECT_PUNCH, Body: body}}
}

// clientByEmail 经任一在线连接的 hub 按 email 查订阅方(hub 是全局共享的)。
func (b *directBroker) clientByEmail(any *Client, email string) *Client {
	return any.hub.GetClientByEmail(email)
}

// relaySession 取一个未过期的中继会话。
func (b *directBroker) relaySession(token string) *relaySession {
	b.mu.Lock()
	defer b.mu.Unlock()
	rs, ok := b.relays[token]
	if !ok || time.Now().After(rs.deadline) {
		return nil
	}
	return rs
}

func (b *directBroker) dropRelay(token string) {
	b.mu.Lock()
	delete(b.relays, token)
	b.mu.Unlock()
}

// failRelay 中继会话任一步失败: 回错误给 A, 并摘除会话。按直连一贯约定直接失败、不兜底。
func (b *directBroker) failRelay(rs *relaySession, reason string) {
	b.dropRelay(rs.token)
	replyOffer(rs.asker, rs.askerID, DirectOffer{Err: reason})
}

// trackRelay 登记一条属于中继会话的 pending(等 VPS 或 C 回 d_ready)。
func (b *directBroker) trackRelay(rs *relaySession, role int) uint {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, p := range b.pending {
		if now.After(p.deadline) {
			delete(b.pending, id)
			go replyOffer(p.asker, p.askerID, DirectOffer{Err: fmt.Sprintf("peer %s did not respond in time", p.email)})
		}
	}
	b.nextID++
	id := b.nextID
	b.pending[id] = &directPending{asker: rs.asker, askerID: rs.askerID, email: rs.cEmail,
		deadline: now.Add(directPendingTTL), relay: rs, role: role}
	return id
}

func (b *directBroker) track(asker *Client, askerID uint, email string) uint {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	// 顺带清理超时项并回错误, 免得 A 一直干等到自己的超时。
	for id, p := range b.pending {
		if now.After(p.deadline) {
			delete(b.pending, id)
			go replyOffer(p.asker, p.askerID, DirectOffer{Err: fmt.Sprintf("peer %s did not respond in time", p.email)})
		}
	}
	b.nextID++
	id := b.nextID
	b.pending[id] = &directPending{asker: asker, askerID: askerID, email: email, deadline: now.Add(directPendingTTL)}
	return id
}

func (b *directBroker) take(id uint) *directPending {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[id]
	if !ok {
		return nil
	}
	delete(b.pending, id)
	if time.Now().After(p.deadline) {
		return nil
	}
	return p
}

func replyOffer(c *Client, id uint, o DirectOffer) {
	if c == nil {
		return
	}
	body, err := encodeDirect(o)
	if err != nil {
		log.Printf("nat direct: encode offer: %v", err)
		return
	}
	c.hub.broadcast <- &CMessage{client: c, message: &Message{ID: id, Type: ConnTCP, Method: METHOD_DIRECT_OFFER, Body: body}}
}

// directMaxCandidates 一方最多允许通告几个候选。
//
// 必须有上限: 服务端把这份列表转给对端后, 对端会朝**每一条**发打洞包。不限制的话,
// 一个恶意订阅方报上几百个地址, 就能让另一台机器替它朝任意目标扫射 —— 服务端在这里
// 成了放大器。三类来源(反射器 v4/v6、端口映射)正常也就两三条, 8 条很宽裕。
const directMaxCandidates = 8

// checkDirectCandidates 过滤并校验一方通告的候选。
//
// 逐条筛而不是一票否决: 多候选的意义就是"有一条能用就行", 某条格式不对不该拖垮整次
// 直连。全部不可用才报错, 并带上每条的原因。
//
// 这里**不再**要求 IPv6 或全局地址 —— IPv4、私有地址、CGNAT 现在都是合法候选, 通不通
// 交给打洞去回答。只挡住明显没有意义的: 解析不出的、非 IP 字面量的、端口为 0 的。
// 要求 IP 字面量而不接受域名, 是因为这份地址会让对端去发包, 不能让它顺带做 DNS 解析
// 去够任意主机。
func checkDirectCandidates(cands []directCandidate) ([]directCandidate, error) {
	var ok []directCandidate
	var bad []string
	for _, c := range cands {
		if err := checkDirectEndpoint(c.Addr); err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", c.Addr, err))
			continue
		}
		ok = append(ok, c)
		if len(ok) >= directMaxCandidates {
			break
		}
	}
	if len(ok) == 0 {
		if len(bad) == 0 {
			return nil, errors.New("no candidate endpoint was announced")
		}
		return nil, errors.New(strings.Join(bad, "; "))
	}
	return ok, nil
}

// checkDirectEndpoint 校验单个候选端点的格式。
func checkDirectEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%s is not an IP literal", host)
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%s is not a unicast address", host)
	}
	if port == "" || port == "0" {
		return errors.New("port is zero")
	}
	return nil
}
