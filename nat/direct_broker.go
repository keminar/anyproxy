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

// directBroker 记录已转交给 C、还在等 C 回话的请求。
type directBroker struct {
	mu      sync.Mutex
	pending map[uint]*directPending
	nextID  uint
}

// directPending 一次转交的上下文: 记住是谁问的, 以便把 C 的回复送回去。
type directPending struct {
	asker    *Client
	askerID  uint // A 那侧的请求 ID, 回 offer 时要原样带回, A 才能对上是哪条入口连接
	email    string
	deadline time.Time
}

var serverBroker = &directBroker{pending: make(map[uint]*directPending)}

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
	default:
		// d_punch / d_offer 是 B 下发给订阅方的方向, 订阅方不该往上发。
		log.Printf("nat direct: unexpected %s from client email %s", msg.Method, c.Email)
	}
	return true
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
	peer := c.hub.GetClientByEmail(req.Email)
	if peer == nil {
		replyOffer(c, msg.ID, DirectOffer{Err: fmt.Sprintf("no subscriber online for email %s", req.Email)})
		return
	}

	// 用 B 自己的 ID 与 C 通信: A 那侧的 ID 是各 A 自行采番的, 不同 A 会撞号。
	id := b.track(c, msg.ID, req.Email)
	// FromEmail 只能由服务端填: 它是从这条已鉴权的 websocket 上得到的, A 自报的身份
	// 不能信 —— 收方要拿它做 receive.allow 判断。
	punch := DirectPunch{PeerAddrs: reqCands, PeerAddr: firstAddr(reqCands),
		Token: req.Token, Port: req.Port, FromEmail: c.Email}
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
