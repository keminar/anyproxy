package nat

import (
	"fmt"
	"log"
	"net"
)

// 服务端(B)侧的直连信令中转。B 不碰任何数据面字节, 只做两件事:
//  1. 记下每个订阅方通告的 QUIC 端点与证书指纹;
//  2. 把 A 的连接请求转交给目标订阅方 C, 并把 C 的端点回给 A。
//
// 端点由订阅方**自己用 QUIC 那个 socket 问 UDP 反射器**要来(见 nat/direct_reflect.go),
// B 只做格式与地址家族校验后原样转交 —— B 从 websocket 上看到的是 TCP socket 的地址,
// 与 QUIC 实际使用的源地址不保证相同。

// handleDirectServer 处理订阅方发来的直连信令(在 B 上执行)。返回 true 表示消息已被
// 直连逻辑消费, 调用方不应再送进数据面的 BridgeHub。
func handleDirectServer(c *Client, msg *Message) bool {
	if !isDirectMethod(msg.Method) {
		return false
	}
	switch msg.Method {
	case METHOD_DIRECT_ANNOUNCE:
		serverOnAnnounce(c, msg)
	case METHOD_DIRECT_REQUEST:
		serverOnRequest(c, msg)
	default:
		// d_punch / d_offer 是 B 下发给订阅方的方向, 订阅方不该往上发。
		log.Printf("nat direct: unexpected %s from client email %s", msg.Method, c.Email)
	}
	return true
}

// serverOnAnnounce 记录该订阅方的 QUIC 端点。
//
// 端点原样采信订阅方上报的值: 它是订阅方用 QUIC 那个 socket 问 UDP 反射器要来的观测
// 结果, 比服务端从 websocket(TCP, 另一个 socket)上看到的地址可靠。服务端这里只做格式
// 与家族校验, 不做替换。
func serverOnAnnounce(c *Client, msg *Message) {
	var an DirectAnnounce
	if err := decodeDirect(msg.Body, &an); err != nil {
		log.Printf("nat direct: bad announce from email %s: %v", c.Email, err)
		return
	}
	if an.Endpoint == "" || an.Fingerprint == "" {
		log.Printf("nat direct: incomplete announce from email %s", c.Email)
		return
	}
	if err := checkDirectEndpoint(an.Endpoint); err != nil {
		log.Printf("nat direct: email %s announced unusable endpoint %s: %v", c.Email, an.Endpoint, err)
		return
	}
	c.setDirectEndpoint(an.Endpoint, an.Fingerprint)
	log.Printf("nat direct: email %s announced quic endpoint %s", c.Email, an.Endpoint)
}

// checkDirectEndpoint 校验端点可用于 IPv6 直连。IPv4 端点在这里就拒掉并说明原因,
// 而不是等对端拨号时才失败得不明不白。
func checkDirectEndpoint(endpoint string) error {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%s is not an IP literal", host)
	}
	if ip.To4() != nil {
		return fmt.Errorf("%s is IPv4; direct connect needs IPv6 on both sides", host)
	}
	if !ip.IsGlobalUnicast() {
		return fmt.Errorf("%s is not a global unicast address", host)
	}
	return nil
}

// serverOnRequest A 请求连接某 email。B 先把请求转交给 C 让它朝 A 打洞, 再把 C 的端点回给 A。
func serverOnRequest(c *Client, msg *Message) {
	var req DirectRequest
	if err := decodeDirect(msg.Body, &req); err != nil {
		log.Printf("nat direct: bad request from email %s: %v", c.Email, err)
		return
	}
	reply := func(o DirectOffer) {
		body, err := encodeDirect(o)
		if err != nil {
			log.Printf("nat direct: encode offer: %v", err)
			return
		}
		c.hub.broadcast <- &CMessage{client: c, message: &Message{ID: msg.ID, Type: msg.Type, Method: METHOD_DIRECT_OFFER, Body: body}}
	}

	if req.Email == "" || req.Token == "" || req.Endpoint == "" {
		reply(DirectOffer{Err: "incomplete direct request"})
		return
	}
	if err := checkDirectEndpoint(req.Endpoint); err != nil {
		reply(DirectOffer{Err: fmt.Sprintf("requester endpoint %s unusable: %v", req.Endpoint, err)})
		return
	}
	// 不允许连自己, 否则 A 会给自己发 punch 再拨自己, 徒增困惑的失败。
	if req.Email == c.Email {
		reply(DirectOffer{Err: "cannot direct-connect to self"})
		return
	}
	peer := c.hub.GetClientByEmail(req.Email)
	if peer == nil {
		reply(DirectOffer{Err: fmt.Sprintf("no subscriber online for email %s", req.Email)})
		return
	}
	peerAddr, peerFP := peer.directEndpoint()
	if peerAddr == "" {
		reply(DirectOffer{Err: fmt.Sprintf("email %s has not announced a quic endpoint (websocket.client.directAccept not enabled?)", req.Email)})
		return
	}

	// 先让 C 朝 A 打洞: IPv6 无 NAT 但家用路由器默认拦主动入站, C 不先发包, A 的
	// QUIC Initial 会被 C 侧防火墙丢掉。这一步必须在回 offer 之前发出, 尽量让 C 的
	// 打洞包早于 A 的拨号到达。
	punch := DirectPunch{
		PeerAddr: req.Endpoint,
		Token:    req.Token,
		Port:     req.Port,
	}
	punchBody, err := encodeDirect(punch)
	if err != nil {
		reply(DirectOffer{Err: "server encode punch failed"})
		return
	}
	peer.hub.broadcast <- &CMessage{client: peer, message: &Message{ID: msg.ID, Type: msg.Type, Method: METHOD_DIRECT_PUNCH, Body: punchBody}}
	log.Printf("nat direct: email %s -> %s, told peer to punch toward %s", c.Email, req.Email, punch.PeerAddr)

	reply(DirectOffer{PeerAddr: peerAddr, Fingerprint: peerFP})
}
