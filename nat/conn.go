package nat

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/tools"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// authSkewLimit 鉴权允许的最大时钟偏差(秒), 双向。token 里带时间戳是为了防重放,
	// 窗口越小越安全, 但两端时钟不同步就会连不上 —— 想彻底摆脱这个限制, 用密钥对
	// 鉴权(见 docs/websocket.md), 那套是挑战-应答, 不依赖时钟。
	authSkewLimit int64 = 300

	// authKeyWait 密钥鉴权里等对端回签名的时限。这一步多一个来回, 不设超时的话
	// 一个不回包的连接会一直占着。
	authKeyWait = 10 * time.Second
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// ServerHub 服务端的ws链接信息
var ServerHub *Hub

// ServerBridge 服务端的http与ws链接
var ServerBridge *BridgeHub

// serverStart 是否开启服务
var serverStart = false

// Eable 检查是否可以发送nat请求
func Eable() bool {
	if !serverStart {
		return false
	}
	if len(ServerHub.clients) == 0 {
		return false
	}
	return true
}

// NewServer 开启服务
func NewServer(addr *string) {
	ServerHub = newHub()
	go ServerHub.run()
	ServerBridge = newBridgeHub()
	go ServerBridge.run()
	serverStart = true

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(ServerHub, w, r)
	})

	// 直连用的 UDP 反射器, 绑同一个端口号(TCP/UDP 互不冲突), 订阅方可直接从 websocket
	// 的连接地址推出它, 不用额外配置。订阅方必须用 QUIC 那个 socket 去问它要端点 ——
	// websocket 是 TCP、是另一个 socket, 观测到的地址不能代表 UDP 会用哪个源地址。
	StartDirectReflector(*addr)

	log.Printf("Listening for websocket connections on %s\n", *addr)

	// 延迟启动
	time.Sleep(2 * time.Second)
	for i := 0; i < 1000; i++ {
		// 副服务，出错不退出并定时重试。方便主服务做平滑重启
		err := http.ListenAndServe(*addr, nil)
		if err != nil {
			log.Printf("ListenAndServe: num=%d, err=%v ,retry\n", i, err)
		}
		time.Sleep(10 * time.Second)
	}
}

// serveWs handles websocket requests from the peer.
func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	// server.allowIP 白名单: 按真实 TCP 来源(r.RemoteAddr)判定, 不信可伪造的头部;
	// 命中即拒绝, 连 upgrade 都不做。为空则不限制。
	peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !serverIPAllowed(peerIP) {
		log.Printf("serveWs deny ip %s, not in websocket.server.allowIP\n", peerIP)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("serveWs", err)
		return
	}

	// 认证
	var user AuthMessage
	err = conn.ReadJSON(&user)
	if err != nil {
		// 客户端没配置user, email会主动断开
		log.Println("serveWs", "maybe client close", err)
		return
	}
	if user.Email == "" { // 增强验证
		log.Println("serveWs", "client email is empty")
		conn.WriteMessage(websocket.TextMessage, []byte("email error"))
		return
	}
	// 先查账号再验凭据: 走哪套鉴权(密码还是密钥)由这个账号自己的配置决定, 而时钟检查
	// 只对密码方案有意义 —— 密钥方案存在的理由正是不依赖时钟, 不能放在分支前一刀切。
	su, found := conf.RouterConfig.Websocket.Server.LookupUser(user.User)
	if !found || su.Disable {
		if found {
			log.Printf("serveWs client email %s ignore, user %s is disabled\n", user.Email, user.User)
		} else {
			log.Printf("serveWs client email %s ignore, user is error\n", user.Email)
		}
		conn.WriteMessage(websocket.TextMessage, []byte("user err"))
		return
	}
	if err := authClient(conn, user, su); err != nil {
		log.Printf("serveWs client email %s ignore, %v\n", user.Email, err)
		return
	}
	conn.WriteMessage(websocket.TextMessage, []byte("ok"))

	// 订阅
	var tmpSub []SubscribeMessage
	err = conn.ReadJSON(&tmpSub)
	if err != nil {
		log.Printf("serveWs client email %s ignore, %v\n", user.Email, err)
		return
	}
	var subscribe []SubscribeMessage
	for _, sub := range tmpSub {
		if sub.Key != "" && sub.Val != "" {
			subscribe = append(subscribe, sub)
		}
	}
	if len(subscribe) == 0 {
		// 空订阅只在两种情况下放行:
		//   1. 该 email 是某条 server.forward 规则的目标(仅走裸TCP转发);
		//   2. 该订阅方参与 IPv6 QUIC 直连 —— 直连的入口在订阅方自己机器上, 服务端
		//      不需要配 server.forward, 订阅方也不需要头部订阅规则, 不放行的话直连
		//      双方都会卡在这一步连不上。
		switch {
		case isForwardEmail(user.Email):
			log.Printf("serveWs client email %s empty subscribe, allowed for forward\n", user.Email)
		case user.Direct:
			log.Printf("serveWs client email %s empty subscribe, allowed for direct\n", user.Email)
		default:
			log.Printf("serveWs client email %s ignore, subscribe is empty\n", user.Email)
			conn.WriteMessage(websocket.TextMessage, []byte("subscribe empty err"))
			return
		}
	}
	conn.WriteMessage(websocket.TextMessage, []byte("ok"))

	clientNum := len(hub.clients)
	// 注册连接
	client := &Client{hub: hub, conn: conn, send: make(chan *Message, SEND_CHAN_LEN), User: user.User, Email: user.Email, Subscribe: subscribe}
	client.hub.register <- client
	clientNum++ //这里不用len计算是因为chan异步不确认谁先执行

	remote := getIPAdress(r, []string{"X-Real-IP"})
	log.Printf("serveWs client email %s ip %s connected, subscribe %v, total client nums %d\n", user.Email, remote, subscribe, clientNum)

	go client.writePump()
	go client.serverReadPump()
}

// getIPAdress 客户端IP
// serverIPAllowed 判断接入 websocket 服务端的客户端 IP 是否在 server.allowIP 内。
// 为空则不限制; loopback(本机自连) 始终放行; 支持 CIDR 与单 IP。
func serverIPAllowed(ip string) bool {
	allows := conf.RouterConfig.Websocket.Server.AllowIP
	if len(allows) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	for _, p := range allows {
		if ipInCIDR(parsed, p) {
			return true
		}
	}
	return false
}

// ipInCIDR 判断 IP 是否在 cidr 内(支持 ipv4/ipv6); 不是 CIDR 时按单 IP 比较。
//
// 单 IP 分支必须解析后用 IP.Equal 比, 不能比字符串: 同一个 IPv6 地址有多种写法
// (大小写、是否压缩零段), 而 IP.String() 只产出规范形式 —— 配置里写
// 2001:0DB8::1 或 2001:db8:0:0:0:0:0:1 都会匹配不上同一个地址。IPv4 因为写法
// 唯一所以看不出问题。
func ipInCIDR(ip net.IP, cidr string) bool {
	if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
		return ipNet.Contains(ip)
	}
	if single := net.ParseIP(strings.TrimSpace(cidr)); single != nil {
		return single.Equal(ip)
	}
	return false
}

func getIPAdress(req *http.Request, head []string) string {
	var ipAddress string
	// X-Forwarded-For容易被伪造,最好不用
	if len(head) == 0 {
		head = []string{"X-Real-IP"}
	}
	for _, h := range head {
		for _, ip := range strings.Split(req.Header.Get(h), ",") {
			ip = strings.TrimSpace(ip)
			realIP := net.ParseIP(ip)
			if realIP != nil {
				ipAddress = ip
			}
		}
	}
	if len(ipAddress) == 0 {
		ipAddress, _, _ = net.SplitHostPort(req.RemoteAddr)
	}
	return ipAddress
}

// authClient 校验一条订阅方的凭据。两套方案二选一, 由服务端上这个账号配了 key 还是
// pass 决定: 配了 key 就只认密钥, 否则只认密码。配错的一方要能从回包看出是哪种不匹配,
// 否则现象只是"连不上"。
//
// 失败时原因已经回给对端, 返回的 error 只用于服务端日志。
func authClient(conn *websocket.Conn, user AuthMessage, su conf.ServerUser) error {
	if su.Key != "" {
		if !user.KeyAuth {
			conn.WriteMessage(websocket.TextMessage, []byte(
				"auth err: server expects key auth for this user, please set websocket.client.key"))
			return fmt.Errorf("user %s is key-auth, but client sent a password token", user.User)
		}
		return authByKey(conn, user, su.Key)
	}
	if user.KeyAuth {
		conn.WriteMessage(websocket.TextMessage, []byte(
			"auth err: server has no key for this user, please use websocket.client.pass"))
		return fmt.Errorf("user %s is password-auth, but client asked for key auth", user.User)
	}
	return authByPass(conn, user, su.Pass)
}

// authByPass 密码方案: token = md5(user|pass|xtime), xtime 必须落在时间窗口内。
func authByPass(conn *websocket.Conn, user AuthMessage, pass string) error {
	// 时间窗口必须取绝对值: 原先只判 xtime-user.Xtime > 300, 即只挡住"客户端慢于
	// 服务端", 客户端时钟快多少都能通过, 防重放窗口是漏的。
	skew := time.Now().Unix() - user.Xtime
	if skew < 0 {
		skew = -skew
	}
	if skew > authSkewLimit {
		// 把实际时差告诉对方: 只说"时间不对"的话, 对端不知道差多少、往哪个方向差,
		// 而它自己是看不到服务端时间的。
		conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(
			"xtime err: your clock differs from the server by %ds (limit %ds), please sync time (NTP) or switch to key auth",
			skew, authSkewLimit)))
		return fmt.Errorf("clock skew %ds exceeds %ds", skew, authSkewLimit)
	}
	token, err := tools.Md5Str(fmt.Sprintf("%s|%s|%d", user.User, pass, user.Xtime))
	if err != nil || user.Token != token {
		conn.WriteMessage(websocket.TextMessage, []byte("token err"))
		return errors.New("token is error")
	}
	return nil
}

// authByKey 密钥方案: 服务端发一次性随机数, 客户端用私钥签名, 服务端用配置里的公钥验签。
// 随机数只用一次, 防重放不靠时间戳, 所以这条路径完全不看时钟。
func authByKey(conn *websocket.Conn, user AuthMessage, pubKey string) error {
	challengeB64, challenge, err := newAuthChallenge()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("auth err: server failed to create challenge"))
		return fmt.Errorf("create challenge: %w", err)
	}
	if err := conn.WriteJSON(AuthChallenge{Challenge: challengeB64}); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}
	// 这一步比密码方案多一个来回, 必须有超时: 对端不回签名的话, 没有 deadline 就会
	// 一直挂在这里占着连接。读完立刻清掉, 后面的 readPump 会设它自己的 deadline。
	conn.SetReadDeadline(time.Now().Add(authKeyWait))
	var sig AuthSignature
	err = conn.ReadJSON(&sig)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	if err := verifyChallenge(pubKey, challenge, sig.Signature); err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("key err: "+err.Error()))
		return fmt.Errorf("key auth failed: %w", err)
	}
	return nil
}
