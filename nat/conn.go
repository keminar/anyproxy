package nat

import (
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
	xtime := time.Now().Unix()
	if xtime-user.Xtime > 300 {
		log.Printf("serveWs client email %s ignore, xtime is error\n", user.Email)
		conn.WriteMessage(websocket.TextMessage, []byte("xtime err, please check local time"))
		return
	}
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

	token, err := tools.Md5Str(fmt.Sprintf("%s|%s|%d", user.User, su.Pass, user.Xtime))
	if err != nil || user.Token != token {
		log.Printf("serveWs client email %s ignore, token is error\n", user.Email)
		conn.WriteMessage(websocket.TextMessage, []byte("token err"))
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
		// 若该email是某条forward规则的目标, 允许空订阅(仅走裸TCP转发)
		if !isForwardEmail(user.Email) {
			log.Printf("serveWs client email %s ignore, subscribe is empty\n", user.Email)
			conn.WriteMessage(websocket.TextMessage, []byte("subscribe empty err"))
			return
		}
		log.Printf("serveWs client email %s empty subscribe, allowed for forward\n", user.Email)
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

// ipInCIDR 判断 IP 是否在 cidr 内(支持 ipv4/ipv6); cidr 非法时按单 IP 精确比较。
func ipInCIDR(ip net.IP, cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ip.String() == cidr
	}
	return ipNet.Contains(ip)
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
