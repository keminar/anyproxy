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

var ServerHub *Hub
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

	log.Println(fmt.Sprintf("Listening for websocket connections on %s", *addr))
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

// serveWs handles websocket requests from the peer.
func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	// 认证
	var user AuthMessage
	err = conn.ReadJSON(&user)
	if err != nil {
		log.Println(err)
		return
	}
	xtime := time.Now().Unix()
	if xtime-user.Xtime > 60 {
		conn.WriteMessage(websocket.TextMessage, []byte("xtime err"))
		return
	}
	if user.User != conf.RouterConfig.Websocket.User {
		conn.WriteMessage(websocket.TextMessage, []byte("user err"))
		return
	}

	token, err := tools.Md5Str(fmt.Sprintf("%s|%s|%d", user.User, conf.RouterConfig.Websocket.Pass, user.Xtime))
	if err != nil || user.Token != token {
		conn.WriteMessage(websocket.TextMessage, []byte("token err"))
		return
	}
	conn.WriteMessage(websocket.TextMessage, []byte("ok"))

	// 订阅
	var subscribe []SubscribeMessage
	err = conn.ReadJSON(&subscribe)
	if err != nil {
		log.Println(err)
		return
	}
	if len(subscribe) == 0 {
		conn.WriteMessage(websocket.TextMessage, []byte("subscribe empty err"))
		return
	}
	conn.WriteMessage(websocket.TextMessage, []byte("ok"))

	clientNum := len(hub.clients)
	// 注册连接
	client := &Client{hub: hub, conn: conn, send: make(chan *Message, 100), User: user.User, Subscribe: subscribe}
	client.hub.register <- client
	clientNum++ //这里不用len计算是因为chan异步不确认谁先执行

	remote := getIPAdress(r, []string{"X-Real-IP"})
	log.Printf("client ip %s connected, total client nums %d\n", remote, clientNum)

	go client.writePump()
	go client.readPump()
}

// getIPAdress 客户端IP
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
