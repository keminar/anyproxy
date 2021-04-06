package nat

import (
	"fmt"
	"log"
	"net/http"
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
	ReadBufferSize:  1024 * 1024 * 1024,
	WriteBufferSize: 1024 * 1024 * 1024,
}

var ServerHub *Hub
var ServerBridge *BridgeHub

func NewServer(addr *string) {
	ServerHub = newHub()
	go ServerHub.run()
	ServerBridge = newBridgeHub()
	go ServerBridge.run()

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

	// 注册连接
	client := &Client{hub: hub, conn: conn, send: make(chan *Message, 100), User: user.User, Subscribe: subscribe}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}
