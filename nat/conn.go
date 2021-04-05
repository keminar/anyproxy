package nat

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
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
	if user.User == "111" && user.Token == "test" {
		conn.WriteMessage(websocket.TextMessage, []byte("ok"))
	} else {
		conn.WriteMessage(websocket.TextMessage, []byte("token err"))
	}

	// 订阅
	var subscribe SubscribeMessage
	err = conn.ReadJSON(&subscribe)
	if err != nil {
		log.Println(err)
		return
	}
	conn.WriteMessage(websocket.TextMessage, []byte("ok"))

	// 注册连接
	client := &Client{hub: hub, conn: conn, send: make(chan *Message, 100), User: user.User, Subscribe: subscribe}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}
