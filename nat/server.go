package nat

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var WsHub *Hub
var ServerBridge *BridgeHub

func NewServer(addr *string) {
	WsHub = newHub()
	go WsHub.run()
	ServerBridge = newBridgeHub()
	go ServerBridge.run()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(WsHub, w, r)
	})
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
	client := &Client{hub: hub, conn: conn, send: make(chan *Message), User: user.User, Subscribe: subscribe}
	client.hub.register <- client

	go client.writePump()
}
