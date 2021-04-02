package nat

import (
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

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// serveWs handles websocket requests from the peer.
func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

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

	var subscribe SubscribeMessage
	err = conn.ReadJSON(&subscribe)
	if err != nil {
		log.Println(err)
		return
	}
	conn.WriteMessage(websocket.TextMessage, []byte("ok"))

	client := &Client{hub: hub, conn: conn, send: make(chan []byte), User: user.User, Subscribe: subscribe}
	client.hub.register <- client

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
}
