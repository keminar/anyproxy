package nat

import (
	"net"
)

type BridgeHub struct {
	// Registered clients.
	bridges map[*Bridge]bool

	// Inbound messages from the clients.
	broadcast chan *Message

	// Register requests from the clients.
	register chan *Bridge

	// Unregister requests from clients.
	unregister chan *Bridge
}

func newBridgeHub() *BridgeHub {
	return &BridgeHub{
		broadcast:  make(chan *Message),
		register:   make(chan *Bridge),
		unregister: make(chan *Bridge),
		bridges:    make(map[*Bridge]bool),
	}
}

func (h *BridgeHub) run() {
	for {
		select {
		case bridge := <-h.register:
			h.bridges[bridge] = true
		case bridge := <-h.unregister:
			if _, ok := h.bridges[bridge]; ok {
				delete(h.bridges, bridge)
				close(bridge.send)
			}
		case message := <-h.broadcast:
			for bridge := range h.bridges {
				if bridge.reqID != message.ID {
					continue
				}
				if message.Method == "close" {
					close(bridge.send)
					delete(h.bridges, bridge)
					return
				}
				select {
				case bridge.send <- message.Body:
				default:
					close(bridge.send)
					delete(h.bridges, bridge)
				}
			}
		}
	}
}

func (h *BridgeHub) Register(ID uint, conn *net.TCPConn) *Bridge {
	b := &Bridge{reqID: ID, conn: conn, send: make(chan []byte)}
	h.register <- b

	// 发送创建连接请求
	b.Open()
	return b
}
