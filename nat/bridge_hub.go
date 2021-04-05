package nat

import (
	"log"
	"net"

	"github.com/keminar/anyproxy/config"
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
			log.Println("bridge nums", len(h.bridges))
		Exit:
			for bridge := range h.bridges {
				if config.DebugLevel >= config.LevelDebugBody {
					log.Println("nat_debug_write_bridge_hub", bridge.reqID, message.ID, message.Method, string(message.Body))
				}
				if bridge.reqID != message.ID {
					continue
				}
				if message.Method == "close" {
					close(bridge.send)
					delete(h.bridges, bridge)
					break Exit
				}
				select {
				case bridge.send <- message.Body:
				default: // 当send chan满时也会走进default
					close(bridge.send)
					delete(h.bridges, bridge)
				}
			}
		}
	}
}

func (h *BridgeHub) Register(wsHub *Hub, ID uint, conn *net.TCPConn) *Bridge {
	b := &Bridge{reqID: ID, conn: conn, send: make(chan []byte, 100), wsHub: wsHub}
	h.register <- b
	return b
}

func (h *BridgeHub) Unregister(b *Bridge) {
	h.unregister <- b
}
