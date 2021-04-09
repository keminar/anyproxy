package nat

import (
	"log"
	"net"

	"github.com/keminar/anyproxy/config"
)

// BridgeHub 桥接组
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
	// 无缓冲通道，保证并发安全
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
			if config.DebugLevel >= config.LevelDebug {
				log.Println("bridge nums", len(h.bridges))
			}
			if config.DebugLevel >= config.LevelDebugBody {
				md5Val, _ := md5Byte(message.Body)
				log.Println("nat_debug_write_bridge_hub", message.ID, message.Method, md5Val)
			}
		Exit:
			for bridge := range h.bridges {
				if bridge.reqID != message.ID {
					continue
				}
				if message.Method == METHOD_CLOSE {
					close(bridge.send)
					delete(h.bridges, bridge)
					break Exit
				}
				select {
				case bridge.send <- message.Body:
					break Exit
				default: // 当send chan写不进时会走进default，防止某一个send卡着影响整个系统
					log.Println("net_bridge_send_chan_full", message.ID)
					close(bridge.send)
					delete(h.bridges, bridge)
				}
			}
		}
	}
}

// Register 注册
func (h *BridgeHub) Register(c *Client, ID uint, conn *net.TCPConn) *Bridge {
	b := &Bridge{bridgeHub: h, reqID: ID, conn: conn, send: make(chan []byte, 100), client: c}
	h.register <- b
	return b
}
