package nat

import (
	"errors"
	"net"
)

type BridgeHub struct {
	// Registered clients.
	bridges map[*Bridge]bool

	// Inbound messages from the clients.
	broadcast chan []byte

	// Register requests from the clients.
	register chan *Bridge

	// Unregister requests from clients.
	unregister chan *Bridge
}

func newBridgeHub() *BridgeHub {
	return &BridgeHub{
		broadcast:  make(chan []byte),
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
				select {
				case bridge.send <- message:
				default:
					close(bridge.send)
					delete(h.bridges, bridge)
				}
			}
		}
	}
}

func (h *BridgeHub) Write(p []byte) (n int, err error) {
	h.broadcast <- p
	return len(p), nil
}

func (h *BridgeHub) Read(p []byte) (n int, err error) {
	for bridge := range h.bridges {
		n, err := bridge.conn.Read(p)
		return n, err
	}
	return 0, errors.New("fail")
}

func (h *BridgeHub) Register(ID uint, conn *net.TCPConn) {
	b := &Bridge{reqID: ID, conn: conn, send: make(chan []byte)}
	h.register <- b
	//go b.writePump()
}
