package nat

import (
	"log"

	"github.com/keminar/anyproxy/config"
)

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages from the clients.
	broadcast chan *Message

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan *Message),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			if config.DebugLevel >= config.LevelDebug {
				log.Println("clients nums", len(h.clients))
			}
		Exit:
			for client := range h.clients {
				if config.DebugLevel >= config.LevelDebugBody {
					log.Println("nat_debug_write_client_hub", message.ID, message.Method, string(message.Body))
				}
				// todo 检查 client subscribe 来判断发送给谁
				select {
				case client.send <- message:
					//发送给一个订阅者就要返回，不然变成多个并发请求了，而且接收数据也会出错。
					break Exit
				default: // 当send chan满时也会走进default
					if config.DebugLevel >= config.LevelDebug {
						log.Println("why go here ?????")
					}
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}
