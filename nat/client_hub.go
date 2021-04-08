package nat

import (
	"log"

	"github.com/keminar/anyproxy/proto/http"
)

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages from the clients.
	broadcast chan *CMessage

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client
}

func newHub() *Hub {
	// 无缓冲通道，保证并发安全
	return &Hub{
		broadcast:  make(chan *CMessage),
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
		case cmessage := <-h.broadcast:
			// 使用broadcast 无缓冲且不会关闭解决并发问题
			// 如果在外部直接写client.send,会与close()有并发安全冲突
		Exit:
			for client := range h.clients {
				if client != cmessage.Client {
					continue
				}
				select {
				case client.send <- cmessage.Message:
					break Exit
				default: // 当send chan写不进时会走进default，防止某一个send卡着影响整个系统
					log.Println("net_client_send_chan_full")
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}

// GetClient 获取某一个订阅者
func (h *Hub) GetClient(header http.Header) *Client {
	for client := range h.clients {
		for _, s := range client.Subscribe {
			val := header.Get(s.Key)
			if val != "" && val == s.Val {
				return client
			}
		}
	}
	return nil
}
