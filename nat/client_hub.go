package nat

import (
	"log"

	"github.com/keminar/anyproxy/config"
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
				close(client.send)
				delete(h.clients, client)
				log.Printf("client email %s disconnected, total client nums %d\n", client.Email, len(h.clients))
			}
		case cmessage := <-h.broadcast:
			if config.DebugLevel >= config.LevelDebug {
				log.Println("client nums", len(h.clients))
			}
			if config.DebugLevel >= config.LevelDebugBody {
				md5Val, _ := md5Byte(cmessage.message.Body)
				log.Println("nat_debug_write_client_hub", cmessage.message.ID, cmessage.message.Method, md5Val)
			}
			// 使用broadcast 无缓冲且不会关闭解决并发问题
			// 如果在外部直接写client.send,会与close()有并发安全冲突
		Exit:
			for client := range h.clients {
				if client != cmessage.client {
					continue
				}
				select {
				case client.send <- cmessage.message:
					break Exit
				default: // 当send chan写不进时会走进default，防止某一个send卡着影响整个系统
					close(client.send)
					delete(h.clients, client)
					log.Printf("net_client_send_chan_full, client email %s disconnected\n", client.Email)
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
			//log.Println("debug", client.Email, s.Key, s.Val, val)
			if val != "" && val == s.Val {
				return client
			}
		}
	}
	return nil
}
