package nat

import (
	"errors"
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
				client.quietLog("client email %s disconnected, total client nums %d\n", client.Email, len(h.clients))
				// 拆掉这个 Client 牵涉到的文件中继路由(如果有): 不拆的话另一端的
				// msgPipe 会在 Read() 上无限期挂着, 表现就是"传输莫名其妙卡住"。
				// 这个 Hub 类型两处角色(B 的 ServerHub、订阅方自己的本地 hub)共用
				// 同一份代码, 但路由表只会在 B 上有条目, 订阅方侧调用是无操作的空查。
				fileRelay.clientGone(client)
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
			//
			// 投递结果要回报给调用方(见 CMessage.done): 队列满时这条消息是被丢掉的,
			// 不告知的话发送方会以为发成功了 —— 对文件中继这种"一个字节流切成多条
			// 消息"的用法, 悄悄少一条就是对端帧错位, 排查起来毫无头绪。
			err := errors.New("client is not registered on this hub")
		Exit:
			for client := range h.clients {
				if client != cmessage.client {
					continue
				}
				select {
				case client.send <- cmessage.message:
					err = nil
					break Exit
				default: // 当send chan写不进时会走进default，防止某一个send卡着影响整个系统
					close(client.send)
					delete(h.clients, client)
					log.Printf("net_client_send_chan_full, client email %s disconnected\n", client.Email)
					err = errors.New("send queue is full, this client was disconnected")
					break Exit
				}
			}
			cmessage.signal(err)
		}
	}
}

// GetClientByEmail 按email获取订阅者(裸TCP转发用, 无http头可匹配)。
// 同email多连接时返回首个命中; 无命中返回nil。
func (h *Hub) GetClientByEmail(email string) *Client {
	if email == "" {
		return nil
	}
	for client := range h.clients {
		if client.Email == email {
			return client
		}
	}
	return nil
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
