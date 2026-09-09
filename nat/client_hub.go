package nat

import (
	"errors"
	"log"
	"sync"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/proto/http"
)

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// mu 保护 clients。register/unregister/broadcast 由 run() 那个 goroutine 串行处理,
	// 本来不需要加锁; 但 GetClientByEmail/GetClient(direct_broker.go、forward.go、
	// file_relay.go、relay_udp_server.go 等都会调)是从各自连接的读循环 goroutine 直接
	// 同步读 clients 的, 并不经过 run() 那几个 channel——不加锁就是并发读写 map, 轻则
	// -race 报错, 重则 "fatal error: concurrent map read and map write" 直接崩掉进程。
	mu sync.RWMutex
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
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			_, ok := h.clients[client]
			if ok {
				delete(h.clients, client)
			}
			n := len(h.clients)
			h.mu.Unlock()
			if ok {
				close(client.send)
				client.quietLog("client email %s disconnected, total client nums %d\n", client.Email, n)
				// 拆掉这个 Client 牵涉到的文件中继路由(如果有): 不拆的话另一端的
				// msgPipe 会在 Read() 上无限期挂着, 表现就是"传输莫名其妙卡住"。
				// 这个 Hub 类型两处角色(B 的 ServerHub、订阅方自己的本地 hub)共用
				// 同一份代码, 但路由表只会在 B 上有条目, 订阅方侧调用是无操作的空查。
				fileRelay.clientGone(client)
			}
		case cmessage := <-h.broadcast:
			if config.DebugLevel >= config.LevelDebug {
				log.Println("client nums", h.ClientCount())
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
			h.mu.Lock()
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
			h.mu.Unlock()
			cmessage.signal(err)
		}
	}
}

// ClientCount 目前登记着的客户端数量, 仅供日志/统计用。
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// GetClientByEmail 按email获取订阅者(裸TCP转发用, 无http头可匹配)。
// 同email多连接时返回首个命中; 无命中返回nil。
func (h *Hub) GetClientByEmail(email string) *Client {
	if email == "" {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for client := range h.clients {
		if client.Email == email {
			return client
		}
	}
	return nil
}

// GetClient 获取某一个订阅者
func (h *Hub) GetClient(header http.Header) *Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
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
