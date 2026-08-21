package nat

import (
	"io"
	"log"
	"time"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/trace"
)

var interruptClose bool

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan *Message

	// 用户
	User string

	Email string

	// 订阅特征
	Subscribe []SubscribeMessage

	// 以下三个仅订阅方(client)侧使用, 服务端(nat/conn.go 的 serveWs 构造 Client 时)不赋值,
	// 保持零值即可(服务端连接不会走 localReadPump/dialForCreate)
	bridge  *BridgeHub        // 替代原全局 LocalBridge, 每条 server 连接一份, 避免多连接间请求ID撞车
	forward map[uint16]string // 替代原全局 localForward, 每条 server 连接一份, 避免入口端口撞车
	tag     string            // 日志前缀, 区分多条并发的 server 连接
}

// 写数据到websocket的对端
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send: //ok为判断channel是否关闭
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				log.Println("nat_debug_client_send_chan_close")
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.BinaryMessage)
			if err != nil {
				return
			}

			if config.DebugLevel >= config.LevelDebugBody {
				md5Val, _ := md5Byte(message.Body)
				log.Println("nat_debug_write_websocket", message.ID, message.Method, md5Val, "\n", string(message.Body))
			}
			msgByte, _ := message.encode()
			w.Write(msgByte)
			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// 服务器从websocket的客户端读取数据
func (c *Client) serverReadPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, p, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("nat_debug_read_message_error: %v", err)
			}
			break
		}
		msg, err := decodeMessage(p)
		if err != nil {
			log.Printf("nat_debug_decode_message_error: %v", err)
			break
		}
		if config.DebugLevel >= config.LevelDebugBody {
			md5Val, _ := md5Byte(msg.Body)
			log.Println("nat_debug_read_from_websocket", msg.ID, msg.Method, md5Val)
		}
		ServerBridge.broadcast <- msg
	}
}

// 本地从websocket服务端取数据
func (c *Client) localReadPump() {
	for {
		_, p, err := c.conn.ReadMessage()
		if err != nil {
			log.Println(c.tag, "nat_local_debug_read_error", err.Error())
			return
		}

		msg, err := decodeMessage(p)
		if err != nil {
			log.Println(c.tag, "nat_local_debug_decode_error", err.Error())
			return
		}
		if config.DebugLevel >= config.LevelDebugBody {
			md5Val, _ := md5Byte(msg.Body)
			log.Println(c.tag, "nat_local_read_from_websocket_message", msg.ID, msg.Method, md5Val)
		}

		if msg.Method == METHOD_CREATE {
			// ConnHTTP: dial 本地代理; ConnTCP: 按入口端口查写死的 target。
			// 查不到 target 或 dial 失败: 不建 bridge, 回 CLOSE 让服务端拆链。
			proxConn, derr := dialForCreate(c, msg)
			if derr != nil {
				log.Println(c.tag, trace.ID(msg.ID), "nat_local_debug dial error", msg.Type, msg.Port, derr.Error())
				closeMsg := &Message{ID: msg.ID, Type: msg.Type, Method: METHOD_CLOSE}
				c.hub.broadcast <- &CMessage{client: c, message: closeMsg}
				continue
			}
			b := c.bridge.Register(c, msg.ID, msg.Type, proxConn)
			go func() {
				written, err := b.WritePump()
				logCopyErr(trace.ID(msg.ID), "nat_local_debug websocket->local", err)
				if config.DebugLevel >= config.LevelDebug {
					log.Println(c.tag, trace.ID(msg.ID), "nat debug response size", written)
				}
			}()

			// 从tcp返回数据到ws
			go func() {
				defer b.Unregister()
				if msg.Type == ConnTCP {
					defer log.Println(c.tag, trace.ID(msg.ID), "local tcp forward closed")
				}
				readSize, err := b.CopyBuffer(b, proxConn, "local")
				logCopyErr(trace.ID(msg.ID), "nat_local_debug local->websocket", err)
				if config.DebugLevel >= config.LevelDebug {
					log.Println(c.tag, trace.ID(msg.ID), "nat debug request body size", readSize)
				}
				b.CloseWrite()
			}()
		} else {
			c.bridge.broadcast <- msg
		}
	}
}

func logCopyErr(traceID, name string, err error) {
	if err == nil {
		return
	}
	if config.DebugLevel >= config.LevelLong {
		log.Println(traceID, name, err.Error())
	} else if err != io.EOF {
		log.Println(traceID, name, err.Error())
	}
}
