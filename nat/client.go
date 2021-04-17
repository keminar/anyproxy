package nat

import (
	"io"
	"log"
	"net"
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

	// 订阅特征
	Subscribe []SubscribeMessage
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
			log.Println("nat_local_debug_read_error", err.Error())
			return
		}

		msg, err := decodeMessage(p)
		if err != nil {
			log.Println("nat_local_debug_decode_error", err.Error())
			return
		}
		if config.DebugLevel >= config.LevelDebugBody {
			md5Val, _ := md5Byte(msg.Body)
			log.Println("nat_local_read_from_websocket_message", msg.ID, msg.Method, md5Val)
		}

		if msg.Method == METHOD_CREATE {
			proxConn := dialProxy() //创建本地与本地代理端口之间的连接
			b := LocalBridge.Register(c, msg.ID, proxConn.(*net.TCPConn))
			go func() {
				written, err := b.WritePump()
				logCopyErr(trace.ID(msg.ID), "nat_local_debug websocket->local", err)
				if config.DebugLevel >= config.LevelDebug {
					log.Println(trace.ID(msg.ID), "nat debug response size", written)
				}
			}()

			// 从tcp返回数据到ws
			go func() {
				defer b.Unregister()
				readSize, err := b.CopyBuffer(b, proxConn, "local")
				logCopyErr(trace.ID(msg.ID), "nat_local_debug local->websocket", err)
				if config.DebugLevel >= config.LevelDebug {
					log.Println(trace.ID(msg.ID), "nat debug request body size", readSize)
				}
				b.CloseWrite()
			}()
		} else {
			LocalBridge.broadcast <- msg
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
