package nat

import (
	"log"
	"time"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/config"
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
				log.Println("nat_debug_write_websocket", message.ID, message.Method, len(message.Body), err, string(message.Body))
			}
			msgByte, err := message.encode()
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

// 从websocket的客户端读取数据
func (c *Client) readPump() {
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
			log.Println("nat_debug_read_from_websocket", msg.ID, msg.Method, len(msg.Body))
		}
		ServerBridge.broadcast <- msg
	}
}
