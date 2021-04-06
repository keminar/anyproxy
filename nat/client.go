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
				log.Println("nat client send chan close")
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			err := c.conn.WriteJSON(message)
			if config.DebugLevel >= config.LevelDebugBody {
				log.Println("nat websocket writeJson", message.ID, message.Method, string(message.Body), err)
			}
			if err != nil {
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
		msg := &Message{}
		err := c.conn.ReadJSON(msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		if config.DebugLevel >= config.LevelDebugBody {
			log.Println("nat_debug_read_from_client", msg.ID, msg.Method, string(msg.Body))
		}
		ServerBridge.broadcast <- msg
	}
}
