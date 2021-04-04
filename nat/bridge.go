package nat

import (
	"net"
	"time"
)

type Bridge struct {
	hub *BridgeHub

	reqID uint
	conn  *net.TCPConn

	// Buffered channel of outbound messages.
	send chan []byte
}

// 向websocket hub写数据
func (b *Bridge) Write(p []byte) (n int, err error) {
	msg := &Message{ID: b.reqID, Body: p}
	WsHub.broadcast <- msg
	return len(p), nil
}

// 通知websocket 创建连接
func (b *Bridge) Open() {
	msg := &Message{ID: b.reqID, Method: "create"}
	WsHub.broadcast <- msg
}

// 通知tcp关闭连接
func (b *Bridge) CloseWrite() {
	msg := &Message{ID: b.reqID, Method: "close"}
	WsHub.broadcast <- msg
}

// 从websocket hub读数据
func (b *Bridge) ReadPump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		b.conn.Close()
	}()
	for {
		select {
		case message, ok := <-b.send: //ok为判断channel是否关闭
			if !ok {
				return
			}

			_, err := b.conn.Write(message)
			if err != nil {
				return
			}
		case <-ticker.C:
			return
		}
	}
}
