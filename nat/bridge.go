package nat

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/trace"
)

type Bridge struct {
	hub   *BridgeHub
	wsHub *Hub

	reqID uint
	conn  *net.TCPConn

	// Buffered channel of outbound messages.
	send chan []byte
}

// 向websocket hub写数据
func (b *Bridge) Write(p []byte) (n int, err error) {
	msg := &Message{ID: b.reqID, Body: p}
	b.wsHub.broadcast <- msg
	return len(p), nil
}

// 通知websocket 创建连接
func (b *Bridge) Open() {
	msg := &Message{ID: b.reqID, Method: "create"}
	b.wsHub.broadcast <- msg
}

// 通知tcp关闭连接
func (b *Bridge) CloseWrite() {
	msg := &Message{ID: b.reqID, Method: "close"}
	b.wsHub.broadcast <- msg
}

// 从websocket hub读数据
func (b *Bridge) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		b.conn.CloseWrite()
		log.Println("net_debug_close_proxy_write")
	}()
	for {
		select {
		case message, ok := <-b.send: //ok为判断channel是否关闭
			if !ok {
				log.Println("nat_debug_bridge_send_close")
				return
			}
			if config.DebugLevel >= config.LevelDebugBody {
				log.Println("nat_debug_write_proxy", string(message))
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

// CopyBuffer 传输数据
func (b *Bridge) CopyBuffer(dst io.Writer, src io.Reader, srcname string) (written int64, err error) {
	//如果设置过大会耗内存高，4k比较合理
	size := 4 * 1024
	buf := make([]byte, size)
	i := 0
	for {
		i++
		if config.DebugLevel >= config.LevelDebug {
			log.Printf("%s bridge of %s proxy, n=%d\n", trace.ID(b.reqID), srcname, i)
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if config.DebugLevel >= config.LevelDebugBody {
				log.Printf("%s bridge of %s proxy, n=%d, data len: %d\n", trace.ID(b.reqID), srcname, i, nr)
				fmt.Println(trace.ID(b.reqID), string(buf[0:nr]))
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			log.Println("nat_debug_read_error", srcname, er)
			break
		}

	}
	return written, err
}
