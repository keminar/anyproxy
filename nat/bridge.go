package nat

import (
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/trace"
)

// Bridge 桥接
type Bridge struct {
	bridgeHub *BridgeHub
	client    *Client

	reqID uint  //请求id
	typ   uint8 //连接类型(ConnHTTP/ConnTCP), 与 reqID 组成复合键
	conn  *net.TCPConn

	// 本连接累计流量(原子, 供存活心跳/关闭汇总实时读取):
	//   copyBytes: CopyBuffer 写出方向(请求端->websocket)
	//   pumpBytes: WritePump 写入方向(websocket->请求端)
	copyBytes int64
	pumpBytes int64

	// lastActive 最近一次两个方向任一发生真实收发的时间(unix nano, 原子), 供空闲
	// 超时判断使用: 双向都无新流量超过阈值即视为僵尸连接(见 forward.go forwardIdleTimeout)。
	lastActive int64

	// Buffered channel of outbound messages.
	send chan []byte
}

// Stats 返回本连接两个方向的累计字节(原子读), 供调用方打存活/汇总日志。
// 服务端入口连接视角: copyBytes 为上行(请求端->内网), pumpBytes 为下行(内网->请求端)。
func (b *Bridge) Stats() (copyBytes, pumpBytes int64) {
	return atomic.LoadInt64(&b.copyBytes), atomic.LoadInt64(&b.pumpBytes)
}

// touch 记录一次真实收发, 刷新 lastActive。
func (b *Bridge) touch() {
	atomic.StoreInt64(&b.lastActive, time.Now().UnixNano())
}

// IdleFor 返回距离上次任一方向有真实收发数据过去的时长。
func (b *Bridge) IdleFor() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&b.lastActive)))
}

// Unregister 包外面调用取消注册
func (b *Bridge) Unregister() {
	b.bridgeHub.unregister <- b
}

// 向websocket hub写数据
func (b *Bridge) Write(p []byte) (n int, err error) {
	// 先把p拷贝一份，否则会被外面的CopyBuffer再次修改，因为是引入传递
	body := make([]byte, len(p))
	copy(body, p)
	msg := &Message{ID: b.reqID, Type: b.typ, Body: body}

	if config.DebugLevel >= config.LevelDebugBody {
		md5Val, _ := md5Byte(msg.Body)
		log.Println("nat_debug_write_chan", msg.ID, md5Val)
	}

	cmsg := &CMessage{client: b.client, message: msg}
	b.client.hub.broadcast <- cmsg
	return len(p), nil
}

// Open 通知websocket 创建连接。port 仅用于裸TCP路径(ConnTCP), 供订阅方查固定
// target; HTTP 路径传 0 即可。
func (b *Bridge) Open(port uint16) {
	msg := &Message{ID: b.reqID, Type: b.typ, Method: METHOD_CREATE, Port: port}
	//b.client.send <- msg //注意:不能直接写send会与close有并发安全冲突
	cmsg := &CMessage{client: b.client, message: msg}
	b.client.hub.broadcast <- cmsg
}

// CloseWrite 通知tcp关闭连接
func (b *Bridge) CloseWrite() {
	msg := &Message{ID: b.reqID, Type: b.typ, Method: METHOD_CLOSE}
	cmsg := &CMessage{client: b.client, message: msg}
	b.client.hub.broadcast <- cmsg
}

// WritePump 从websocket hub读数据写到请求http端
func (b *Bridge) WritePump() (written int64, err error) {
	defer func() {
		b.conn.CloseWrite()
		if config.DebugLevel >= config.LevelDebug {
			log.Println("net_debug_write_proxy_close")
		}
	}()
	for {
		select {
		case message, ok := <-b.send: //ok为判断channel是否关闭
			if !ok {
				if config.DebugLevel >= config.LevelDebug {
					log.Println("nat_debug_bridge_send_chan_closed")
				}
				return
			}
			var nw int
			nw, err = b.conn.Write(message)
			if config.DebugLevel >= config.LevelDebugBody {
				md5Val, _ := md5Byte(message)
				log.Println("nat_debug_write_proxy", md5Val, err, "\n", string(message))
			}
			if err != nil {
				return
			}
			written += int64(nw)
			atomic.AddInt64(&b.pumpBytes, int64(nw))
			b.touch()
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
				md5Val, _ := md5Byte(buf[0:nr])
				log.Println(trace.ID(b.reqID), "net_debug_copy_buffer", srcname, i, nr, md5Val)
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
				atomic.AddInt64(&b.copyBytes, int64(nw))
				b.touch()
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
			if config.DebugLevel >= config.LevelDebug {
				log.Println("nat_debug_read_error", srcname, er)
			}
			break
		}

	}
	return written, err
}
