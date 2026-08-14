package proto

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/keminar/anyproxy/proto/tcp"
	"github.com/keminar/anyproxy/utils/trace"
)

const SO_ORIGINAL_DST = 80

type stream interface {
	validHead() bool
	readRequest(from string) (canProxy bool, err error)
	response() error
}

type tcpStream struct {
	req *Request
}

func newTCPStream(req *Request) *tcpStream {
	c := &tcpStream{
		req: req,
	}
	return c
}

func (that *tcpStream) validHead() bool {
	return true
}
func (that *tcpStream) readRequest(from string) (canProxy bool, err error) {
	// 透明代理(iptables/TUN)只知道目标IP。这里在不消费数据的前提下
	// 从TLS ClientHello首包嗅探SNI域名，使配置文件按域名匹配的规则也能生效。
	// (明文HTTP走httpStream由Host头处理，不到这里)
	that.req.DstName = sniffPeekDomain(that.req.conn, that.req.reader)
	return true, nil
}

// sniffPeekDomain 从TLS ClientHello首包嗅探SNI域名，仅Peek不消费，
// 使后续 UnreadBuf 仍能把首包补发给服务端。
// 仅在客户端先发TLS数据(0x16)时才扩展读取，避免对"服务端先说话"的协议造成阻塞。
func sniffPeekDomain(conn *net.TCPConn, r *tcp.Reader) string {
	head, err := r.Peek(1)
	if err != nil || len(head) < 1 || head[0] != 0x16 { // 非TLS
		return ""
	}
	// 加读超时，防止 ClientHello 分片时长时间阻塞
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	defer conn.SetReadDeadline(time.Time{})

	hdr, err := r.Peek(5)
	if err != nil || len(hdr) < 5 {
		return ""
	}
	need := 5 + (int(hdr[3])<<8 | int(hdr[4]))
	if need > r.Size() {
		need = r.Size()
	}
	full, _ := r.Peek(need)
	return sniffDomain(full)
}

// 处理iptables转发的流量
func (that *tcpStream) response() error {
	tunnel := newTunnel(that.req)
	var err error
	var newTCPConn *net.TCPConn
	that.req.DstIP, that.req.DstPort, newTCPConn, err = GetOriginalDstAddr(that.req.conn)
	if err != nil {
		log.Println(trace.ID(that.req.ID), "GetOriginalDstAddr err", err.Error())
		return err
	}
	defer newTCPConn.Close()

	that.showIP("TCP")
	err = tunnel.handshake(protoTCP, that.req.DstName, that.req.DstIP, uint16(that.req.DstPort))
	if err != nil {
		log.Println(trace.ID(that.req.ID), "dail err", err.Error())
		return err
	}

	// 将前面读的字节补上
	tmpBuf := that.req.reader.UnreadBuf(-1)
	tunnel.Write(tmpBuf)
	// 切换为新连接
	reader := tcp.NewReader(newTCPConn)
	that.req.reader = reader
	that.req.conn = newTCPConn
	tunnel.transfer(-1)
	return nil
}

func (that *tcpStream) showIP(method string) {
	if that.req.DstName != "" {
		log.Println(trace.ID(that.req.ID), fmt.Sprintf("%s %s -> %s (%s:%d)", method, that.req.conn.RemoteAddr().String(), that.req.DstName, that.req.DstIP, that.req.DstPort))
		return
	}
	log.Println(trace.ID(that.req.ID), fmt.Sprintf("%s %s -> %s:%d", method, that.req.conn.RemoteAddr().String(), that.req.DstIP, that.req.DstPort))
}
