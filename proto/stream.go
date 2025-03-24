package proto

import (
	"fmt"
	"log"
	"net"

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
	return true, nil
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
	err = tunnel.handshake(protoTCP, "", that.req.DstIP, uint16(that.req.DstPort))
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
	log.Println(trace.ID(that.req.ID), fmt.Sprintf("%s %s -> %s:%d", method, that.req.conn.RemoteAddr().String(), that.req.DstIP, that.req.DstPort))
}
