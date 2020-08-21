package proto

import (
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/keminar/anyproxy/utils/trace"
)

const SO_ORIGINAL_DST = 80

// GetOriginalDstAddr 目标
func GetOriginalDstAddr(tcpConn *net.TCPConn) (dstIP string, dstPort uint16, newTCPConn *net.TCPConn, err error) {
	if tcpConn == nil {
		err = errors.New("ERR: tcpConn is nil")
		return
	}

	// test if the underlying fd is nil
	if tcpConn.RemoteAddr() == nil {
		err = errors.New("ERR: clientConn.fd is nil")
		return
	}

	srcipport := fmt.Sprintf("%v", tcpConn.RemoteAddr())

	newTCPConn = nil
	// connection => file, will make a copy
	// 会使得连接变成阻塞模式，需要自己手动 close 原来的 tcp 连接
	tcpConnFile, err := tcpConn.File()
	if err != nil {
		err = fmt.Errorf("GETORIGINALDST|%v->?->FAILEDTOBEDETERMINED|ERR: %v", srcipport, err)
		return
	}
	// 旧链接关闭
	tcpConn.Close()
	// 文件句柄关闭
	defer tcpConnFile.Close()

	mreq, err := syscall.GetsockoptIPv6Mreq(int(tcpConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		err = fmt.Errorf("GETORIGINALDST|%v->?->FAILEDTOBEDETERMINED|ERR: getsocketopt(SO_ORIGINAL_DST) failed: %v", srcipport, err)
		return
	}

	// 开新连接
	newConn, err := net.FileConn(tcpConnFile)
	if err != nil {
		err = fmt.Errorf("GETORIGINALDST|%v->?->%v|ERR: could not create a FileConn from clientConnFile=%+v: %v", srcipport, mreq, tcpConnFile, err)
		return
	}
	if _, ok := newConn.(*net.TCPConn); ok {
		newTCPConn = newConn.(*net.TCPConn)

		// only support ipv4
		dstIP = net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7]).String()
		dstPort = uint16(mreq.Multiaddr[2])<<8 + uint16(mreq.Multiaddr[3])
		return
	}
	err = fmt.Errorf("GETORIGINALDST|%v|ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", srcipport, newConn, newConn)
	return
}

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

func (that *tcpStream) response() error {
	tunnel := newTunnel(that.req)
	if ip, ok := tunnel.isAllowed(); !ok {
		return errors.New(ip + " is not allowed")
	}
	var err error
	var newTCPConn *net.TCPConn
	that.req.DstIP, that.req.DstPort, newTCPConn, err = GetOriginalDstAddr(that.req.conn)
	defer newTCPConn.Close()
	if err != nil {
		log.Println(trace.ID(that.req.ID), "GetOriginalDstAddr err", err.Error())
		return err
	}

	that.showIP("TCP")
	err = tunnel.handshake(protoTCP, "", that.req.DstIP, uint16(that.req.DstPort))
	if err != nil {
		log.Println(trace.ID(that.req.ID), "dail err", err.Error())
		return err
	}

	// 将前面读的字节补上
	tmpBuf := that.req.reader.UnreadBuf()
	tunnel.conn.Write(tmpBuf)
	tunnel.transfer(newTCPConn, -1)
	return nil
}

func (that *tcpStream) showIP(method string) {
	log.Println(trace.ID(that.req.ID), fmt.Sprintf("%s %s -> %s:%d", method, that.req.conn.RemoteAddr().String(), that.req.DstIP, that.req.DstPort))
}
