// 条件编译 https://segmentfault.com/a/1190000017846997

// +build !windows

package proto

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/keminar/anyproxy/config"
)

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

		ipArr := strings.Split(srcipport, ":")
		// 来源和目标地址是同一个ip，且目标端口和本服务是同一个端口
		if ipArr[0] == dstIP && dstPort == config.ListenPort {
			err = fmt.Errorf("may be loop call: %s=>%s:%d", srcipport, dstIP, dstPort)
		}
		return
	}
	err = fmt.Errorf("GETORIGINALDST|%v|ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", srcipport, newConn, newConn)
	return
}
