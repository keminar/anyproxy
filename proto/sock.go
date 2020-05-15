package proto

import (
	"fmt"
	"net"
	"syscall"
)

const SO_ORIGINAL_DST = 80

// GetOriginalDstAddr 目标
func GetOriginalDstAddr(tcpConn *net.TCPConn) (dstIP string, dstPort uint16, leftConn *net.TCPConn, err error) {
	// connection => file, will make a copy
	tcpConnFile, err := tcpConn.File()
	if err != nil {
		return
	}
	tcpConn.Close()
	defer tcpConnFile.Close()

	mreq, err := syscall.GetsockoptIPv6Mreq(int(tcpConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return
	}

	// only support ipv4
	dstIP = net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7]).String()
	dstPort = uint16(mreq.Multiaddr[2])<<8 + uint16(mreq.Multiaddr[3])

	newConn, err := net.FileConn(tcpConnFile)
	if err != nil {
		return
	}
	if _, ok := newConn.(*net.TCPConn); ok {
		leftConn = newConn.(*net.TCPConn)
		return
	}
	err = fmt.Errorf("ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", newConn, newConn)
	return
}
