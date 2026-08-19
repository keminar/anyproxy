// 条件编译 https://segmentfault.com/a/1190000017846997

// +build !windows

package proto

import (
	"errors"
	"fmt"
	"net"
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

	// 先记下来源 IP(下面会 Close 原连接, RemoteAddr 就取不到了), 并据此判断连接族:
	// 远端是 IPv6(非 v4-mapped)则走 ip6tables 的 IP6T_SO_ORIGINAL_DST 取原目标。
	var srcIP string
	isV6 := false
	if ta, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
		srcIP = ta.IP.String()
		isV6 = ta.IP.To4() == nil
	}

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

	fd := int(tcpConnFile.Fd())
	if isV6 {
		// IPv6: ip6tables REDIRECT, 用 IP6T_SO_ORIGINAL_DST 取原始目标(仅 Linux)
		dstIP, dstPort, err = getOriginalDstV6(fd)
	} else {
		// IPv4: iptables REDIRECT, 用 SO_ORIGINAL_DST 取原始目标
		var mreq *syscall.IPv6Mreq
		mreq, err = syscall.GetsockoptIPv6Mreq(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err == nil {
			dstIP = net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7]).String()
			dstPort = uint16(mreq.Multiaddr[2])<<8 + uint16(mreq.Multiaddr[3])
		}
	}
	if err != nil {
		err = fmt.Errorf("GETORIGINALDST|%v->?->FAILEDTOBEDETERMINED|ERR: getsocketopt(SO_ORIGINAL_DST) failed: %v", srcipport, err)
		return
	}

	// 开新连接
	newConn, err := net.FileConn(tcpConnFile)
	if err != nil {
		err = fmt.Errorf("GETORIGINALDST|%v->?->%s:%d|ERR: could not create a FileConn from clientConnFile=%+v: %v", srcipport, dstIP, dstPort, tcpConnFile, err)
		return
	}
	if _, ok := newConn.(*net.TCPConn); ok {
		newTCPConn = newConn.(*net.TCPConn)

		// 来源和目标地址是同一个ip，且目标端口和本服务是同一个端口
		if srcIP == dstIP && dstPort == config.ListenPort {
			err = fmt.Errorf("may be loop call: %s=>%s:%d", srcipport, dstIP, dstPort)
		}
		return
	}
	err = fmt.Errorf("GETORIGINALDST|%v|ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", srcipport, newConn, newConn)
	return
}
