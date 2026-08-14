//go:build darwin
// +build darwin

package proto

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/keminar/anyproxy/config"
)

// tunDial 强制出向连接从物理网卡出，绕过 TUN 路由环路。
//
// macOS 同 Windows：出接口由「目标路由」决定。TUN 装了 0.0.0.0/1 + 128.0.0.0/1，
// 仅靠 LocalAddr 绑源 IP 无法把包送出物理网卡，包会回灌 anyproxy 形成死循环
// (target=local 直连时表现为无限新建连接)。
//
// 正解是 IP_BOUND_IF：直接指定出接口，覆盖路由表查找(等价于 Windows 的
// IP_UNICAST_IF / Linux 的 SO_BINDTODEVICE)。索引用主机字节序，无需字节交换。
func tunDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	ip := config.TUNBypassIP
	if ip == "" {
		return net.DialTimeout(network, addr, timeout)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if isLocalNet(host) {
		return net.DialTimeout(network, addr, timeout)
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)},
	}
	if iface, err2 := net.InterfaceByName(config.TUNBypassDev); err2 == nil {
		dialer.Control = bindBoundIF(iface.Index)
	}
	return dialer.Dial(network, addr)
}

// bindBoundIF 返回一个 Dialer.Control，把 socket 的出接口固定为 idx(host order)。
func bindBoundIF(idx int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
		}); err != nil {
			return err
		}
		return serr
	}
}
