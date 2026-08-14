//go:build linux
// +build linux

package nat

import (
	"net"
	"syscall"
	"time"

	"github.com/keminar/anyproxy/config"
)

// bypassDial 绑定到物理网卡，绕过 TUN 路由。本机直连子网走普通路由。
func bypassDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	dev := config.TUNBypassDev
	if dev == "" {
		return net.DialTimeout(network, addr, timeout)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if isLocalNet(host) {
		return net.DialTimeout(network, addr, timeout)
	}
	dialer := &net.Dialer{Timeout: timeout}
	dialer.Control = func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
		})
	}
	return dialer.Dial(network, addr)
}
