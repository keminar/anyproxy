//go:build darwin
// +build darwin

package nat

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/keminar/anyproxy/config"
)

// bypassDial 强制出向连接从物理网卡出，绕过 TUN 路由环路。
// macOS 弱主机模型下出接口由目标路由决定，仅绑 LocalAddr 无法绕出 TUN，
// 必须用 IP_BOUND_IF 指定出接口。详见 proto/dialer_darwin.go 的说明。
func bypassDial(network, addr string, timeout time.Duration) (net.Conn, error) {
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
		idx := iface.Index
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	return dialer.Dial(network, addr)
}
