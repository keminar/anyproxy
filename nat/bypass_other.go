//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package nat

import (
	"net"
	"time"

	"github.com/keminar/anyproxy/config"
)

// bypassDial 绑定到物理网卡 IP，绕过 TUN 路由。本机直连子网走普通路由。
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
	return (&net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)},
	}).Dial(network, addr)
}
