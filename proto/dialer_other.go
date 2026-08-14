//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package proto

import (
	"net"
	"time"

	"github.com/keminar/anyproxy/config"
)

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
	var localAddr net.Addr
	switch network {
	case "udp", "udp4", "udp6":
		localAddr = &net.UDPAddr{IP: net.ParseIP(ip)}
	default:
		localAddr = &net.TCPAddr{IP: net.ParseIP(ip)}
	}
	return (&net.Dialer{Timeout: timeout, LocalAddr: localAddr}).Dial(network, addr)
}

