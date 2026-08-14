//go:build windows
// +build windows

package nat

import (
	"net"
	"time"
)

// bypassDial 在 Windows(WinDivert 模型)下即普通拨号。逃逸机制(IP_UNICAST_IF /
// dynroute)已随 wintun 一并移除, 自环由 WinDivert 的 SOCKET 层 guard 防止
// (anyproxy 自身出向源端口被排除, 不会被重新捕获)。
func bypassDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}
