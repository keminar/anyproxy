//go:build windows
// +build windows

package proto

import (
	"net"
	"time"
)

// tunDial 在 Windows(WinDivert 模型)下即普通拨号。
//
// 旧的 IP_UNICAST_IF + 动态 /32 路由(dynroute)逃逸机制是为 wintun 的 0.0.0.0/1
// 路由防自环而设; WinDivert 模型不改路由表, 自环改由 SOCKET 层 per-process guard
// (排除 anyproxy 自身出向源端口) + filter 排除上游代理来防止, 故拨号侧无需再做
// 任何绕行, 直接普通 Dial 即可。
func tunDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}
