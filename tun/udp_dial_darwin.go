//go:build darwin
// +build darwin

package tun

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/keminar/anyproxy/config"
)

// listenUDP 建一个「未连接」的 UDP socket，强制 UDP 从物理网卡出，绕过 TUN 路由环路。
// 用 IP_BOUND_IF 指定出接口，本地绑物理网卡 IP 作兜底。
//
// TODO: 与 TCP 同源问题——IP_BOUND_IF 压不过 0/1 路由(实测见 proto/dialer_darwin.go
// 的 dynroute 修复)。UDP 无连接、目标动态, dynroute 引用计数方案不适用, 需另行设计
// (如按目标动态加/删 /32, 或把 UDP 也纳入 TUN 接管); 若实测 UDP 逃逸失效
// (DNS 查询报 no route to host), 按此方向修。
//
// firstDst 仅用于判断目标是否落在本机直连子网(是则无需绑)。
func listenUDP(firstDst string) (*net.UDPConn, error) {
	ip := config.TUNBypassIP
	if ip == "" || dstInBypassNet(firstDst) {
		return net.ListenUDP("udp4", nil)
	}

	lc := &net.ListenConfig{}
	if iface, err2 := net.InterfaceByName(config.TUNBypassDev); err2 == nil {
		idx := iface.Index
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
