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
// 注: IP_BOUND_IF 对 TCP 压不过 0/1 路由(实测 no route to host), 对 UDP 同样失效。
// 但 UDP 目标是动态复用的(一个源口一个 socket), 无法用 TCP 的 per-connection
// dynroute; 对 DNS(53) 目标改用 TTL 缓存的 /32 例外路由(见 udp_dynroute_darwin.go,
// 由 udp.go 在发送前调用)。本函数仍保留 IP_BOUND_IF 作为 QUIC 等非 DNS UDP 的
// 尽力而为(其直连失败会促使浏览器降级 TCP, 可接受)。
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
