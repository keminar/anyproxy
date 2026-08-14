//go:build linux
// +build linux

package tun

import (
	"context"
	"net"
	"syscall"

	"github.com/keminar/anyproxy/config"
)

// listenUDP 建一个「未连接」的 UDP socket 强制出向物理网卡, 逃出 TUN 路由。
// firstDst 仅用于判断目标是否落在本机直连子网(是则无需绑)。
//
// 与 TCP tunDial 同理, 逃逸靠两步(缺一不可):
//  1. 绑源 IP=物理网卡 IP(bind 到 TUNBypassIP:0): 策略路由 pref 100(from 物理IP lookup main)
//     按「源 IP」匹配, 只有源 IP 是物理 IP 才命中 pref 100 走物理网卡; 否则掉进 pref 120 的
//     TUN 表, 出向包又进 anytun0 被回抓成环路。这是关键。
//  2. SO_BINDTODEVICE 硬绑物理网卡, 作为兜底(取不到源 IP、或一网卡多 IP 时保证从该网卡出)。
func listenUDP(firstDst string) (*net.UDPConn, error) {
	dev := config.TUNBypassDev
	if dev == "" || dstInBypassNet(firstDst) {
		return net.ListenUDP("udp4", nil)
	}
	// SO_BINDTODEVICE 是逃出 TUN 的最后保证: 一旦它失败, 未连接 UDP socket 发包会选到
	// 10.9.0.x 回灌 anytun0 成环, 故把 set 失败当硬错误上抛, 让 ListenPacket 失败, 绝不
	// 带着"没绑上网卡"的 socket 继续用(由上层负缓存丢包, 而非环路)。
	lc := &net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var soErr error
		if err := c.Control(func(fd uintptr) {
			soErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
		}); err != nil {
			return err
		}
		return soErr
	}}
	// 绑源 IP=物理网卡 IP 命中 pref 100; 取不到则退回 ":0" 仅靠 SO_BINDTODEVICE。
	laddr := ":0"
	if config.TUNBypassIP != "" {
		laddr = config.TUNBypassIP + ":0"
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", laddr)
	if err != nil {
		// 绑源 IP 失败(如该 IP 已不在网卡上)时退回仅绑网卡(仍带 SO_BINDTODEVICE, 安全不环)。
		if laddr != ":0" {
			if pc2, err2 := lc.ListenPacket(context.Background(), "udp4", ":0"); err2 == nil {
				return pc2.(*net.UDPConn), nil
			}
		}
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
