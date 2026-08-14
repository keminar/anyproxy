//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package tun

import (
	"fmt"
	"net"
	"runtime"
)

// defaultTunName 非 linux/windows 平台无默认 TUN 网卡名
const defaultTunName = ""

// 非 linux/windows 平台暂不支持TUN虚拟网卡
func newDevice(name string, mtu uint32) (Device, error) {
	return nil, fmt.Errorf("tun device is not supported on %s", runtime.GOOS)
}

func defaultRoute() (gw, dev string) { return }

// defaultLocalIP 返回指定网卡的第一个 IPv4 地址，绑 LocalAddr 绕过 TUN 路由（含 macOS）。
func defaultLocalIP(dev string) string { return localIPByIface(dev) }

// bypassIfIndex 返回物理网卡的出接口索引，按名解析，失败返回 0。
func bypassIfIndex(dev string) int {
	if iface, err := net.InterfaceByName(dev); err == nil {
		return iface.Index
	}
	return 0
}
