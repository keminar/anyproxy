//go:build darwin
// +build darwin

package tun

import "net"

// localIPByIface 返回指定网卡名的第一个 IPv4 地址。
// 用于 Windows/macOS 上将出向连接绑定到物理网卡 IP，绕过 TUN 路由。
func localIPByIface(dev string) string {
	if dev == "" {
		return ""
	}
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}
