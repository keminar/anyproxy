//go:build !windows
// +build !windows

package tun

import (
	"net"

	"github.com/keminar/anyproxy/config"
)

// initBypassNets 收集本机除 excludeNames 指定网卡外所有接口的 IPv4 子网。
// 目标 IP 落在这些子网内时，内核已有直连路由（比 TUN 的 0/1 更具体），
// tunDial 无需绑定物理网卡，用普通 net.Dial 即可。
// excludeNames 通常是本进程或另一进程的 TUN 网卡名，避免其网段被当作本地直连。
func initBypassNets(excludeNames ...string) {
	exclude := make(map[string]bool, len(excludeNames))
	for _, n := range excludeNames {
		if n != "" {
			exclude[n] = true
		}
	}
	var nets []*net.IPNet
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if exclude[iface.Name] {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && ipnet.IP.To4() != nil {
				nets = append(nets, ipnet)
			}
		}
	}
	config.TUNBypassNets = nets
}
