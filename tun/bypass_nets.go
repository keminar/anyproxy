//go:build !windows
// +build !windows

package tun

import (
	"net"
	"strings"

	"github.com/keminar/anyproxy/config"
)

// ipInBypassNets 判断一个 bypass 例外(IP 或 CIDR)是否落在本机某个直连子网内
// (含物理与虚拟网卡, 由 initBypassNets 收集)。
//
// autoRoute 对这类例外不应再加「via 物理网关 dev 物理网卡」的显式 /32 路由:
// 内核对该子网已有更精确的直连路由, LAN 例外规则(linux pref 110 suppress
// default / darwin 的具体路由优先于 0/1)本就让它走对网卡。若强行 via 物理网关,
// 会盖掉虚拟网卡(virbr0/VPN 等)的正确直连路由, 使该目标不可达。
func ipInBypassNets(ipOrCIDR string) bool {
	host := ipOrCIDR
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range config.TUNBypassNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

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
