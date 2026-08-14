package proto

import (
	"net"

	"github.com/keminar/anyproxy/config"
)

// isLocalNet 判断目标 IP 是否属于本机直连子网。
// 直连子网内核已有精确路由，不需要绑定物理网卡。
func isLocalNet(host string) bool {
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
