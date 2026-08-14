package nat

import (
	"net"

	"github.com/keminar/anyproxy/config"
)

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
