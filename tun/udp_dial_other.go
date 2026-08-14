//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package tun

import (
	"net"

	"github.com/keminar/anyproxy/config"
)

// listenUDP 建一个「未连接」的 UDP socket，本地绑物理网卡 IP 兜底出向。
// firstDst 仅用于判断目标是否落在本机直连子网(是则无需绑)。
func listenUDP(firstDst string) (*net.UDPConn, error) {
	ip := config.TUNBypassIP
	if ip == "" || dstInBypassNet(firstDst) {
		return net.ListenUDP("udp4", nil)
	}
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
}
