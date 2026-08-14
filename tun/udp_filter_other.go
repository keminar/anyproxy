//go:build !windows
// +build !windows

package tun

import "gvisor.dev/gvisor/pkg/tcpip"

// dropNoiseUDP 非 windows 平台不做过滤(WSAENOBUFS 是 windows 特有问题)。
func dropNoiseUDP(dstIP tcpip.Address, dstPort uint16) bool { return false }
