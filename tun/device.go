//go:build !windows
// +build !windows

package tun

import (
	"fmt"
	"net"
)

// Device 是对TUN虚拟网卡的单包(一个IP数据包)读写抽象。
// Linux 基于 /dev/net/tun，Windows 基于 wintun，二者对上层提供一致接口。
type Device interface {
	// ReadPacket 读取一个完整的IP数据包
	ReadPacket() ([]byte, error)
	// WritePacket 写入一个完整的IP数据包
	WritePacket(pkt []byte) error
	// SetupAddr 给网卡分配接口地址(CIDR)并启用，如 "10.9.0.1/24"
	SetupAddr(cidr string) error
	// Name 实际网卡名
	Name() string
	// MTU 最大传输单元
	MTU() uint32
	// Close 关闭并释放设备
	Close() error
}

// New 创建并打开一个TUN设备(具体实现按平台编译)
func New(name string, mtu uint32) (Device, error) {
	return newDevice(name, mtu)
}

// parseCIDR 解析 "10.9.0.1/24" 为 主机IP、点分掩码、前缀长度
func parseCIDR(cidr string) (ip string, mask string, prefix int, err error) {
	hostIP, ipNet, e := net.ParseCIDR(cidr)
	if e != nil {
		err = fmt.Errorf("invalid tun addr %q: %v", cidr, e)
		return
	}
	if hostIP.To4() == nil {
		err = fmt.Errorf("tun addr %q must be IPv4", cidr)
		return
	}
	ip = hostIP.String()
	m := ipNet.Mask
	mask = fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
	prefix, _ = ipNet.Mask.Size()
	return
}
