//go:build linux

package proto

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// IP6T_SO_ORIGINAL_DST 是 ip6tables 取原始目标的 sockopt(值同 IPv4 的 SO_ORIGINAL_DST=80),
// x/sys/unix 未导出该常量, 这里本地定义。level 用 SOL_IPV6。
const IP6T_SO_ORIGINAL_DST = 80

// getOriginalDstV6 通过 IP6T_SO_ORIGINAL_DST 取 ip6tables REDIRECT 改写前的原始目标(IPv6)。
// 与 IPv4 的 SO_ORIGINAL_DST 对应: REDIRECT 把目标改写成本机监听口, 真实目标存在 conntrack,
// 用该 sockopt 从内核取回。返回目标 IP 字符串与端口。
func getOriginalDstV6(fd int) (string, uint16, error) {
	// 内核按 struct sockaddr_in6 写回(28 字节)
	var sa unix.RawSockaddrInet6
	size := uint32(unsafe.Sizeof(sa))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_IPV6),
		uintptr(IP6T_SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&sa)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return "", 0, fmt.Errorf("getsockopt(IP6T_SO_ORIGINAL_DST): %v", errno)
	}
	// sa.Port 在内存里是网络序的两字节, 直接按字节取避免主机字节序差异(与 IPv4 分支同理)
	pb := (*[2]byte)(unsafe.Pointer(&sa.Port))
	port := uint16(pb[0])<<8 | uint16(pb[1])
	// sa.Addr 已是网络序的 16 字节地址, net.IP 可直接使用
	ip := make(net.IP, net.IPv6len)
	copy(ip, sa.Addr[:])
	return ip.String(), port, nil
}
