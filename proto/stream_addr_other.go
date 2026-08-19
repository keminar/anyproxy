//go:build !windows && !linux

package proto

import "errors"

// getOriginalDstV6 仅 Linux(ip6tables)实现; 其它类 Unix(如 darwin, 走 TUN 而非透明重定向)
// 不支持, 保留同名桩以便 stream_addr.go 编译通过。
func getOriginalDstV6(fd int) (string, uint16, error) {
	return "", 0, errors.New("ipv6 SO_ORIGINAL_DST only supported on linux")
}
