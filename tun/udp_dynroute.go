//go:build !darwin

package tun

// ensureUDPDynRoute 非 darwin 平台空操作。
// Linux 的 UDP 逃逸用 SO_BINDTODEVICE(对 Linux 有效); Windows 是 WinDivert 模型,
// 无 TUN UDP 路径。
func ensureUDPDynRoute(ip string) {}
