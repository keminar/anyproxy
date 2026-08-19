//go:build !darwin

package tun

// ensureUDPDynRoute 非 darwin 平台空操作。
// Linux 的 UDP 逃逸用 SO_BINDTODEVICE(对 Linux 有效); Windows 是 WinDivert 模型,
// 无 TUN UDP 路径。
func ensureUDPDynRoute(ip string) {}

// udpDirectBlocked 非 darwin 平台: 绑定物理网卡的 UDP socket 总能正常出向,
// 不存在"注定 no route to host"的目标。
func udpDirectBlocked(dst string) bool { return false }
