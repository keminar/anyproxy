//go:build !linux

package tun

import (
	"errors"
)

// InitBypassOnly 在非 Linux 平台返回错误：mode=bypass 已从 macOS/Windows 移除。
// macOS 的入站回包放行用 mode=tun + tun.inboundPorts；Windows 用 WinDivert 模型，
// 逃逸靠 tun.windows 的 excludeProcs/bypassIPs + egress 源端口段。
func InitBypassOnly(cfg BypassConfig) error {
	return errors.New("mode=bypass is only supported on linux; removed on macOS/Windows")
}

// CleanupBypass 非 Linux 平台空操作。
func CleanupBypass() {}
