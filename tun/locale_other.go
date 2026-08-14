//go:build !windows
// +build !windows

package tun

// systemIsChinese 非 Windows 平台已通过 POSIX 环境变量判断，此处返回 false 作为兜底。
func systemIsChinese() bool { return false }
