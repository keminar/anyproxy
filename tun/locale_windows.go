//go:build windows
// +build windows

package tun

import (
	"strings"
	"syscall"
	"unsafe"
)

// systemIsChinese 通过 kernel32!GetUserDefaultLocaleName 读取 Windows 用户区域设置。
func systemIsChinese() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetUserDefaultLocaleName")
	buf := make([]uint16, 85) // LOCALE_NAME_MAX_LENGTH
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return false
	}
	name := syscall.UTF16ToString(buf)
	return strings.HasPrefix(strings.ToLower(name), "zh")
}
