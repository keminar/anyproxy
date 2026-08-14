//go:build windows
// +build windows

// Package rss 让归还的内存立即从进程 RSS 扣减(Windows 无需处理, 见 Ensure)。
package rss

// Ensure 在 Windows 上无需处理: 无 madvise 语义，Go runtime 归还内存
// 直接调用 VirtualFree(MEM_DECOMMIT) 即时生效，工作集自然回落。
func Ensure() {}
