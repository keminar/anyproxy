//go:build !windows

package conf

// hideFile 非 Windows 系统上无事可做: 文件名的点前缀本身就是隐藏约定。
func hideFile(path string) {}
