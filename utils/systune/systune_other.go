//go:build !linux
// +build !linux

package systune

import "fmt"

// Check 非 Linux 平台无 sysctl 网络调优概念, 提示不支持。
func Check() int {
	fmt.Println("系统调优检查(-check)仅支持 Linux。")
	return 0
}

// Apply 非 Linux 平台不支持。
func Apply() {
	fmt.Println("系统调优应用(-check-fix)仅支持 Linux。")
}
