//go:build !linux
// +build !linux

package systune

import "fmt"

// Check 非 Linux 平台无 sysctl 网络调优概念, 提示不支持。
func Check() int {
	fmt.Println("system tuning check (-check) is only supported on Linux.")
	return 0
}

// Apply 非 Linux 平台不支持。
func Apply() {
	fmt.Println("system tuning apply (-check-fix) is only supported on Linux.")
}
