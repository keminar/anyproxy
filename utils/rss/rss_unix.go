//go:build !windows
// +build !windows

// Package rss 让归还的内存立即从进程 RSS 扣减，使 top 里的 RES 数字直观可预测。
package rss

import (
	"log"
	"os"
	"strings"
	"syscall"
)

// Ensure 让归还的内存立即从 RSS 扣减，使 RES 数字直观可预测。
//
// Go 默认用 MADV_FREE 归还内存: 页标记为可回收，但内核只在有内存压力时才真正
// 扣减 RSS，导致 top 里 RES 长期偏高(虽非真实占用)。设 GODEBUG=madvdontneed=1
// 改用 MADV_DONTNEED, 归还即扣 RSS。该开关 runtime 仅在启动时读取一次，无法运行时
// 更改，故这里在最早期设置环境变量并 exec 重启自身(幂等: 已设置则跳过，避免死循环)。
// 配合每 15s 的 FreeOSMemory, RSS 最多 15s 后即回落到工作集大小。
//
// 必须在 main 最早期调用: 在任何堆分配/goroutine 之前，保证 runtime 读到该开关。
func Ensure() {
	god := os.Getenv("GODEBUG")
	if strings.Contains(god, "madvdontneed=1") {
		return // 已设置(或 exec 后的二次进入)，直接继续启动
	}
	if god == "" {
		god = "madvdontneed=1"
	} else {
		god += ",madvdontneed=1"
	}
	_ = os.Setenv("GODEBUG", god)

	exe, err := os.Executable()
	if err != nil {
		// 拿不到可执行路径就放弃优化，不影响正常功能
		log.Println("rss.Ensure: get executable path err:", err)
		return
	}
	// 用相同 args/fd/env 替换当前进程镜像(PID 不变)。graceful/daemon 子进程会继承
	// 已设好的 GODEBUG 环境变量，二次进入时命中上面的 return，不会重复 exec。
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Println("rss.Ensure: re-exec err:", err)
	}
}
