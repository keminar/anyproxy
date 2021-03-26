// https://github.com/immortal/immortal/blob/master/fork.go
// https://github.com/icattlecoder/godaemon/blob/master/godaemon.go

package daemon

import (
	"flag"
	"log"
	"os"
)

var daemon = flag.Bool("daemon", false, "run app as a daemon")

// Daemonize 后台化
func Daemonize(envName string, fd *os.File) {
	if !flag.Parsed() {
		flag.Parse()
	}
	// 如果启用daemon模式，Fork的进行在主进程退出后PPID为1
	if *daemon && os.Getppid() > 1 {
		// 为了兼容平滑重启，和二重保证不死循环。主动替换daemon参数
		args := os.Args[1:]
		for i := 0; i < len(args); i++ {
			if args[i] == "-daemon" || args[i] == "-daemon=true" {
				args[i] = "-daemon=false"
				break
			}
		}
		if pid, err := Fork(envName, fd, args); err != nil {
			log.Fatalf("error while forking: %s", err)
		} else {
			if pid > 0 {
				os.Exit(0)
			}
		}
	}
}

// IsForeground 是否在前台执行
// 因ppid的方案在graceful平滑重启时不准，又不想加太多的外部参数， 所以用环境变量
func IsForeground(envName string) bool {
	if os.Getenv(envName) == "" {
		return true
	}
	return false
}
