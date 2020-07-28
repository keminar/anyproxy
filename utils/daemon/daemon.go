// https://github.com/immortal/immortal/blob/master/fork.go
// https://github.com/icattlecoder/godaemon/blob/master/godaemon.go

package daemon

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"syscall"
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

// Fork crete a new process
func Fork(envName string, fd *os.File, args []string) (int, error) {
	cmd := exec.Command(os.Args[0], args...)
	val := os.Getenv(envName)
	if val == "" { //若未设置则为空字符串
		//为子进程设置特殊的环境变量标识
		os.Setenv(envName, "daemon")
	}
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	//为捕获执行程序的输出，非设置新进程的os.Stdout 不要理解错
	//新进程的os.Stdout.Name()值还是默认值，但输出到/dev/stdout的这边能获取到
	//这边必须设置，否则新进程内的错误可能捕获不到
	//  用 os.NewFile(uintptr(syscall.Stderr), "/dev/stderr").WriteString("test\n") 复现
	cmd.Stdout = fd
	cmd.Stderr = fd
	cmd.ExtraFiles = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Setsid is used to detach the process from the parent (normally a shell)
		//
		// The disowning of a child process is accomplished by executing the system call
		// setpgrp() or setsid(), (both of which have the same functionality) as soon as
		// the child is forked. These calls create a new process session group, make the
		// child process the session leader, and set the process group ID to the process
		// ID of the child. https://bsdmag.org/unix-kernel-system-calls/
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}
