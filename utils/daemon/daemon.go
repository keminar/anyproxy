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
func Daemonize() {
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
		if pid, err := Fork(args); err != nil {
			log.Fatalf("error while forking: %s", err)
		} else {
			if pid > 0 {
				os.Exit(0)
			}
		}
	}
}

// Fork crete a new process
func Fork(args []string) (int, error) {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
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
