package grace

import (
	"fmt"
	"log"
	"net"
	"os"
)

// sdNotify 向 systemd 的 sd_notify 协议 socket($NOTIFY_SOCKET) 发一条状态消息。
// 未在 systemd(Type=notify) 下运行时 $NOTIFY_SOCKET 为空, 静默跳过, 不算错误。
func sdNotify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:] // abstract namespace socket
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// NotifyReady 告知 systemd(Type=notify) 启动完成, 可从 activating 转为 active。
// 平滑重启后新起的进程也会调用一次, 重复的 READY=1 对 systemd 无害。
func NotifyReady() {
	if err := sdNotify("READY=1"); err != nil {
		log.Println(os.Getpid(), "sd_notify READY err:", err)
	}
}

// NotifyReloading 告知 systemd 平滑重启正在进行, 仅影响 systemctl status 展示。
func NotifyReloading() {
	if err := sdNotify("RELOADING=1"); err != nil {
		log.Println(os.Getpid(), "sd_notify RELOADING err:", err)
	}
}

// NotifyMainPID 把 systemd 的 MAINPID 追踪目标迁移到 pid。必须由当前仍被 systemd
// 识别为主进程的老进程在其退出前调用(默认 NotifyAccess=main 只认可来自当前 MAINPID
// 的消息)——否则新进程接管后老进程一退出, systemd 会误判服务已停止, 按
// KillMode=control-group 清理整个 cgroup, 把刚接管的新进程一起杀掉。
func NotifyMainPID(pid int) {
	if err := sdNotify(fmt.Sprintf("MAINPID=%d\n", pid)); err != nil {
		log.Println(os.Getpid(), "sd_notify MAINPID err:", err)
	}
}
