//go:build linux
// +build linux

package tun

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxDevice 基于 /dev/net/tun 的实现
type linuxDevice struct {
	fd   int
	name string
	mtu  uint32
}

// defaultTunName Linux 平台默认 TUN 网卡名
const defaultTunName = "anytun0"

func newDevice(name string, mtu uint32) (Device, error) {
	if name == "" {
		name = defaultTunName
	}
	// O_CLOEXEC 必须带上: 否则本 fd 会被后续 fork+exec 的子进程继承一份副本
	// (Run 清理时执行的 `ip route` 命令、平滑重启 grace.fork() 再 exec 自身等)。
	// 泄漏的副本会让内核 TUN 网卡(anytun0)在本进程关闭 fd 后依旧存活, 导致新进程
	// 对同名网卡 ioctl(TUNSETIFF) 报 "device or resource busy", 平滑重启偶发失败。
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	// struct ifreq: char ifr_name[IFNAMSIZ(16)]; short ifr_flags; ...
	var ifr [40]byte
	copy(ifr[:15], name)
	// IFF_TUN: 三层IP包; IFF_NO_PI: 不加4字节包信息头，读到的即纯IP包
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF: %v", errno)
	}

	// 读回内核分配的实际网卡名
	realName := string(bytes.TrimRight(ifr[:16], "\x00"))
	return &linuxDevice{fd: fd, name: realName, mtu: mtu}, nil
}

func (d *linuxDevice) ReadPacket() ([]byte, error) {
	buf := make([]byte, int(d.mtu)+4)
	n, err := unix.Read(d.fd, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (d *linuxDevice) WritePacket(pkt []byte) error {
	_, err := unix.Write(d.fd, pkt)
	return err
}

func (d *linuxDevice) SetupAddr(cidr string) error {
	// 设置MTU、分配地址并启用网卡
	run := func(args ...string) error {
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip %v: %v: %s", args, err, bytes.TrimSpace(out))
		}
		return nil
	}
	if err := run("link", "set", "dev", d.name, "mtu", fmt.Sprintf("%d", d.mtu)); err != nil {
		return err
	}
	if err := run("addr", "add", cidr, "dev", d.name); err != nil {
		return err
	}
	return run("link", "set", "dev", d.name, "up")
}

func (d *linuxDevice) Name() string { return d.name }
func (d *linuxDevice) MTU() uint32  { return d.mtu }
func (d *linuxDevice) Close() error { return unix.Close(d.fd) }

// defaultRoute 返回系统默认路由的网关和网卡名，解析失败时返回空字符串。
func defaultRoute() (gw, dev string) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return
	}
	// 格式: "default via 192.168.1.1 dev eth0 ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		switch f {
		case "via":
			if i+1 < len(fields) {
				gw = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				dev = fields[i+1]
			}
		}
	}
	return
}

// defaultLocalIP 返回指定物理网卡的第一个 IPv4 地址, 供 tunDial 绑定源 IP。
// 逃出 TUN 靠策略路由 pref 100(from 物理IP lookup main); 只有把出向连接的源 IP 显式绑成
// 物理网卡 IP, 路由查找时才命中 pref 100 走物理网卡默认路由。仅靠 SO_BINDTODEVICE 时
// 路由查找阶段源 IP 尚未确定, 命中不了 pref 100, 会掉进 pref 120 的 TUN 表被回抓成环路。
func defaultLocalIP(dev string) string {
	if ips := physIPv4s(dev); len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// bypassIfIndex Linux 用网卡名做 SO_BINDTODEVICE，不需要出接口索引，返回 0 即可。
func bypassIfIndex(dev string) int { return 0 }
