//go:build darwin
// +build darwin

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// macOS utun 相关常量。x/sys/unix 未导出这两个稳定的内核常量，本地定义。
//
//	SYSPROTO_CONTROL: kernel control 协议号(sys/kern_control.h)
//	utunControlName : utun 内核控制名(net/if_utun.h)
//	optIfName       : getsockopt 取网卡名的选项号(UTUN_OPT_IFNAME)
const (
	sysprotoControl = 2
	utunControlName = "com.apple.net.utun_control"
	optIfName       = 2
)

// defaultTunName macOS 由内核自动分配 utun 单元, 无固定默认名
const defaultTunName = ""

// utunDevice 基于 macOS utun 控制 socket 的实现。
// utun 每个包前带 4 字节地址族头(AF_INET/AF_INET6, 大端), 读写时剥/补,
// 对上层协议栈保持与 Linux(纯IP包) 一致的抽象。
type utunDevice struct {
	fd   int
	name string
	mtu  uint32
}

func newDevice(name string, mtu uint32) (Device, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("open utun control socket: %w", err)
	}
	// 设置 close-on-exec: 避免本 fd 被后续 fork+exec(如平滑重启 grace.fork() 再 exec
	// 自身、清理时执行的外部命令)的子进程继承副本。泄漏副本会让 utun 网卡在本进程关闭
	// fd 后仍存活, 导致新进程创建同名网卡失败。macOS 的 socket() 不支持 SOCK_CLOEXEC
	// 标志, 故创建后立即用 fcntl(F_SETFD) 补设。
	unix.CloseOnExec(fd)

	// 查 utun 内核控制的 ctl id
	var ci unix.CtlInfo
	copy(ci.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, &ci); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl CTLIOCGINFO: %w", err)
	}

	// name 形如 "utunN" 时指定单元号(Unit=N+1); 为空则 Unit=0 让内核自选空闲单元
	unit, err := parseUtunUnit(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: ci.Id, Unit: unit}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connect utun control: %w", err)
	}

	// 读回内核分配的真实网卡名(如 utun4)
	realName, err := unix.GetsockoptString(fd, sysprotoControl, optIfName)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("get utun ifname: %w", err)
	}
	return &utunDevice{fd: fd, name: realName, mtu: mtu}, nil
}

// parseUtunUnit 把 "utunN" 解析为内核 Unit(=N+1); 空名返回 0(内核自选)。
func parseUtunUnit(name string) (uint32, error) {
	if name == "" {
		return 0, nil
	}
	if !strings.HasPrefix(name, "utun") {
		return 0, fmt.Errorf("tun name %q must be like utunN on darwin", name)
	}
	n, err := strconv.Atoi(name[len("utun"):])
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid utun name %q", name)
	}
	return uint32(n) + 1, nil
}

func (d *utunDevice) ReadPacket() ([]byte, error) {
	buf := make([]byte, int(d.mtu)+4)
	n, err := unix.Read(d.fd, buf)
	if err != nil {
		return nil, err
	}
	if n <= 4 {
		// 只有 AF 头或空包, 交由上层跳过
		return nil, nil
	}
	// 剥掉前 4 字节地址族头, 返回纯 IP 包
	return buf[4:n], nil
}

func (d *utunDevice) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	var af uint32
	switch pkt[0] >> 4 {
	case 4:
		af = unix.AF_INET
	case 6:
		af = unix.AF_INET6
	default:
		return nil
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], af)
	// writev 零拷贝: 4 字节 AF 头 + 纯 IP 包
	_, err := unix.Writev(d.fd, [][]byte{hdr[:], pkt})
	return err
}

func (d *utunDevice) SetupAddr(cidr string) error {
	ip, mask, _, err := parseCIDR(cidr)
	if err != nil {
		return err
	}
	// utun 为点对点设备, 本端地址 == 对端地址; 实际分流靠 0/1 + 128/1 路由
	out, err := exec.Command("ifconfig", d.name, "inet", ip, ip,
		"netmask", mask, "mtu", strconv.Itoa(int(d.mtu)), "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %v: %s", d.name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *utunDevice) Name() string { return d.name }
func (d *utunDevice) MTU() uint32  { return d.mtu }
func (d *utunDevice) Close() error { return unix.Close(d.fd) }

// defaultRoute 返回系统默认路由的网关和网卡名, 解析失败时返回空字符串。
func defaultRoute() (gw, dev string) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return
	}
	// 输出含 "  gateway: 192.168.1.1" 和 "  interface: en0"
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "gateway:":
			gw = fields[1]
		case "interface:":
			dev = fields[1]
		}
	}
	return
}

// defaultLocalIP 返回指定网卡的第一个 IPv4 地址, 供绑定 LocalAddr 绕过 TUN 路由。
func defaultLocalIP(dev string) string { return localIPByIface(dev) }

// bypassIfIndex 返回物理网卡的出接口索引。TCP 逃逸已改 dynroute(/32 例外路由,
// 见 proto/dialer_darwin.go), 本值仅作诊断日志; UDP 逃逸(tun/udp_dial_darwin.go)
// 仍用它设 IP_BOUND_IF(有同类失效风险, 待验证)。macOS 网卡名(en0 等)稳定,
// 按名解析即可；失败返回 0。
func bypassIfIndex(dev string) int {
	if iface, err := net.InterfaceByName(dev); err == nil {
		return iface.Index
	}
	return 0
}
