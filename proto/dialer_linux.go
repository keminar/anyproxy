//go:build linux
// +build linux

package proto

import (
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/keminar/anyproxy/config"
)

// tunDial 在 TUN 模式下让出向连接逃出 TUN 路由, 避免被 gVisor 回抓成环路。
// 本机直连子网（如 virbr0 上的 VM）走普通路由。
//
// 逃逸靠两步:
//  1. SO_BINDTODEVICE 硬绑物理网卡: 把路由查找限制在该网卡可达的路由上, 内核会自动挑该网卡
//     的 IP 作源, 通常即可命中策略路由 pref 100(from 物理IP lookup main) 走物理网卡逃出 TUN。
//  2. 绑源 IP = 物理网卡 IP: 显式把源固定成物理 IP, 保证命中 pref 100(覆盖内核选到别的源、
//     非对称路由等边角情况)。这是「加固」而非「必需」——但绑死源 IP 会让「该源 IP 暂时无可用
//     路由」变成硬失败(no route to host), 故失败时回退到只绑网卡重试一次。
func tunDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	dev := config.TUNBypassDev
	if dev == "" {
		return net.DialTimeout(network, addr, timeout)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if isLocalNet(host) {
		return net.DialTimeout(network, addr, timeout)
	}
	// bindDev 绑物理网卡。SO_BINDTODEVICE 是逃出 TUN 的最后保证(从物理层锁死出口网卡,
	// 内核只会选该网卡 IP 作源, 命中 pref 100); 一旦它都失败, 出向可能选到 10.9.0.x 回灌
	// anytun0 成环, 故这里把 set 失败当硬错误上抛, 让 Dial 失败, 绝不带着"没绑上网卡"的
	// socket 继续用。
	bindDev := func(_, _ string, c syscall.RawConn) error {
		var soErr error
		if err := c.Control(func(fd uintptr) {
			soErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
		}); err != nil {
			return err
		}
		return soErr
	}

	// 主路径: 绑网卡 + 绑源 IP(仅 IPv4 目标; 域名/IPv6 时不绑源, 只绑网卡)。
	var srcAddr *net.TCPAddr
	if config.TUNBypassIP != "" {
		if dstIP := net.ParseIP(host); dstIP != nil && dstIP.To4() != nil {
			if srcIP := net.ParseIP(config.TUNBypassIP); srcIP != nil {
				srcAddr = &net.TCPAddr{IP: srcIP}
			}
		}
	}
	dialer := &net.Dialer{Timeout: timeout, LocalAddr: srcAddr, Control: bindDev}
	conn, err := dialer.Dial(network, addr)
	if err == nil || srcAddr == nil {
		return conn, err
	}
	// 绑死源 IP 时若遇路由层错误(no route to host / network unreachable), 说明该源此刻无可用
	// 路由; 回退到只绑网卡重试一次——内核会自行挑物理网卡 IP 作源, 一样命中 pref 100 逃逸。
	if isRouteErr(err) {
		fallback := &net.Dialer{Timeout: timeout, Control: bindDev}
		if c2, err2 := fallback.Dial(network, addr); err2 == nil {
			return c2, nil
		}
	}
	return conn, err
}

// isRouteErr 判断是否为路由层不可达错误(EHOSTUNREACH / ENETUNREACH)。
func isRouteErr(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH)
}
