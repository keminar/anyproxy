//go:build darwin
// +build darwin

package proto

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/keminar/anyproxy/config"
)

// macOS 动态 /32 例外路由(dynroute)逃逸。
//
// 背景: macOS 上 TUN(utun) 装了 0.0.0.0/1 + 128.0.0.0/1 全量路由后, anyproxy 自身
// 的出向连接(直连目标 / 连上游代理)也会命中 0/1 被吸回 TUN 形成死循环。macOS 无
// Linux 的 ip rule 源策略路由, 旧方案用 IP_BOUND_IF 强制出接口, 但实测
// 「IP_BOUND_IF + 0/1 路由」组合对 TCP 返回 EHOSTUNREACH(no route to host):
//
//	dial tcp <物理IP>:0 -> 目标:443: connect: no route to host
//
// 与 Windows 上 IP_UNICAST_IF 压不过 0/1 的结论一致: socket 级绑接口选项对 TCP
// 无法覆盖更精确的 0/1 路由。可靠方案是给目标加 /32 via 物理网关 例外路由
// (同 Linux tun.bypassIPs / Windows 旧 dynroute), 使该目标的路由查找命中最精确的
// /32 走物理网卡, 与 0/1 无关。经 examples/macos-tun-repro 在 CI(macOS) 验证:
// /32 例外后普通拨号连通。
//
// 副作用控制: /32 例外是全局路由, 若加而不删, 会令「外部应用访问该目标」也走
// 物理网卡直连、绕过 TUN 代理。故用引用计数, 路由只在 anyproxy 自身连接存活期间
// 保留, 引用归零即删除; TUN 退出时 CleanupDynRoutes 兜底清理残留。
//
// 已知行为: 极短连接(acquire 后立即 release)会让 refs 在 0↔1 间振荡, 每轮振荡
// 触发一次 route add/del。真实 TCP 连接有持有期(毫秒级以上), 此开销可忽略。
type dynRoute struct {
	mu   sync.Mutex
	refs map[string]int  // 目标 IP -> 活跃连接数
	ipv6 bool            // 当前 TUN 是否接管 IPv6(预留; 现 TUN 只接管 IPv4)
}

var macDynRoute = &dynRoute{refs: map[string]int{}}

// acquire 给目标 IP 加 /32 via 物理网关 例外路由(首次)并增加引用。
// IPv6 / 无网关 / 非 IP 目标: 不处理(macOS TUN 只接管 IPv4, IPv6 直连无需逃逸)。
func (d *dynRoute) acquire(ip string) {
	gw := config.TUNBypassGW
	if ip == "" || gw == "" {
		return
	}
	a := net.ParseIP(ip)
	if a == nil || a.To4() == nil {
		return
	}
	d.mu.Lock()
	if d.refs[ip] == 0 {
		if err := macRouteAdd(ip+"/32", gw); err != nil {
			log.Printf("dynroute: add %s via %s: %v\n", ip, gw, err)
		}
	}
	d.refs[ip]++
	d.mu.Unlock()
}

// release 减少引用, 归零时删除 /32 例外路由。
func (d *dynRoute) release(ip string) {
	if ip == "" {
		return
	}
	d.mu.Lock()
	if d.refs[ip] > 0 {
		d.refs[ip]--
	}
	if d.refs[ip] == 0 {
		delete(d.refs, ip)
		_ = macRouteDel(ip + "/32")
	}
	d.mu.Unlock()
}

// CleanupDynRoutes 清理残留的 /32 例外路由。TUN 退出/重启时调用(见 tun/route_darwin.go)。
func CleanupDynRoutes() {
	macDynRoute.mu.Lock()
	ips := make([]string, 0, len(macDynRoute.refs))
	for ip := range macDynRoute.refs {
		ips = append(ips, ip)
	}
	macDynRoute.refs = map[string]int{}
	macDynRoute.mu.Unlock()
	for _, ip := range ips {
		_ = macRouteDel(ip + "/32")
	}
}

// macRouteAdd/macRouteDel 是包级函数变量, 便于单测注入(不改真路由, 无需 root)。
// 默认实现走 `route -n` 命令(需 root)。
var (
	macRouteAdd = macRouteAddCmd
	macRouteDel = macRouteDelCmd
)

func macRouteAddCmd(cidr, gw string) error {
	out, err := exec.Command("route", "-n", "add", "-net", cidr, gw).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add %s via %s: %v: %s", cidr, gw, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func macRouteDelCmd(cidr string) error {
	out, err := exec.Command("route", "-n", "delete", "-net", cidr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete %s: %v: %s", cidr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// tunDial 拨号前给目标 IPv4 加 /32 via 物理网关 例外路由(dynroute), 使出向连接
// 走物理网卡逃出 0/1 全量路由; 连接关闭时删除。本机直连子网无需逃逸(内核直连
// 路由比 0/1 更精确), IPv6 目标(macOS TUN 不接管 IPv6)亦普通拨号。
func tunDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if isLocalNet(host) {
		return net.DialTimeout(network, addr, timeout)
	}
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		// IPv6 目标: TUN 只接管 IPv4, 普通拨号即可
		return net.DialTimeout(network, addr, timeout)
	}
	ip := host // 仅 IPv4 目标需要 /32 例外
	macDynRoute.acquire(ip)
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		macDynRoute.release(ip)
		return nil, err
	}
	return &dynConn{Conn: conn, ip: ip}, nil
}

// dynConn 包装连接, Close 时释放 dynroute 引用(删除 /32 例外路由)。
type dynConn struct {
	net.Conn
	ip   string
	once sync.Once
}

func (c *dynConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { macDynRoute.release(c.ip) })
	return err
}
