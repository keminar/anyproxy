//go:build darwin

package tun

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

// macOS UDP 逃逸: 给 DNS 服务器等 UDP 目标加 /32 via 物理网关 例外路由(TTL 缓存)。
//
// 与 TCP 同源问题: IP_BOUND_IF 压不过 0/1 全量路由, UDP(未连接 socket, 见 udp.go)
// 同样 EHOSTUNREACH → DNS 查询直连失败。UDP 是「一个源口一个 socket、目标动态
// 复用」(按目标建 socket 会被 P2P 洪泛打爆), 无法用 TCP 那种 per-connection 引用
// 计数, 故用 TTL 缓存: 目标首次命中加 /32, TTL 内复用, 过期后懒清理(下次 ensure
// 时顺带删除过期项的 /32 路由)。
//
// 只对 UDP 53(DNS)调用: DNS 必须直连; 其他 UDP(QUIC/443)故意不加例外——让其直连
// 失败促使浏览器降级 TCP 走 TUN 代理(与 blockQUIC 语义一致), 也避免给 QUIC 目标
// 加 /32 后连累该目标的 TCP 绕过代理。
type udpDynRoute struct {
	mu  sync.Mutex
	ttl time.Duration
	rt  map[string]time.Time // 目标 IP -> 过期时间
}

var macUDPDynRoute = &udpDynRoute{ttl: 30 * time.Minute, rt: map[string]time.Time{}}

// ensureUDPDynRoute 包级入口(udp.go 在 DNS 发送前调用), 转发到 TTL 缓存管理器。
func ensureUDPDynRoute(ip string) {
	macUDPDynRoute.ensure(ip)
}

// udpDirectBlocked 判断该 UDP 目标在 macOS 上是否注定无法直连逃逸 TUN。
// macOS scoped routing: socket 绑定物理网卡(IP_BOUND_IF/源IP)后, 若目标路由仍
// 命中 TUN 的 0/1+128/1 全量路由(即目标不在本机直连子网), sendto 必然
// EHOSTUNREACH(no route to host)。DNS(53) 由 ensureUDPDynRoute 加 /32 例外路由
// 解决; 其余 UDP 故意不加 /32(会让该目标的 TCP 也绕过代理), 调用方应直接 drop,
// 促客户端回退 TCP 走 TUN 代理——既符合设计意图, 也避免每包
// listen→写失败→淘汰 的 socket 风暴与错误日志刷屏。
func udpDirectBlocked(dst string) bool {
	if config.TUNBypassDev == "" {
		return false
	}
	return !dstInBypassNet(dst)
}

// ensure 确保目标 IPv4 有 /32 例外路由(TTL 缓存)。无网关/IPv6/非 IP 跳过。
func (d *udpDynRoute) ensure(ip string) {
	gw := config.TUNBypassGW
	if ip == "" || gw == "" {
		return
	}
	a := net.ParseIP(ip)
	if a == nil || a.To4() == nil {
		return
	}
	now := time.Now()
	d.mu.Lock()
	// 懒清理: 顺带删除过期项的 /32 路由(DNS 目标仅几个, 遍历开销可忽略)
	for k, exp := range d.rt {
		if now.After(exp) {
			delete(d.rt, k)
			_ = macUDPRouteDel(k + "/32")
		}
	}
	if exp, ok := d.rt[ip]; ok && now.Before(exp) {
		d.mu.Unlock()
		return // TTL 内, 路由已存在, 无需重复加
	}
	d.rt[ip] = now.Add(d.ttl)
	d.mu.Unlock()
	if err := macUDPRouteAdd(ip+"/32", gw); err != nil {
		log.Printf("udp-dynroute: add %s via %s: %v\n", ip, gw, err)
	}
}

// CleanupUDPDynRoutes 清理残留的 UDP /32 例外路由(TUN teardown 时调用)。
func CleanupUDPDynRoutes() {
	macUDPDynRoute.mu.Lock()
	ips := make([]string, 0, len(macUDPDynRoute.rt))
	for k := range macUDPDynRoute.rt {
		ips = append(ips, k)
	}
	macUDPDynRoute.rt = map[string]time.Time{}
	macUDPDynRoute.mu.Unlock()
	for _, ip := range ips {
		_ = macUDPRouteDel(ip + "/32")
	}
}

// macUDPRouteAdd/macUDPRouteDel 是包级函数变量, 便于单测注入(不改真路由, 无需 root)。
var (
	macUDPRouteAdd = macUDPRouteAddCmd
	macUDPRouteDel = macUDPRouteDelCmd
)

func macUDPRouteAddCmd(cidr, gw string) error {
	out, err := exec.Command("route", "-n", "add", "-net", cidr, gw).CombinedOutput()
	if err != nil {
		return fmt.Errorf("udp-dynroute add %s via %s: %v: %s", cidr, gw, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func macUDPRouteDelCmd(cidr string) error {
	out, err := exec.Command("route", "-n", "delete", "-net", cidr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("udp-dynroute delete %s: %v: %s", cidr, err, strings.TrimSpace(string(out)))
	}
	return nil
}
