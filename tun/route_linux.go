//go:build linux
// +build linux

package tun

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

// tunRouteTable 是存放 TUN 默认路由的独立路由表 ID(数字表, 无需 rt_tables 登记)。
// 把 TUN 的默认路由从 main 表挪到这里, 配合下面的 ip rule 做策略路由, 是为了
// 让「入站连接的回包」不被 TUN 吸走(否则外网 SSH 进来 sshd 回包命中 0/1 路由
// 被塞进 TUN, 握手回不去)。
const tunRouteTable = "1088"

// ip rule 优先级(数字越小越优先)。
const (
	ruleFromPhys = "100" // 源=物理网卡IP(入站回包/已绑源的本机流量) → main 表出物理网卡
	ruleMainSupp = "110" // 所有流量: 用 main 的具体路由(LAN/环回/上游代理/32), 但忽略默认路由
	ruleToTun    = "120" // 其余(本机新建出站) → TUN 表
)

// linTunPhysIPs 保存本次 setup 用到的物理网卡 IPv4, 供 teardown 精确删规则。
var linTunPhysIPs []string

// setupTUNRoutes 用策略路由接管全局流量, 同时保证入站连接的回包仍走物理网卡。
//
// 设计(等价 sing-box/clash 的 TUN 策略路由):
//   - TUN 默认路由放在独立表 tunRouteTable, 不污染 main;
//   - rule pref 100: 源自物理网卡 IP 的包(sshd 等入站连接回包, 源已固定为物理IP)
//     查 main 表 → 走物理网卡默认路由回给外网客户端, 不进 TUN;
//   - rule pref 110: 所有包先查 main 但 suppress_prefixlength 0(忽略默认路由),
//     使 LAN/环回/上游代理 /32 等具体路由照常走物理, 只有「本该走默认路由」的落空;
//   - rule pref 120: 落空的(本机新建出站上网)查 TUN 表 → 进 anytun0 被 gVisor 接管。
//
// bypassIPs 仍加到 main(经物理网卡直连上游代理)。
func setupTUNRoutes(tunName, tunIP, gw, dev string, bypassIPs []string) error {
	run := func(args ...string) error {
		log.Printf("autoRoute: %s\n", strings.Join(args, " "))
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// 幂等: 先清掉可能残留的同名规则/表路由(忽略错误)
	runSoft := func(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }
	cleanupPolicyRules(runSoft)

	// 上游代理等直连例外仍走 main 表
	for _, ip := range bypassIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		if err := run("ip", "route", "add", ip, "via", gw, "dev", dev); err != nil {
			log.Printf("autoRoute: bypass route %s skipped: %v\n", ip, err)
		}
	}

	// TUN 默认路由放独立表
	if err := run("ip", "route", "replace", "default", "dev", tunName, "table", tunRouteTable); err != nil {
		return fmt.Errorf("add tun default route (table %s): %w", tunRouteTable, err)
	}

	// pref 100: 物理网卡 IP 源(入站回包)走 main, 不进 TUN
	linTunPhysIPs = physIPv4s(dev)
	if len(linTunPhysIPs) == 0 {
		log.Printf("autoRoute: WARN 未能取到物理网卡 %q 的 IPv4, 入站连接(如外网SSH)回包可能被 TUN 吸走\n", dev)
	}
	for _, ip := range linTunPhysIPs {
		if err := run("ip", "rule", "add", "from", ip+"/32", "lookup", "main", "pref", ruleFromPhys); err != nil {
			log.Printf("autoRoute: add rule from %s skipped: %v\n", ip, err)
		}
	}

	// pref 110: 用 main 的具体路由但忽略默认路由(LAN/环回/上游代理照常走物理)
	if err := run("ip", "rule", "add", "from", "all", "lookup", "main", "suppress_prefixlength", "0", "pref", ruleMainSupp); err != nil {
		cleanupPolicyRules(runSoft)
		runSoft("ip", "route", "flush", "table", tunRouteTable)
		return fmt.Errorf("add suppress rule: %w", err)
	}
	// pref 120: 其余(本机新建出站)进 TUN 表
	if err := run("ip", "rule", "add", "from", "all", "lookup", tunRouteTable, "pref", ruleToTun); err != nil {
		cleanupPolicyRules(runSoft)
		runSoft("ip", "route", "flush", "table", tunRouteTable)
		return fmt.Errorf("add tun table rule: %w", err)
	}
	return nil
}

// teardownTUNRoutes 删除策略路由规则和 TUN 表, 直连例外(bypassIPs)由用户管理。
func teardownTUNRoutes(tunName string) {
	runSoft := func(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }
	cleanupPolicyRules(runSoft)
	runSoft("ip", "route", "flush", "table", tunRouteTable)
	linTunPhysIPs = nil
}

// cleanupPolicyRules 删除本模块加的三类 ip rule(按 pref 删, 多次删净可能的重复)。
func cleanupPolicyRules(runSoft func(args ...string)) {
	for _, ip := range linTunPhysIPs {
		runSoft("ip", "rule", "del", "from", ip+"/32", "lookup", "main", "pref", ruleFromPhys)
	}
	// 兜底: 按 pref 再删一遍(覆盖 linTunPhysIPs 为空但规则残留的情况), 删到不存在为止
	for i := 0; i < 4; i++ {
		runSoft("ip", "rule", "del", "pref", ruleFromPhys)
	}
	for i := 0; i < 2; i++ {
		runSoft("ip", "rule", "del", "from", "all", "lookup", "main", "suppress_prefixlength", "0", "pref", ruleMainSupp)
		runSoft("ip", "rule", "del", "from", "all", "lookup", tunRouteTable, "pref", ruleToTun)
	}
}

// physIPv4s 返回指定网卡的所有 IPv4 地址(用于策略路由放行入站回包)。
func physIPv4s(dev string) []string {
	if dev == "" {
		return nil
	}
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, ip4.String())
		}
	}
	return out
}

// bypass 模式 /32 例外路由仅 Windows 需要(Linux bypass 用 SO_BINDTODEVICE 硬绑网卡,
// 出向不会回灌他机 TUN), 此处空操作。
func bypassEnableDirectRoutes(gw string) {}
func bypassCleanupDirectRoutes()         {}
func tunEnableDirectRoutes(gw string)     {}
