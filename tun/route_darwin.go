//go:build darwin
// +build darwin

package tun

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/keminar/anyproxy/config"
)

// setupTUNRoutes 添加直连例外路由和 TUN 默认路由。
// bypassIPs 中的 IP 经默认网关直连, 0.0.0.0/1 和 128.0.0.0/1 流量走 TUN(点对点接口)。
func setupTUNRoutes(tunName, tunIP, gw, dev string, bypassIPs []string) error {
	run := func(args ...string) error {
		log.Printf("autoRoute: route %s\n", strings.Join(args, " "))
		out, err := exec.Command("route", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("route %v: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	for _, ip := range bypassIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		// bypass 路由失败只记警告(常见原因: 路由已存在), 不中断后续
		if gw == "" {
			log.Printf("autoRoute: bypass route %s skipped: no default gateway\n", ip)
			continue
		}
		if err := run("-n", "add", "-net", ip, gw); err != nil {
			log.Printf("autoRoute: bypass route %s skipped: %v\n", ip, err)
		}
	}
	if err := run("-n", "add", "-net", "0.0.0.0/1", "-interface", tunName); err != nil {
		return fmt.Errorf("add tun route 0.0.0.0/1: %w", err)
	}
	if err := run("-n", "add", "-net", "128.0.0.0/1", "-interface", tunName); err != nil {
		return fmt.Errorf("add tun route 128.0.0.0/1: %w", err)
	}
	// macOS 无源策略路由: 用 pf reply-to 让配置的入站端口(如 SSH)回包沿物理网卡原路返回,
	// 否则会被上面的 0/1 路由吸进 utun 而断。仅配置了 inboundPorts 时启用。
	setupInboundPF(dev, gw, config.TUNInboundPorts)
	return nil
}

// teardownTUNRoutes 只删除 TUN 默认路由, 直连例外路由由用户管理。
func teardownTUNRoutes(tunName string) {
	cleanupInboundPF()
	run := func(args ...string) { _ = exec.Command("route", args...).Run() }
	run("-n", "delete", "-net", "0.0.0.0/1")
	run("-n", "delete", "-net", "128.0.0.0/1")
}

// bypass 模式 /32 例外路由仅 Windows 需要(darwin bypass 用 IP_BOUND_IF 绑网卡), 空操作。
func bypassEnableDirectRoutes(gw string) {}
func bypassCleanupDirectRoutes()         {}
func tunEnableDirectRoutes(gw string)    {}
