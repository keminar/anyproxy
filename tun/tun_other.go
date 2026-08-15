//go:build !windows
// +build !windows

package tun

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/keminar/anyproxy/config"
)

// Run 启动TUN虚拟网卡全局代理，阻塞直到出错或 ctx 结束。
// 流程: 创建网卡 -> 配置接口IP -> 打印路由提示 -> 运行用户态协议栈转发。
func Run(ctx context.Context, cfg Config) error {
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if cfg.Addr == "" {
		cfg.Addr = "10.9.0.1/24"
	}

	dev, err := newDeviceWithRetry(ctx, cfg.Name, cfg.MTU)
	if err != nil {
		return fmt.Errorf("create tun device: %w", err)
	}
	defer dev.Close()

	// 当 ctx 被取消时(如收到 SIGINT/SIGTERM)，主动关闭设备，
	// 使 runStack 中的 ReadPacket/ReadContext 立即返回，
	// 确保 wintun 虚拟网卡在进程退出前被清理。
	go func() {
		<-ctx.Done()
		log.Println("tun: ctx cancelled, closing device")
		dev.Close()
	}()

	if err := dev.SetupAddr(cfg.Addr); err != nil {
		return fmt.Errorf("setup tun addr %s: %w", cfg.Addr, err)
	}
	log.Printf("TUN device %q is up, addr=%s mtu=%d\n", dev.Name(), cfg.Addr, cfg.MTU)

	// 记录物理网卡名/IP，供 direct 连接绑定网卡绕过 TUN 路由
	bypassGW, bypassDev := defaultRoute()
	config.TUNDevName = dev.Name()
	config.TUNSelfIP = strings.SplitN(cfg.Addr, "/", 2)[0]
	config.TUNBypassDev = bypassDev
	config.TUNBypassIP = defaultLocalIP(bypassDev)
	config.TUNBypassIfIndex = bypassIfIndex(bypassDev)
	config.TUNBypassGW = bypassGW
	config.TUNInboundPorts = cfg.InboundPorts // macOS: pf reply-to 放行入站回包用
	initBypassNets(dev.Name())
	log.Printf("TUN bypass: device=%q ip=%q ifIndex=%d gw=%q\n", bypassDev, config.TUNBypassIP, config.TUNBypassIfIndex, bypassGW)

	// 启用 /32 直连例外路由(与 autoRoute 解耦): target=local 直连出向靠它逃出本机 TUN
	// 的 0/1(Windows 上 socket 选项对 TCP 压不过 /1)。gw 为空则内部不启用。
	tunEnableDirectRoutes(bypassGW)
	defer bypassCleanupDirectRoutes()

	if cfg.AutoRoute {
		if bypassGW == "" || bypassDev == "" {
			log.Println("autoRoute: cannot detect default gateway, skipping auto route setup")
		} else {
			tunIP := strings.SplitN(cfg.Addr, "/", 2)[0]
			if err := setupTUNRoutes(dev.Name(), tunIP, bypassGW, bypassDev, cfg.BypassIPs); err != nil {
				log.Printf("autoRoute setup err: %v\n", err)
			} else {
				log.Printf("autoRoute: routes added (gateway=%s device=%s)\n", bypassGW, bypassDev)
				defer teardownTUNRoutes(dev.Name())
			}
		}
	}

	// 提示语在 runStack 前打印（gw/dev 已传入，不再二次执行 PowerShell）
	printRouteHint(dev.Name(), cfg.Addr, cfg.AutoRoute, bypassGW, bypassDev)

	// gVisor 处理流量高峰后堆内存不会主动还给 OS(Linux 默认 MADV_FREE 仍计入 RSS)，
	// 周期性把空闲内存归还，把常驻内存压回接近工作集大小
	go scavengeMemory(ctx)

	return runStack(ctx, dev)
}

// newDeviceWithRetry 创建 TUN 设备，遇到"设备被占用"错误时短暂退避重试。
// 平滑重启时旧进程已在 fork 前(SIGHUP PreSignal 钩子)释放了 TUN 设备，
// 正常情况下新进程首次创建即成功；此处重试仅为覆盖释放与接管之间的极短时间窗
// (设备 fd 关闭到内核回收)，几秒内拿不到即视为异常，返回错误。ctx 取消则放弃。
func newDeviceWithRetry(ctx context.Context, name string, mtu uint32) (Device, error) {
	const maxWait = 5 * time.Second
	delay := 200 * time.Millisecond
	start := time.Now()
	for {
		dev, err := New(name, mtu)
		if err == nil {
			return dev, nil
		}
		// 非占用类错误(如权限不足)或已超过最大等待时间，直接返回
		if !isDeviceBusyErr(err) || time.Since(start) >= maxWait {
			return nil, err
		}
		log.Printf("tun device busy, retry in %v\n", delay)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		if delay < time.Second {
			delay *= 2
		}
	}
}

// isDeviceBusyErr 判断是否为"设备被占用/已存在"类错误(可通过重试解决)。
func isDeviceBusyErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "busy") || // Linux: device or resource busy
		strings.Contains(s, "in use") || // 通用: address/resource in use
		strings.Contains(s, "already exists") // Windows: adapter 已存在
}

// scavengeMemory 周期性归还空闲内存给操作系统，降低 RSS 常驻。
// FreeOSMemory 只归还真正空闲的页，不影响活跃连接的缓冲；进程空闲时
// 这点 GC 开销可忽略。ctx 结束即退出。
func scavengeMemory(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			debug.FreeOSMemory()
		}
	}
}

// printRouteHint 打印把全局流量导向TUN网卡所需的路由命令，供用户按需执行。
// gw/dev 由调用方传入，避免重复执行 defaultRoute()/PowerShell。
func printRouteHint(name, cidr string, autoRoute bool, gw, dev string) {
	tunIP := strings.SplitN(cidr, "/", 2)[0]
	zh := isChinese()

	log.Println("------------------------------------------------------------")
	if autoRoute {
		// 路由已自动添加，只打印确认信息
		if zh {
			log.Println("TUN 已就绪，路由已自动配置。注意: TCP 全代理; UDP 经物理网卡直连，DNS 查询按 anyproxy 配置劫持")
		} else {
			log.Println("TUN is ready. Routes configured automatically. Note: TCP is fully proxied; UDP goes via physical NIC, DNS queries are hijacked locally per hosts config.")
		}
		log.Println("------------------------------------------------------------")
		return
	}

	orGW := gw
	orDev := dev
	if zh {
		if orGW == "" {
			orGW = "<原网关>"
		}
		if orDev == "" {
			orDev = "<原网卡>"
		}
	} else {
		if orGW == "" {
			orGW = "<gateway>"
		}
		if orDev == "" {
			orDev = "<iface>"
		}
	}

	if zh {
		log.Println("TUN 已就绪。要实现全局代理，请按需添加路由(需管理员/root权限):")
		log.Println("注意: TCP 全代理; UDP 经物理网卡直连，DNS 查询按 anyproxy 配置劫持")
	} else {
		log.Println("TUN is ready. Add routes as needed to enable global proxy (requires admin/root):")
		log.Println("Note: TCP is fully proxied. UDP goes via physical NIC, DNS queries are hijacked locally per hosts config.")
	}
	switch runtime.GOOS {
	case "linux":
		if zh {
			log.Printf("  # 方式一: 只代理指定网段(示例)\n")
			log.Printf("  sudo ip route add 8.8.8.8/32 dev %s\n", name)
			log.Printf("  # 方式二: 接管默认路由(先给你的代理出口服务器加直连例外, 否则会环路断网)\n")
			log.Printf("  sudo ip route add <你的上级代理IP>/32 via %s dev %s\n", orGW, orDev)
			log.Printf("  sudo ip route add 0.0.0.0/1 dev %s\n", name)
			log.Printf("  sudo ip route add 128.0.0.0/1 dev %s\n", name)
		} else {
			log.Printf("  # Option 1: proxy specific subnets (example)\n")
			log.Printf("  sudo ip route add 8.8.8.8/32 dev %s\n", name)
			log.Printf("  # Option 2: take over default route (add a bypass for your upstream proxy first, or you will lose connectivity)\n")
			log.Printf("  sudo ip route add <upstream-proxy-ip>/32 via %s dev %s\n", orGW, orDev)
			log.Printf("  sudo ip route add 0.0.0.0/1 dev %s\n", name)
			log.Printf("  sudo ip route add 128.0.0.0/1 dev %s\n", name)
		}
	case "windows":
		if zh {
			log.Printf("  :: 方式一: 只代理指定网段(示例)\n")
			log.Printf("  route add 8.8.8.8 mask 255.255.255.255 0.0.0.0 if <TUN接口索引>\n")
			log.Printf("  :: 方式二: 接管默认路由(先给上级代理IP加直连例外, 否则会环路断网)\n")
			log.Printf("  route add <你的上级代理IP> mask 255.255.255.255 %s\n", orGW)
			log.Printf("  route add 0.0.0.0 mask 128.0.0.0 %s\n", tunIP)
			log.Printf("  route add 128.0.0.0 mask 128.0.0.0 %s\n", tunIP)
		} else {
			log.Printf("  :: Option 1: proxy specific subnets (example)\n")
			log.Printf("  route add 8.8.8.8 mask 255.255.255.255 0.0.0.0 if <TUN-interface-index>\n")
			log.Printf("  :: Option 2: take over default route (add a bypass for your upstream proxy first, or you will lose connectivity)\n")
			log.Printf("  route add <upstream-proxy-ip> mask 255.255.255.255 %s\n", orGW)
			log.Printf("  route add 0.0.0.0 mask 128.0.0.0 %s\n", tunIP)
			log.Printf("  route add 128.0.0.0 mask 128.0.0.0 %s\n", tunIP)
		}
	case "darwin":
		if zh {
			log.Printf("  # 方式一: 只代理指定网段(示例)\n")
			log.Printf("  sudo route add -net 8.8.8.8/32 -interface %s\n", name)
			log.Printf("  # 方式二: 接管默认路由(先给你的上级代理IP加直连例外, 否则会环路断网)\n")
			log.Printf("  sudo route add -net <你的上级代理IP>/32 %s\n", orGW)
			log.Printf("  sudo route add -net 0.0.0.0/1 -interface %s\n", name)
			log.Printf("  sudo route add -net 128.0.0.0/1 -interface %s\n", name)
		} else {
			log.Printf("  # Option 1: proxy specific subnets (example)\n")
			log.Printf("  sudo route add -net 8.8.8.8/32 -interface %s\n", name)
			log.Printf("  # Option 2: take over default route (add a bypass for your upstream proxy first, or you will lose connectivity)\n")
			log.Printf("  sudo route add -net <upstream-proxy-ip>/32 %s\n", orGW)
			log.Printf("  sudo route add -net 0.0.0.0/1 -interface %s\n", name)
			log.Printf("  sudo route add -net 128.0.0.0/1 -interface %s\n", name)
		}
	default:
		if zh {
			log.Printf("  当前平台请自行配置路由，将目标流量导向网卡 %s\n", name)
		} else {
			log.Printf("  Configure routes manually to direct traffic to interface %s\n", name)
		}
	}
	log.Println("------------------------------------------------------------")
}
