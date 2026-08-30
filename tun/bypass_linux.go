//go:build linux

package tun

import (
	"log"

	"github.com/keminar/anyproxy/config"
)

// InitBypassOnly 只初始化物理网卡绕行参数，不创建 TUN 设备、不加路由。
// 用于本机存在另一个 anyproxy TUN 进程时：让本进程的出向连接(tunDial)绑定
// 物理网卡，逃出对方 TUN 的 0/1 路由，避免 target=local 请求被再次劫持成死循环。
// 与 Run 互斥——本进程若自身开 TUN 则已在 Run 内完成同样的初始化，无需再调用。
// 仅 Linux 支持；macOS/Windows 已移除该模式(见 bypass_other.go)。
//
// cfg.ExcludeNics: 采集直连子网时要排除的网卡名(通常是另一进程的 TUN 网卡名)。
// 为空时默认排除本平台默认 TUN 网卡名(linux anytun0)。
// cfg.Device: 手动指定用于绑定的物理网卡名; 为空则回退 defaultRoute 自动探测,
// 兜住探测失败(device="")时 tunDial 静默退回普通 Dial 导致 bypass 形同虚设的情况。
func InitBypassOnly(cfg BypassConfig) error {
	excludeNics := cfg.ExcludeNics
	device := cfg.Device
	if len(excludeNics) == 0 && defaultTunName != "" {
		excludeNics = []string{defaultTunName}
	}
	gw, autoDev := defaultRoute()
	if device == "" {
		device = autoDev
	}
	config.TUNBypassDev = device
	config.TUNBypassIP = defaultLocalIP(device)
	config.TUNBypassIfIndex = bypassIfIndex(device)
	config.TUNBypassGW = gw
	initBypassNets(excludeNics...)
	log.Printf("bypass-only: device=%q ip=%q ifIndex=%d gw=%q exclude=%v\n", device, config.TUNBypassIP, config.TUNBypassIfIndex, gw, excludeNics)
	// 同机 A(tun) 的 0/1 路由会吸走 B(bypass) 的直连出向, 故加 /32 物理网关例外路由
	// 才能真正逃出。gw 为空则不启用(非持久路由, 漏删也随重启消失)。
	bypassEnableDirectRoutes(gw)
	return nil
}

// CleanupBypass 清理 bypass 模式添加的 /32 例外路由。
// 进程退出/平滑重启前调用, 避免残留路由(非持久路由, 漏删也随重启消失)。
func CleanupBypass() {
	bypassCleanupDirectRoutes()
}
