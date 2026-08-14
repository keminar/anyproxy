package tun

// Config TUN运行参数(跨平台)。
//
// 注意: Windows 上采用 WinDivert 透明重定向(见 tun_windows.go)，不创建虚拟网卡，
// 故 Addr/Name/MTU/AutoRoute/BypassIPs 这些字段在 Windows 上被忽略；它们只对
// 非 Windows 的 wintun/gVisor 路径(tun_other.go)有意义。
type Config struct {
	Name         string   // 网卡名, 为空则用平台默认
	Addr         string   // 接口地址CIDR, 如 10.9.0.1/24, 为空默认 10.9.0.1/24
	MTU          uint32   // 为0默认1500
	AutoRoute    bool     // 启动时自动添加路由，退出时只删除 0.0.0.0/1 和 128.0.0.0/1
	BypassIPs    []string // 走物理网卡的IP列表（直连例外）。Windows(WinDivert)下亦作排除捕获的目的IP
	ExcludeProcs []string // 仅 Windows(WinDivert): 这些进程(exe名)的出向不重定向，用于逃出同机隧道(如openvpn.exe)
	InboundPorts []int    // 仅 macOS: 需放行回包的入站 TCP 端口(如 22)，用 pf reply-to 让回包原路返回
}

// BypassConfig bypass 模式运行参数(跨平台)。
//
// 各字段生效平台:
//
//	ExcludeNics  仅 linux/darwin: 采集直连子网时排除的网卡名
//	Device       仅 linux/darwin: 手动指定物理网卡名
//	ExcludeProcs 仅 windows: 这些进程的出向不被WinDivert捕获(配合TUN进程使用)
//	BypassIPs    仅 windows: 这些目标IP排除WinDivert捕获(直连)
type BypassConfig struct {
	ExcludeNics  []string
	Device       string
	ExcludeProcs []string
	BypassIPs    []string
}
