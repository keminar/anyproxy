package tun

// Config TUN运行参数(跨平台)。
//
// 注意: Windows 上采用 WinDivert 透明重定向(见 tun_windows.go)，不创建虚拟网卡，
// 故 Addr/Name/MTU/AutoRoute/BypassIPs 这些字段在 Windows 上被忽略；它们只对
// 非 Windows 的 wintun/gVisor 路径(tun_other.go)有意义。
type Config struct {
	Name          string   // 网卡名, 为空则用平台默认
	Addr          string   // 接口地址CIDR, 如 10.9.0.1/24, 为空默认 10.9.0.1/24
	MTU           uint32   // 为0默认1500
	AutoRoute     bool     // 启动时自动添加路由，退出时只删除 0.0.0.0/1 和 128.0.0.0/1
	BypassIPs     []string // 走物理网卡的IP列表（直连例外）。Windows(WinDivert)下亦作排除捕获的目的IP
	BypassPrivate bool     // 仅 Windows(WinDivert): 私网/LAN/链路本地地址一律直连不进引擎(不配默认true)
	ExcludeProcs  []string // 仅 Windows(WinDivert): 这些进程(exe名)的出向不重定向，用于逃出同机隧道(如openvpn.exe)
	InboundPorts  []int    // 仅 macOS: 需放行回包的入站 TCP 端口(如 22)，用 pf reply-to 让回包原路返回
	WindivertDir  string   // 仅 Windows: WinDivert.dll+WinDivert64.sys 所在目录，空=exe同目录
}

// BypassConfig bypass 模式运行参数(仅 Linux 支持; macOS/Windows 已移除该模式)。
type BypassConfig struct {
	ExcludeNics []string // 采集直连子网时排除的网卡名
	Device      string   // 手动指定物理网卡名
}
