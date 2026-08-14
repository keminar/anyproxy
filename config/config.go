package config

import (
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/keminar/anyproxy/utils/tools"
)

// ProxyScheme 协议,目前支持 tunnel为自定义协议，socks5,http为标准协议
var ProxyScheme string = "tunnel"

// ProxyServer 代理服务器
var ProxyServer string

// ProxyPort 代理端口
var ProxyPort uint16

// ProxyCmdline 命令行 -p 指定的全局代理原始值(空表示未指定)。
// 它是「固定」的, 优先级高于配置文件的 default.proxy; 未指定 -p 时请求侧实时读取
// conf.RouterConfig.Default.Proxy, 从而让 default.proxy 支持热加载。
var ProxyCmdline string

// TimeFormat 格式化时间
var TimeFormat string = "2006-01-02 15:04:05"

// DebugLevel 调试级别
var DebugLevel int

// ListenPort 监听端口
var ListenPort uint16

// TUNBypassDev TUN 模式下出向连接绑定的物理网卡名（Linux SO_BINDTODEVICE 用）。
var TUNBypassDev string

// TUNDevName TUN 虚拟网卡名（如 anytun0）。
var TUNDevName string

// TUNSelfIP TUN 虚拟网卡自身的 IP（如 10.9.0.1）。
// 源 IP 等于它，说明是本机自己经 TUN 出来的流量，allowIP 检查应默认放行。
var TUNSelfIP string

// TUNBypassNets 本机除 TUN 外的所有直连子网，目标 IP 在这些子网内时不需要绑定物理网卡。
var TUNBypassNets []*net.IPNet

// TUNBypassIP 物理网卡本机 IP。仅作 LocalAddr 兜底绑定用（macOS/其它平台，及 Windows KVM 等环境），
// 靠友好名解析得来、不一定可靠；不能作为“是否绑定”的判据，为空时不应关闭绑定。
var TUNBypassIP string

// TUNBypassIfIndex 物理网卡的出接口索引。Windows 用它设 IP_UNICAST_IF 强制出接口
// （弱主机模型下这是逃出 TUN 路由的正解），也是判断能否绑定的唯一可靠依据；0 表示未知。
// 相比 TUNBypassIP，索引可从系统路由表(Get-NetRoute ifIndex)直接拿到，不依赖友好名匹配。
var TUNBypassIfIndex int

// TUNBypassGW 物理网卡默认网关。Windows 上给动态 /32 例外路由作 nexthop 用
// （route add <ip> mask 255.255.255.255 <gw>，使包经物理网卡出、逃出 TUN 的 0/1）。
// 为空表示网关探测失败，动态 /32 不启用，出向环路只能靠 loopguard 兜底。
var TUNBypassGW string

// TUNInboundPorts macOS 专用: 需要放行回包的入站 TCP 端口(如 SSH 22)。
// utun 的 0/1 路由会把「入站连接的回包」也吸进 TUN 导致对外服务断; macOS 无源策略
// 路由, 靠 pf reply-to 让这些端口的回包沿物理网卡原路返回。为空=不启用。
var TUNInboundPorts []int

const (
	// LevelShort 简短格式
	LevelShort int = iota
	// LevelLong 长格式日志
	LevelLong
	// LevelDebug 长日志 + 更多日志
	LevelDebug
	// LevelDebugBody 打印body
	LevelDebugBody
)

// SetProxyServer 解析全局代理的「首个代理」到 ProxyScheme/ProxyServer/ProxyPort。
// 这些值供 tun_windows 排除捕获(需要上游代理 IP:端口)与日志用, 在启动时确定即可。
// 请求侧的实际选择(多代理连通性挑选、local/deny 兜底、热加载)在 proto 层按请求完成,
// 不依赖这里的快照值。支持的写法(与单域名 host.proxy 一致):
//   - 单代理:            socks5://127.0.0.1:1080
//   - 逗号分隔多代理:     http://127.0.0.1:8888, http://127.0.0.1:7777
//   - 末尾 local/deny:   ... 7777 local  (全部代理都连不通时: local 走本地直连, deny 拒绝)
func SetProxyServer(gProxyServerSpec string) {
	if gProxyServerSpec == "" {
		return
	}
	spec := gProxyServerSpec
	// 剥离末尾 local/deny 后缀
	switch {
	case strings.HasSuffix(spec, " local"):
		spec = strings.TrimSpace(strings.TrimSuffix(spec, " local"))
	case strings.HasSuffix(spec, " deny"):
		spec = strings.TrimSpace(strings.TrimSuffix(spec, " deny"))
	}
	// 取逗号分隔的首个代理
	first := strings.TrimSpace(strings.Split(spec, ",")[0])
	// 先检查协议
	tmp := strings.Split(first, "://")
	if len(tmp) == 2 {
		ProxyScheme = tmp[0]
		first = tmp[1]
	}
	// 检查端口，和上面的顺序不能反
	tmp = strings.Split(first, ":")
	if len(tmp) == 2 {
		portInt, err := strconv.Atoi(tmp[1])
		if err == nil {
			ProxyServer = tmp[0]
			ProxyPort = uint16(portInt)
			log.Printf("Proxy server is %s://%s:%d\n", ProxyScheme, ProxyServer, ProxyPort)
		} else {
			log.Printf("Set proxy port err %s\n", err.Error())
		}
	}
}

// SetDebugLevel 调试级别
func SetDebugLevel(gDebug int) {
	DebugLevel = gDebug
}

// SetListenPort 端口
func SetListenPort(gListenAddrPort string) {
	intStr := tools.GetPort(gListenAddrPort)
	intNum, err := strconv.Atoi(intStr)
	if err != nil {
		log.Printf("SetListenPort err %s\n", err.Error())
	}
	ListenPort = uint16(intNum)
}

// IfEmptyThen 取值
func IfEmptyThen(str string, str2 string, str3 string) string {
	if str == "" {
		if str2 == "" {
			return str3
		}
		return str2
	}
	return str
}
