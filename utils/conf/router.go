package conf

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v2"
)

type PortMap struct {
	From uint16 `yaml:"from"` //原目标地址
	To   uint16 `yaml:"to"`   //新目标地址
}

// Host 域名
// name 支持首/尾 * 通配, 无需再配 match(去掉星号后的部分记为 X):
//
//	name: google.com     精确匹配      → 仅 google.com
//	name: "*google.com"  末尾一致(后缀) → www.google.com 命中, www.google.com.hk 不命中
//	name: "google.com*"  开头一致(前缀) → google.com/google.com.hk 命中, www.google.com 不命中
//	name: "*google.com*" 子串包含       → 含 google.com 的任意位置都命中
//
// 显式配置 match 时以 match 为准(向后兼容 contain/equal, name 原样不解析星号)。
type Host struct {
	Name    string    `yaml:"name"`    //域名关键字, 首/尾 * 通配(见上)
	Match   string    `yaml:"match"`   //可选, 显式指定: contain 包含, equal 完全相等
	Target  string    `yaml:"target"`  //local 当前环境, remote 远程, deny 禁止, auto根据dial选择
	DNS     string    `yaml:"dns"`     //local 当前环境, remote 远程, 仅当target使用remote有效
	IP      string    `yaml:"ip"`      //本地解析ip
	Port    []PortMap `yaml:"port"`    //目标端口转换
	Proxy   string    `yaml:"proxy"`   //指定代理服务器
	AllowIP []string  `yaml:"allowIP"` //可以访问的客户端IP
}

// Matched 判断 target(域名或IP) 是否命中本 host 规则。
// 优先级: 显式 Match(旧语义, name 原样) > name 首/尾 * 通配 > defaultMatch > equal。
func (h Host) Matched(target, defaultMatch string) bool {
	name := h.Name
	// 显式配置 match 时按旧语义处理, 保证向后兼容
	if h.Match != "" {
		switch h.Match {
		case "equal":
			return name == target
		case "contain":
			return strings.Contains(target, name)
		default:
			return false //未支持的比对方式, 不匹配
		}
	}
	// 未显式配 match: 解析 name 首/尾 * 通配
	hasPre := strings.HasPrefix(name, "*")
	hasSuf := strings.HasSuffix(name, "*")
	if hasPre || hasSuf {
		core := strings.Trim(name, "*")
		switch {
		case hasPre && hasSuf:
			return strings.Contains(target, core)
		case hasPre:
			return strings.HasSuffix(target, core)
		default: // 仅尾部 *
			return strings.HasPrefix(target, core)
		}
	}
	// 无 * : 走 default.match, 兜底 equal
	switch defaultMatch {
	case "contain":
		return strings.Contains(target, name)
	case "equal", "":
		return name == target
	default:
		return false //未支持的比对方式, 与显式 match 保持一致
	}
}

// Log 日志
type Log struct {
	Dir string `yaml:"dir"`
}

// Subscribe 订阅标志
type Subscribe struct {
	Key string `yaml:"key"` //Header的key
	Val string `yaml:"val"` //Header的val
}

// Websocket 与服务端websocket通信
type Websocket struct {
	Listen    string      `yaml:"listen"`    //websocket 监听
	Connect   string      `yaml:"connect"`   //websocket 连接
	Host      string      `yaml:"host"`      //connect的域名
	User      string      `yaml:"user"`      //认证用户
	Pass      string      `yaml:"pass"`      //密码
	Email     string      `yaml:"email"`     //邮箱
	Subscribe []Subscribe `yaml:"subscribe"` //订阅信息
}

// Default 域名
type Default struct {
	Match     string `yaml:"match"`     //默认域名比对
	Target    string `yaml:"target"`    //http默认访问策略
	DNS       string `yaml:"dns"`       //默认的DNS服务器
	Proxy     string `yaml:"proxy"`     //全局代理服务器
	TCPTarget string `yaml:"tcpTarget"` //tcp默认访问策略: auto/local/remote/deny/localport
	//tcpTarget=localport 时，这些端口走本地直连、其余走代理。
	//不配置则默认 21(ftp)/22(ssh)；一旦配置则完全以此为准(覆盖默认)。
	LocalPort []int `yaml:"localPort"`
}

// TcpCopy 端口转发模式: 每个连接改投到固定 ip:port(见 proto/request.go)，与 proxy/
// tunnel/tun/bypass 互斥。推荐用顶层 mode: tcpcopy 开启; enable 为旧写法, 仍兼容。
type TcpCopy struct {
	Enable bool   `yaml:"enable"` //已废弃，改用顶层 mode: tcpcopy；为true时向后兼容(等价 mode: tcpcopy)
	IP     string `yaml:"ip"`     //转发目标ip
	Port   uint16 `yaml:"port"`   //转发目标端口
}

// TunOS 是一套 tun 参数。既可写在 tun 顶层(扁平, 三平台通用)，也可写在按系统
// 分块的 tun.linux / tun.darwin / tun.windows 下(只填该系统用得到的字段)。
//
// 各字段生效平台(不生效即忽略):
//
//	name/addr/mtu/autoRoute  仅 linux/darwin(gVisor 虚拟网卡)；windows(WinDivert 无网卡)忽略
//	bypassIPs                三平台: linux/darwin 加 /32 直连路由；windows 排除捕获(直连)
//	blockQUIC                三平台
//	excludeProcs             仅 windows(WinDivert 按进程名排除, 逃 OpenVPN 等同机隧道)
//	inboundPorts             仅 darwin(pf reply-to 放行入站服务回包; linux 自动, windows 无需)
type TunOS struct {
	Name         string   `yaml:"name"`         //网卡名, linux默认anytun0, darwin默认utunN
	Addr         string   `yaml:"addr"`         //接口地址CIDR, 如 10.9.0.1/24
	MTU          uint32   `yaml:"mtu"`          //MTU, 默认1500
	AutoRoute    *bool    `yaml:"autoRoute"`    //不配置默认true自动加路由; 显式false只打印命令
	BypassIPs    []string `yaml:"bypassIPs"`    //这些目标直连(不代理): linux/darwin加/32路由; windows排除捕获
	BlockQUIC    *bool    `yaml:"blockQUIC"`    //不配置默认true: drop命中hosts(配ip/deny)域名的UDP443, 逼QUIC回退TCP
	ExcludeProcs []string `yaml:"excludeProcs"` //仅windows: 这些进程(exe名, 如openvpn.exe)的出向不重定向
	InboundPorts []int    `yaml:"inboundPorts"` //仅darwin: 需pf放行回包的入站TCP端口(如22)
}

// Tun 虚拟网卡全局代理。
//
// 两种写法(可混用, 系统块优先):
//  1. 扁平(旧写法, 三平台通用): 直接在 tun 下写 name/addr/... 字段。
//  2. 按系统分块(推荐): 在 tun.linux / tun.darwin / tun.windows 下各写该系统的字段,
//     程序按当前系统取对应块整体覆盖扁平字段(见 applyOS)。这样每个系统块里只出现
//     该系统用得到的字段, 避免"某字段在本平台无效"的困惑。
type Tun struct {
	TunOS `yaml:",inline"` //扁平字段(三平台通用, 未配对应系统块时用)

	Linux   *TunOS `yaml:"linux"`   //仅在 linux 上生效的一组配置
	Darwin  *TunOS `yaml:"darwin"`  //仅在 darwin(macOS) 上生效的一组配置
	Windows *TunOS `yaml:"windows"` //仅在 windows 上生效的一组配置
}

// applyOS 把当前系统对应的分块(若配置了)整体压平进扁平字段, 使所有消费者
// (anyproxy.go / dnsutil 等)无需感知分块即可拿到本系统的值。整块覆盖: 配了对应
// 系统块就以块为准, 块内未设的字段各自走默认(与旧扁平配置行为一致)。
func (t *Tun) applyOS(goos string) {
	var b *TunOS
	switch goos {
	case "linux":
		b = t.Linux
	case "darwin":
		b = t.Darwin
	case "windows":
		b = t.Windows
	}
	if b != nil {
		t.TunOS = *b
	}
}

// BypassOS 是一套 bypass(物理网卡绕行)参数。既可扁平写在 bypass 顶层(三平台通用)，
// 也可按系统分块写在 bypass.linux / bypass.darwin / bypass.windows 下。
//
// 各字段生效平台(不生效即忽略):
//
//	excludeNics   仅 linux/darwin: 采集直连子网时排除的网卡名(通常填另一进程的TUN网卡名)
//	device        仅 linux/darwin: 手动指定物理网卡名, 为空则回退 defaultRoute 自动探测
//	excludeProcs  仅 windows(bypass模式): 记录用途, 实际逃逸需配在 TUN 进程的 tun.windows 下
//	bypassIPs     仅 windows(bypass模式): 记录用途, 实际逃逸需配在 TUN 进程的 tun.windows 下
type BypassOS struct {
	ExcludeNics  []string `yaml:"excludeNics"`  //linux/darwin: 采集直连子网时排除的网卡名(通常填另一进程的TUN网卡名)
	Device       string   `yaml:"device"`       //linux/darwin: 手动指定物理网卡名, 为空则回退 defaultRoute 自动探测
	ExcludeProcs []string `yaml:"excludeProcs"` //windows: 这些进程(exe名)的出向不被WinDivert捕获
	BypassIPs    []string `yaml:"bypassIPs"`    //windows: 这些目标IP排除捕获(直连)
}

// Bypass 物理网卡绕行(不建TUN网卡)。
// 用于本机已有另一个 anyproxy TUN 进程时：让本进程出向连接绑定物理网卡，
// 逃出对方 TUN 的 0/1 路由，避免 target=local 请求被再次劫持成死循环。
// 通过顶层 mode=bypass 启用，与 tun 模式互斥。
//
// 两种写法(可混用, 系统块优先):
//  1. 扁平(旧写法, 三平台通用): 直接在 bypass 下写 excludeNics/device 字段。
//  2. 按系统分块(推荐): 在 bypass.linux / bypass.darwin / bypass.windows 下各写该系统的字段,
//     程序按当前系统取对应块整体覆盖扁平字段(见 applyOS)。
type Bypass struct {
	BypassOS `yaml:",inline"` //扁平字段(三平台通用, 未配对应系统块时用)

	Linux   *BypassOS `yaml:"linux"`   //仅在 linux 上生效的一组配置
	Darwin  *BypassOS `yaml:"darwin"`  //仅在 darwin(macOS) 上生效的一组配置
	Windows *BypassOS `yaml:"windows"` //仅在 windows 上生效的一组配置
}

// applyOS 把当前系统对应的分块(若配置了)整体压平进扁平字段。
func (b *Bypass) applyOS(goos string) {
	var blk *BypassOS
	switch goos {
	case "linux":
		blk = b.Linux
	case "darwin":
		blk = b.Darwin
	case "windows":
		blk = b.Windows
	}
	if blk != nil {
		b.BypassOS = *blk
	}
}

// LoopGuard 死循环兜底熔断器。
// 同机 A(mode=tun)+B(mode=bypass) 部署时, 正常应由 bypass 从路由层根治环路;
// 若 bypass 未生效, 句柄会堆积且都指向同一目标(环路特征)。
// 判定: 全局在传连接数达到 minActive(闸门)后, 若某个 host:port 占用的在传连接
// 超过 total*ratio%, 判为环路并拒绝其新连接。这是最后防线, 非主方案。
type LoopGuard struct {
	MinActive int `yaml:"minActive"` //全局在传连接数达到此值才启用占比检查; 0=用内置默认(1000,默认开启); <0=关闭。需 ulimit -n 远大于其2倍(每连接约2个fd)
	Ratio     int `yaml:"ratio"`     //单目标占全局在传连接的百分比阈值(如80=80%); <=0 用默认80
}

// http首行请求格式，一般vue本地项目要把域名配置为off
// 注意：custom配置域名和端口中间的冒号改为点，如localhost:5173配置为localhost.5173
type FirstLine struct {
	Host   string            `yaml:"host"`   //是否带Host, on带，off不带，默认带
	Custom map[string]string `yaml:"custom"` //按域名配带Host，on带，off不带,其他用默认
}

// Router 配置文件模型
type Router struct {
	Listen    string    `yaml:"listen"`    //监听端口
	Network   string    `yaml:"network"`   //监听协议
	Log       Log       `yaml:"log"`       //日志目录
	Watcher   bool      `yaml:"watcher"`   //是否监听配置文件变化
	Token     string    `yaml:"token"`     //加密值, 和tunnel通信密钥, 必须16位长度
	TcpCopy   TcpCopy   `yaml:"tcpcopy"`   //进行tcp转发模式
	Mode      string    `yaml:"mode"`      //运行模式: proxy=客户端(默认); tunnel=服务端tunneld; tun=建TUN网卡全局代理; bypass=仅绑物理网卡绕行; tcpcopy=端口转发。命令行 -mode 优先
	Tun       Tun       `yaml:"tun"`       //TUN虚拟网卡全局代理(mode=tun时生效)
	Bypass    Bypass    `yaml:"bypass"`    //物理网卡绕行(mode=bypass时生效)
	LoopGuard LoopGuard `yaml:"loopGuard"` //死循环兜底熔断器
	Default   Default   `yaml:"default"`   //默认配置
	Hosts     []Host    `yaml:"hosts"`     //域名列表
	AllowIP   []string  `yaml:"allowIP"`   //可以访问的客户端IP
	FirstLine FirstLine `yaml:"firstLine"` //http请求首行域名和头部域名相同时删除首行域名
	Websocket Websocket `yaml:"websocket"` //会话订阅请求信息
}

// LoadRouterConfig 加载配置
func LoadRouterConfig(configPath string) (cnf Router, err error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	err = yaml.Unmarshal(data, &cnf)
	if err == nil {
		// 按当前系统把 tun.<os> / bypass.<os> 分块压平进扁平字段, 消费者无需感知分块
		cnf.Tun.applyOS(runtime.GOOS)
		cnf.Bypass.applyOS(runtime.GOOS)
		// mode: tcpcopy 归一为 tcpcopy.enable(与旧写法统一, 消费方只看 Enable; 热重载安全)
		if cnf.Mode == "tcpcopy" {
			cnf.TcpCopy.Enable = true
		}
	}
	return
}

// 获取文件路径
func GetPath(filename string) (string, error) {
	// 当前登录用户所在目录
	workPath, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	configPath := filepath.Join(workPath, "conf", filename)
	if !fileExists(configPath) {
		configPath = filepath.Join(AppPath, "conf", filename)
		if !fileExists(configPath) {
			configPath = filepath.Join(AppSrcPath, "conf", filename)
			if !fileExists(configPath) {
				log.Println("workPath:", workPath)
				log.Println("appPath:", AppPath)
				return "", errors.New("conf/" + filename + " not found")
			}
		}
	}
	return configPath, nil
}

// fileExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
