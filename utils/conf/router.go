package conf

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/keminar/anyproxy/utils/geo"
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
// 也支持按 geo 数据集匹配(需配 geo.ip / geo.site 加载 .dat):
//
//	name: geoip:cn       目标 IP 命中 geoip 类别 cn
//	name: geosite:cn     目标域名命中 geosite 类别 cn
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
	// geo 数据集匹配: geoip:xx 按 target(IP) 匹, geosite:xx 按 target(域名) 匹。
	// findHost 会分别用域名和 IP 各调一次, 传错类型时 geo.MatchIP/MatchSite 自然返回 false。
	if cat, ok := strings.CutPrefix(name, "geoip:"); ok {
		return geo.MatchIP(cat, target)
	}
	if cat, ok := strings.CutPrefix(name, "geosite:"); ok {
		return geo.MatchSite(cat, target)
	}
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

// ServerForward 服务端(tunnel侧)裸TCP端口转发入口(内网穿透)。
// 在 Listen 端口起裸TCP监听, 每个连接经websocket转发给该 Email 的订阅方。
type ServerForward struct {
	Listen string `yaml:"listen"` //监听地址, 如 ":2222"
	Email  string `yaml:"email"`  //转发给此email的订阅方

	// Protocol 入口协议: tcp(默认) / udp / both, 取值同 ClientDirect.Protocol。
	//
	// 两种协议在这条中继路径上**各走各的**, 不共用一条通道: TCP 仍旧经 websocket
	// 转发, UDP 另起一条 UDP 中继(见 nat/relay_udp.go)。绝不能把 UDP 塞进 websocket
	// —— 那是 TCP, 会给每个数据报强加重传与保序, 把 RDP 的 UDP 通道特意要绕开的
	// 队头阻塞又请回来, 只会更卡。
	//
	// both 用于 RDP: mstsc 的主通道是 TCP 3389, RDP 8+ 的图形通道另用同号 UDP 3389,
	// 只转发 TCP 等于把后者堵死。入口两个监听同号, 客户端不用改配置。
	Protocol string `yaml:"protocol"`
}

// WantTCP 是否要起 TCP 入口(经 websocket 中继)。留空按 tcp 处理, 与旧配置一致。
func (f ServerForward) WantTCP() bool { return protoWantTCP(f.Protocol) }

// WantUDP 是否要起 UDP 中继入口。
func (f ServerForward) WantUDP() bool { return protoWantUDP(f.Protocol) }

// ValidProtocol 配置里写了不认识的值时要能报出来, 而不是静默退化成 tcp。
func (f ServerForward) ValidProtocol() bool { return protoValid(f.Protocol) }

// ClientForward 订阅方(proxy侧)裸TCP端口转发目标。
// 收到服务端 Port 端口来的连接时, dial 写死的 Target(内网真实目标)。
// Port 未在本地命中则拒绝(天然白名单)。
type ClientForward struct {
	Port   uint16 `yaml:"port"`   //对应服务端入口端口
	Target string `yaml:"target"` //写死的dial目标, 如 "127.0.0.1:22"
}

// ClientDirect 订阅方(A侧)的直连入口规则: 在本机 Listen 起裸TCP监听, 进来的连接不再经
// 服务端中转, 而是用 QUIC 直接连到 Email 对应的另一个订阅方(C), 由对方按 Port 查它
// 自己的 client.forward[port] 决定 dial 哪个内网目标。
//
// 与 ServerForward 的区别: ServerForward 的入口在服务端(B)上、数据经 websocket 由 B 转发;
// 这里的入口在订阅方(A)自己机器上、数据走 A<->C 直连, B 只参与交换地址的信令。
type ClientDirect struct {
	Listen string `yaml:"listen"` //本机入口监听地址, 如 ":13389"
	Email  string `yaml:"email"`  //目标订阅方的 email(须与本条 server 连接下同一个 B 上的另一订阅方一致)
	Port   uint16 `yaml:"port"`   //告诉对方要用哪条 client.forward[port] 规则, 对方未映射该端口即拒绝

	// Protocol 入口与落地要还原的协议: tcp(默认) / udp / both。
	//
	// 两种协议在 QUIC 上的承载不同, 语义才对得上: TCP 走 stream(可靠有序), UDP 走
	// datagram(不可靠无序, RFC 9221)。不能拿 stream 扛 UDP —— 那会给 UDP 强加重传与
	// 保序, 把队头阻塞又请回来。
	//
	// both 常用于 RDP: mstsc 的主通道走 TCP 3389, 而 RDP 8+ 的 Enhanced RDP 会用
	// UDP 3389 走图形通道专门对抗卡顿, 只转发 TCP 等于把它堵死。
	Protocol string `yaml:"protocol"`
}

// 入口支持的协议取值。直连入口(ClientDirect)与中继入口(ServerForward)共用。
const (
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoBoth = "both"
)

func protoWantTCP(p string) bool { return p == "" || p == ProtoTCP || p == ProtoBoth }
func protoWantUDP(p string) bool { return p == ProtoUDP || p == ProtoBoth }
func protoValid(p string) bool {
	switch p {
	case "", ProtoTCP, ProtoUDP, ProtoBoth:
		return true
	}
	return false
}

// WantTCP 是否要起 TCP 入口。留空按 tcp 处理, 保持与旧配置一致。
func (d ClientDirect) WantTCP() bool { return protoWantTCP(d.Protocol) }

// WantUDP 是否要起 UDP 入口。
func (d ClientDirect) WantUDP() bool { return protoWantUDP(d.Protocol) }

// ValidProtocol 配置里写了不认识的值时要能报出来, 而不是静默退化成 tcp。
func (d ClientDirect) ValidProtocol() bool { return protoValid(d.Protocol) }

// ServerUser 服务端多用户鉴权的一条 {user, pass}, 见 WsServer.Users。
type ServerUser struct {
	User string `yaml:"user"` //认证用户
	Pass string `yaml:"pass"` //密码(与 key 二选一)
	// Key 为该账号的 Ed25519 公钥(base64), 与 Pass 二选一; 两者都配时优先用 Key。
	// 用 anyproxy -genkey 生成密钥对: 私钥配在订阅方 client.key, 公钥配在这里。
	//
	// 相比密码的两个好处: 鉴权走挑战-应答, 不依赖两端时钟同步(密码方案的 token 带
	// 时间戳, 时差超限即连不上); 服务端只存公钥, 配置泄露也无法用于登录。
	Key     string `yaml:"key"`
	Disable bool   `yaml:"disable"` //true 时该账号停用: 鉴权直接拒绝, 不用删配置/改密码就能临时停掉某个订阅端
}

// WsServer 服务端(tunnel侧)websocket配置。配了 server.listen 才起服务。
type WsServer struct {
	Listen  string          `yaml:"listen"`  //websocket 监听地址
	Users   []ServerUser    `yaml:"users"`   //鉴权账号数组, 每条 {user, pass, disable}, 不同订阅方各用各的账号
	AllowIP []string        `yaml:"allowIP"` //可接入来源IP(CIDR/单IP), 为空不限制; 按真实TCP来源判定; 同时约束 websocket 订阅方接入与裸TCP转发入口(forward.listen)的来源
	Forward []ServerForward `yaml:"forward"` //裸TCP端口转发入口(见 ServerForward)
}

// LookupUser 按订阅方发来的 user 查 users 里的账号。found=false 表示查无此人;
// found=true 时调用方还要看返回的 ServerUser.Disable 决定是否放行(停用的账号查得到但不该通过鉴权)。
func (s WsServer) LookupUser(user string) (ServerUser, bool) {
	if user == "" {
		return ServerUser{}, false
	}
	for _, u := range s.Users {
		if u.User == user {
			return u, true
		}
	}
	return ServerUser{}, false
}

// WsClient 客户端(proxy侧)websocket配置。未配 connect / user / email 则不发起连接。
type WsClient struct {
	Connect   string          `yaml:"connect"`   //连接的 ip:端口
	Host      string          `yaml:"host"`      //connect 的域名(Host头)
	User      string          `yaml:"user"`      //认证用户(发给服务端)
	Pass      string          `yaml:"pass"`      //密码(与 key 二选一)
	Key       string          `yaml:"key"`       //Ed25519 私钥(base64), 与 pass 二选一; 两者都配时优先用 key。见 ServerUser.Key
	Email     string          `yaml:"email"`     //Email用于定位用户, 不鉴权
	Subscribe []Subscribe     `yaml:"subscribe"` //订阅头部信息
	Forward   []ClientForward `yaml:"forward"`   //裸TCP端口转发目标(见 ClientForward)

	// 以下两项为 QUIC 直连(A<->C 不经服务端转发数据), 见 ClientDirect。
	// 两者互相独立: 只想被别人直连就单开 directAccept, 只想主动直连别人就单配 direct。
	DirectAccept bool           `yaml:"directAccept"` //true 时起 QUIC 监听并把端点通告给服务端, 允许其它订阅方直连自己
	Direct       []ClientDirect `yaml:"direct"`       //本机直连入口规则(见 ClientDirect)
}

// Websocket 会话订阅通信, 按角色分 server(服务端)/ client(客户端)两块配置。
type Websocket struct {
	Server  WsServer   `yaml:"server"`  //服务端(tunnel侧)
	Client  WsClient   `yaml:"client"`  //客户端(proxy侧), 兼容单 server 的旧写法
	Clients []WsClient `yaml:"clients"` //客户端(proxy侧), 同时订阅多台 server 时每台一个独立配置块
}

// ClientList 汇总要连接的 server 列表。配了 clients 用 clients; 否则退化为
// Client 包装成的单元素列表(Client.Connect 为空则不发起连接, 返回 nil)。
func (w Websocket) ClientList() []WsClient {
	if len(w.Clients) > 0 {
		return w.Clients
	}
	if w.Client.Connect == "" {
		return nil
	}
	return []WsClient{w.Client}
}

// Default 域名
type Default struct {
	Match     string `yaml:"match"`     //默认域名比对
	Target    string `yaml:"target"`    //http默认访问策略
	DNS       string `yaml:"dns"`       //默认的DNS服务器
	Proxy     string `yaml:"proxy"`     //全局代理服务器
	TCPTarget string `yaml:"tcpTarget"` //tcp默认访问策略: auto/local/remote/deny/localport
	//黑洞哨兵IP: 系统hosts或本配置里把域名指向它(如 192.0.0.0 example.com), 达成"无代理时本地不可达(拦截)、
	//有代理时强制走代理并由下级远程DNS解析"。不配默认 192.0.0.0; 设为 off/none/disable 关闭。命中该IP的连接
	//强制按 target=remote + dns=remote 处理(见 proto/tunnel.go handshake), 并在 windows WinDivert 捕获阶段
	//强制拦截进引擎(不受 bypassPrivate 影响)。
	BlackholeIP string `yaml:"blackholeIP"`
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
//	excludeNics/device       仅 linux 且 mode=bypass(物理网卡绕行, 见 Tun 注释)
type TunOS struct {
	Name          string   `yaml:"name"`          //网卡名, linux默认anytun0, darwin默认utunN
	Addr          string   `yaml:"addr"`          //接口地址CIDR, 如 10.9.0.1/24
	MTU           uint32   `yaml:"mtu"`           //MTU, 默认1500
	AutoRoute     *bool    `yaml:"autoRoute"`     //不配置默认true自动加路由; 显式false只打印命令
	BypassIPs     []string `yaml:"bypassIPs"`     //这些目标直连(不代理): linux/darwin加/32路由; windows排除捕获
	BypassPrivate *bool    `yaml:"bypassPrivate"` //仅windows: 不配默认true=私网/LAN/链路本地(含虚拟机/VM网段)一律直连不进引擎; 显式false则私网80/443进引擎按router规则。loopback始终直连
	BlockQUIC     *bool    `yaml:"blockQUIC"`     //不配置默认true: drop命中hosts(配ip/deny)域名的UDP443, 逼QUIC回退TCP
	ExcludeProcs  []string `yaml:"excludeProcs"`  //仅windows: 这些进程(exe名, 如openvpn.exe)的出向不重定向
	InboundPorts  []int    `yaml:"inboundPorts"`  //仅darwin: 需pf放行回包的入站TCP端口(如22)
	WindivertDir  string   `yaml:"windivertDir"`  //仅windows: WinDivert.dll+WinDivert64.sys 所在目录, 空=exe同目录(可用它把驱动放到无空格/中文的干净路径)
	ExcludeNics   []string `yaml:"excludeNics"`   //仅linux且mode=bypass: 采集直连子网时排除的网卡名(通常填另一进程的TUN网卡名)
	Device        string   `yaml:"device"`        //仅linux且mode=bypass: 手动指定用于绑定的物理网卡名, 为空则回退defaultRoute自动探测
}

// Tun 虚拟网卡全局代理。
//
// 两种写法(可混用, 系统块优先):
//  1. 扁平(旧写法, 三平台通用): 直接在 tun 下写 name/addr/... 字段。
//  2. 按系统分块(推荐): 在 tun.linux / tun.darwin / tun.windows 下各写该系统的字段,
//     程序按当前系统取对应块整体覆盖扁平字段(见 applyOS)。这样每个系统块里只出现
//     该系统用得到的字段, 避免"某字段在本平台无效"的困惑。
//
// mode=bypass(物理网卡绕行, 不建TUN网卡, 仅Linux) 也复用本块的 tun.linux.excludeNics /
// tun.linux.device: 本机已有另一个 anyproxy TUN 进程时, 让本进程出向连接绑定物理网卡,
// 逃出对方 TUN 的 0/1 路由, 避免 target=local 请求被再次劫持成死循环。与 tun 模式互斥。
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

// GeoFile 一个 geoip/geosite 数据文件及要加载的类别(顶层 geoip:/geosite: 用)。
// 配了才启用 hosts 的 geoip:/geosite: 匹配。文件按扩展名区分:
//   - .dat : protobuf 数据集(一个文件多类别)。cats 列出要用的类别; cats 留空=加载文件内全部类别。
//   - 其它 : 纯文本列表(整个文件即一个类别), cats 必须恰好给一个类别名。
//     geoip 每行 CIDR/IP; geosite 每行域名, 支持 full:/domain:/keyword:/regexp: 前缀
//     (无前缀默认 domain 后缀), # 注释, keyword/regexp 丢弃当国外。
type GeoFile struct {
	File string   `yaml:"file"` //数据文件路径(.dat 或文本列表)
	Cats []string `yaml:"cats"` //要加载的类别; .dat 留空=全部类别; 文本列表须恰好一个
}

// LoopGuard 死循环兜底熔断器。
// 同机 A(mode=tun)+B(mode=bypass, 仅Linux) 部署时, 正常应由 bypass 从路由层根治环路;
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
	Tun       Tun       `yaml:"tun"`       //TUN虚拟网卡全局代理(mode=tun); mode=bypass 复用 tun.linux.excludeNics/device
	LoopGuard LoopGuard `yaml:"loopGuard"` //死循环兜底熔断器
	GeoIP     []GeoFile `yaml:"geoip"`     //geoip 数据文件列表(一个文件可多类别; cats 空=全部)
	GeoSite   []GeoFile `yaml:"geosite"`   //geosite 数据文件列表
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
		// 按当前系统把 tun.<os> 分块压平进扁平字段, 消费者无需感知分块
		cnf.Tun.applyOS(runtime.GOOS)
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
