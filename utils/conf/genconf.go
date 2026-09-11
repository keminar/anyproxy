package conf

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// 配置模板生成(anyproxy -genconf): 新机器上没有配置文件、也记不住字段格式时,
// 先生成一份带注释的骨架再改, 免得对着文档一行行抄。
//
// 模板按运行模式裁剪(-mode, 默认 proxy): 该模式用得到的字段直接给出可用默认值,
// 用不到的只留注释。全量字段说明仍以 conf/router.yaml 与 docs/ 为准, 这里只保证
// "改几个值就能跑"。

// GenModes 支持生成的模式, 与运行时 -mode 取值一致。
var GenModes = []string{"proxy", "tunnel", "tun", "bypass", "tcpcopy"}

// ValidGenMode 是否是可生成的模式名。
func ValidGenMode(mode string) bool {
	for _, m := range GenModes {
		if m == mode {
			return true
		}
	}
	return false
}

// DefaultGenPath 默认生成位置: 程序所在目录下的 conf/router.yaml。
// 与 GetPath 的第一优先级一致, 生成后不带 -c 直接启动就能被找到。
func DefaultGenPath() string {
	return filepath.Join(AppPath, "conf", "router.yaml")
}

// DefaultLogDir 配置里 log.dir 留空时程序实际使用的目录(见 anyproxy.go)。
// 该目录必须已存在, 否则启动即退出, 所以生成配置时顺手建出来。
func DefaultLogDir() string {
	return filepath.Join(AppPath, "logs")
}

// GenerateConfig 按模式生成配置文件内容。
func GenerateConfig(mode string) (string, error) {
	if mode == "" {
		mode = "proxy"
	}
	if !ValidGenMode(mode) {
		return "", fmt.Errorf("unknown mode %q, expect %s", mode, strings.Join(GenModes, "|"))
	}
	var b strings.Builder
	b.WriteString(genHead(mode))
	b.WriteString(genBase(mode))
	b.WriteString(genModeBlock(mode))
	b.WriteString(genRouting(mode))
	b.WriteString(genWebsocket(mode))
	return b.String(), nil
}

// WriteConfigTemplate 把模板写到 path(为空则用 DefaultGenPath), 返回实际写入路径。
// 已存在的文件一律不覆盖: 初始化配置是"新机器第一次跑"的动作, 真要重来自己删掉或
// 用 -c 指个新路径, 比手滑一下把在跑的配置冲掉强。
func WriteConfigTemplate(mode, path string) (string, error) {
	body, err := GenerateConfig(mode)
	if err != nil {
		return "", err
	}
	if path == "" {
		path = DefaultGenPath()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if fileExists(abs) {
		return "", fmt.Errorf("%s already exists, remove it or write elsewhere with -c", abs)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(abs, []byte(body), 0644); err != nil {
		return "", err
	}
	return abs, nil
}

// EnsureLogDir 建出 log.dir 留空时用到的默认日志目录(不存在才建), 返回是否是这次新建的。
// 日志目录不存在时程序会直接退出, 生成配置却不建目录等于留了个必踩的坑。
func EnsureLogDir() (dir string, created bool, err error) {
	dir = DefaultLogDir()
	if fileExists(dir) {
		return dir, false, nil
	}
	if err = os.MkdirAll(dir, 0755); err != nil {
		return dir, false, err
	}
	return dir, true, nil
}

// GenNextSteps 生成后的"接下来干什么", 免得拿到文件还得翻文档。
func GenNextSteps(mode, path string) []string {
	steps := []string{fmt.Sprintf("edit %s, at least change token (16 chars) and confirm listen", path)}
	switch mode {
	case "proxy":
		steps = append(steps, "set default.proxy, or pass -p at startup to point at an upstream proxy")
	case "tunnel":
		steps = append(steps, "on the client side, use -p tunnel://<this host's IP>:<listen> to point here; token must match on both ends")
	case "tun":
		steps = append(steps, "needs admin/root to run; on Windows also put WinDivert.dll and WinDivert64.sys next to the exe (or set tun.windows.windivertDir)")
	case "bypass":
		steps = append(steps, "Linux only; used when another anyproxy TUN process is already running on this host, to escape its 0/1 route")
	case "tcpcopy":
		steps = append(steps, "change tcpcopy.ip/port to the real forwarding target")
	}
	cmd := "anyproxy"
	if DefaultGenPath() != path {
		cmd = fmt.Sprintf("anyproxy -c %s", path)
	}
	return append(steps, "start it: "+cmd)
}

func genHead(mode string) string {
	desc := map[string]string{
		"proxy":   "客户端/代理: 本机起 socks5+http 代理端口, 按 hosts 规则分流",
		"tunnel":  "服务端 tunneld: 带 token 校验, 只处理 anyproxy 客户端过来的请求",
		"tun":     "TUN 虚拟网卡全局代理: 接管整机 TCP 流量(需管理员/root)",
		"bypass":  "物理网卡绕行(仅 Linux): 不建网卡, 只让本进程出向逃出同机另一个 TUN",
		"tcpcopy": "端口转发: 每个连接都改投到 tcpcopy.ip:port, hosts 规则不再生效",
	}[mode]
	return fmt.Sprintf(`# anyproxy 配置模板 (由 anyproxy -genconf -mode %s 生成)
# 模式: %s
#
# 这里只给出本模式用得到的字段, 其余留作注释。全量字段与完整说明见:
#   仓库 conf/router.yaml     带注释的全量样例
#   docs/configuration.md     字段总表        docs/config-examples.md  场景示例
#   docs/cli.md               命令行参数      docs/routing.md          分流规则
#   docs/websocket.md         内网穿透/文件收发
# 改完直接启动: anyproxy -c <本文件路径>; 放在程序目录 conf/router.yaml 下则不用带 -c。

`, mode, desc)
}

func genBase(mode string) string {
	listen := ":3000"
	listenNote := "# 代理监听地址端口, 优先级低于启动传参 -l。填 off 则不起代理监听, 只跑 websocket/tun 等后台服务"
	if mode == "tunnel" {
		listen = ":3001"
		listenNote = "# tunneld 服务端监听地址端口, 客户端用 -p tunnel://<本机IP>:3001 指过来"
	}
	return fmt.Sprintf(`%s
listen: %s

# 日志目录, 必须已存在。留空 = 程序所在目录下的 logs/
log:
  dir:

# 配置文件改动后自动热加载(default/hosts 等即时生效)
watcher: true

# anyproxy 与 tunneld 之间的通信密钥, 必须 16 位。两端必须一致, 请改掉这个默认值
token: anyproxyproxyany

# 允许连接本机监听端口的客户端 IP(单 IP 或 CIDR), 留空不限制
allowIP:
#  - 192.168.1.0/24

# 运行模式, 优先级低于启动传参 -mode
#   proxy 客户端 / tunnel 服务端 / tun 全局代理 / bypass 网卡绕行 / tcpcopy 端口转发
mode: %s
`, listenNote, listen, mode)
}

// genTunBlock TUN 全局代理参数。tun.<os> 是按系统分块的配置(见 conf.Tun 的注释:
// 程序按当前系统取对应块整体覆盖), 生成配置的机器和最终运行的机器通常是同一台
// (这本来就是"新机器初始化配置"这个命令要解决的场景), 所以这里按 runtime.GOOS
// (-genconf 运行时所在的系统, 不是编译时的目标系统——三平台各自的可执行文件本来就
// 只会在对应系统上跑, 两者始终一致)只生成用得到的那一块, 不把另外两个系统的示例也
// 堆进来: 那些字段在这台机器上一个都不会生效, 只会让人误以为要三块都填。
// 真要跨机器复用一份配置模板(如 CI 里统一生成再分发), 手动从 docs/config-examples.md
// 抄另外两块过来即可。
func genTunBlock() string {
	head := `
# TUN 全局代理参数, 按系统分块写(tun.<os>); 这里已按运行 -genconf 的系统(` + runtime.GOOS + `)
# 只生成对应的这一块——其它系统的块在这台机器上不会生效, 也就不在模板里列出。
# 注意: 以 IP 指定的上级代理会自动并入 bypassIPs; 以域名指定的无法在此确定 IP,
#       仍需手工把 IP 填进 bypassIPs, 否则 anyproxy 到上级代理的连接会被自己抓走成环路。
tun:
`
	switch runtime.GOOS {
	case "linux":
		return head + `  linux:
    name: anytun0            # 网卡名
    addr: 10.9.0.1/24        # 接口地址 CIDR
    mtu: 1500
    autoRoute: true          # 默认 true 自动加路由; false 只打印命令自己执行
    blockQUIC: true          # drop 命中 hosts 域名的 UDP 443, 逼 QUIC 回退 TCP
    bypassIPs:               # 这些目标直连(自动加 /32 路由): 上级代理 / VPN 服务器 IP
    #  - 192.168.199.1
`
	case "darwin":
		return head + `  darwin:
    addr: 10.9.0.1/24
    autoRoute: true
    blockQUIC: true
    bypassIPs:
    #  - 192.168.199.1
    inboundPorts:            # 需放行回包的入站 TCP 端口(如外网 SSH 22), 用 pf reply-to, 需 root
    #  - 22
`
	case "windows":
		return head + `  windows:
    blockQUIC: true
    bypassPrivate: true      # 私网/LAN 一律直连不进引擎; 要代理某个私网目标才改 false
    #windivertDir:           # WinDivert.dll+WinDivert64.sys 所在目录, 留空 = exe 同目录
    bypassIPs:               # 这些目标"排除捕获"直连
    #  - 203.0.113.10
    excludeProcs:            # 这些进程的出向一律不重定向(逃 OpenVPN 等同机隧道死循环)
    #  - openvpn.exe
`
	default:
		// 本仓库只往 linux/darwin/windows(含 alpine/mips, 都是 GOOS=linux)出包(见
		// scripts/build.sh), 正常不会走到这里; 万一真出现未知系统, 三块都给, 好过
		// 生成一个连 tun 都配不了的空块。
		return head + `  linux:
    name: anytun0
    addr: 10.9.0.1/24
    autoRoute: true
    blockQUIC: true
    bypassIPs:
  darwin:
    addr: 10.9.0.1/24
    autoRoute: true
    blockQUIC: true
    bypassIPs:
  windows:
    blockQUIC: true
    bypassPrivate: true
    bypassIPs:
`
	}
}

func genModeBlock(mode string) string {
	switch mode {
	case "tun":
		return genTunBlock() + `
# 死循环兜底熔断器: 全局在传连接数达 minActive 后, 单个 host:port 占比超 ratio% 即拒绝其新连接。
# 需 ulimit -n 远大于 minActive*2(每连接约 2 个 fd), 否则会先撞 too many open files。
loopGuard:
#  minActive: 1000           # 0 = 用内置默认 1000; <0 = 关闭
#  ratio: 80                 # 百分比阈值, <=0 用默认 80
`
	case "bypass":
		// bypass 本身仅 Linux 支持(见 anyproxy.go: 非 Linux 上启动时会打日志退回
		// proxy)。跟 tun 一样按运行 -genconf 的系统裁剪——在非 Linux 上生成一段
		// linux 专属、这台机器永远用不上的 tun.linux 示例没有意义, 只留一句说明。
		if runtime.GOOS != "linux" {
			return fmt.Sprintf("\n# mode: bypass 仅 Linux 支持, 在 %s 上不生效(启动时会打日志退回 proxy 模式),\n"+
				"# 没有可生成的示例; 到 Linux 机器上再用 -genconf -mode bypass 生成。\n", runtime.GOOS)
		}
		return `
# mode=bypass 只复用 tun.linux 里的这两项(仅 Linux 生效, 不建虚拟网卡):
tun:
  linux:
    excludeNics:             # 采集直连子网时排除的网卡名, 通常填另一进程的 TUN 网卡名
    #  - anytun0
    device:                  # 手动指定绑定用的物理网卡名, 留空则自动探测默认路由网卡
    #  eth0
`
	case "tcpcopy":
		return `
# 端口转发目标: 本机 listen 收到的每个连接都改投到这里。
# 开启后 hosts 域名规则不再生效, allowIP 仍有效。
tcpcopy:
  ip: 127.0.0.1
  port: 3306
`
	}
	return ""
}

func genRouting(mode string) string {
	switch mode {
	case "tcpcopy":
		// 端口转发模式下 default/hosts 都不参与决策, 写出来只会让人以为配了有用。
		return ""
	case "tunnel":
		return `
# 出口策略。tunneld 收到的请求由这台机器发出, 一般全部本地直连。
default:
  dns: local
  target: local
  tcpTarget: local
  match: equal
  # 这台机器再往上还有一级代理时填这里(支持逗号分隔多代理 + 末尾 local/deny 后缀)
  proxy:

# 域名规则(可热加载), 服务端一般用来拦掉不许经本机出去的域名
hosts:
#  - name: "*doubleclick.net"
#    target: deny
`
	}
	return `
# 默认出口策略(可热加载), hosts 未命中时用这里
default:
  # DNS 解析位置: local 本机解析, remote 交给下级代理远程解析(仅 target=remote 有效)
  dns: local
  # http(s) 出口: local 本机直连, remote 走代理, deny 拒绝, auto 本机连不通再走代理
  target: auto
  # 裸 TCP 出口: local / remote / deny / auto, 或 localport(命中 localPort 走本地, 其余走代理)
  tcpTarget: remote
  # tcpTarget=localport 时这些端口走本地直连; 不配默认 21(ftp)/22(ssh), 配了就以此为准
  #localPort:
  #  - 22
  # name 无星号且未配 match 时的比对方式: equal 完全相等, contain 包含
  match: equal
  # 全局上级代理, 优先级低于启动传参 -p。支持 tunnel:// socks5:// http://, 不写前缀按 tunnel://
  # 可逗号分隔多个(依次取第一个连得通), 末尾加 local/deny 表示全都连不通时直连 / 拒绝
  #proxy: socks5://127.0.0.1:10000, http://127.0.0.1:8888 local
  proxy:

# 域名规则(可热加载), 自上而下匹配, 命中即止。
# name 通配: "*x" 后缀一致, "x*" 前缀一致, "*x*" 包含, 无星号按 default.match;
#            也支持 geoip:cn / geosite:cn(需在下面 geoip:/geosite: 里加载数据集)
hosts:
#  - name: "*google.com"      # 后缀匹配: 走代理, 并由下级代理远程解析 DNS
#    target: remote
#    dns: remote
#    proxy: tunnel://10.2.2.2:3001
#  - name: "*doubleclick.net" # 直接拒绝
#    target: deny
#  - name: dev.example.com    # 换 IP + 换端口, 并限制哪些客户端能访问
#    ip: 127.0.0.1
#    port:
#      - from: 80
#        to: 8080
#    allowIP:
#      - 172.17.0.12

# geoip/geosite 数据集, 配了才能在 hosts 里用 geoip:xx / geosite:xx 规则。
# .dat 为 protobuf 数据集(cats 留空 = 该文件全部类别), 其它扩展名按纯文本列表处理(cats 恰好一个)。
# 大文件可先离线提取: anyproxy -geo-extract -geo-in geosite.dat -geo-cat cn -geo-out geosite-cn.dat
#geoip:
#  - file: ./geoip-cn.dat
#    cats: [cn]
#geosite:
#  - file: ./geosite-cn.dat
#    cats: [cn]
`
}

// genWebsocket 生成 websocket 内网穿透段。server(服务端角色)/client(订阅端角色)
// 是彼此独立的两块, 跟 -mode 没有从属关系——mode=proxy 的机器一样能同时开
// websocket.server 接别人连进来, mode=tunnel 的机器也一样能同时开 websocket.client
// 去连别的服务端(见 docs/websocket.md「两个角色」)。
//
// 模板按 -mode 给出的默认角色只是"大概率用得到"的那一个(tunnel -> server,
// 其它 -> client), 生效、可直接改; 另一个角色仍然完整给出、只是整段注释掉——
// 不这样的话没人会知道这个功能还能反过来用。两者共享同一个 websocket: 顶层键,
// 不能像别的字段那样简单留空, 所以用 commentOutBlock 整段打注释。
func genWebsocket(mode string) string {
	if mode == "tcpcopy" || mode == "bypass" {
		return ""
	}
	server := genWebsocketServer()
	client := genWebsocketClient()
	head := "\n# 内网穿透(websocket): server(服务端角色)/client(订阅端角色)彼此独立, 跟 -mode 无关,\n" +
		"# 想用哪个就打开哪个, 也可以同时开两个。详见 docs/websocket.md\nwebsocket:\n"
	if mode == "tunnel" {
		return head + server + commentOutBlock(client)
	}
	return head + commentOutBlock(server) + client
}

// genWebsocketServer websocket 服务端角色一整块(2 空格缩进, 顶格是 "server:")。
func genWebsocketServer() string {
	return `  server:
    # 监听地址端口, 订阅方的 client.connect 指过来
    listen:
    # 鉴权账号, 每条 user + (pass 或 key)。pass 至少 18 位且要有字母和数字, 不达标的账号
    # 加载时会被自动停用; key 是 anyproxy -genkey 生成的公钥(推荐: 不依赖两端时钟, 只存公钥)
    users:
    #  - user: someone
    #    pass:
    #    key:
    #    disable: false
    # 可接入来源 IP 白名单(CIDR/单 IP), 留空不限制; loopback 始终放行
    allowIP:
    #  - 172.17.0.0/16
    # 端口转发入口: 在本机 listen 收连接, 转给该 email 的订阅方, 由对方按端口查它的 client.forward
    # listen 可加协议前缀 tcp://(默认, 可不写) / udp:// / both://, both 适合 RDP(TCP 3389 + UDP 3389)
    forward:
    #  - listen: "tcp://:2222"
    #    email: someone@example.com
`
}

// genWebsocketClient websocket 订阅端角色一整块(2 空格缩进, 顶格是 "client:")。
func genWebsocketClient() string {
	return `  client:
    # 服务端 ip:端口
    connect:
    # connect 的域名(Host 头), 走域名/反代时填
    host:
    # 账号, 与服务端 websocket.server.users 里的一条对应
    user:
    # 密码(与 key 二选一), 服务端要求至少 18 位且要有字母和数字; 强度校验只在服务端做,
    # 这里不达标本机也照样会拿去发起连接(方便老服务端场景), 但服务端会拒绝鉴权
    pass:
    # 私钥(与 pass 二选一, 都配时用 key), anyproxy -genkey 生成, 对应公钥配到服务端 users[].key
    key:
    # 用于定位本订阅方, 不参与鉴权
    email:
    # 订阅头部信息
    subscribe:
    #  - key:
    #    val:
    # 裸 TCP 落地表: 服务端(或直连)按 port 找到这里, dial 写死的 target; 未列出的 port 一律拒绝
    forward:
    #  - port: 2222
    #    target: 127.0.0.1:22
    # 允许别的订阅方 QUIC 直连本机(数据不经服务端), 监听按需起, 平时不占端口
    directAccept: false
    # 本机直连入口: 在 listen 收连接, 直接送给 email 对应的订阅方, 由对方按 forwardPort 查它的 forward
    # listen 可加协议前缀 tcp://(默认, 可不写) / udp:// / both://, both 适合 RDP(TCP 3389 + UDP 3389)
    direct:
    #  - listen: "both://:13389"
    #    email: someone@example.com
    #    forwardPort: 3389  # 选对方 forward[] 里哪条规则, 不是内网目标端口; 对方没配这个端口就拒绝(白名单), 别人不能靠瞎填端口探到对方的其它转发目标
    # 直连(QUIC)默认吃 quic-go 对 UDP 的批量收发/ECN 优化; 极少数机器上(常见于某些
    # 网卡驱动/虚拟网卡)这条优化本身会导致丢包、拥塞窗口涨不起来, 症状是直连传输
    # 明显偏慢且丢包率异常高。不配则跟随命令行 -direct-plain-udp 的全局默认值,
    # 显式配了 true/false 只影响这一条连接
    #directPlainUdp: false
    # 与别人收发文件(anyproxy -send / -recv)的目录, 收和取共用这一份。不配 dir 则收发一律拒绝
    receive:
    #  dir: /data/incoming
    #  readonly: false        # true 时只能被取走, 不接受任何人写入
    #  allow:                 # 留空 = 谁都不接受; uuid 抄对方的 .<配置文件同名>.uuid(隐藏文件), 名单双向生效
    #    - email: someone@example.com
    #      uuid:
    # 上面 subscribe/forward/direct/directAccept/receive 全不配时, 常驻进程会自动跳过
    # 这条配置(只留给 -send/-recv 命令行用), 通常不用管这项; 想强制跳过就设 true
    #sendRecvOnly: false
  # 要同时订阅多台服务端就改用 clients 数组(配了它, 上面的 client 块被忽略), 字段完全相同:
  #clients:
  #  - connect:
  #    user:
  #    pass:
  #    email:
`
}

// commentOutBlock 把一段已经按目标缩进写好的 yaml 片段整段注释掉: 在每一行原有
// 缩进之后插入一个 "#"。用于在模板里完整展示"另一个角色"的示例但不让它生效——
// websocket.server 和 websocket.client 共享同一个 websocket: 顶层键, 没法像别的
// 字段那样简单留空/去掉, 只能整段变注释。空行原样保留。
func commentOutBlock(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l == "" {
			continue
		}
		j := 0
		for j < len(l) && l[j] == ' ' {
			j++
		}
		lines[i] = l[:j] + "#" + l[j:]
	}
	return strings.Join(lines, "\n")
}
