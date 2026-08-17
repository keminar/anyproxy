package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/logging"
	"github.com/keminar/anyproxy/nat"
	"github.com/keminar/anyproxy/proto"
	"github.com/keminar/anyproxy/tun"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/daemon"
	"github.com/keminar/anyproxy/utils/geo"
	"github.com/keminar/anyproxy/utils/help"
	"github.com/keminar/anyproxy/utils/rss"
	"github.com/keminar/anyproxy/utils/systune"
	"github.com/keminar/anyproxy/utils/tools"
)

var (
	gListenAddrPort  string
	gProxyServerSpec string
	gConfigFile      string
	gWebsocketListen string
	gWebsocketConn   string
	gMode            string
	gHelp            bool
	gDebug           int
	gPprof           string
	gVersion         bool
	gGeoExtract      bool
	gGeoIn           string
	gGeoCat          string
	gGeoOut          string
	gCheck           bool
	gCheckFix        bool
)

func init() {
	flag.Usage = help.Usage
	flag.StringVar(&gListenAddrPort, "l", "", "listen address of socks5 and http proxy")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use")
	flag.StringVar(&gConfigFile, "c", "", "Config file path, default is router.yaml")
	flag.StringVar(&gWebsocketListen, "ws-listen", "", "Websocket address and port to listen on")
	flag.StringVar(&gWebsocketConn, "ws-connect", "", "Websocket Address and port to connect")
	flag.StringVar(&gMode, "mode", "", "Run mode: proxy (default) | tunnel | tun (build TUN NIC, needs admin/root) | bypass (bind physical NIC only, escape another process's TUN) | tcpcopy (forward every connection to tcpcopy.ip:port)")
	flag.IntVar(&gDebug, "debug", 0, "debug mode (0, 1, 2, 3)")
	flag.StringVar(&gPprof, "pprof", "", "pprof port, disable if empty")
	flag.BoolVar(&gVersion, "v", false, "Show build version")
	flag.BoolVar(&gHelp, "h", false, "This usage message")
	// geo 数据集离线提取(提取完即退出, 不启代理): 从全量 geoip.dat/geosite.dat 提取
	// 指定类别成小文件随发布携带。geoip 与 geosite 外层格式一致, 同一命令通用。
	flag.BoolVar(&gGeoExtract, "geo-extract", false, "Extract categories from a geoip.dat/geosite.dat and exit")
	flag.StringVar(&gGeoIn, "geo-in", "", "geo-extract: source geoip.dat/geosite.dat")
	flag.StringVar(&gGeoCat, "geo-cat", "", "geo-extract: comma-separated categories to keep, e.g. cn,google")
	flag.StringVar(&gGeoOut, "geo-out", "", "geo-extract: output .dat path")
	// 系统调优检查/应用(仅 Linux): 对照建议的 sysctl/ulimit 报告, 或一键写入并应用。
	flag.BoolVar(&gCheck, "check", false, "Check system tuning (sysctl/ulimit) against recommendations and exit")
	flag.BoolVar(&gCheckFix, "check-fix", false, "Apply recommended sysctl tuning (needs root) and exit")
}

func main() {
	// 尽早设置 GODEBUG=madvdontneed=1 并 exec 重启自身，使归还的内存立即扣 RSS。
	// 必须在任何堆分配/goroutine 之前，保证 runtime 读到该开关(幂等，二次进入直接跳过)。
	rss.Ensure()

	flag.Parse()
	if gHelp {
		flag.Usage()
		return
	}
	if gVersion {
		help.ShowVersion()
		return
	}
	// geo 数据集离线提取: 生成精简 .dat 后退出, 不启动代理。
	if gGeoExtract {
		if gGeoIn == "" || gGeoCat == "" || gGeoOut == "" {
			log.Fatalln("geo-extract 需要 -geo-in -geo-cat -geo-out")
		}
		if err := geo.Extract(gGeoIn, strings.Split(gGeoCat, ","), gGeoOut); err != nil {
			log.Fatalln("geo-extract:", err)
		}
		fmt.Printf("geo-extract: 已从 %s 提取类别 [%s] 写入 %s\n", gGeoIn, gGeoCat, gGeoOut)
		return
	}
	// 系统调优检查/一键应用(仅 Linux), 完成即退出。
	if gCheckFix {
		systune.Apply()
		return
	}
	if gCheck {
		systune.Check()
		return
	}

	config.SetDebugLevel(gDebug)
	conf.LoadAllConfig(gConfigFile)

	// 检查配置是否存在
	if conf.RouterConfig == nil {
		time.Sleep(60 * time.Second)
		os.Exit(2)
	}

	cmdName := "anyproxy"
	defLogDir := fmt.Sprintf("%s%s%s%s", conf.AppPath, string(os.PathSeparator), "logs", string(os.PathSeparator))
	logDir := config.IfEmptyThen(conf.RouterConfig.Log.Dir, defLogDir, "")
	if _, err := os.Stat(logDir); err != nil {
		log.Println(err)
		time.Sleep(60 * time.Second)
		os.Exit(2)
	}

	envRunMode := fmt.Sprintf("%s_run_mode", cmdName)
	fd := logging.ErrlogFd(logDir, cmdName)
	// 是否后台运行
	daemon.Daemonize(envRunMode, fd)

	gListenAddrPort = config.IfEmptyThen(gListenAddrPort, conf.RouterConfig.Listen, ":3000")
	gListenAddrPort = tools.FillPort(gListenAddrPort)
	config.SetListenPort(gListenAddrPort)

	var writer io.Writer
	// 前台执行，daemon运行根据环境变量识别
	if daemon.IsForeground(envRunMode) {
		// 同时输出到日志和标准输出
		writer = io.Writer(os.Stdout)
	}

	logging.SetDefaultLogger(logDir, fmt.Sprintf("%s.%d", cmdName, config.ListenPort), true, 3, writer)
	// 设置代理。命令行 -p 为固定值(记入 ProxyCmdline, 优先于配置);
	// 未指定 -p 时请求侧实时读取 default.proxy, 使其支持热加载。
	config.ProxyCmdline = gProxyServerSpec
	// 启动时按「-p > default.proxy」解析首个代理, 供 tun_windows 排除捕获与日志用
	config.SetProxyServer(config.IfEmptyThen(config.ProxyCmdline, conf.RouterConfig.Default.Proxy, ""))

	// 加载 geoip/geosite 数据集(配了才加载, 供 hosts 的 geoip:/geosite: 匹配)
	loadGeo()

	// 调试模式
	if len(gPprof) > 0 {
		go func() {
			gPprof = tools.FillPort(gPprof)
			//浏览器访问: http://:5001/debug/pprof/
			log.Println("Starting pprof debug server ...")
			// 这里不要使用log.Fatal会在平滑重启时导致进程退出
			// 因为http server现在没办法一次平滑重启，会报端口冲突，可以通过多次重试来启动pprof
			for i := 0; i < 10; i++ {
				log.Println(http.ListenAndServe(gPprof, nil))
				time.Sleep(10 * time.Second)
			}
		}()
	}

	// websocket 服务端
	gWebsocketListen = config.IfEmptyThen(gWebsocketListen, conf.RouterConfig.Websocket.Listen, "")
	if gWebsocketListen != "" {
		gWebsocketListen = tools.FillPort(gWebsocketListen)
		go nat.NewServer(&gWebsocketListen)
		// 服务端裸TCP端口转发入口(内网穿透)
		go nat.StartForward(conf.RouterConfig.Websocket.Forward)
	}
	// websocket 客户端
	gWebsocketConn = config.IfEmptyThen(gWebsocketConn, conf.RouterConfig.Websocket.Connect, "")
	if gWebsocketConn != "" {
		gWebsocketConn = tools.FillPort(gWebsocketConn)
		// 订阅方裸TCP转发目标映射(端口->写死target)
		nat.SetLocalForward(conf.RouterConfig.Websocket.Forward)
		go nat.ConnectServer(&gWebsocketConn)
	}

	// TUN 虚拟网卡全局代理
	// 使用可取消的 context，在收到 SIGINT/SIGTERM 时关闭设备，
	// 确保 wintun 虚拟网卡在进程退出前被清理。
	tunCtx, tunCancel := context.WithCancel(context.Background())
	var tunWG sync.WaitGroup
	// 解析运行模式: 命令行 -mode > 配置 mode > proxy
	mode := config.IfEmptyThen(gMode, conf.RouterConfig.Mode, "proxy")
	switch mode {
	case "tun":
		// autoRoute 不配置时默认 true(自动加路由); 显式设 false 才关闭
		autoRoute := true
		if conf.RouterConfig.Tun.AutoRoute != nil {
			autoRoute = *conf.RouterConfig.Tun.AutoRoute
		}
		tunCfg := tun.Config{
			Name:         conf.RouterConfig.Tun.Name,
			Addr:         conf.RouterConfig.Tun.Addr,
			MTU:          conf.RouterConfig.Tun.MTU,
			AutoRoute:    autoRoute,
			ExcludeProcs: conf.RouterConfig.Tun.ExcludeProcs,
			InboundPorts: conf.RouterConfig.Tun.InboundPorts,
			WindivertDir: conf.RouterConfig.Tun.WindivertDir,
			// 所有以 IP 指定的上级代理默认并入 bypassIPs(直连例外/排除捕获)，
			// 避免 anyproxy→上级代理 的连接被自己的 TUN/WinDivert 再抓走成环路
			BypassIPs: withProxyBypassIPs(conf.RouterConfig.Tun.BypassIPs),
			// 仅 Windows(WinDivert): 私网/LAN/链路本地一律直连。不配默认 true(与
			// linux/darwin 直连子网不进 TUN 的行为一致); 显式 false 才让私网 80/443 进引擎
			BypassPrivate: conf.RouterConfig.Tun.BypassPrivate == nil || *conf.RouterConfig.Tun.BypassPrivate,
		}
		tunWG.Add(1)
		go func() {
			defer tunWG.Done()
			if err := tun.Run(tunCtx, tunCfg); err != nil {
				log.Println("tun run err:", err)
			}
		}()
	case "bypass":
		// 仅 Linux 支持: 绑定物理网卡绕行, 逃出同机另一个 TUN 进程的 0/1 路由。
		// macOS/Windows 已移除该模式(见 tun/bypass_other.go)。
		if err := tun.InitBypassOnly(tun.BypassConfig{
			ExcludeNics: conf.RouterConfig.Bypass.ExcludeNics,
			Device:      conf.RouterConfig.Bypass.Device,
		}); err != nil {
			log.Printf("mode=bypass unsupported: %v; fallback proxy", err)
			mode = "proxy"
			break
		}
		// 退出/平滑重启前清理 bypass 加的 /32 例外路由(复用 tunCtx 取消信号 + tunWG 等待)
		tunWG.Add(1)
		go func() {
			defer tunWG.Done()
			<-tunCtx.Done()
			tun.CleanupBypass()
		}()
	case "proxy", "tunnel":
		// 不接管全局流量，仅按监听端口收流
	case "tcpcopy":
		// 端口转发: 不接管全局流量, 每个连接改投到 tcpcopy.ip:port(见 proto/request.go)。
		// 命令行 -mode tcpcopy 时配置里可能没有 mode 字段, 这里补上归一(配置文件写 mode:
		// tcpcopy 时已在 LoadRouterConfig 归一)。
		conf.RouterConfig.TcpCopy.Enable = true
	default:
		log.Printf("unknown mode %q, expect proxy|tunnel|tun|bypass|tcpcopy, fallback proxy\n", mode)
		mode = "proxy"
	}

	// tcp   同是监听IPv4 和 IPv6
	// tcp4  仅监听使用IPv4
	// tcp6  仅监听使用IPv6
	network := "tcp"
	if conf.RouterConfig.Network != "" {
		network = conf.RouterConfig.Network
	}
	// tunnel 为服务端(tunneld); proxy/tun/bypass 均为客户端
	handler := proto.ClientHandler
	if mode == "tunnel" {
		handler = proto.ServerHandler
	}
	server := grace.NewServer(gListenAddrPort, handler, network)
	registerTUNCleanup(server, tunCancel, &tunWG)
	server.ListenAndServe()
}

// registerTUNCleanup 注册 SIGHUP/SIGINT/SIGTERM 的 PreSignal 钩子，
// 在 grace server fork 子进程或关闭 TCP 监听之前，先取消 TUN context 并等待设备关闭。
//   - SIGHUP(平滑重启): fork 前主动释放 TUN 设备，让新进程能立即接管，
//     否则新进程创建同名设备会 EBUSY(TUN 设备独占)。
//   - SIGINT/SIGTERM(退出): 确保 TUN 虚拟网卡在进程退出前被清理。
//
// PreSignal 钩子在 fork()/shutdown() 之前执行，保证释放先于接管/退出。
func registerTUNCleanup(server *grace.Server, cancel context.CancelFunc, wg *sync.WaitGroup) {
	cleanup := func() {
		cancel()
		wg.Wait()
	}
	server.RegisterSignalHook(grace.PreSignal, syscall.SIGHUP, cleanup)
	server.RegisterSignalHook(grace.PreSignal, syscall.SIGINT, cleanup)
	server.RegisterSignalHook(grace.PreSignal, syscall.SIGTERM, cleanup)
}

// withProxyBypassIPs 把「所有以 IP 字面量指定的上级代理」并入 base(bypassIPs)后返回。
// 覆盖全局代理(-p / default.proxy, 取 config.ProxyServer)与各 hosts[].proxy(支持多代理
// 逗号分隔及 " last"/" deny" 后缀)。只收 IPv4 字面量; 域名指定的代理无法在此确定 IP, 跳过。
// 目的: 让 anyproxy 到上级代理的连接默认直连(不被自己的 TUN/WinDivert 抓走成环路)。
func withProxyBypassIPs(base []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(base))
	for _, s := range base {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add := func(host string) {
		host = strings.TrimSpace(host)
		ip := net.ParseIP(host)
		// 回环上级代理无需并入: WinDivert 对 loopback 一律直连, linux/darwin 的
		// /32 直连路由对 127.x 也无意义, 加进去只是冗余噪音。
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, host)
	}
	// 全局代理(命令行 -p / default.proxy 解析后的服务器地址)
	add(config.ProxyServer)
	// 各 host 的自定义代理
	for _, h := range conf.RouterConfig.Hosts {
		p := strings.TrimSpace(h.Proxy)
		if p == "" {
			continue
		}
		// 去掉尾部 " last" / " deny" 操作后缀
		if i := strings.LastIndex(p, " "); i >= 0 {
			if suf := p[i+1:]; suf == "last" || suf == "deny" {
				p = p[:i]
			}
		}
		for _, spec := range strings.Split(p, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			if j := strings.Index(spec, "://"); j >= 0 { // 去 scheme
				spec = spec[j+3:]
			}
			host := spec
			if k := strings.LastIndex(spec, ":"); k >= 0 { // 去端口(IPv6 字面量会解析失败被跳过)
				host = spec[:k]
			}
			add(host)
		}
	}
	return out
}

// loadGeo 按配置加载 geoip/geosite 数据集(配了才加载)。加载失败只记日志、不中断启动;
// 若 hosts 用了 geoip:/geosite: 但对应数据没配/没加载, 该规则永不命中, 给出提示。
func loadGeo() {
	for cat, path := range conf.RouterConfig.Geo.IP {
		if path = strings.TrimSpace(path); path == "" {
			continue
		}
		if err := geo.LoadIP(cat, path); err != nil {
			log.Printf("geo: 加载 geoip:%s <- %s 失败: %v", cat, path, err)
		}
	}
	for cat, path := range conf.RouterConfig.Geo.Site {
		if path = strings.TrimSpace(path); path == "" {
			continue
		}
		if err := geo.LoadSite(cat, path); err != nil {
			log.Printf("geo: 加载 geosite:%s <- %s 失败: %v", cat, path, err)
		}
	}
	if ic, sc := geo.Stat(); ic > 0 || sc > 0 {
		log.Printf("geo: loaded geoip categories=%d, geosite categories=%d", ic, sc)
	}
	// 用了 geoip:/geosite: 规则但数据未就绪时提示
	for _, h := range conf.RouterConfig.Hosts {
		if strings.HasPrefix(h.Name, "geoip:") && !geo.HasIP() {
			log.Printf("geo: 规则 %q 需要 geo.ip 加载 geoip.dat, 当前未加载, 该规则不会命中", h.Name)
		}
		if strings.HasPrefix(h.Name, "geosite:") && !geo.HasSite() {
			log.Printf("geo: 规则 %q 需要 geo.site 加载 geosite.dat, 当前未加载, 该规则不会命中", h.Name)
		}
	}
}
